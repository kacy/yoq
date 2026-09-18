const std = @import("std");

const cli = @import("../../lib/cli.zig");
const spec = @import("../spec.zig");
const oci = @import("../../image/oci.zig");
const container = @import("../../runtime/container.zig");
const process = @import("../../runtime/process.zig");
const store = @import("../../state/store.zig");
const net_setup = @import("../../network/setup.zig");
const log = @import("../../lib/log.zig");
const logs = @import("../../runtime/logs.zig");
const watcher_mod = @import("../../dev/watcher.zig");
const gpu_runtime = @import("../gpu_runtime.zig");
const service_runtime = @import("service_runtime.zig");
const startup_runtime = @import("startup_runtime.zig");
const runtime_wait = @import("../../lib/runtime_wait.zig");

const instances = @import("instances.zig");
const ownership = @import("ownership.zig");

const published_ports = @import("../../network/published_ports.zig");

const writeErr = cli.writeErr;

const initial_backoff_ms: u64 = service_runtime.initial_backoff_ms;
const max_backoff_ms: u64 = service_runtime.max_backoff_ms;
const healthy_run_threshold_ns: i128 = service_runtime.healthy_run_threshold_ns;
const restart_poll_ms: u64 = 200;

const PreparedService = struct {
    alloc: std.mem.Allocator,
    img: service_runtime.ServiceImageConfig,
    resolved: oci.ResolvedCommand,
    merged_env: std.ArrayList([]const u8),
    owned_env_start: usize,
    working_dir: []const u8,
    vols: service_runtime.ServiceVolumes,
    net_config: ?net_setup.NetworkConfig,
    gpu_lease: @import("../../gpu/lease.zig").Lease,

    fn init(io: std.Io, orch: anytype, idx: usize) !PreparedService {
        const svc = orch.manifest.services[instances.serviceIndex(orch.manifest.services, idx)];
        const alloc = orch.alloc;

        var img = service_runtime.resolveServiceImageWithIo(io, alloc, svc.image) orelse return error.ImageUnavailable;
        errdefer img.deinit(alloc);

        var resolved = oci.resolveCommand(alloc, img.entrypoint, img.default_cmd, svc.command) catch {
            log.err("failed to resolve command for {s}: out of memory", .{svc.name});
            return error.PreparationFailed;
        };
        errdefer resolved.args.deinit(alloc);

        var merged_env = service_runtime.mergeServiceEnv(alloc, img.image_env, svc.env);
        const owned_env_start = merged_env.items.len;
        errdefer {
            for (merged_env.items[owned_env_start..]) |entry| alloc.free(entry);
            merged_env.deinit(alloc);
        }

        var working_dir = img.working_dir;
        if (svc.working_dir) |wd| working_dir = wd;

        var vols = service_runtime.resolveServiceVolumes(alloc, svc.volumes, orch.manifest.volumes, orch.app_name) catch {
            return error.PreparationFailed;
        };
        errdefer vols.deinit(alloc);

        var gpu_lease = if (svc.gpu) |gpu_spec|
            try @import("../../gpu/lease.zig").Lease.acquireWithMinimum(gpu_spec.count, gpu_spec.model, gpu_spec.vram_min_mb)
        else
            @import("../../gpu/lease.zig").Lease{};
        errdefer gpu_lease.deinit();
        if (gpu_lease.count > 0) {
            var gpu_env: [4096]u8 = undefined;
            const data = try @import("../../gpu/passthrough.zig").generateGpuEnv(gpu_lease.indices[0..gpu_lease.count], &gpu_env);
            try gpu_runtime.appendRequiredEnv(alloc, &merged_env, data);
        }

        const has_health_check = svc.health_check != null;
        const net_config: ?net_setup.NetworkConfig = .{ .skip_dns = has_health_check };

        return .{
            .alloc = alloc,
            .img = img,
            .resolved = resolved,
            .merged_env = merged_env,
            .owned_env_start = owned_env_start,
            .working_dir = working_dir,
            .vols = vols,
            .net_config = net_config,
            .gpu_lease = gpu_lease,
        };
    }

    fn deinit(self: *PreparedService) void {
        self.gpu_lease.deinit();
        self.vols.deinit(self.alloc);
        for (self.merged_env.items[self.owned_env_start..]) |entry| self.alloc.free(entry);
        self.merged_env.deinit(self.alloc);
        self.resolved.args.deinit(self.alloc);
        self.img.deinit(self.alloc);
    }

    fn createContainer(self: *const PreparedService, orch: anytype, idx: usize, id: []const u8, hostname: []const u8) container.Container {
        return .{
            .config = .{
                .id = id,
                .rootfs = self.img.rootfs,
                .command = self.resolved.command,
                .args = self.resolved.args.items,
                .env = self.merged_env.items,
                .working_dir = self.working_dir,
                .user = self.img.user,
                .lower_dirs = self.img.layer_paths,
                .network = self.net_config,
                .hostname = hostname,
                .mounts = self.vols.bind_mounts.items,
                .dev_service_name = if (orch.dev_mode) hostname else null,
                .dev_color_idx = idx,
                .gpu_indices = self.gpu_lease.indices[0..self.gpu_lease.count],
            },
            .status = .created,
            .pid = null,
            .exit_code = null,
            .created_at = std.Io.Clock.real.now(std.Options.debug_io).toSeconds(),
        };
    }
};

pub fn serviceThread(orch: anytype, idx: usize, shutdown_requested: *const std.atomic.Value(bool)) void {
    const svc = orch.manifest.services[instances.serviceIndex(orch.manifest.services, idx)];

    var threaded_io = std.Io.Threaded.init(orch.alloc, .{});
    defer threaded_io.deinit();

    var supervised_id: ?[12]u8 = null;
    defer if (supervised_id) |id| ownership.removeInstance(&id) catch {};

    var prepared = PreparedService.init(threaded_io.io(), orch, idx) catch |err| {
        log.err("failed to prepare service {s}: {}", .{ svc.name, err });
        orch.states[idx].setStatus(.failed);
        return;
    };
    defer prepared.deinit();

    var backoff_ms: u64 = initial_backoff_ms;

    var started_once = false;
    while (!orch.states[idx].stop_requested.load(.acquire) and !shutdown_requested.load(.acquire)) {
        if (!(ownership.isOwner(orch.app_name, svc.name, &orch.supervisor_token) catch false)) break;
        if (supervised_id) |id| ownership.removeInstance(&id) catch {};
        supervised_id = null;
        orch.states[idx].setStatus(.starting);
        var id_buf: [12]u8 = undefined;
        container.generateId(&id_buf) catch {
            writeErr("failed to generate container ID for {s}\n", .{svc.name});
            orch.states[idx].setStatus(.failed);
            return;
        };
        const id = id_buf[0..];
        orch.states[idx].setContainerId(id_buf);

        store.save(.{
            .id = id,
            .rootfs = prepared.img.rootfs,
            .command = prepared.resolved.command,
            .hostname = svc.name,
            .status = "created",
            .pid = null,
            .exit_code = null,
            .app_name = orch.app_name,
            .created_at = std.Io.Clock.real.now(std.Options.debug_io).toSeconds(),
        }) catch {
            orch.states[idx].setStatus(.failed);
            return;
        };

        ownership.registerInstance(orch.app_name, svc.name, &orch.supervisor_token, id) catch |err| {
            log.warn("service {s} lost supervisor ownership: {}", .{ svc.name, err });
            cleanupContainerArtifacts(id);
            orch.states[idx].setStatus(.stopped);
            return;
        };

        supervised_id = id_buf;

        var c = prepared.createContainer(orch, idx, id, svc.name);
        const start_time = std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds();

        c.start() catch {
            cleanupContainerArtifacts(id);
            orch.states[idx].setStatus(.failed);
            return;
        };

        // shutdown can arrive while start is creating the process. recheck here
        // so a stop request cannot join a supervisor waiting on a new child.
        if (orch.states[idx].stop_requested.load(.acquire) or shutdown_requested.load(.acquire) or
            !(ownership.isOwner(orch.app_name, svc.name, &orch.supervisor_token) catch false))
        {
            c.forceStop() catch {};
            _ = c.wait() catch 255;
            cleanupContainerArtifacts(id);
            orch.states[idx].setStatus(.stopped);
            return;
        }

        startup_runtime.refreshServiceRuntimeBindings(
            orch.alloc,
            svc,
            &orch.states[idx],
            if (orch.tls_resources) |resources| resources.backend_registry else null,
        );

        published_ports.publishInstance(orch.alloc, orch.app_name, svc.name, id, svc.ports) catch |err| {
            log.err("failed to publish ports for {s}: {}", .{ svc.name, err });
            c.forceStop() catch {};
            _ = c.wait() catch 255;
            @import("../health.zig").unregisterContainer(id);
            if (svc.ports.len > 0) published_ports.removeInstance(orch.alloc, id) catch |cleanup_err| {
                log.warn("failed to release published ports for {s}: {}", .{ svc.name, cleanup_err });
            };
            cleanupContainerArtifacts(id);
            orch.states[idx].setStatus(.failed);
            return;
        };
        if (started_once) @import("../alerts/runtime.zig").recordRestart(orch.app_name, svc.name, &orch.supervisor_token);
        started_once = true;
        orch.states[idx].setStatus(.running);

        const exit_code = @import("../child_wait.zig").wait(&c, .{ .flag = &orch.states[idx].stop_requested, .shutdown = shutdown_requested });
        @import("../health.zig").unregisterContainer(id);
        if (svc.ports.len > 0) published_ports.removeInstance(orch.alloc, id) catch |err| {
            log.warn("failed to release published ports for {s}: {}", .{ svc.name, err });
        };
        const run_duration_ns = std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds() - start_time;
        cleanupContainerArtifacts(id);

        if (shutdown_requested.load(.acquire) or orch.states[idx].stop_requested.load(.acquire) or
            !(ownership.isOwner(orch.app_name, svc.name, &orch.supervisor_token) catch false)) break;

        if (orch.dev_mode) {
            if (!handleDevModeRestart(orch, idx, svc.name, shutdown_requested)) break;
            continue;
        }

        if (!handleRestartPolicyExit(
            svc,
            exit_code,
            run_duration_ns,
            &backoff_ms,
            shutdown_requested,
            &orch.states[idx].stop_requested,
            orch.app_name,
            &orch.supervisor_token,
        )) break;
    }

    orch.states[idx].setStatus(.stopped);
}

pub fn watcherThread(orch: anytype, w: *watcher_mod.Watcher, shutdown_requested: *const std.atomic.Value(bool)) void {
    var services: [64]usize = undefined;

    while (!shutdown_requested.load(.acquire)) {
        const changed_services = w.waitForChange(&services);
        if (changed_services.len == 0) break;
        if (shutdown_requested.load(.acquire)) break;

        for (changed_services) |service_idx| {
            const svc = orch.manifest.services[service_idx];
            writeErr("change detected in {s}, restarting...\n", .{svc.name});

            for (0..svc.replicas) |replica| {
                const instance = instances.instanceIndex(orch.manifest.services, service_idx, replica);
                const id = orch.states[instance].containerId();
                const record = store.load(orch.alloc, id[0..]) catch |err| {
                    log.debug("watcher: container {s} not found (may have exited): {}", .{ svc.name, err });
                    orch.restart_requested[instance].store(true, .release);
                    continue;
                };
                defer record.deinit(orch.alloc);

                terminateStableProcess(orch, svc.name, id[0..], record.pid);
                orch.restart_requested[instance].store(true, .release);
            }
        }
    }
}

fn cleanupContainerArtifacts(id: []const u8) void {
    logs.deleteLogFile(id);
    container.cleanupContainerDirs(id);
    store.remove(id) catch {};
}

fn handleDevModeRestart(
    orch: anytype,
    idx: usize,
    service_name: []const u8,
    shutdown_requested: *const std.atomic.Value(bool),
) bool {
    if (orch.restart_requested[idx].load(.acquire)) {
        orch.restart_requested[idx].store(false, .release);
        writeErr("restarting {s}...\n", .{service_name});
        return true;
    }

    orch.states[idx].setStatus(.stopped);
    while (!shutdown_requested.load(.acquire) and !orch.states[idx].stop_requested.load(.acquire)) {
        if (!(ownership.isOwner(orch.app_name, service_name, &orch.supervisor_token) catch false)) return false;
        if (orch.restart_requested[idx].load(.acquire)) {
            orch.restart_requested[idx].store(false, .release);
            writeErr("restarting {s}...\n", .{service_name});
            return true;
        }
        if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(@intCast(restart_poll_ms)), "dev restart wait")) return false;
    }
    return false;
}

fn handleRestartPolicyExit(
    svc: spec.Service,
    exit_code: u8,
    run_duration_ns: i128,
    backoff_ms: *u64,
    shutdown_requested: *const std.atomic.Value(bool),
    stop_requested: *const std.atomic.Value(bool),
    app_name: []const u8,
    supervisor_token: []const u8,
) bool {
    const should_restart = switch (svc.restart) {
        .none => false,
        .always => true,
        .on_failure => exit_code != 0,
    };
    if (!should_restart) return false;

    if (run_duration_ns >= healthy_run_threshold_ns) {
        backoff_ms.* = initial_backoff_ms;
    }

    writeErr("{s} exited (code {d}), restarting in {d}ms...\n", .{
        svc.name,
        exit_code,
        backoff_ms.*,
    });

    var slept_ms: u64 = 0;
    while (slept_ms < backoff_ms.*) {
        if (shutdown_requested.load(.acquire) or stop_requested.load(.acquire) or
            !(ownership.isOwner(app_name, svc.name, supervisor_token) catch false)) return false;
        const remaining = backoff_ms.* - slept_ms;
        const sleep_chunk: u64 = @min(remaining, restart_poll_ms);
        if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(@intCast(sleep_chunk)), "restart backoff wait")) return false;
        slept_ms += sleep_chunk;
    }

    if (shutdown_requested.load(.acquire) or stop_requested.load(.acquire)) return false;
    backoff_ms.* = @min(backoff_ms.* * 2, max_backoff_ms);
    return true;
}

fn terminateStableProcess(
    orch: anytype,
    service_name: []const u8,
    id: []const u8,
    pid: ?i32,
) void {
    const running_pid = pid orelse return;
    const verify_record = store.load(orch.alloc, id) catch null;
    if (verify_record) |vr| {
        defer vr.deinit(orch.alloc);
        if (vr.pid == pid) {
            process.terminate(running_pid) catch {
                process.kill(running_pid) catch {};
            };
        } else {
            const new_pid = vr.pid orelse 0;
            log.debug("watcher: PID changed for {s} (was {d}, now {d}), skipping terminate", .{
                service_name,
                running_pid,
                new_pid,
            });
        }
    }
}
