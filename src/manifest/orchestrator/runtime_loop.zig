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
    working_dir: []const u8,
    vols: service_runtime.ServiceVolumes,
    port_maps: std.ArrayList(net_setup.PortMap),
    net_config: ?net_setup.NetworkConfig,
    gpu_indices_buf: [8]u32,
    gpu_indices_len: usize,
    mesh_support: ?gpu_runtime.MeshSupport,

    fn init(io: std.Io, orch: anytype, idx: usize) ?PreparedService {
        const svc = orch.manifest.services[idx];
        const alloc = orch.alloc;

        var img = service_runtime.resolveServiceImageWithIo(io, alloc, svc.image) orelse return null;
        errdefer img.deinit(alloc);

        var resolved = oci.resolveCommand(alloc, img.entrypoint, img.default_cmd, svc.command) catch {
            log.err("failed to resolve command for {s}: out of memory", .{svc.name});
            return null;
        };
        errdefer resolved.args.deinit(alloc);

        var merged_env = service_runtime.mergeServiceEnv(alloc, img.image_env, svc.env);
        errdefer merged_env.deinit(alloc);

        var working_dir = img.working_dir;
        if (svc.working_dir) |wd| working_dir = wd;

        var vols = service_runtime.resolveServiceVolumes(alloc, svc.volumes, orch.manifest.volumes, orch.app_name) catch {
            return null;
        };
        errdefer vols.deinit(alloc);

        var port_maps: std.ArrayList(net_setup.PortMap) = .empty;
        errdefer port_maps.deinit(alloc);
        for (svc.ports) |pm| {
            port_maps.append(alloc, .{
                .host_port = pm.host_port,
                .container_port = pm.container_port,
                .protocol = .tcp,
            }) catch |err| {
                log.warn("failed to add port map: {}", .{err});
            };
        }

        var gpu_indices_buf: [8]u32 = undefined;
        var gpu_indices_len: usize = 0;
        if (svc.gpu) |gpu_spec| {
            const count = @min(gpu_spec.count, gpu_indices_buf.len);
            for (0..count) |i| gpu_indices_buf[i] = @intCast(i);
            gpu_indices_len = count;
            gpu_runtime.appendGpuPassthroughEnv(alloc, &merged_env, gpu_indices_buf[0..count]);
        }

        var mesh_support: ?gpu_runtime.MeshSupport = null;
        errdefer if (mesh_support) |*support| support.deinit();
        if (svc.gpu_mesh) |mesh_spec| {
            mesh_support = gpu_runtime.MeshSupport.init(alloc);
            mesh_support.?.appendEnv(
                alloc,
                &merged_env,
                "127.0.0.1",
                mesh_spec.master_port,
                mesh_spec.world_size,
                0,
                0,
            );
        }

        const has_health_check = svc.health_check != null;
        const net_config: ?net_setup.NetworkConfig = if (port_maps.items.len > 0)
            .{ .port_maps = port_maps.items, .skip_dns = has_health_check }
        else
            .{ .skip_dns = has_health_check };

        return .{
            .alloc = alloc,
            .img = img,
            .resolved = resolved,
            .merged_env = merged_env,
            .working_dir = working_dir,
            .vols = vols,
            .port_maps = port_maps,
            .net_config = net_config,
            .gpu_indices_buf = gpu_indices_buf,
            .gpu_indices_len = gpu_indices_len,
            .mesh_support = mesh_support,
        };
    }

    fn deinit(self: *PreparedService) void {
        if (self.mesh_support) |*support| support.deinit();
        self.port_maps.deinit(self.alloc);
        self.vols.deinit(self.alloc);
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
                .lower_dirs = self.img.layer_paths,
                .network = self.net_config,
                .hostname = hostname,
                .mounts = self.vols.bind_mounts.items,
                .dev_service_name = if (orch.dev_mode) hostname else null,
                .dev_color_idx = idx,
                .gpu_indices = self.gpu_indices_buf[0..self.gpu_indices_len],
            },
            .status = .created,
            .pid = null,
            .exit_code = null,
            .created_at = std.Io.Clock.real.now(std.Options.debug_io).toSeconds(),
        };
    }
};

pub fn serviceThread(orch: anytype, idx: usize, shutdown_requested: *const std.atomic.Value(bool)) void {
    const svc = orch.manifest.services[idx];

    var threaded_io = std.Io.Threaded.init(orch.alloc, .{});
    defer threaded_io.deinit();

    var prepared = PreparedService.init(threaded_io.io(), orch, idx) orelse {
        orch.states[idx].status = .failed;
        return;
    };
    defer prepared.deinit();

    var backoff_ms: u64 = initial_backoff_ms;

    while (true) {
        var id_buf: [12]u8 = undefined;
        container.generateId(&id_buf) catch {
            writeErr("failed to generate container ID for {s}\n", .{svc.name});
            orch.states[idx].status = .failed;
            return;
        };
        const id = id_buf[0..];
        @memcpy(&orch.states[idx].container_id, id);

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
            orch.states[idx].status = .failed;
            return;
        };

        var c = prepared.createContainer(orch, idx, id, svc.name);
        const start_time = std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds();

        c.start() catch {
            cleanupContainerArtifacts(id);
            orch.states[idx].status = .failed;
            return;
        };

        orch.states[idx].status = .running;
        startup_runtime.refreshServiceRuntimeBindings(
            orch.alloc,
            svc,
            &orch.states[idx],
            orch.backend_registry,
        );

        const exit_code = c.wait() catch 255;
        const run_duration_ns = std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds() - start_time;
        cleanupContainerArtifacts(id);

        if (shutdown_requested.load(.acquire)) break;

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
        )) break;
    }

    orch.states[idx].status = .stopped;
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

            const id = orch.states[service_idx].container_id;
            const record = store.load(orch.alloc, id[0..]) catch |err| {
                log.debug("watcher: container {s} not found (may have exited): {}", .{ svc.name, err });
                orch.restart_requested[service_idx].store(true, .release);
                continue;
            };
            defer record.deinit(orch.alloc);

            terminateStableProcess(orch, svc.name, id[0..], record.pid);
            orch.restart_requested[service_idx].store(true, .release);
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

    orch.states[idx].status = .stopped;
    while (!shutdown_requested.load(.acquire)) {
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
        if (shutdown_requested.load(.acquire)) return false;
        const remaining = backoff_ms.* - slept_ms;
        const sleep_chunk: u64 = @min(remaining, restart_poll_ms);
        if (!runtime_wait.sleep(std.Io.Duration.fromMilliseconds(@intCast(sleep_chunk)), "restart backoff wait")) return false;
        slept_ms += sleep_chunk;
    }

    if (shutdown_requested.load(.acquire)) return false;
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
