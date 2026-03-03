// orchestrator — multi-service lifecycle management
//
// starts and stops services defined in a manifest.toml. each service
// runs in its own thread because Container.start() blocks until exit.
//
// startup ordering follows the manifest's topological sort — services
// are started in dependency order, waiting for each to reach "running"
// before starting its dependents.
//
// usage:
//   var orch = Orchestrator.init(alloc, &manifest, app_name);
//   defer orch.deinit();
//   orch.startAll() catch |err| { ... };
//   orch.waitForShutdown();
//   orch.stopAll();

const std = @import("std");
const posix = std.posix;

const spec = @import("spec.zig");
const image_spec = @import("../image/spec.zig");
const registry = @import("../image/registry.zig");
const layer = @import("../image/layer.zig");
const container = @import("../runtime/container.zig");
const process = @import("../runtime/process.zig");
const store = @import("../state/store.zig");
const net_setup = @import("../network/setup.zig");
const log = @import("../lib/log.zig");
const watcher_mod = @import("../dev/watcher.zig");
const logs = @import("../runtime/logs.zig");

pub const OrchestratorError = error{
    PullFailed,
    StartFailed,
    ManifestEmpty,
};

/// per-service state tracked by the orchestrator
pub const ServiceState = struct {
    container_id: [12]u8,
    thread: ?std.Thread,
    status: Status,

    pub const Status = enum {
        pending,
        pulling,
        starting,
        running,
        failed,
        stopped,
    };
};

/// orchestrates the lifecycle of all services in a manifest.
/// each service gets its own thread for Container.start() which blocks.
pub const Orchestrator = struct {
    alloc: std.mem.Allocator,
    manifest: *spec.Manifest,
    app_name: []const u8,
    states: []ServiceState,
    dev_mode: bool = false,
    restart_requested: []std.atomic.Value(bool),

    pub fn init(alloc: std.mem.Allocator, manifest: *spec.Manifest, app_name: []const u8) Orchestrator {
        const states = alloc.alloc(ServiceState, manifest.services.len) catch &.{};
        for (states) |*s| {
            s.* = .{
                .container_id = undefined,
                .thread = null,
                .status = .pending,
            };
        }

        const restart_flags = alloc.alloc(std.atomic.Value(bool), manifest.services.len) catch &.{};
        for (restart_flags) |*f| {
            f.* = std.atomic.Value(bool).init(false);
        }

        return .{
            .alloc = alloc,
            .manifest = manifest,
            .app_name = app_name,
            .states = states,
            .restart_requested = restart_flags,
        };
    }

    pub fn deinit(self: *Orchestrator) void {
        if (self.states.len > 0) {
            self.alloc.free(self.states);
        }
        if (self.restart_requested.len > 0) {
            self.alloc.free(self.restart_requested);
        }
    }

    /// pull all images, then start services in dependency order.
    /// blocks until all services are running or one fails.
    pub fn startAll(self: *Orchestrator) OrchestratorError!void {
        const services = self.manifest.services;
        if (services.len == 0) return OrchestratorError.ManifestEmpty;

        // phase 1: pull images sequentially
        for (services, 0..) |svc, i| {
            self.states[i].status = .pulling;
            writeErr("pulling {s}...\n", .{svc.image});

            if (!self.ensureImage(svc.image)) {
                writeErr("failed to pull image: {s}\n", .{svc.image});
                self.states[i].status = .failed;
                return OrchestratorError.PullFailed;
            }
            writeErr("  {s} ready\n", .{svc.image});
        }

        // phase 2: start services in dependency order (already sorted)
        for (services, 0..) |svc, i| {
            // wait for dependencies to be running
            for (svc.depends_on) |dep_name| {
                const dep_idx = self.serviceIndex(dep_name) orelse continue;
                if (!self.waitForRunning(dep_idx)) {
                    writeErr("dependency '{s}' failed to start\n", .{dep_name});
                    self.stopAll();
                    return OrchestratorError.StartFailed;
                }
            }

            // spawn service thread
            self.states[i].status = .starting;
            container.generateId(&self.states[i].container_id);

            const thread = std.Thread.spawn(.{}, serviceThread, .{
                self, i,
            }) catch {
                writeErr("failed to spawn thread for {s}\n", .{svc.name});
                self.states[i].status = .failed;
                self.stopAll();
                return OrchestratorError.StartFailed;
            };
            self.states[i].thread = thread;

            // wait for this service to reach running (or fail)
            if (!self.waitForRunning(i)) {
                writeErr("service '{s}' failed to start\n", .{svc.name});
                self.stopAll();
                return OrchestratorError.StartFailed;
            }

            const id = self.states[i].container_id;
            writeErr("started {s} ({s})\n", .{ svc.name, id[0..] });
        }
    }

    /// stop all running services in reverse dependency order.
    pub fn stopAll(self: *Orchestrator) void {
        const services = self.manifest.services;

        // reverse order — dependents first
        var i: usize = services.len;
        while (i > 0) {
            i -= 1;
            if (self.states[i].status != .running and
                self.states[i].status != .starting)
                continue;

            const id = self.states[i].container_id;
            writeErr("stopping {s}...\n", .{services[i].name});

            // find the container's PID and send SIGTERM
            const record = store.load(self.alloc, id[0..]) catch continue;
            defer record.deinit(self.alloc);

            if (record.pid) |pid| {
                process.terminate(pid) catch {
                    // if SIGTERM fails, try SIGKILL
                    process.kill(pid) catch {};
                };
            }

            self.states[i].status = .stopped;
        }

        // join all threads
        for (self.states) |*s| {
            if (s.thread) |t| {
                t.join();
                s.thread = null;
            }
        }
    }

    /// block until shutdown is requested (SIGINT/SIGTERM) or all services exit.
    pub fn waitForShutdown(self: *Orchestrator) void {
        while (!shutdown_requested.load(.acquire)) {
            // check if all services have exited
            var all_done = true;
            for (self.states) |s| {
                if (s.status == .running or s.status == .starting or s.status == .pulling) {
                    all_done = false;
                    break;
                }
            }
            if (all_done) break;

            std.time.sleep(200 * std.time.ns_per_ms);
        }
    }

    // -- internal --

    /// check if image exists locally, pull if not
    fn ensureImage(self: *Orchestrator, image: []const u8) bool {
        const ref = image_spec.parseImageRef(image);

        // check if already pulled
        const existing = store.findImage(self.alloc, ref.repository, ref.reference);
        if (existing) |img| {
            img.deinit(self.alloc);
            return true;
        } else |_| {}

        // pull from registry
        var result = registry.pull(self.alloc, ref) catch return false;
        defer result.deinit();

        // extract layers
        const layer_paths = layer.assembleRootfs(self.alloc, result.layer_digests) catch return false;
        defer {
            for (layer_paths) |p| self.alloc.free(p);
            self.alloc.free(layer_paths);
        }

        // save image record
        store.saveImage(.{
            .id = result.manifest_digest,
            .repository = ref.repository,
            .tag = ref.reference,
            .manifest_digest = result.manifest_digest,
            .config_digest = "sha256:config",
            .total_size = @intCast(result.total_size),
            .created_at = std.time.timestamp(),
        }) catch return false;

        return true;
    }

    /// find the index of a service by name
    fn serviceIndex(self: *Orchestrator, name: []const u8) ?usize {
        for (self.manifest.services, 0..) |svc, i| {
            if (std.mem.eql(u8, svc.name, name)) return i;
        }
        return null;
    }

    /// poll until a service reaches running status. timeout 30s.
    fn waitForRunning(self: *Orchestrator, idx: usize) bool {
        const timeout_ns: u64 = 30 * std.time.ns_per_s;
        const start = @as(u64, @intCast(std.time.nanoTimestamp()));

        while (true) {
            const status = self.states[idx].status;
            if (status == .running) return true;
            if (status == .failed or status == .stopped) return false;

            const now = @as(u64, @intCast(std.time.nanoTimestamp()));
            if (now - start > timeout_ns) return false;

            std.time.sleep(100 * std.time.ns_per_ms);
        }
    }
};

/// runs a single service in its own thread.
/// in normal mode: runs once, then exits.
/// in dev mode: restarts the container whenever restart_requested is set.
fn serviceThread(orch: *Orchestrator, idx: usize) void {
    const svc = orch.manifest.services[idx];
    const alloc = orch.alloc;

    // resolve image config for defaults
    const ref = image_spec.parseImageRef(svc.image);
    const img = store.findImage(alloc, ref.repository, ref.reference) catch {
        orch.states[idx].status = .failed;
        return;
    };
    defer img.deinit(alloc);

    // extract layers for this container
    var pull_result: ?registry.PullResult = null;
    defer if (pull_result) |*r| r.deinit();

    // we need the image config to get defaults — re-pull manifest for config
    pull_result = registry.pull(alloc, ref) catch {
        orch.states[idx].status = .failed;
        return;
    };

    var config_parsed = image_spec.parseImageConfig(alloc, pull_result.?.config_bytes) catch {
        orch.states[idx].status = .failed;
        return;
    };
    defer config_parsed.deinit();

    // extract image defaults
    var entrypoint: []const []const u8 = &.{};
    var default_cmd: []const []const u8 = &.{};
    var image_env: []const []const u8 = &.{};
    var working_dir: []const u8 = "/";

    if (config_parsed.value.config) |cc| {
        if (cc.Entrypoint) |ep| entrypoint = ep;
        if (cc.Cmd) |cmd| default_cmd = cmd;
        if (cc.Env) |env| image_env = env;
        if (cc.WorkingDir) |wd| {
            if (wd.len > 0) working_dir = wd;
        }
    }

    // extract layers
    const layer_paths = layer.assembleRootfs(alloc, pull_result.?.layer_digests) catch {
        orch.states[idx].status = .failed;
        return;
    };

    const rootfs_str: []const u8 = if (layer_paths.len > 0)
        layer_paths[layer_paths.len - 1]
    else
        "/";

    // resolve effective command: manifest command overrides image defaults
    const effective_args: []const []const u8 = if (svc.command.len > 0)
        svc.command
    else if (entrypoint.len > 0)
        // entrypoint set, use default cmd as args
        default_cmd
    else
        default_cmd;

    const effective_cmd: []const u8 = if (svc.command.len > 0)
        svc.command[0]
    else if (entrypoint.len > 0)
        entrypoint[0]
    else if (default_cmd.len > 0)
        default_cmd[0]
    else
        "/bin/sh";

    // build full args list
    var full_args: std.ArrayList([]const u8) = .empty;
    defer full_args.deinit(alloc);

    if (svc.command.len > 0) {
        // manifest command overrides everything — skip first element (it's the cmd)
        if (svc.command.len > 1) {
            for (svc.command[1..]) |arg| {
                full_args.append(alloc, arg) catch {};
            }
        }
    } else {
        // use image entrypoint + cmd
        if (entrypoint.len > 1) {
            for (entrypoint[1..]) |ep_arg| {
                full_args.append(alloc, ep_arg) catch {};
            }
        }
        if (entrypoint.len > 0) {
            for (effective_args) |arg| {
                full_args.append(alloc, arg) catch {};
            }
        } else if (effective_args.len > 1) {
            for (effective_args[1..]) |arg| {
                full_args.append(alloc, arg) catch {};
            }
        }
    }

    // merge env: image env + manifest env (manifest overrides by key)
    var merged_env: std.ArrayList([]const u8) = .empty;
    defer merged_env.deinit(alloc);

    for (image_env) |img_var| {
        // check if manifest overrides this key
        const img_key = envKey(img_var);
        var overridden = false;
        for (svc.env) |manifest_var| {
            if (std.mem.eql(u8, envKey(manifest_var), img_key)) {
                overridden = true;
                break;
            }
        }
        if (!overridden) {
            merged_env.append(alloc, img_var) catch {};
        }
    }
    for (svc.env) |manifest_var| {
        merged_env.append(alloc, manifest_var) catch {};
    }

    // use manifest working_dir if set, else image default
    if (svc.working_dir) |wd| working_dir = wd;

    // resolve bind mounts from manifest volumes
    var bind_mounts: std.ArrayList(container.BindMount) = .empty;
    defer bind_mounts.deinit(alloc);

    // track resolved source paths so we can free them after start()
    var resolved_sources: std.ArrayList([]const u8) = .empty;
    defer {
        for (resolved_sources.items) |s| alloc.free(s);
        resolved_sources.deinit(alloc);
    }

    for (svc.volumes) |vol| {
        if (vol.kind != .bind) continue;

        // resolve relative paths to absolute
        var resolve_buf: [4096]u8 = undefined;
        const abs_source = std.fs.cwd().realpath(vol.source, &resolve_buf) catch {
            log.warn("failed to resolve bind mount source: {s}", .{vol.source});
            continue;
        };

        // dupe the resolved path so it outlives the stack buffer
        const duped = alloc.dupe(u8, abs_source) catch continue;
        resolved_sources.append(alloc, duped) catch {
            alloc.free(duped);
            continue;
        };

        bind_mounts.append(alloc, .{
            .source = duped,
            .target = vol.target,
        }) catch {};
    }

    // convert manifest port mappings to network PortMap
    var port_maps: std.ArrayList(net_setup.PortMap) = .empty;
    defer port_maps.deinit(alloc);

    for (svc.ports) |pm| {
        port_maps.append(alloc, .{
            .host_port = pm.host_port,
            .container_port = pm.container_port,
            .protocol = .tcp,
        }) catch {};
    }

    // build network config (reused across restarts)
    const net_config: ?net_setup.NetworkConfig = if (port_maps.items.len > 0)
        .{ .port_maps = port_maps.items }
    else
        .{};

    // main run loop — runs once in normal mode, loops in dev mode
    while (true) {
        // generate a fresh container id for each run
        var id_buf: [12]u8 = undefined;
        container.generateId(&id_buf);
        const id = id_buf[0..];

        // copy id into orchestrator state so stopAll can find it
        @memcpy(&orch.states[idx].container_id, id);

        // save container record with app_name
        store.save(.{
            .id = id,
            .rootfs = rootfs_str,
            .command = effective_cmd,
            .hostname = svc.name,
            .status = "created",
            .pid = null,
            .exit_code = null,
            .app_name = orch.app_name,
            .created_at = std.time.timestamp(),
        }) catch {
            orch.states[idx].status = .failed;
            return;
        };

        // create and start container
        var c = container.Container{
            .config = .{
                .id = id,
                .rootfs = rootfs_str,
                .command = effective_cmd,
                .args = full_args.items,
                .env = merged_env.items,
                .working_dir = working_dir,
                .lower_dirs = layer_paths,
                .network = net_config,
                .hostname = svc.name,
                .mounts = bind_mounts.items,
                .dev_service_name = if (orch.dev_mode) svc.name else null,
                .dev_color_idx = idx,
            },
            .status = .created,
            .pid = null,
            .exit_code = null,
            .created_at = std.time.timestamp(),
        };

        // mark as running once the container starts
        orch.states[idx].status = .running;

        // this blocks until the container exits
        c.start() catch {
            orch.states[idx].status = .failed;
            return;
        };

        // clean up this container's resources before potentially restarting
        logs.deleteLogFile(id);
        container.cleanupContainerDirs(id);
        store.remove(id) catch {};

        // in normal mode, we're done after one run
        if (!orch.dev_mode) break;

        // in dev mode, check if we should restart or wait
        if (shutdown_requested.load(.acquire)) break;

        if (orch.restart_requested[idx].load(.acquire)) {
            // restart was requested by the watcher — clear flag and loop
            orch.restart_requested[idx].store(false, .release);
            writeErr("restarting {s}...\n", .{svc.name});
            continue;
        }

        // container exited on its own (crash or normal exit) — wait for
        // either a restart signal or shutdown
        orch.states[idx].status = .stopped;
        var got_restart = false;
        while (!shutdown_requested.load(.acquire)) {
            if (orch.restart_requested[idx].load(.acquire)) {
                orch.restart_requested[idx].store(false, .release);
                writeErr("restarting {s}...\n", .{svc.name});
                got_restart = true;
                break;
            }
            std.time.sleep(200 * std.time.ns_per_ms);
        }
        if (!got_restart) break;
    }

    orch.states[idx].status = .stopped;
}

/// watcher thread for dev mode — monitors bind-mounted directories
/// and triggers container restarts when files change.
pub fn watcherThread(orch: *Orchestrator, w: *watcher_mod.Watcher) void {
    while (!shutdown_requested.load(.acquire)) {
        const service_idx = w.waitForChange() orelse break;

        if (shutdown_requested.load(.acquire)) break;

        const svc = orch.manifest.services[service_idx];
        writeErr("change detected in {s}, restarting...\n", .{svc.name});

        // stop the running container by sending SIGTERM to its process
        const id = orch.states[service_idx].container_id;
        const record = store.load(orch.alloc, id[0..]) catch {
            // container might already be stopped
            orch.restart_requested[service_idx].store(true, .release);
            continue;
        };
        defer record.deinit(orch.alloc);

        if (record.pid) |pid| {
            process.terminate(pid) catch {
                process.kill(pid) catch {};
            };
        }

        // signal the service thread to restart
        orch.restart_requested[service_idx].store(true, .release);
    }
}

/// extract the key part from a "KEY=VALUE" env var string
fn envKey(env_var: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, env_var, '=')) |eq| {
        return env_var[0..eq];
    }
    return env_var;
}

// -- signal handling --

pub var shutdown_requested: std.atomic.Value(bool) = .init(false);

/// install SIGINT and SIGTERM handlers for graceful shutdown
pub fn installSignalHandlers() void {
    const act = posix.Sigaction{
        .handler = .{ .handler = sigHandler },
        .mask = posix.empty_sigset,
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &act, null) catch {};
    posix.sigaction(posix.SIG.TERM, &act, null) catch {};
}

fn sigHandler(_: c_int) callconv(.c) void {
    shutdown_requested.store(true, .release);
}

// -- helpers --

fn writeErr(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var w = std.fs.File.stderr().writer(&buf);
    const out = &w.interface;
    out.print(fmt, args) catch {};
    out.flush() catch {};
}

// -- tests --

test "envKey extracts key from KEY=VALUE" {
    try std.testing.expectEqualStrings("FOO", envKey("FOO=bar"));
    try std.testing.expectEqualStrings("A", envKey("A="));
    try std.testing.expectEqualStrings("X", envKey("X=Y=Z"));
    try std.testing.expectEqualStrings("NOEQUALS", envKey("NOEQUALS"));
}

test "ServiceState defaults" {
    const s = ServiceState{
        .container_id = undefined,
        .thread = null,
        .status = .pending,
    };
    try std.testing.expectEqual(ServiceState.Status.pending, s.status);
    try std.testing.expect(s.thread == null);
}

test "shutdown_requested starts false" {
    try std.testing.expect(!shutdown_requested.load(.acquire));
}
