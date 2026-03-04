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

const cli = @import("../lib/cli.zig");
const spec = @import("spec.zig");
const image_spec = @import("../image/spec.zig");
const registry = @import("../image/registry.zig");
const layer = @import("../image/layer.zig");
const oci = @import("../image/oci.zig");
const container = @import("../runtime/container.zig");
const process = @import("../runtime/process.zig");
const store = @import("../state/store.zig");
const net_setup = @import("../network/setup.zig");
const log = @import("../lib/log.zig");
const watcher_mod = @import("../dev/watcher.zig");
const logs = @import("../runtime/logs.zig");
const health = @import("health.zig");

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
    health_status: ?health.HealthStatus = null,

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

    pub fn init(alloc: std.mem.Allocator, manifest: *spec.Manifest, app_name: []const u8) !Orchestrator {
        const states = try alloc.alloc(ServiceState, manifest.services.len);
        for (states) |*s| {
            s.* = .{
                .container_id = undefined,
                .thread = null,
                .status = .pending,
            };
        }

        const restart_flags = try alloc.alloc(std.atomic.Value(bool), manifest.services.len);
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

        // phase 3: register health checks and start checker thread.
        // brief delay to let container networking finish setup —
        // the service thread sets status=running then enters c.start()
        // which does network setup synchronously before blocking.
        self.registerHealthChecks();
    }

    /// register services for health checking and start the checker thread.
    fn registerHealthChecks(self: *Orchestrator) void {
        var has_checks = false;

        for (self.manifest.services, 0..) |svc, i| {
            const hc = svc.health_check orelse continue;
            has_checks = true;

            // look up the container's IP from the store
            const id = self.states[i].container_id;
            const record = store.load(self.alloc, id[0..]) catch continue;
            defer record.deinit(self.alloc);

            const container_ip = if (record.ip_address) |ip_str|
                parseIpAddress(ip_str)
            else
                [4]u8{ 0, 0, 0, 0 };

            health.registerService(svc.name, id, container_ip, hc);
            self.states[i].health_status = .starting;
        }

        if (has_checks) {
            health.startChecker();
        }
    }

    /// stop all running services in reverse dependency order.
    pub fn stopAll(self: *Orchestrator) void {
        // stop health checker first so it doesn't see partially-stopped services
        health.stopChecker();

        const services = self.manifest.services;

        // unregister all services from health checking
        for (services) |svc| {
            health.unregisterService(svc.name);
        }

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

            std.Thread.sleep(200 * std.time.ns_per_ms);
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
        oci.saveImageFromPull(ref, result.manifest_digest, result.total_size) catch return false;

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

            std.Thread.sleep(100 * std.time.ns_per_ms);
        }
    }
};

// -- service thread helpers --
//
// these extract the setup phases from serviceThread so the main function
// reads as a short sequence of steps rather than a wall of code.

/// resolved image configuration — owns the pull result, parsed config,
/// and image record so they live as long as the service thread needs them.
const ServiceImageConfig = struct {
    rootfs: []const u8,
    entrypoint: []const []const u8 = &.{},
    default_cmd: []const []const u8 = &.{},
    image_env: []const []const u8 = &.{},
    working_dir: []const u8 = "/",
    layer_paths: []const []const u8 = &.{},
    pull_result: ?registry.PullResult = null,
    config_parsed: ?image_spec.ParseResult(image_spec.ImageConfig) = null,
    img_record: ?store.ImageRecord = null,

    fn deinit(self: *ServiceImageConfig, alloc: std.mem.Allocator) void {
        if (self.pull_result) |*r| r.deinit();
        if (self.config_parsed) |*c| c.deinit();
        if (self.img_record) |img| img.deinit(alloc);
    }
};

/// resolve image config for a service: find image, pull for config,
/// extract defaults (entrypoint, cmd, env, working_dir), assemble layers.
fn resolveServiceImage(alloc: std.mem.Allocator, image: []const u8) ?ServiceImageConfig {
    const ref = image_spec.parseImageRef(image);
    const img = store.findImage(alloc, ref.repository, ref.reference) catch return null;

    var result = ServiceImageConfig{ .rootfs = "/", .img_record = img };

    // re-pull manifest for config
    result.pull_result = registry.pull(alloc, ref) catch return null;

    result.config_parsed = image_spec.parseImageConfig(alloc, result.pull_result.?.config_bytes) catch return null;

    // extract image defaults
    if (result.config_parsed.?.value.config) |cc| {
        if (cc.Entrypoint) |ep| result.entrypoint = ep;
        if (cc.Cmd) |cmd| result.default_cmd = cmd;
        if (cc.Env) |env| result.image_env = env;
        if (cc.WorkingDir) |wd| {
            if (wd.len > 0) result.working_dir = wd;
        }
    }

    // assemble layers
    result.layer_paths = layer.assembleRootfs(alloc, result.pull_result.?.layer_digests) catch return null;

    if (result.layer_paths.len > 0) {
        result.rootfs = result.layer_paths[result.layer_paths.len - 1];
    }

    return result;
}

/// merge image env with manifest env. manifest vars override image vars
/// with the same key (before the '=').
fn mergeServiceEnv(
    alloc: std.mem.Allocator,
    image_env: []const []const u8,
    manifest_env: []const []const u8,
) std.ArrayList([]const u8) {
    var merged: std.ArrayList([]const u8) = .empty;

    for (image_env) |img_var| {
        const img_key = envKey(img_var);
        var overridden = false;
        for (manifest_env) |manifest_var| {
            if (std.mem.eql(u8, envKey(manifest_var), img_key)) {
                overridden = true;
                break;
            }
        }
        if (!overridden) {
            merged.append(alloc, img_var) catch |e| {
                log.warn("failed to merge image env var: {}", .{e});
            };
        }
    }
    for (manifest_env) |manifest_var| {
        merged.append(alloc, manifest_var) catch |e| {
            log.warn("failed to merge manifest env var: {}", .{e});
        };
    }

    return merged;
}

/// resolved bind mounts with their allocated source paths.
const ServiceVolumes = struct {
    bind_mounts: std.ArrayList(container.BindMount),
    resolved_sources: std.ArrayList([]const u8),

    fn deinit(self: *ServiceVolumes, alloc: std.mem.Allocator) void {
        for (self.resolved_sources.items) |s| alloc.free(s);
        self.resolved_sources.deinit(alloc);
        self.bind_mounts.deinit(alloc);
    }
};

/// resolve bind mounts from manifest volume declarations.
/// relative source paths are resolved to absolute paths.
fn resolveServiceVolumes(alloc: std.mem.Allocator, volumes: []const spec.VolumeMount) ServiceVolumes {
    var result = ServiceVolumes{
        .bind_mounts = .empty,
        .resolved_sources = .empty,
    };

    for (volumes) |vol| {
        if (vol.kind != .bind) continue;

        var resolve_buf: [4096]u8 = undefined;
        const abs_source = std.fs.cwd().realpath(vol.source, &resolve_buf) catch {
            log.warn("failed to resolve bind mount source: {s}", .{vol.source});
            continue;
        };

        const duped = alloc.dupe(u8, abs_source) catch continue;
        result.resolved_sources.append(alloc, duped) catch {
            alloc.free(duped);
            continue;
        };

        result.bind_mounts.append(alloc, .{
            .source = duped,
            .target = vol.target,
        }) catch |e| {
            log.warn("failed to add bind mount for {s}: {}", .{ vol.target, e });
        };
    }

    return result;
}

/// runs a single service in its own thread.
/// in normal mode: runs once, then exits.
/// in dev mode: restarts the container whenever restart_requested is set.
fn serviceThread(orch: *Orchestrator, idx: usize) void {
    const svc = orch.manifest.services[idx];
    const alloc = orch.alloc;

    // resolve image config
    var img = resolveServiceImage(alloc, svc.image) orelse {
        orch.states[idx].status = .failed;
        return;
    };
    defer img.deinit(alloc);

    // resolve command
    var resolved = oci.resolveCommand(alloc, img.entrypoint, img.default_cmd, svc.command);
    defer resolved.args.deinit(alloc);

    // merge env
    var merged_env = mergeServiceEnv(alloc, img.image_env, svc.env);
    defer merged_env.deinit(alloc);

    // working dir override
    var working_dir = img.working_dir;
    if (svc.working_dir) |wd| working_dir = wd;

    // resolve volumes
    var vols = resolveServiceVolumes(alloc, svc.volumes);
    defer vols.deinit(alloc);

    // port mappings
    var port_maps: std.ArrayList(net_setup.PortMap) = .empty;
    defer port_maps.deinit(alloc);
    for (svc.ports) |pm| {
        port_maps.append(alloc, .{
            .host_port = pm.host_port,
            .container_port = pm.container_port,
            .protocol = .tcp,
        }) catch |e| {
            log.warn("failed to add port map: {}", .{e});
        };
    }

    // if the service has a health check, skip DNS registration on startup.
    // the health checker will register it after the first successful check.
    const has_health_check = svc.health_check != null;

    const net_config: ?net_setup.NetworkConfig = if (port_maps.items.len > 0)
        .{ .port_maps = port_maps.items, .skip_dns = has_health_check }
    else
        .{ .skip_dns = has_health_check };

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
            .rootfs = img.rootfs,
            .command = resolved.command,
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
                .rootfs = img.rootfs,
                .command = resolved.command,
                .args = resolved.args.items,
                .env = merged_env.items,
                .working_dir = working_dir,
                .lower_dirs = img.layer_paths,
                .network = net_config,
                .hostname = svc.name,
                .mounts = vols.bind_mounts.items,
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
            std.Thread.sleep(200 * std.time.ns_per_ms);
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

/// parse a dotted IP string like "10.42.0.5" into a 4-byte array.
/// returns all zeros on parse failure.
fn parseIpAddress(s: []const u8) [4]u8 {
    var result: [4]u8 = .{ 0, 0, 0, 0 };
    var octet_idx: usize = 0;
    var current: u16 = 0;

    for (s) |c| {
        if (c == '.') {
            if (octet_idx >= 3 or current > 255) return .{ 0, 0, 0, 0 };
            result[octet_idx] = @intCast(current);
            octet_idx += 1;
            current = 0;
        } else if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
        } else {
            return .{ 0, 0, 0, 0 };
        }
    }

    if (octet_idx != 3 or current > 255) return .{ 0, 0, 0, 0 };
    result[3] = @intCast(current);

    return result;
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
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &act, null);
    posix.sigaction(posix.SIG.TERM, &act, null);
}

fn sigHandler(_: c_int) callconv(.c) void {
    shutdown_requested.store(true, .release);
}

const writeErr = cli.writeErr;

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

test "parseIpAddress — valid IPs" {
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 5 }, parseIpAddress("10.42.0.5"));
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, parseIpAddress("127.0.0.1"));
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, parseIpAddress("0.0.0.0"));
    try std.testing.expectEqual([4]u8{ 255, 255, 255, 255 }, parseIpAddress("255.255.255.255"));
}

test "parseIpAddress — invalid IPs return zeros" {
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, parseIpAddress(""));
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, parseIpAddress("not an ip"));
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, parseIpAddress("256.0.0.1"));
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, parseIpAddress("10.42"));
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, parseIpAddress("10.42.0.5.6"));
}
