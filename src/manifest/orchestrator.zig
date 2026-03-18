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
const container = @import("../runtime/container.zig");
const process = @import("../runtime/process.zig");
const store = @import("../state/store.zig");
const log = @import("../lib/log.zig");
const watcher_mod = @import("../dev/watcher.zig");
const health = @import("health.zig");
const tls_proxy = @import("../tls/proxy.zig");
const tls_backend = @import("../tls/backend.zig");
const cert_store_mod = @import("../tls/cert_store.zig");
const cron_scheduler = @import("cron_scheduler.zig");
const sqlite = @import("sqlite");
const runtime_loop = @import("orchestrator/runtime_loop.zig");
const startup_runtime = @import("orchestrator/startup_runtime.zig");
const service_runtime = @import("orchestrator/service_runtime.zig");

pub const OrchestratorError = error{
    /// one or more container images could not be pulled from the registry
    PullFailed,
    /// a service container failed to reach running state during startup
    StartFailed,
    /// the manifest contains no service definitions
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
    backend_registry: ?*tls_backend.BackendRegistry = null,
    proxy: ?*tls_proxy.TlsProxy = null,
    tls_certs: ?*cert_store_mod.CertStore = null,
    tls_db: ?*sqlite.Db = null,
    cron_sched: ?*cron_scheduler.CronScheduler = null,
    /// when set, only start these services (+ transitive deps).
    /// null means start everything.
    service_filter: ?[]const []const u8 = null,
    /// computed from service_filter — the full set of service names to start
    /// (targets + all transitive dependencies). null means start everything.
    start_set: ?std.StringHashMapUnmanaged(void) = null,

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
        // clean up TLS resources in reverse init order
        if (self.proxy) |p| {
            p.deinit();
            self.alloc.destroy(p);
        }
        if (self.tls_certs) |c| {
            // zero the master key before freeing
            std.crypto.secureZero(u8, &c.key);
            self.alloc.destroy(c);
        }
        if (self.tls_db) |db| {
            db.deinit();
            self.alloc.destroy(db);
        }
        if (self.backend_registry) |r| {
            r.deinit();
            self.alloc.destroy(r);
        }
        if (self.cron_sched) |cs| {
            cs.deinit();
            self.alloc.destroy(cs);
        }
        if (self.start_set) |*set| {
            set.deinit(self.alloc);
        }
        if (self.states.len > 0) {
            self.alloc.free(self.states);
        }
        if (self.restart_requested.len > 0) {
            self.alloc.free(self.restart_requested);
        }
    }

    /// compute the set of services to start from a list of target names.
    /// walks depends_on transitively to include all required dependencies.
    pub fn computeStartSet(self: *Orchestrator) OrchestratorError!void {
        const targets = self.service_filter orelse return;

        var set: std.StringHashMapUnmanaged(void) = .empty;

        // seed with the requested targets
        for (targets) |name| {
            set.put(self.alloc, name, {}) catch return OrchestratorError.StartFailed;
        }

        // fixed-point iteration: keep adding deps until nothing changes.
        // walks both service and worker depends_on chains.
        var changed = true;
        while (changed) {
            changed = false;
            for (self.manifest.services) |svc| {
                if (!set.contains(svc.name)) continue;
                for (svc.depends_on) |dep| {
                    if (!set.contains(dep)) {
                        set.put(self.alloc, dep, {}) catch return OrchestratorError.StartFailed;
                        changed = true;
                    }
                }
            }
            for (self.manifest.workers) |w| {
                if (!set.contains(w.name)) continue;
                for (w.depends_on) |dep| {
                    if (!set.contains(dep)) {
                        set.put(self.alloc, dep, {}) catch return OrchestratorError.StartFailed;
                        changed = true;
                    }
                }
            }
        }

        self.start_set = set;
    }

    /// check if a service should be started (passes the filter)
    fn shouldStart(self: *const Orchestrator, name: []const u8) bool {
        const set = self.start_set orelse return true;
        return set.contains(name);
    }

    /// pull all images, then start services in dependency order.
    /// blocks until all services are running or one fails.
    /// respects service_filter — only starts filtered services + their deps.
    pub fn startAll(self: *Orchestrator) OrchestratorError!void {
        const services = self.manifest.services;
        if (services.len == 0) return OrchestratorError.ManifestEmpty;

        // compute the start set from service_filter (if any)
        try self.computeStartSet();

        // phase 1: pull images sequentially (only for services we'll start)
        for (services, 0..) |svc, i| {
            if (!self.shouldStart(svc.name)) continue;

            self.states[i].status = .pulling;
            writeErr("pulling {s}...\n", .{svc.image});

            if (!self.ensureImage(svc.image)) {
                writeErr("failed to pull image: {s}\n", .{svc.image});
                self.states[i].status = .failed;
                return OrchestratorError.PullFailed;
            }
            writeErr("  {s} ready\n", .{svc.image});
        }

        // phase 2: start services in dependency order (already sorted).
        // if a dependency is a worker, run it to completion first.
        var completed_workers: std.StringHashMapUnmanaged(void) = .empty;
        defer completed_workers.deinit(self.alloc);

        for (services, 0..) |svc, i| {
            if (!self.shouldStart(svc.name)) continue;

            // wait for dependencies — services wait for running, workers run to completion
            for (svc.depends_on) |dep_name| {
                if (self.manifest.workerByName(dep_name)) |worker| {
                    // worker dependency — run it once if not already done
                    if (!completed_workers.contains(dep_name)) {
                        writeErr("running worker {s}...\n", .{dep_name});
                        if (!runOneShot(self.alloc, worker.image, worker.command, worker.env, worker.volumes, worker.working_dir, dep_name, self.manifest.volumes, self.app_name)) {
                            writeErr("worker '{s}' failed\n", .{dep_name});
                            self.stopAll();
                            return OrchestratorError.StartFailed;
                        }
                        completed_workers.put(self.alloc, dep_name, {}) catch {};
                        writeErr("  worker {s} completed\n", .{dep_name});
                    }
                } else {
                    // service dependency — wait for it to reach running
                    const dep_idx = self.serviceIndex(dep_name) orelse continue;
                    if (!self.waitForRunning(dep_idx)) {
                        writeErr("dependency '{s}' failed to start\n", .{dep_name});
                        self.stopAll();
                        return OrchestratorError.StartFailed;
                    }
                }
            }

            // spawn service thread
            self.states[i].status = .starting;
            container.generateId(&self.states[i].container_id) catch {
                writeErr("failed to generate container ID for {s}\n", .{svc.name});
                self.states[i].status = .failed;
                self.stopAll();
                return OrchestratorError.StartFailed;
            };

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

        // phase 4: start TLS proxy if any services have TLS configs.
        // this runs after all services are up so backends are resolvable.
        self.startTlsProxy();

        // phase 5: start cron scheduler if there are crons and no service filter.
        // crons run independently of services — they don't make sense with a filter.
        if (self.service_filter == null and self.manifest.crons.len > 0) {
            const cs = self.alloc.create(cron_scheduler.CronScheduler) catch {
                writeErr("failed to allocate cron scheduler\n", .{});
                return;
            };
            cs.* = cron_scheduler.CronScheduler.init(self.alloc, self.manifest.crons, self.manifest.volumes, self.app_name) catch {
                self.alloc.destroy(cs);
                writeErr("failed to init cron scheduler\n", .{});
                return;
            };
            self.cron_sched = cs;
            cs.start();
            writeErr("{d} cron(s) scheduled\n", .{self.manifest.crons.len});
        }
    }

    /// register services for health checking and start the checker thread.
    fn registerHealthChecks(self: *Orchestrator) void {
        startup_runtime.registerHealthChecks(
            self.alloc,
            self.manifest.services,
            self.states,
            self.start_set,
        );
    }

    /// start the TLS reverse proxy if any services have TLS configs.
    /// registers backends for each TLS-enabled service and starts the proxy.
    fn startTlsProxy(self: *Orchestrator) void {
        const resources = startup_runtime.startTlsProxy(
            self.alloc,
            self.manifest.services,
            self.states,
            self.start_set,
        ) orelse return;

        self.backend_registry = resources.backend_registry;
        self.tls_db = resources.tls_db;
        self.tls_certs = resources.tls_certs;
        self.proxy = resources.proxy;
    }

    /// stop all running services in reverse dependency order.
    pub fn stopAll(self: *Orchestrator) void {
        // stop cron scheduler first — prevent new cron containers from starting
        if (self.cron_sched) |cs| {
            cs.stop();
            writeErr("stopped cron scheduler\n", .{});
        }

        // stop TLS proxy before stopping services so it stops routing traffic
        if (self.proxy) |p| {
            p.stop();
            writeErr("stopped tls proxy\n", .{});
        }

        // stop health checker so it doesn't see partially-stopped services
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
            const record = store.load(self.alloc, id[0..]) catch {
                log.warn("orchestrator: failed to load container for shutdown: {s}", .{services[i].name});
                continue;
            };
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

    /// check if image exists locally, pull if not (instance method)
    fn ensureImage(self: *Orchestrator, image: []const u8) bool {
        return ensureImageAvailable(self.alloc, image);
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

// -- standalone image helpers --

/// check if image exists locally, pull if not.
/// usable outside the Orchestrator (e.g., for run-worker command).
pub fn ensureImageAvailable(alloc: std.mem.Allocator, image: []const u8) bool {
    return service_runtime.ensureImageAvailable(alloc, image);
}

// -- service thread helpers --
//
// these extract the setup phases from serviceThread so the main function
// reads as a short sequence of steps rather than a wall of code.

/// resolved image configuration — owns the pull result, parsed config,
/// and image record so they live as long as the service thread needs them.
/// resolve image config for a service: find image, pull for config,
/// extract defaults (entrypoint, cmd, env, working_dir), assemble layers.
fn resolveServiceImage(alloc: std.mem.Allocator, image: []const u8) ?service_runtime.ServiceImageConfig {
    return service_runtime.resolveServiceImage(alloc, image);
}

/// merge image env with manifest env. manifest vars override image vars
/// with the same key (before the '=').
fn mergeServiceEnv(
    alloc: std.mem.Allocator,
    image_env: []const []const u8,
    manifest_env: []const []const u8,
) std.ArrayList([]const u8) {
    return service_runtime.mergeServiceEnv(alloc, image_env, manifest_env);
}

/// resolved bind mounts with their allocated source paths.
/// resolve bind mounts from manifest volume declarations.
/// relative source paths are resolved to absolute paths.
/// named volumes are resolved via the volumes module.
fn resolveServiceVolumes(
    alloc: std.mem.Allocator,
    volumes: []const spec.VolumeMount,
    manifest_volumes: []const spec.Volume,
    app_name: []const u8,
) error{VolumeFailed}!service_runtime.ServiceVolumes {
    return service_runtime.resolveServiceVolumes(alloc, volumes, manifest_volumes, app_name);
}

/// find a volume definition by name in the manifest volumes list.
fn findVolumeByName(manifest_volumes: []const spec.Volume, name: []const u8) ?spec.Volume {
    return service_runtime.findVolumeByName(manifest_volumes, name);
}

/// run a container to completion and return whether it succeeded (exit code 0).
/// used for workers — one-shot tasks like database migrations.
/// resolves the image, creates a container, runs it, and cleans up.
pub fn runOneShot(
    alloc: std.mem.Allocator,
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    volumes: []const spec.VolumeMount,
    working_dir: ?[]const u8,
    hostname: []const u8,
    manifest_volumes: []const spec.Volume,
    app_name: []const u8,
) bool {
    return service_runtime.runOneShot(alloc, image, command, env, volumes, working_dir, hostname, manifest_volumes, app_name);
}

/// runs a single service in its own thread.
/// handles three modes of operation:
///   - normal mode with restart policy (none/always/on_failure)
///   - dev mode (restarts on file change via restart_requested flag)
///
/// restart policy uses exponential backoff: 1s → 2s → 4s → ... → 30s max.
/// backoff resets when the container runs for longer than 10 seconds,
/// indicating a healthy start rather than a crash loop.
fn serviceThread(orch: *Orchestrator, idx: usize) void {
    runtime_loop.serviceThread(orch, idx, &shutdown_requested);
}

// -- restart policy constants --

/// initial backoff delay when restarting a service (1 second)
const initial_backoff_ms: u64 = service_runtime.initial_backoff_ms;

/// maximum backoff delay (30 seconds)
const max_backoff_ms: u64 = service_runtime.max_backoff_ms;

/// how long a container must run before we consider it a healthy start
/// and reset the backoff timer (10 seconds)
const healthy_run_threshold_ns: i128 = service_runtime.healthy_run_threshold_ns;

/// watcher thread for dev mode — monitors bind-mounted directories
/// and triggers container restarts when files change.
pub fn watcherThread(orch: *Orchestrator, w: *watcher_mod.Watcher) void {
    runtime_loop.watcherThread(orch, w, &shutdown_requested);
}

/// extract the key part from a "KEY=VALUE" env var string
fn envKey(env_var: []const u8) []const u8 {
    return service_runtime.envKey(env_var);
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

// -- restart policy tests --

test "restart policy constants are sensible" {
    // backoff starts at 1s
    try std.testing.expectEqual(@as(u64, 1_000), initial_backoff_ms);
    // max backoff is 30s
    try std.testing.expectEqual(@as(u64, 30_000), max_backoff_ms);
    // healthy threshold is 10s
    try std.testing.expectEqual(@as(i128, 10 * std.time.ns_per_s), healthy_run_threshold_ns);
    // initial < max (otherwise backoff would never increase)
    try std.testing.expect(initial_backoff_ms < max_backoff_ms);
}

test "exponential backoff progression" {
    // simulate the backoff progression that happens in serviceThread
    var backoff: u64 = initial_backoff_ms;

    try std.testing.expectEqual(@as(u64, 1_000), backoff);

    backoff = @min(backoff * 2, max_backoff_ms);
    try std.testing.expectEqual(@as(u64, 2_000), backoff);

    backoff = @min(backoff * 2, max_backoff_ms);
    try std.testing.expectEqual(@as(u64, 4_000), backoff);

    backoff = @min(backoff * 2, max_backoff_ms);
    try std.testing.expectEqual(@as(u64, 8_000), backoff);

    backoff = @min(backoff * 2, max_backoff_ms);
    try std.testing.expectEqual(@as(u64, 16_000), backoff);

    // next step would be 32000, but capped at 30000
    backoff = @min(backoff * 2, max_backoff_ms);
    try std.testing.expectEqual(@as(u64, 30_000), backoff);

    // stays capped
    backoff = @min(backoff * 2, max_backoff_ms);
    try std.testing.expectEqual(@as(u64, 30_000), backoff);
}

test "restart policy decision logic" {
    // simulate the should_restart decision from serviceThread
    const RestartPolicy = spec.RestartPolicy;

    // none: never restart regardless of exit code
    {
        const policy = RestartPolicy.none;
        try std.testing.expect(!(switch (policy) {
            .none => false,
            .always => true,
            .on_failure => @as(u8, 0) != 0,
        }));
        try std.testing.expect(!(switch (policy) {
            .none => false,
            .always => true,
            .on_failure => @as(u8, 1) != 0,
        }));
    }

    // always: restart regardless of exit code
    {
        const policy = RestartPolicy.always;
        try std.testing.expect(switch (policy) {
            .none => false,
            .always => true,
            .on_failure => @as(u8, 0) != 0,
        });
    }

    // on_failure: restart only on non-zero exit
    {
        const policy = RestartPolicy.on_failure;
        // exit code 0 — don't restart
        const exit_code_0: u8 = 0;
        try std.testing.expect(!(switch (policy) {
            .none => false,
            .always => true,
            .on_failure => exit_code_0 != 0,
        }));
        // exit code 1 — restart
        const exit_code_1: u8 = 1;
        try std.testing.expect(switch (policy) {
            .none => false,
            .always => true,
            .on_failure => exit_code_1 != 0,
        });
        // exit code 128 (signal) — restart
        const exit_code_128: u8 = 128;
        try std.testing.expect(switch (policy) {
            .none => false,
            .always => true,
            .on_failure => exit_code_128 != 0,
        });
    }
}

// -- start set tests --

/// helper: build a minimal service for testing (no allocations to free)
fn testSvc(name: []const u8, deps: []const []const u8) spec.Service {
    return .{
        .name = name,
        .image = "scratch",
        .command = &.{},
        .ports = &.{},
        .env = &.{},
        .depends_on = deps,
        .working_dir = null,
        .volumes = &.{},
    };
}

test "computeStartSet: single target with no deps" {
    const alloc = std.testing.allocator;

    var services = [_]spec.Service{
        testSvc("web", &.{}),
        testSvc("db", &.{}),
    };
    var manifest = spec.Manifest{
        .services = &services,
        .workers = &.{},
        .crons = &.{},
        .training_jobs = &.{},
        .volumes = &.{},
        .alloc = alloc,
    };

    const states = try alloc.alloc(ServiceState, 2);
    defer alloc.free(states);
    for (states) |*s| s.* = .{ .container_id = undefined, .thread = null, .status = .pending };

    const flags = try alloc.alloc(std.atomic.Value(bool), 2);
    defer alloc.free(flags);
    for (flags) |*f| f.* = std.atomic.Value(bool).init(false);

    const filter = [_][]const u8{"web"};

    var orch = Orchestrator{
        .alloc = alloc,
        .manifest = &manifest,
        .app_name = "test",
        .states = states,
        .restart_requested = flags,
        .service_filter = &filter,
    };

    try orch.computeStartSet();
    defer {
        if (orch.start_set) |*set| set.deinit(alloc);
    }

    try std.testing.expect(orch.start_set != null);
    try std.testing.expect(orch.shouldStart("web"));
    try std.testing.expect(!orch.shouldStart("db"));
}

test "computeStartSet: transitive dependencies" {
    const alloc = std.testing.allocator;

    // web -> api -> db
    const api_deps = [_][]const u8{"db"};
    const web_deps = [_][]const u8{"api"};
    var services = [_]spec.Service{
        testSvc("db", &.{}),
        testSvc("api", &api_deps),
        testSvc("web", &web_deps),
    };
    var manifest = spec.Manifest{
        .services = &services,
        .workers = &.{},
        .crons = &.{},
        .training_jobs = &.{},
        .volumes = &.{},
        .alloc = alloc,
    };

    const states = try alloc.alloc(ServiceState, 3);
    defer alloc.free(states);
    for (states) |*s| s.* = .{ .container_id = undefined, .thread = null, .status = .pending };

    const flags = try alloc.alloc(std.atomic.Value(bool), 3);
    defer alloc.free(flags);
    for (flags) |*f| f.* = std.atomic.Value(bool).init(false);

    const filter = [_][]const u8{"web"};

    var orch = Orchestrator{
        .alloc = alloc,
        .manifest = &manifest,
        .app_name = "test",
        .states = states,
        .restart_requested = flags,
        .service_filter = &filter,
    };

    try orch.computeStartSet();
    defer {
        if (orch.start_set) |*set| set.deinit(alloc);
    }

    // web depends on api which depends on db — all three should be in the set
    try std.testing.expect(orch.shouldStart("web"));
    try std.testing.expect(orch.shouldStart("api"));
    try std.testing.expect(orch.shouldStart("db"));
}

test "computeStartSet: no filter starts everything" {
    const alloc = std.testing.allocator;

    var services = [_]spec.Service{
        testSvc("web", &.{}),
        testSvc("db", &.{}),
    };
    var manifest = spec.Manifest{
        .services = &services,
        .workers = &.{},
        .crons = &.{},
        .training_jobs = &.{},
        .volumes = &.{},
        .alloc = alloc,
    };

    const states = try alloc.alloc(ServiceState, 2);
    defer alloc.free(states);
    for (states) |*s| s.* = .{ .container_id = undefined, .thread = null, .status = .pending };

    const flags = try alloc.alloc(std.atomic.Value(bool), 2);
    defer alloc.free(flags);
    for (flags) |*f| f.* = std.atomic.Value(bool).init(false);

    var orch = Orchestrator{
        .alloc = alloc,
        .manifest = &manifest,
        .app_name = "test",
        .states = states,
        .restart_requested = flags,
    };

    try orch.computeStartSet();

    // no filter — shouldStart returns true for everything
    try std.testing.expect(orch.shouldStart("web"));
    try std.testing.expect(orch.shouldStart("db"));
    try std.testing.expect(orch.shouldStart("anything"));
}
