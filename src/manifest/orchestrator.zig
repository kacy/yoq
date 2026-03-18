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
const oci = @import("../image/oci.zig");
const container = @import("../runtime/container.zig");
const process = @import("../runtime/process.zig");
const store = @import("../state/store.zig");
const net_setup = @import("../network/setup.zig");
const log = @import("../lib/log.zig");
const ip_mod = @import("../network/ip.zig");
const watcher_mod = @import("../dev/watcher.zig");
const logs = @import("../runtime/logs.zig");
const health = @import("health.zig");
const tls_proxy = @import("../tls/proxy.zig");
const tls_backend = @import("../tls/backend.zig");
const cert_store_mod = @import("../tls/cert_store.zig");
const acme_mod = @import("../tls/acme.zig");
const cron_scheduler = @import("cron_scheduler.zig");
const gpu_runtime = @import("gpu_runtime.zig");
const sqlite = @import("sqlite");
const service_runtime = @import("orchestrator/service_runtime.zig");
const tls_support = @import("orchestrator/tls_support.zig");

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
        var has_checks = false;

        for (self.manifest.services, 0..) |svc, i| {
            if (!self.shouldStart(svc.name)) continue;
            const hc = svc.health_check orelse continue;
            has_checks = true;

            // look up the container's IP from the store
            const id = self.states[i].container_id;
            const record = store.load(self.alloc, id[0..]) catch {
                log.warn("orchestrator: failed to load container for health check registration: {s}", .{svc.name});
                continue;
            };
            defer record.deinit(self.alloc);

            const container_ip = if (record.ip_address) |ip_str|
                ip_mod.parseIp(ip_str) orelse [4]u8{ 0, 0, 0, 0 }
            else
                [4]u8{ 0, 0, 0, 0 };

            health.registerService(svc.name, id, container_ip, hc) catch {
                writeErr("health: registry full, health checks disabled for {s}\n", .{svc.name});
            };
            self.states[i].health_status = .starting;
        }

        if (has_checks) {
            health.startChecker();
        }
    }

    /// start the TLS reverse proxy if any services have TLS configs.
    /// registers backends for each TLS-enabled service and starts the proxy.
    fn startTlsProxy(self: *Orchestrator) void {
        // check if any services have TLS configs
        var has_tls = false;
        for (self.manifest.services) |svc| {
            if (!self.shouldStart(svc.name)) continue;
            if (svc.tls != null) {
                has_tls = true;
                break;
            }
        }
        if (!has_tls) return;

        // create backend registry
        const reg = self.alloc.create(tls_backend.BackendRegistry) catch {
            writeErr("failed to allocate backend registry\n", .{});
            return;
        };
        reg.* = tls_backend.BackendRegistry.init(self.alloc);
        self.backend_registry = reg;

        // register backends for TLS-enabled services
        for (self.manifest.services, 0..) |svc, i| {
            if (!self.shouldStart(svc.name)) continue;
            const tls = svc.tls orelse continue;

            // look up the container's IP from the store
            const id = self.states[i].container_id;
            const record = store.load(self.alloc, id[0..]) catch {
                log.warn("could not find container for {s}, skipping TLS backend", .{svc.name});
                continue;
            };
            defer record.deinit(self.alloc);

            const ip = record.ip_address orelse {
                log.warn("no IP for {s}, skipping TLS backend", .{svc.name});
                continue;
            };

            // use the first port mapping's container port, or default to 80
            const port: u16 = if (svc.ports.len > 0) svc.ports[0].container_port else 80;

            reg.register(tls.domain, ip, port) catch {
                log.warn("failed to register backend for {s}", .{tls.domain});
                continue;
            };
            writeErr("  tls: {s} -> {s}:{d}\n", .{ tls.domain, ip, port });
        }

        // open database and cert store
        const db_ptr = self.alloc.create(sqlite.Db) catch {
            writeErr("failed to allocate database for cert store\n", .{});
            return;
        };
        db_ptr.* = store.openDb() catch {
            self.alloc.destroy(db_ptr);
            writeErr("failed to open database for cert store\n", .{});
            return;
        };

        const certs = self.alloc.create(cert_store_mod.CertStore) catch {
            db_ptr.deinit();
            self.alloc.destroy(db_ptr);
            writeErr("failed to allocate cert store\n", .{});
            return;
        };
        certs.* = cert_store_mod.CertStore.init(db_ptr, self.alloc) catch {
            db_ptr.deinit();
            self.alloc.destroy(db_ptr);
            self.alloc.destroy(certs);
            writeErr("failed to init cert store (is the master key set?)\n", .{});
            return;
        };

        // auto-provision ACME certificates for services that need them.
        // runs before starting the proxy so certs are ready when traffic arrives.
        var acme_email: ?[]const u8 = null;
        for (self.manifest.services) |svc| {
            const tls = svc.tls orelse continue;
            if (!tls.acme) continue;

            // save the email for renewal config
            if (acme_email == null) acme_email = tls.email;

            // skip if a valid cert already exists
            const needs = certs.needsRenewal(tls.domain, 30) catch |err| blk: {
                if (err == cert_store_mod.CertError.NotFound) break :blk true;
                break :blk false;
            };
            if (!needs) {
                writeErr("  tls: {s} has valid certificate\n", .{tls.domain});
                continue;
            }

            writeErr("  tls: provisioning certificate for {s}...\n", .{tls.domain});
            provisionAcmeCert(self.alloc, certs, tls.domain, tls.email orelse "admin@localhost");
        }

        // create and start proxy
        const proxy = self.alloc.create(tls_proxy.TlsProxy) catch {
            std.crypto.secureZero(u8, &certs.key);
            db_ptr.deinit();
            self.alloc.destroy(db_ptr);
            self.alloc.destroy(certs);
            writeErr("failed to allocate TLS proxy\n", .{});
            return;
        };
        proxy.* = tls_proxy.TlsProxy.init(self.alloc, reg, certs, 443, 80) catch {
            std.crypto.secureZero(u8, &certs.key);
            db_ptr.deinit();
            self.alloc.destroy(db_ptr);
            self.alloc.destroy(certs);
            self.alloc.destroy(proxy);
            writeErr("failed to bind TLS proxy ports (443/80)\n", .{});
            return;
        };

        // configure auto-renewal if any service uses ACME
        if (acme_email) |email| {
            proxy.setRenewalConfig(.{
                .email = email,
                .directory_url = acme_mod.letsencrypt_production,
            });
        }

        self.tls_db = db_ptr;
        self.tls_certs = certs;
        self.proxy = proxy;
        proxy.start();
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

// -- ACME provisioning --

/// attempt to provision a certificate via ACME for the given domain.
/// logs progress and errors but does not fail the startup — the service
/// can still work without TLS if provisioning fails (e.g., DNS not ready).
fn provisionAcmeCert(
    alloc: std.mem.Allocator,
    certs: *cert_store_mod.CertStore,
    domain: []const u8,
    email: []const u8,
) void {
    return tls_support.provisionAcmeCert(alloc, certs, domain, email);
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
    const svc = orch.manifest.services[idx];
    const alloc = orch.alloc;

    // resolve image config
    var img = resolveServiceImage(alloc, svc.image) orelse {
        orch.states[idx].status = .failed;
        return;
    };
    defer img.deinit(alloc);

    // resolve command
    var resolved = oci.resolveCommand(alloc, img.entrypoint, img.default_cmd, svc.command) catch {
        log.err("failed to resolve command for {s}: out of memory", .{svc.name});
        orch.states[idx].status = .failed;
        return;
    };
    defer resolved.args.deinit(alloc);

    // merge env
    var merged_env = mergeServiceEnv(alloc, img.image_env, svc.env);
    defer merged_env.deinit(alloc);

    // working dir override
    var working_dir = img.working_dir;
    if (svc.working_dir) |wd| working_dir = wd;

    // resolve volumes
    var vols = resolveServiceVolumes(alloc, svc.volumes, orch.manifest.volumes, orch.app_name) catch {
        orch.states[idx].status = .failed;
        return;
    };
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

    // build GPU indices from manifest gpu spec
    var gpu_indices_buf: [8]u32 = undefined;
    var gpu_indices_len: usize = 0;
    if (svc.gpu) |gpu_spec| {
        const count = @min(gpu_spec.count, 8);
        for (0..count) |i| {
            gpu_indices_buf[i] = @intCast(i);
        }
        gpu_indices_len = count;

        gpu_runtime.appendGpuPassthroughEnv(alloc, &merged_env, gpu_indices_buf[0..count]);
    }

    // inject NCCL mesh environment for multi-GPU distributed training
    var mesh_support: ?gpu_runtime.MeshSupport = null;
    defer if (mesh_support) |*support| support.deinit();
    if (svc.gpu_mesh) |mesh_spec| {
        mesh_support = gpu_runtime.MeshSupport.init(alloc);
        // for local orchestrator, rank 0 is always this node at 127.0.0.1
        mesh_support.?.appendEnv(
            alloc,
            &merged_env,
            "127.0.0.1",
            mesh_spec.master_port,
            mesh_spec.world_size,
            0, // rank (local orchestrator = single node, rank 0)
            0, // local_rank
        );
    }

    // if the service has a health check, skip DNS registration on startup.
    // the health checker will register it after the first successful check.
    const has_health_check = svc.health_check != null;

    const net_config: ?net_setup.NetworkConfig = if (port_maps.items.len > 0)
        .{ .port_maps = port_maps.items, .skip_dns = has_health_check }
    else
        .{ .skip_dns = has_health_check };

    // exponential backoff state for restart policies.
    // starts at 1s, doubles each restart, caps at 30s.
    // resets when the container runs for longer than 10s (healthy start).
    var backoff_ms: u64 = initial_backoff_ms;

    // main run loop
    while (true) {
        // generate a fresh container id for each run
        var id_buf: [12]u8 = undefined;
        container.generateId(&id_buf) catch {
            writeErr("failed to generate container ID for {s}\n", .{svc.name});
            orch.states[idx].status = .failed;
            return;
        };
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
                .gpu_indices = gpu_indices_buf[0..gpu_indices_len],
            },
            .status = .created,
            .pid = null,
            .exit_code = null,
            .created_at = std.time.timestamp(),
        };

        // mark as running once the container starts
        orch.states[idx].status = .running;

        const start_time = std.time.nanoTimestamp();

        c.start() catch {
            orch.states[idx].status = .failed;
            return;
        };

        const run_duration_ns = std.time.nanoTimestamp() - start_time;
        const exit_code = c.wait() catch 255;

        // clean up this container's resources before potentially restarting
        logs.deleteLogFile(id);
        container.cleanupContainerDirs(id);
        store.remove(id) catch {};

        // check for shutdown first — always takes priority
        if (shutdown_requested.load(.acquire)) break;

        // decide whether to restart based on mode and policy
        if (orch.dev_mode) {
            // dev mode: restart on file watcher signal
            if (orch.restart_requested[idx].load(.acquire)) {
                orch.restart_requested[idx].store(false, .release);
                writeErr("restarting {s}...\n", .{svc.name});
                continue;
            }

            // container exited on its own — wait for watcher signal or shutdown
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
        } else {
            // normal mode: check restart policy
            const should_restart = switch (svc.restart) {
                .none => false,
                .always => true,
                .on_failure => exit_code != 0,
            };

            if (!should_restart) break;

            // reset backoff if the container ran long enough to be considered healthy
            if (run_duration_ns >= healthy_run_threshold_ns) {
                backoff_ms = initial_backoff_ms;
            }

            writeErr("{s} exited (code {d}), restarting in {d}ms...\n", .{
                svc.name, exit_code, backoff_ms,
            });

            // sleep for backoff duration, checking for shutdown periodically
            var slept_ms: u64 = 0;
            while (slept_ms < backoff_ms) {
                if (shutdown_requested.load(.acquire)) break;
                const remaining = backoff_ms - slept_ms;
                const sleep_chunk: u64 = @min(remaining, 200);
                std.Thread.sleep(sleep_chunk * std.time.ns_per_ms);
                slept_ms += sleep_chunk;
            }

            if (shutdown_requested.load(.acquire)) break;

            // increase backoff for next time (exponential, capped)
            backoff_ms = @min(backoff_ms * 2, max_backoff_ms);
        }
    }

    orch.states[idx].status = .stopped;
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
    var services: [64]usize = undefined;

    while (!shutdown_requested.load(.acquire)) {
        // wait for changes, collect up to 64 services
        const changed_services = w.waitForChange(&services);
        if (changed_services.len == 0) break; // watcher closed

        if (shutdown_requested.load(.acquire)) break;

        // process all services that had changes
        for (changed_services) |service_idx| {
            const svc = orch.manifest.services[service_idx];
            writeErr("change detected in {s}, restarting...\n", .{svc.name});

            // stop the running container by sending SIGTERM to its process
            const id = orch.states[service_idx].container_id;

            // load container record - if this fails, container might already be stopped
            const record = store.load(orch.alloc, id[0..]) catch |e| {
                log.debug("watcher: container {s} not found (may have exited): {}", .{ svc.name, e });
                // still request restart since file changed
                orch.restart_requested[service_idx].store(true, .release);
                continue;
            };
            defer record.deinit(orch.alloc);

            if (record.pid) |pid| {
                // double-check PID to avoid race with container restart
                // re-load record to verify PID hasn't changed
                const verify_record = store.load(orch.alloc, id[0..]) catch null;
                if (verify_record) |vr| {
                    defer vr.deinit(orch.alloc);
                    if (vr.pid == record.pid) {
                        // PID is stable, safe to terminate
                        process.terminate(pid) catch {
                            process.kill(pid) catch {};
                        };
                    } else {
                        const new_pid = vr.pid orelse 0;
                        log.debug("watcher: PID changed for {s} (was {d}, now {d}), skipping terminate", .{ svc.name, pid, new_pid });
                    }
                }
            }

            // signal the service thread to restart
            orch.restart_requested[service_idx].store(true, .release);
        }
    }
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
