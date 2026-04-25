const std = @import("std");

const cli = @import("../../lib/cli.zig");
const container = @import("../../runtime/container.zig");
const process = @import("../../runtime/process.zig");
const store = @import("../../state/store.zig");
const log = @import("../../lib/log.zig");
const health = @import("../health.zig");
const cron_scheduler = @import("../cron_scheduler.zig");
const service_runtime = @import("service_runtime.zig");

const writeErr = cli.writeErr;

pub fn computeStartSet(self: anytype, comptime OrchestratorError: type) OrchestratorError!void {
    const targets = self.service_filter orelse return;

    var set: std.StringHashMapUnmanaged(void) = .empty;

    for (targets) |name| {
        set.put(self.alloc, name, {}) catch return OrchestratorError.StartFailed;
    }

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
        for (self.manifest.workers) |worker| {
            if (!set.contains(worker.name)) continue;
            for (worker.depends_on) |dep| {
                if (!set.contains(dep)) {
                    set.put(self.alloc, dep, {}) catch return OrchestratorError.StartFailed;
                    changed = true;
                }
            }
        }
    }

    self.start_set = set;
}

pub fn shouldStart(self: anytype, name: []const u8) bool {
    const set = self.start_set orelse return true;
    return set.contains(name);
}

pub fn startAll(self: anytype, comptime OrchestratorError: type, serviceThreadFn: anytype) OrchestratorError!void {
    const services = self.manifest.services;
    if (services.len == 0) return OrchestratorError.ManifestEmpty;

    try self.computeStartSet();

    var pull_io = std.Io.Threaded.init(self.alloc, .{});
    defer pull_io.deinit();

    for (services, 0..) |svc, i| {
        if (!shouldStart(self, svc.name)) continue;

        self.states[i].status = .pulling;
        writeErr("pulling {s}...\n", .{svc.image});

        if (!service_runtime.ensureImageAvailableWithIo(pull_io.io(), self.alloc, svc.image)) {
            writeErr("failed to pull image: {s}\n", .{svc.image});
            self.states[i].status = .failed;
            return OrchestratorError.PullFailed;
        }
        writeErr("  {s} ready\n", .{svc.image});
    }

    var completed_workers: std.StringHashMapUnmanaged(void) = .empty;
    defer completed_workers.deinit(self.alloc);

    for (services, 0..) |svc, i| {
        if (!shouldStart(self, svc.name)) continue;
        startServiceByIndex(self, OrchestratorError, i, &completed_workers, serviceThreadFn) catch |err| {
            self.stopAll();
            return err;
        };
    }

    finishRuntimeSetup(self);
}

pub fn finishRuntimeSetup(self: anytype) void {
    self.registerHealthChecks();
    self.startTlsProxy();
    startCronSchedulerIfNeeded(self);
}

fn startCronSchedulerIfNeeded(self: anytype) void {
    if (self.service_filter != null or self.manifest.crons.len == 0 or self.cron_sched != null) return;

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

pub fn startServiceByIndex(
    self: anytype,
    comptime OrchestratorError: type,
    idx: usize,
    completed_workers: *std.StringHashMapUnmanaged(void),
    serviceThreadFn: anytype,
) OrchestratorError!void {
    const svc = self.manifest.services[idx];

    for (svc.depends_on) |dep_name| {
        if (self.manifest.workerByName(dep_name)) |worker| {
            if (!completed_workers.contains(dep_name)) {
                writeErr("running worker {s}...\n", .{dep_name});

                var worker_io = std.Io.Threaded.init(self.alloc, .{});
                defer worker_io.deinit();

                if (!service_runtime.runOneShotWithIo(
                    worker_io.io(),
                    self.alloc,
                    worker.image,
                    worker.command,
                    worker.env,
                    worker.volumes,
                    worker.working_dir,
                    dep_name,
                    self.manifest.volumes,
                    self.app_name,
                )) {
                    writeErr("worker '{s}' failed\n", .{dep_name});
                    return OrchestratorError.StartFailed;
                }
                completed_workers.put(self.alloc, dep_name, {}) catch {};
                writeErr("  worker {s} completed\n", .{dep_name});
            }
        } else {
            const dep_idx = serviceIndex(self, dep_name) orelse continue;
            if (!waitForRunning(self, dep_idx)) {
                writeErr("dependency '{s}' failed to start\n", .{dep_name});
                return OrchestratorError.StartFailed;
            }
        }
    }

    self.states[idx].status = .starting;
    container.generateId(&self.states[idx].container_id) catch {
        writeErr("failed to generate container ID for {s}\n", .{svc.name});
        self.states[idx].status = .failed;
        return OrchestratorError.StartFailed;
    };

    const thread = std.Thread.spawn(.{}, serviceThreadFn, .{ self, idx }) catch {
        writeErr("failed to spawn thread for {s}\n", .{svc.name});
        self.states[idx].status = .failed;
        return OrchestratorError.StartFailed;
    };
    self.states[idx].thread = thread;

    if (!waitForRunning(self, idx)) {
        writeErr("service '{s}' failed to start\n", .{svc.name});
        return OrchestratorError.StartFailed;
    }

    const id = self.states[idx].container_id;
    writeErr("started {s} ({s})\n", .{ svc.name, id[0..] });
}

pub fn stopAll(self: anytype) void {
    if (self.cron_sched) |cs| {
        cs.stop();
        writeErr("stopped cron scheduler\n", .{});
    }

    if (self.proxy) |p| {
        p.stop();
        writeErr("stopped tls proxy\n", .{});
    }

    health.stopChecker();

    const services = self.manifest.services;
    for (services) |svc| {
        health.unregisterService(svc.name);
    }

    var i: usize = services.len;
    while (i > 0) {
        i -= 1;
        stopServiceByIndex(self, i);
    }
}

pub fn stopServiceByIndex(self: anytype, idx: usize) void {
    if (self.states[idx].status != .running and self.states[idx].status != .starting) return;

    const svc = self.manifest.services[idx];
    health.unregisterService(svc.name);

    const id = self.states[idx].container_id;
    writeErr("stopping {s}...\n", .{svc.name});

    const record = store.load(self.alloc, id[0..]) catch {
        log.warn("orchestrator: failed to load container for shutdown: {s}", .{svc.name});
        self.states[idx].status = .stopped;
        if (self.states[idx].thread) |thread| {
            thread.join();
            self.states[idx].thread = null;
        }
        return;
    };
    defer record.deinit(self.alloc);

    if (record.pid) |pid| {
        process.terminate(pid) catch {
            process.kill(pid) catch {};
        };
    }

    self.states[idx].status = .stopped;
    if (self.states[idx].thread) |thread| {
        thread.join();
        self.states[idx].thread = null;
    }
}

pub fn waitForShutdown(self: anytype, shutdown_requested: *const std.atomic.Value(bool)) void {
    while (!shutdown_requested.load(.acquire)) {
        var all_done = true;
        for (self.states) |state| {
            if (state.status == .running or state.status == .starting or state.status == .pulling) {
                all_done = false;
                break;
            }
        }
        if (all_done) break;

        std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(200), .awake) catch unreachable;
    }
}

pub fn serviceIndex(self: anytype, name: []const u8) ?usize {
    for (self.manifest.services, 0..) |svc, i| {
        if (std.mem.eql(u8, svc.name, name)) return i;
    }
    return null;
}

pub fn waitForRunning(self: anytype, idx: usize) bool {
    const timeout_ns: u64 = 30 * std.time.ns_per_s;
    const start = @as(u64, @intCast(std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds()));

    while (true) {
        const status = self.states[idx].status;
        if (status == .running) return true;
        if (status == .failed or status == .stopped) return false;

        const now = @as(u64, @intCast(std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds()));
        if (now - start > timeout_ns) return false;

        std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(100), .awake) catch unreachable;
    }
}
