const std = @import("std");
const log = @import("../../lib/log.zig");
const service_observability = @import("../../network/service_observability.zig");
const service_registry_bridge = @import("../../network/service_registry_bridge.zig");
const service_registry_runtime = @import("../../network/service_registry_runtime.zig");
const types = @import("types.zig");
const checks = @import("check_runtime.zig");
const registry = @import("registry_support.zig");

const Transition = enum {
    none,
    became_healthy,
    became_unhealthy,
};

const Completion = enum {
    applied,
    stale,
};

pub fn startChecker() void {
    if (registry.checker_running.load(.acquire)) return;

    registry.checker_running.store(true, .release);
    registry.scheduler_thread = std.Thread.spawn(.{}, schedulerLoop, .{}) catch |err| {
        log.warn("health: failed to spawn scheduler thread: {}", .{err});
        registry.checker_running.store(false, .release);
        return;
    };

    registry.worker_thread_count = 0;
    for (&registry.worker_threads, 0..) |*slot, idx| {
        slot.* = std.Thread.spawn(.{}, workerLoop, .{idx}) catch |err| {
            log.warn("health: failed to spawn worker thread {d}: {}", .{ idx, err });
            registry.checker_running.store(false, .release);
            if (registry.scheduler_thread) |thread| {
                thread.join();
                registry.scheduler_thread = null;
            }
            for (registry.worker_threads[0..idx]) |maybe_thread| {
                if (maybe_thread) |thread| thread.join();
            }
            for (&registry.worker_threads) |*maybe_thread| maybe_thread.* = null;
            registry.worker_thread_count = 0;
            return;
        };
        registry.worker_thread_count += 1;
    }

    log.info("health checker started with {d} workers", .{registry.worker_thread_count});
}

pub fn stopChecker() void {
    if (!registry.checker_running.load(.acquire)) return;

    registry.checker_running.store(false, .release);

    if (registry.scheduler_thread) |thread| {
        thread.join();
        registry.scheduler_thread = null;
    }

    for (&registry.worker_threads) |*maybe_thread| {
        if (maybe_thread.*) |thread| {
            thread.join();
            maybe_thread.* = null;
        }
    }
    registry.worker_thread_count = 0;
}

fn schedulerLoop() void {
    while (registry.checker_running.load(.acquire)) {
        const now = std.time.timestamp();
        scheduleDueChecks(now);
        std.Thread.sleep(types.scheduler_interval_ms * std.time.ns_per_ms);
    }
}

fn workerLoop(_: usize) void {
    while (registry.checker_running.load(.acquire)) {
        const item = registry.dequeueCheck() orelse {
            std.Thread.sleep(50 * std.time.ns_per_ms);
            continue;
        };

        const started_ns = std.time.nanoTimestamp();
        const success = checks.runCheck(item.container_ip, item.config);
        const completed_at = std.time.timestamp();
        const completion = applyCompletedCheck(item, success, completed_at);
        registry.noteCompletedCheck(completion == .stale, completed_at);
        const elapsed_ns = std.time.nanoTimestamp() - started_ns;
        const latency_seconds = @as(f64, @floatFromInt(@max(elapsed_ns, 0))) / @as(f64, std.time.ns_per_s);
        service_observability.noteHealthCheckCompleted(item.serviceName(), completion == .stale, latency_seconds);
    }
}

fn scheduleDueChecks(now: i64) void {
    registry.health_mutex.lock();
    defer registry.health_mutex.unlock();

    for (registry.health_states.items) |*entry| {
        if (entry.in_flight) continue;
        if (entry.started_at) |started| {
            if (now - started < entry.config.start_period) continue;
        }
        if (now < entry.next_check_at) continue;

        entry.in_flight = true;
        const item = buildCheckItem(entry);
        const queued = registry.enqueueCheck(item, now) catch |err| {
            entry.in_flight = false;
            log.warn("health: failed to enqueue check for {s}: {}", .{ entry.serviceName(), err });
            continue;
        };
        if (!queued) entry.in_flight = false;
    }
}

fn buildCheckItem(entry: *const types.ServiceHealth) types.CheckItem {
    var item = types.CheckItem{
        .container_ip = entry.container_ip,
        .container_id = entry.container_id,
        .config = entry.config,
        .generation = entry.generation,
        .registration_epoch = entry.registration_epoch,
        .service_name_len = @intCast(entry.serviceName().len),
        .endpoint_id_len = @intCast(entry.endpointId().len),
    };
    @memcpy(item.service_name_buf[0..entry.serviceName().len], entry.serviceName());
    @memcpy(item.endpoint_id_buf[0..entry.endpointId().len], entry.endpointId());
    return item;
}

fn applyCompletedCheck(item: types.CheckItem, success: bool, completed_at: i64) Completion {
    const transition = blk: {
        registry.health_mutex.lock();
        defer registry.health_mutex.unlock();

        const entry = findTrackedEntry(item) orelse break :blk null;
        if (entry.generation != item.generation or entry.registration_epoch != item.registration_epoch) break :blk null;

        entry.in_flight = false;
        entry.last_check = completed_at;
        const transition = updateState(entry, success);
        entry.next_check_at = completed_at + nextIntervalSeconds(entry, success);
        break :blk transition;
    };

    const applied_transition = transition orelse return .stale;
    switch (applied_transition) {
        .none => return .applied,
        .became_healthy => {
            if (service_registry_runtime.noteProbeResultForGeneration(item.serviceName(), item.endpointId(), item.generation, true) == .applied) {
                service_registry_bridge.markEndpointHealthy(item.serviceName(), item.container_id[0..], item.container_ip);
            }
        },
        .became_unhealthy => {
            if (service_registry_runtime.noteProbeResultForGeneration(item.serviceName(), item.endpointId(), item.generation, false) == .applied) {
                service_registry_bridge.markEndpointUnhealthy(item.serviceName(), item.container_id[0..], item.container_ip);
            }
        },
    }
    return .applied;
}

pub fn updateState(entry: *types.ServiceHealth, success: bool) Transition {
    if (success) {
        entry.consecutive_successes += 1;
        entry.consecutive_failures = 0;
        entry.last_error = null;

        switch (entry.status) {
            .starting => {
                entry.status = .healthy;
                entry.flap_count += 1;
                service_observability.noteEndpointFlap(entry.serviceName());
                log.info("health: {s} is now healthy", .{entry.serviceName()});
                return .became_healthy;
            },
            .unhealthy => {
                entry.status = .healthy;
                entry.flap_count += 1;
                service_observability.noteEndpointFlap(entry.serviceName());
                log.info("health: {s} recovered, now healthy", .{entry.serviceName()});
                return .became_healthy;
            },
            .healthy => return .none,
        }
    }

    entry.consecutive_failures += 1;
    entry.consecutive_successes = 0;

    switch (entry.status) {
        .starting => {
            if (entry.consecutive_failures >= entry.config.retries) {
                entry.status = .unhealthy;
                entry.flap_count += 1;
                service_observability.noteEndpointFlap(entry.serviceName());
                log.warn("health: {s} failed to start (after {d} retries)", .{
                    entry.serviceName(),
                    entry.config.retries,
                });
                return .became_unhealthy;
            }
        },
        .healthy => {
            if (entry.consecutive_failures >= entry.config.retries) {
                entry.status = .unhealthy;
                entry.flap_count += 1;
                service_observability.noteEndpointFlap(entry.serviceName());
                log.warn("health: {s} is now unhealthy (after {d} consecutive failures)", .{
                    entry.serviceName(),
                    entry.config.retries,
                });
                return .became_unhealthy;
            }
        },
        .unhealthy => {},
    }
    return .none;
}

fn nextIntervalSeconds(entry: *const types.ServiceHealth, success: bool) i64 {
    var delay: i64 = entry.config.interval;
    if (!success and entry.status == .unhealthy) {
        const multiplier_shift = @min(entry.consecutive_failures, 3);
        delay *= @as(i64, 1) << @intCast(multiplier_shift);
        if (delay > 60) delay = 60;
    }
    return delay + jitterSeconds(entry, delay);
}

fn jitterSeconds(entry: *const types.ServiceHealth, delay: i64) i64 {
    if (delay <= 1) return 0;
    var hash = std.hash.Wyhash.init(0);
    hash.update(entry.serviceName());
    hash.update(entry.endpointId());
    const bucket = hash.final() % 3;
    return switch (bucket) {
        0 => -1,
        1 => 0,
        else => 1,
    };
}

fn findTrackedEntry(item: types.CheckItem) ?*types.ServiceHealth {
    for (registry.health_states.items) |*entry| {
        if (!std.mem.eql(u8, entry.serviceName(), item.serviceName())) continue;
        if (!std.mem.eql(u8, entry.endpointId(), item.endpointId())) continue;
        return entry;
    }
    return null;
}

test "applyCompletedCheck rejects stale registration epochs" {
    registry.resetForTest();
    defer registry.resetForTest();

    var entry = types.ServiceHealth{
        .status = .starting,
        .consecutive_failures = 0,
        .consecutive_successes = 0,
        .last_check = null,
        .last_error = null,
        .started_at = 100,
        .container_id = "abcdef123456".*,
        .container_ip = .{ 10, 42, 0, 9 },
        .config = .{
            .check_type = .{ .tcp = .{ .port = 8080 } },
            .retries = 3,
        },
        .generation = 2,
        .registration_epoch = 2,
        .next_check_at = 100,
        .in_flight = true,
        .name_len = 3,
        .endpoint_id_len = 14,
    };
    @memcpy(entry.name_buf[0..3], "api");
    @memcpy(entry.endpoint_id_buf[0..14], "abcdef123456:0");
    try registry.health_states.append(std.heap.page_allocator, entry);

    var stale = buildCheckItem(&registry.health_states.items[0]);
    stale.registration_epoch = 1;
    try std.testing.expectEqual(Completion.stale, applyCompletedCheck(stale, true, 200));
    try std.testing.expectEqual(types.HealthStatus.starting, registry.health_states.items[0].status);
}

test "scheduleDueChecks bounds the queued work" {
    registry.resetForTest();
    defer registry.resetForTest();

    for (0..(types.max_queued_checks + 2)) |idx| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "svc-{d}", .{idx});
        var entry = types.ServiceHealth{
            .status = .starting,
            .consecutive_failures = 0,
            .consecutive_successes = 0,
            .last_check = null,
            .last_error = null,
            .started_at = 0,
            .container_id = "abcdef123456".*,
            .container_ip = .{ 10, 42, 0, 9 },
            .config = .{
                .check_type = .{ .tcp = .{ .port = 8080 } },
                .retries = 3,
            },
            .generation = 1,
            .registration_epoch = 1,
            .next_check_at = 0,
            .name_len = @intCast(name.len),
            .endpoint_id_len = 14,
        };
        @memcpy(entry.name_buf[0..name.len], name);
        @memcpy(entry.endpoint_id_buf[0..14], "abcdef123456:0");
        try registry.health_states.append(std.heap.page_allocator, entry);
    }

    scheduleDueChecks(100);

    const snapshot = registry.snapshotChecker();
    try std.testing.expectEqual(@as(usize, types.max_queued_checks), snapshot.queued_checks);
    try std.testing.expect(snapshot.dropped_queue_full_total > 0);
}
