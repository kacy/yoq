const std = @import("std");
const log = @import("../../lib/log.zig");
const service_registry_runtime = @import("../../network/service_registry_runtime.zig");
const store = @import("../../state/store.zig");
const types = @import("types.zig");

pub var health_states: std.ArrayList(types.ServiceHealth) = .empty;
pub var health_mutex: std.Thread.Mutex = .{};

pub var scheduler_thread: ?std.Thread = null;
pub var worker_threads: [types.max_worker_threads]?std.Thread = [_]?std.Thread{null} ** types.max_worker_threads;
pub var worker_thread_count: usize = 0;
pub var checker_running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

pub var work_queue: std.ArrayList(types.CheckItem) = .empty;
pub var work_mutex: std.Thread.Mutex = .{};
pub var scheduled_total: u64 = 0;
pub var completed_total: u64 = 0;
pub var stale_results_total: u64 = 0;
pub var dropped_queue_full_total: u64 = 0;
pub var last_scheduled_at: ?i64 = null;
pub var last_completed_at: ?i64 = null;

pub fn registerService(
    service_name: []const u8,
    container_id: [12]u8,
    container_ip: [4]u8,
    config: anytype,
) types.HealthError!void {
    var endpoint_id_buf: [96]u8 = undefined;
    const endpoint_id = activeEndpointId(&container_id, &endpoint_id_buf);
    const generation = resolveEndpointGeneration(service_name, endpoint_id);
    const now = std.time.timestamp();

    service_registry_runtime.syncServiceFromStore(service_name);
    const pending_outcome = service_registry_runtime.markEndpointPending(service_name, endpoint_id, generation);
    if (pending_outcome == .stale_generation) {
        log.warn("health: pending gate rejected for {s}/{s} generation={}", .{ service_name, endpoint_id, generation });
    }

    health_mutex.lock();
    defer health_mutex.unlock();

    const len = @min(service_name.len, 64);
    const endpoint_len = @min(endpoint_id.len, 96);
    if (findServiceIndex(service_name)) |index| {
        var entry = &health_states.items[index];
        entry.status = .starting;
        entry.consecutive_failures = 0;
        entry.consecutive_successes = 0;
        entry.last_check = null;
        entry.last_error = null;
        entry.started_at = now;
        entry.container_id = container_id;
        entry.container_ip = container_ip;
        entry.config = config;
        entry.name_len = @intCast(len);
        @memcpy(entry.name_buf[0..len], service_name[0..len]);
        entry.endpoint_id_len = @intCast(endpoint_len);
        @memcpy(entry.endpoint_id_buf[0..endpoint_len], endpoint_id[0..endpoint_len]);
        entry.generation = generation;
        entry.registration_epoch += 1;
        entry.next_check_at = now;
        entry.in_flight = false;
        entry.flap_count = 0;
        return;
    }

    var entry = types.ServiceHealth{
        .status = .starting,
        .consecutive_failures = 0,
        .consecutive_successes = 0,
        .last_check = null,
        .last_error = null,
        .started_at = now,
        .container_id = container_id,
        .container_ip = container_ip,
        .config = config,
        .generation = generation,
        .registration_epoch = 1,
        .next_check_at = now,
        .in_flight = false,
        .flap_count = 0,
        .name_len = @intCast(len),
        .endpoint_id_len = @intCast(endpoint_len),
    };
    @memcpy(entry.name_buf[0..len], service_name[0..len]);
    @memcpy(entry.endpoint_id_buf[0..endpoint_len], endpoint_id[0..endpoint_len]);
    health_states.append(std.heap.page_allocator, entry) catch return types.HealthError.OutOfMemory;
}

pub fn unregisterService(service_name: []const u8) void {
    health_mutex.lock();
    defer health_mutex.unlock();

    const index = findServiceIndex(service_name) orelse return;
    _ = health_states.orderedRemove(index);
}

pub fn getStatus(service_name: []const u8) ?types.HealthStatus {
    health_mutex.lock();
    defer health_mutex.unlock();

    const index = findServiceIndex(service_name) orelse return null;
    return health_states.items[index].status;
}

pub fn getServiceHealth(service_name: []const u8) ?types.ServiceHealth {
    health_mutex.lock();
    defer health_mutex.unlock();

    const index = findServiceIndex(service_name) orelse return null;
    return health_states.items[index];
}

pub fn snapshotChecker() types.CheckerSnapshot {
    work_mutex.lock();
    defer work_mutex.unlock();
    health_mutex.lock();
    defer health_mutex.unlock();

    var in_flight: usize = 0;
    for (health_states.items) |entry| {
        if (entry.in_flight) in_flight += 1;
    }

    return .{
        .running = checker_running.load(.acquire),
        .tracked_endpoints = health_states.items.len,
        .in_flight_checks = in_flight,
        .queued_checks = work_queue.items.len,
        .worker_threads = worker_thread_count,
        .scheduled_total = scheduled_total,
        .completed_total = completed_total,
        .stale_results_total = stale_results_total,
        .dropped_queue_full_total = dropped_queue_full_total,
        .last_scheduled_at = last_scheduled_at,
        .last_completed_at = last_completed_at,
    };
}

pub fn resetForTest() void {
    checker_running.store(false, .release);

    if (scheduler_thread) |thread| {
        thread.join();
        scheduler_thread = null;
    }

    for (&worker_threads) |*maybe_thread| {
        if (maybe_thread.*) |thread| {
            thread.join();
            maybe_thread.* = null;
        }
    }
    worker_thread_count = 0;

    health_mutex.lock();
    defer health_mutex.unlock();
    work_mutex.lock();
    defer work_mutex.unlock();

    health_states.clearRetainingCapacity();
    work_queue.clearRetainingCapacity();
    scheduled_total = 0;
    completed_total = 0;
    stale_results_total = 0;
    dropped_queue_full_total = 0;
    last_scheduled_at = null;
    last_completed_at = null;
}

pub fn enqueueCheck(item: types.CheckItem, scheduled_at: i64) types.HealthError!bool {
    work_mutex.lock();
    defer work_mutex.unlock();

    if (work_queue.items.len >= types.max_queued_checks) {
        dropped_queue_full_total += 1;
        return false;
    }

    work_queue.append(std.heap.page_allocator, item) catch return types.HealthError.OutOfMemory;
    scheduled_total += 1;
    last_scheduled_at = scheduled_at;
    return true;
}

pub fn dequeueCheck() ?types.CheckItem {
    work_mutex.lock();
    defer work_mutex.unlock();

    if (work_queue.items.len == 0) return null;
    return work_queue.orderedRemove(0);
}

pub fn noteCompletedCheck(stale: bool, completed_at: i64) void {
    work_mutex.lock();
    defer work_mutex.unlock();
    completed_total += 1;
    if (stale) stale_results_total += 1;
    last_completed_at = completed_at;
}

fn resolveEndpointGeneration(service_name: []const u8, endpoint_id: []const u8) i64 {
    const alloc = std.heap.page_allocator;
    const endpoint = store.getServiceEndpoint(alloc, service_name, endpoint_id) catch |err| switch (err) {
        store.StoreError.NotFound => return 1,
        else => {
            log.warn("health: failed to load persisted endpoint generation for {s}/{s}: {}", .{ service_name, endpoint_id, err });
            return 1;
        },
    };
    defer endpoint.deinit(alloc);
    return endpoint.generation;
}

fn activeEndpointId(container_id: *const [12]u8, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{s}:0", .{container_id}) catch container_id[0..];
}

fn findServiceIndex(service_name: []const u8) ?usize {
    for (health_states.items, 0..) |entry, idx| {
        if (std.mem.eql(u8, entry.serviceName(), service_name)) return idx;
    }
    return null;
}
