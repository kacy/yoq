const std = @import("std");
const platform = @import("platform");

const Allocator = std.mem.Allocator;

pub const ServiceCounters = struct {
    service_name: []const u8,
    reconcile_requested_total: u64,
    reconcile_succeeded_total: u64,
    reconcile_failed_total: u64,
    reconcile_duration_seconds: f64,
    dns_interceptor_sync_failures_total: u64,
    load_balancer_sync_failures_total: u64,
    health_checks_scheduled_total: u64,
    health_checks_completed_total: u64,
    health_stale_results_total: u64,
    health_check_latency_seconds: f64,
    endpoint_flaps_total: u64,

    pub fn deinit(self: ServiceCounters, alloc: Allocator) void {
        alloc.free(self.service_name);
    }
};

pub const Snapshot = struct {
    vip_alloc_failures_total: u64,
    services: std.ArrayList(ServiceCounters),

    pub fn deinit(self: *Snapshot, alloc: Allocator) void {
        for (self.services.items) |service| service.deinit(alloc);
        self.services.deinit(alloc);
    }
};

const MutableServiceCounters = struct {
    service_name: []const u8,
    reconcile_requested_total: u64 = 0,
    reconcile_succeeded_total: u64 = 0,
    reconcile_failed_total: u64 = 0,
    reconcile_requested_at: ?i64 = null,
    reconcile_duration_seconds: f64 = 0,
    dns_interceptor_sync_failures_total: u64 = 0,
    load_balancer_sync_failures_total: u64 = 0,
    health_checks_scheduled_total: u64 = 0,
    health_checks_completed_total: u64 = 0,
    health_stale_results_total: u64 = 0,
    health_check_latency_seconds: f64 = 0,
    endpoint_flaps_total: u64 = 0,

    fn deinit(self: MutableServiceCounters, alloc: Allocator) void {
        alloc.free(self.service_name);
    }
};

var mutex: std.Io.Mutex = .init;
var service_counters: std.ArrayList(MutableServiceCounters) = .empty;
var vip_alloc_failures_total: u64 = 0;

pub fn resetForTest() void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    for (service_counters.items) |entry| entry.deinit(std.heap.page_allocator);
    service_counters.clearRetainingCapacity();
    vip_alloc_failures_total = 0;
}

pub fn noteReconcileRequested(service_name: []const u8) void {
    noteServiceCounter(service_name, .reconcile_requested);
}

pub fn noteReconcileSucceeded(service_name: []const u8) void {
    noteServiceCounter(service_name, .reconcile_succeeded);
}

pub fn noteReconcileFailed(service_name: []const u8) void {
    noteServiceCounter(service_name, .reconcile_failed);
}

pub fn noteHealthCheckScheduled(service_name: []const u8) void {
    noteServiceCounter(service_name, .health_scheduled);
}

pub fn noteHealthCheckCompleted(service_name: []const u8, stale: bool, latency_seconds: f64) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    var counters = ensureServiceCountersLocked(service_name) catch return;
    counters.health_checks_completed_total += 1;
    if (stale) counters.health_stale_results_total += 1;
    counters.health_check_latency_seconds = latency_seconds;
}

pub fn noteEndpointFlap(service_name: []const u8) void {
    noteServiceCounter(service_name, .endpoint_flap);
}

pub fn noteVipAllocFailure() void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    vip_alloc_failures_total += 1;
}

pub const BpfComponent = enum {
    dns_interceptor,
    load_balancer,
};

pub fn noteBpfSyncFailure(service_name: []const u8, component: BpfComponent) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    var counters = ensureServiceCountersLocked(service_name) catch return;
    switch (component) {
        .dns_interceptor => counters.dns_interceptor_sync_failures_total += 1,
        .load_balancer => counters.load_balancer_sync_failures_total += 1,
    }
}

pub fn snapshot(alloc: Allocator) !Snapshot {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    var services: std.ArrayList(ServiceCounters) = .empty;
    errdefer {
        for (services.items) |entry| entry.deinit(alloc);
        services.deinit(alloc);
    }

    for (service_counters.items) |entry| {
        try services.append(alloc, .{
            .service_name = try alloc.dupe(u8, entry.service_name),
            .reconcile_requested_total = entry.reconcile_requested_total,
            .reconcile_succeeded_total = entry.reconcile_succeeded_total,
            .reconcile_failed_total = entry.reconcile_failed_total,
            .reconcile_duration_seconds = entry.reconcile_duration_seconds,
            .dns_interceptor_sync_failures_total = entry.dns_interceptor_sync_failures_total,
            .load_balancer_sync_failures_total = entry.load_balancer_sync_failures_total,
            .health_checks_scheduled_total = entry.health_checks_scheduled_total,
            .health_checks_completed_total = entry.health_checks_completed_total,
            .health_stale_results_total = entry.health_stale_results_total,
            .health_check_latency_seconds = entry.health_check_latency_seconds,
            .endpoint_flaps_total = entry.endpoint_flaps_total,
        });
    }

    return .{
        .vip_alloc_failures_total = vip_alloc_failures_total,
        .services = services,
    };
}

pub fn findServiceCounters(items: []const ServiceCounters, service_name: []const u8) ?ServiceCounters {
    for (items) |entry| {
        if (std.mem.eql(u8, entry.service_name, service_name)) return entry;
    }
    return null;
}

const CounterKind = enum {
    reconcile_requested,
    reconcile_succeeded,
    reconcile_failed,
    health_scheduled,
    endpoint_flap,
};

fn noteServiceCounter(service_name: []const u8, kind: CounterKind) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    var counters = ensureServiceCountersLocked(service_name) catch return;
    switch (kind) {
        .reconcile_requested => counters.reconcile_requested_total += 1,
        .reconcile_succeeded => counters.reconcile_succeeded_total += 1,
        .reconcile_failed => counters.reconcile_failed_total += 1,
        .health_scheduled => counters.health_checks_scheduled_total += 1,
        .endpoint_flap => counters.endpoint_flaps_total += 1,
    }
    switch (kind) {
        .reconcile_requested => counters.reconcile_requested_at = platform.timestamp(),
        .reconcile_succeeded, .reconcile_failed => {
            if (counters.reconcile_requested_at) |started_at| {
                const now = platform.timestamp();
                counters.reconcile_duration_seconds = @floatFromInt(@max(now - started_at, 0));
                counters.reconcile_requested_at = null;
            }
        },
        else => {},
    }
}

fn ensureServiceCountersLocked(service_name: []const u8) !*MutableServiceCounters {
    for (service_counters.items) |*entry| {
        if (std.mem.eql(u8, entry.service_name, service_name)) return entry;
    }

    try service_counters.append(std.heap.page_allocator, .{
        .service_name = try std.heap.page_allocator.dupe(u8, service_name),
    });
    return &service_counters.items[service_counters.items.len - 1];
}

test "snapshot includes recorded service counters" {
    resetForTest();
    defer resetForTest();

    noteReconcileRequested("api");
    noteReconcileSucceeded("api");
    noteReconcileFailed("api");
    noteHealthCheckScheduled("api");
    noteHealthCheckCompleted("api", false, 0.125);
    noteHealthCheckCompleted("api", true, 0.25);
    noteBpfSyncFailure("api", .dns_interceptor);
    noteBpfSyncFailure("api", .load_balancer);
    noteEndpointFlap("api");
    noteVipAllocFailure();

    var snap = try snapshot(std.testing.allocator);
    defer snap.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 1), snap.vip_alloc_failures_total);
    const service = findServiceCounters(snap.services.items, "api").?;
    try std.testing.expectEqual(@as(u64, 1), service.reconcile_requested_total);
    try std.testing.expectEqual(@as(u64, 1), service.reconcile_succeeded_total);
    try std.testing.expectEqual(@as(u64, 1), service.reconcile_failed_total);
    try std.testing.expect(service.reconcile_duration_seconds >= 0);
    try std.testing.expectEqual(@as(u64, 1), service.dns_interceptor_sync_failures_total);
    try std.testing.expectEqual(@as(u64, 1), service.load_balancer_sync_failures_total);
    try std.testing.expectEqual(@as(u64, 1), service.health_checks_scheduled_total);
    try std.testing.expectEqual(@as(u64, 2), service.health_checks_completed_total);
    try std.testing.expectEqual(@as(u64, 1), service.health_stale_results_total);
    try std.testing.expectEqual(@as(f64, 0.25), service.health_check_latency_seconds);
    try std.testing.expectEqual(@as(u64, 1), service.endpoint_flaps_total);
}
