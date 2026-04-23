const std = @import("std");
const platform = @import("platform");
const log = @import("../lib/log.zig");
const rollout = @import("service_rollout.zig");
const store = @import("../state/store.zig");

pub const Snapshot = struct {
    enabled: bool,
    runs_total: u64,
    services_created_total: u64,
    endpoints_created_total: u64,
    last_run_at: ?i64,
    last_error: ?[]const u8,

    pub fn deinit(self: *Snapshot, alloc: std.mem.Allocator) void {
        if (self.last_error) |message| alloc.free(message);
    }
};

var mutex: std.Io.Mutex = .init;
var runs_total: u64 = 0;
var services_created_total: u64 = 0;
var endpoints_created_total: u64 = 0;
var last_run_at: ?i64 = null;
var last_error: ?[]const u8 = null;

pub fn runIfEnabled() void {
    if (rollout.mode() == .legacy) return;

    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    runs_total += 1;
    last_run_at = platform.timestamp();
    clearLastErrorLocked();

    runLocked() catch |err| {
        setLastErrorLocked(@errorName(err)) catch {};
        log.warn("service registry backfill: failed: {}", .{err});
    };
}

pub fn snapshot(alloc: std.mem.Allocator) !Snapshot {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    return .{
        .enabled = rollout.mode() != .legacy,
        .runs_total = runs_total,
        .services_created_total = services_created_total,
        .endpoints_created_total = endpoints_created_total,
        .last_run_at = last_run_at,
        .last_error = if (last_error) |message| try alloc.dupe(u8, message) else null,
    };
}

pub fn resetForTest() void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    runs_total = 0;
    services_created_total = 0;
    endpoints_created_total = 0;
    last_run_at = null;
    clearLastErrorLocked();
}

fn runLocked() !void {
    const alloc = std.heap.page_allocator;
    var legacy_names = try store.listServiceNames(alloc);
    defer {
        for (legacy_names.items) |record| record.deinit(alloc);
        legacy_names.deinit(alloc);
    }

    for (legacy_names.items) |record| {
        const existing_service = store.getService(alloc, record.name) catch |err| switch (err) {
            store.StoreError.NotFound => null,
            else => return err,
        };
        const service_missing = existing_service == null;
        if (existing_service) |service_value| {
            service_value.deinit(alloc);
        }

        const service = try store.ensureService(alloc, record.name, "consistent_hash");
        defer service.deinit(alloc);
        if (service_missing) services_created_total += 1;

        var endpoint_id_buf: [96]u8 = undefined;
        const endpoint_id = try std.fmt.bufPrint(&endpoint_id_buf, "{s}:0", .{record.container_id});
        const existing_endpoint = store.getServiceEndpoint(alloc, record.name, endpoint_id) catch |err| switch (err) {
            store.StoreError.NotFound => null,
            else => return err,
        };
        if (existing_endpoint) |endpoint| {
            endpoint.deinit(alloc);
            continue;
        }

        try store.upsertServiceEndpoint(.{
            .service_name = record.name,
            .endpoint_id = endpoint_id,
            .container_id = record.container_id,
            .node_id = null,
            .ip_address = record.ip_address,
            .port = 0,
            .weight = 1,
            .admin_state = "active",
            .generation = 1,
            .registered_at = record.registered_at,
            .last_seen_at = record.registered_at,
        });
        endpoints_created_total += 1;
    }
}

fn clearLastErrorLocked() void {
    if (last_error) |message| std.heap.page_allocator.free(message);
    last_error = null;
}

fn setLastErrorLocked(message: []const u8) !void {
    clearLastErrorLocked();
    last_error = try std.heap.page_allocator.dupe(u8, message);
}

test "backfill from service_names is idempotent" {
    try store.initTestDb();
    defer store.deinitTestDb();
    resetForTest();
    defer resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();

    try store.registerServiceName("api", "abc123", "10.42.0.9");
    try store.registerServiceName("web", "def456", "10.42.0.10");

    runIfEnabled();
    runIfEnabled();

    const api_service = try store.getService(std.testing.allocator, "api");
    defer api_service.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("10.43.0.2", api_service.vip_address);

    var api_endpoints = try store.listServiceEndpoints(std.testing.allocator, "api");
    defer {
        for (api_endpoints.items) |endpoint| endpoint.deinit(std.testing.allocator);
        api_endpoints.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), api_endpoints.items.len);
    try std.testing.expectEqualStrings("abc123:0", api_endpoints.items[0].endpoint_id);

    const state = try snapshot(std.testing.allocator);
    defer {
        var mutable = state;
        mutable.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(u64, 2), state.runs_total);
    try std.testing.expectEqual(@as(u64, 2), state.services_created_total);
    try std.testing.expectEqual(@as(u64, 2), state.endpoints_created_total);
}
