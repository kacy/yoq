const std = @import("std");
const log = @import("../../lib/log.zig");
const service_registry_runtime = @import("../service_registry_runtime.zig");
const service_rollout = @import("../service_rollout.zig");

pub const Snapshot = struct {
    enabled: bool,
    running: bool,
    configured_services: u32,
    routes: u32,
    last_sync_at: ?i64,
    last_error: ?[]const u8,

    pub fn deinit(self: Snapshot, alloc: std.mem.Allocator) void {
        if (self.last_error) |message| alloc.free(message);
    }
};

var mutex: std.Thread.Mutex = .{};
var running: bool = false;
var configured_services: u32 = 0;
var routes: u32 = 0;
var last_sync_at: ?i64 = null;
var last_error: ?[]u8 = null;

pub fn resetForTest() void {
    mutex.lock();
    defer mutex.unlock();

    running = false;
    configured_services = 0;
    routes = 0;
    last_sync_at = null;
    clearLastErrorLocked();
}

pub fn bootstrapIfEnabled() void {
    if (!service_rollout.current().l7_proxy_http) return;

    mutex.lock();
    defer mutex.unlock();

    syncLocked() catch |err| {
        setLastErrorLocked(err);
        log.warn("l7 proxy runtime: bootstrap failed: {}", .{err});
    };
}

pub fn snapshot(alloc: std.mem.Allocator) !Snapshot {
    mutex.lock();
    defer mutex.unlock();

    return .{
        .enabled = service_rollout.current().l7_proxy_http,
        .running = running,
        .configured_services = configured_services,
        .routes = routes,
        .last_sync_at = last_sync_at,
        .last_error = if (last_error) |message| try alloc.dupe(u8, message) else null,
    };
}

fn syncLocked() !void {
    var services = try service_registry_runtime.snapshotServices(std.heap.page_allocator);
    defer {
        for (services.items) |service| service.deinit(std.heap.page_allocator);
        services.deinit(std.heap.page_allocator);
    }

    clearLastErrorLocked();

    var next_configured_services: u32 = 0;
    var next_routes: u32 = 0;
    for (services.items) |service| {
        if (service.http_proxy_host == null) continue;
        next_configured_services += 1;
        next_routes += 1;
    }

    configured_services = next_configured_services;
    routes = next_routes;
    running = true;
    last_sync_at = std.time.timestamp();
}

fn clearLastErrorLocked() void {
    if (last_error) |message| std.heap.page_allocator.free(message);
    last_error = null;
}

fn setLastErrorLocked(err: anyerror) void {
    clearLastErrorLocked();
    last_error = std.fmt.allocPrint(std.heap.page_allocator, "{}", .{err}) catch null;
    running = false;
}

test "bootstrap tracks configured proxy routes from service state" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/v1",
        .http_proxy_retries = 2,
        .http_proxy_connect_timeout_ms = 1500,
        .http_proxy_request_timeout_ms = 5000,
        .http_proxy_preserve_host = true,
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.createService(.{
        .service_name = "worker",
        .vip_address = "10.43.0.3",
        .lb_policy = "consistent_hash",
        .created_at = 1001,
        .updated_at = 1001,
    });

    bootstrapIfEnabled();

    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);

    try std.testing.expect(state.enabled);
    try std.testing.expect(state.running);
    try std.testing.expectEqual(@as(u32, 1), state.configured_services);
    try std.testing.expectEqual(@as(u32, 1), state.routes);
    try std.testing.expect(state.last_sync_at != null);
    try std.testing.expect(state.last_error == null);
}

test "bootstrap is inert when l7 proxy flag is disabled" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    service_rollout.setForTest(.{ .service_registry_v2 = true });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .created_at = 1000,
        .updated_at = 1000,
    });

    bootstrapIfEnabled();

    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);

    try std.testing.expect(!state.enabled);
    try std.testing.expect(!state.running);
    try std.testing.expectEqual(@as(u32, 0), state.configured_services);
    try std.testing.expectEqual(@as(u32, 0), state.routes);
    try std.testing.expect(state.last_sync_at == null);
}
