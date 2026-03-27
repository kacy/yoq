const std = @import("std");
const log = @import("../../lib/log.zig");
const router = @import("router.zig");
const service_registry_runtime = @import("../service_registry_runtime.zig");
const service_rollout = @import("../service_rollout.zig");

pub const max_routes_in_status = 16;

pub const RouteSnapshot = struct {
    name: []const u8,
    service: []const u8,
    vip_address: []const u8,
    host: []const u8,
    path_prefix: []const u8,
    retries: u8,
    connect_timeout_ms: u32,
    request_timeout_ms: u32,
    preserve_host: bool,

    pub fn deinit(self: RouteSnapshot, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.service);
        alloc.free(self.vip_address);
        alloc.free(self.host);
        alloc.free(self.path_prefix);
    }
};

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
var materialized_routes: std.ArrayList(router.Route) = .empty;
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
    deinitRoutesLocked();
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

pub fn snapshotRoutes(alloc: std.mem.Allocator) !std.ArrayList(RouteSnapshot) {
    mutex.lock();
    defer mutex.unlock();

    var routes_snapshot: std.ArrayList(RouteSnapshot) = .empty;
    errdefer {
        for (routes_snapshot.items) |route| route.deinit(alloc);
        routes_snapshot.deinit(alloc);
    }

    for (materialized_routes.items) |route| {
        const snapshot_route = try cloneRouteSnapshot(alloc, route);
        errdefer snapshot_route.deinit(alloc);
        try routes_snapshot.append(alloc, snapshot_route);
    }

    return routes_snapshot;
}

pub fn snapshotServiceRoutes(alloc: std.mem.Allocator, service_name: []const u8) !std.ArrayList(RouteSnapshot) {
    {
        const service = try service_registry_runtime.snapshotService(alloc, service_name);
        service.deinit(alloc);
    }

    mutex.lock();
    defer mutex.unlock();

    var routes_snapshot: std.ArrayList(RouteSnapshot) = .empty;
    errdefer {
        for (routes_snapshot.items) |route| route.deinit(alloc);
        routes_snapshot.deinit(alloc);
    }

    for (materialized_routes.items) |route| {
        if (!std.mem.eql(u8, route.service, service_name)) continue;

        const snapshot_route = try cloneRouteSnapshot(alloc, route);
        errdefer snapshot_route.deinit(alloc);
        try routes_snapshot.append(alloc, snapshot_route);
    }

    return routes_snapshot;
}

fn cloneRouteSnapshot(alloc: std.mem.Allocator, route: router.Route) !RouteSnapshot {
    return .{
        .name = try alloc.dupe(u8, route.name),
        .service = try alloc.dupe(u8, route.service),
        .vip_address = try alloc.dupe(u8, route.vip_address),
        .host = try alloc.dupe(u8, route.match.host orelse ""),
        .path_prefix = try alloc.dupe(u8, route.match.path_prefix),
        .retries = route.retries,
        .connect_timeout_ms = route.connect_timeout_ms,
        .request_timeout_ms = route.request_timeout_ms,
        .preserve_host = route.preserve_host,
    };
}

fn syncLocked() !void {
    var services = try service_registry_runtime.snapshotServices(std.heap.page_allocator);
    defer {
        for (services.items) |service| service.deinit(std.heap.page_allocator);
        services.deinit(std.heap.page_allocator);
    }

    clearLastErrorLocked();
    deinitRoutesLocked();
    errdefer {
        deinitRoutesLocked();
        configured_services = 0;
        routes = 0;
        last_sync_at = null;
    }

    var next_configured_services: u32 = 0;
    var next_routes: u32 = 0;
    for (services.items) |service| {
        const host = service.http_proxy_host orelse continue;
        next_configured_services += 1;
        next_routes += 1;
        const route = router.Route{
            .name = try std.fmt.allocPrint(std.heap.page_allocator, "{s}:{s}", .{
                service.service_name,
                service.http_proxy_path_prefix orelse "/",
            }),
            .service = try std.heap.page_allocator.dupe(u8, service.service_name),
            .vip_address = try std.heap.page_allocator.dupe(u8, service.vip_address),
            .match = .{
                .host = try std.heap.page_allocator.dupe(u8, host),
                .path_prefix = try std.heap.page_allocator.dupe(u8, service.http_proxy_path_prefix orelse "/"),
            },
            .retries = service.http_proxy_retries orelse 0,
            .connect_timeout_ms = service.http_proxy_connect_timeout_ms orelse 1000,
            .request_timeout_ms = service.http_proxy_request_timeout_ms orelse 5000,
            .preserve_host = service.http_proxy_preserve_host orelse true,
        };
        errdefer {
            std.heap.page_allocator.free(route.name);
            std.heap.page_allocator.free(route.service);
            std.heap.page_allocator.free(route.vip_address);
            if (route.match.host) |owned_host| std.heap.page_allocator.free(owned_host);
            std.heap.page_allocator.free(route.match.path_prefix);
        }
        try materialized_routes.append(std.heap.page_allocator, route);
    }

    configured_services = next_configured_services;
    routes = next_routes;
    running = true;
    last_sync_at = std.time.timestamp();
}

fn deinitRoutesLocked() void {
    for (materialized_routes.items) |route| {
        std.heap.page_allocator.free(route.name);
        std.heap.page_allocator.free(route.service);
        std.heap.page_allocator.free(route.vip_address);
        if (route.match.host) |host| std.heap.page_allocator.free(host);
        std.heap.page_allocator.free(route.match.path_prefix);
    }
    materialized_routes.clearAndFree(std.heap.page_allocator);
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

    var routes_snapshot = try snapshotRoutes(std.testing.allocator);
    defer {
        for (routes_snapshot.items) |route| route.deinit(std.testing.allocator);
        routes_snapshot.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), routes_snapshot.items.len);
    try std.testing.expectEqualStrings("api", routes_snapshot.items[0].service);
    try std.testing.expectEqualStrings("10.43.0.2", routes_snapshot.items[0].vip_address);
    try std.testing.expectEqualStrings("api.internal", routes_snapshot.items[0].host);
    try std.testing.expectEqualStrings("/v1", routes_snapshot.items[0].path_prefix);
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

test "snapshotServiceRoutes filters routes by service" {
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
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.createService(.{
        .service_name = "web",
        .vip_address = "10.43.0.3",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "web.internal",
        .http_proxy_path_prefix = "/",
        .created_at = 1001,
        .updated_at = 1001,
    });

    bootstrapIfEnabled();

    var routes_snapshot = try snapshotServiceRoutes(std.testing.allocator, "api");
    defer {
        for (routes_snapshot.items) |route| route.deinit(std.testing.allocator);
        routes_snapshot.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), routes_snapshot.items.len);
    try std.testing.expectEqualStrings("api.internal", routes_snapshot.items[0].host);
}
