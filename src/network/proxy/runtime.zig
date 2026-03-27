const std = @import("std");
const http = @import("../../api/http.zig");
const log = @import("../../lib/log.zig");
const router = @import("router.zig");
const upstream_mod = @import("upstream.zig");
const service_registry_runtime = @import("../service_registry_runtime.zig");
const service_rollout = @import("../service_rollout.zig");

pub const max_routes_in_status = 16;

pub const RouteSnapshot = struct {
    name: []const u8,
    service: []const u8,
    vip_address: []const u8,
    host: []const u8,
    path_prefix: []const u8,
    eligible_endpoints: u32,
    healthy_endpoints: u32,
    degraded: bool,
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
    requests_total: u64,
    responses_2xx_total: u64,
    responses_4xx_total: u64,
    responses_5xx_total: u64,
    retries_total: u64,
    loop_rejections_total: u64,
    upstream_connect_failures_total: u64,
    upstream_send_failures_total: u64,
    upstream_receive_failures_total: u64,
    upstream_other_failures_total: u64,
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
var requests_total: u64 = 0;
var responses_2xx_total: u64 = 0;
var responses_4xx_total: u64 = 0;
var responses_5xx_total: u64 = 0;
var retries_total: u64 = 0;
var loop_rejections_total: u64 = 0;
var upstream_connect_failures_total: u64 = 0;
var upstream_send_failures_total: u64 = 0;
var upstream_receive_failures_total: u64 = 0;
var upstream_other_failures_total: u64 = 0;
var last_sync_at: ?i64 = null;
var last_error: ?[]u8 = null;

pub const UpstreamFailureKind = enum {
    connect,
    send,
    receive,
    other,
};

pub fn resetForTest() void {
    mutex.lock();
    defer mutex.unlock();

    running = false;
    configured_services = 0;
    routes = 0;
    requests_total = 0;
    responses_2xx_total = 0;
    responses_4xx_total = 0;
    responses_5xx_total = 0;
    retries_total = 0;
    loop_rejections_total = 0;
    upstream_connect_failures_total = 0;
    upstream_send_failures_total = 0;
    upstream_receive_failures_total = 0;
    upstream_other_failures_total = 0;
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
        .requests_total = requests_total,
        .responses_2xx_total = responses_2xx_total,
        .responses_4xx_total = responses_4xx_total,
        .responses_5xx_total = responses_5xx_total,
        .retries_total = retries_total,
        .loop_rejections_total = loop_rejections_total,
        .upstream_connect_failures_total = upstream_connect_failures_total,
        .upstream_send_failures_total = upstream_send_failures_total,
        .upstream_receive_failures_total = upstream_receive_failures_total,
        .upstream_other_failures_total = upstream_other_failures_total,
        .last_sync_at = last_sync_at,
        .last_error = if (last_error) |message| try alloc.dupe(u8, message) else null,
    };
}

pub fn recordRequestStart() void {
    mutex.lock();
    defer mutex.unlock();
    requests_total += 1;
}

pub fn recordResponse(status: http.StatusCode) void {
    recordResponseCode(@intFromEnum(status));
}

pub fn recordResponseCode(status_code: u16) void {
    mutex.lock();
    defer mutex.unlock();

    switch (status_code) {
        200...299 => responses_2xx_total += 1,
        400...499 => responses_4xx_total += 1,
        500...599 => responses_5xx_total += 1,
        else => {},
    }
}

pub fn recordRetry() void {
    mutex.lock();
    defer mutex.unlock();
    retries_total += 1;
}

pub fn recordLoopRejection() void {
    mutex.lock();
    defer mutex.unlock();
    loop_rejections_total += 1;
}

pub fn recordUpstreamFailure(kind: UpstreamFailureKind) void {
    mutex.lock();
    defer mutex.unlock();

    switch (kind) {
        .connect => upstream_connect_failures_total += 1,
        .send => upstream_send_failures_total += 1,
        .receive => upstream_receive_failures_total += 1,
        .other => upstream_other_failures_total += 1,
    }
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

pub fn resolveRoute(alloc: std.mem.Allocator, host: []const u8, path: []const u8) !RouteSnapshot {
    mutex.lock();
    defer mutex.unlock();

    const matched = router.matchRoute(materialized_routes.items, host, path) orelse return error.RouteNotFound;
    return cloneRouteSnapshot(alloc, matched);
}

pub fn resolveUpstream(alloc: std.mem.Allocator, service_name: []const u8) !upstream_mod.Upstream {
    var endpoints = try service_registry_runtime.snapshotServiceEndpoints(alloc, service_name);
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(alloc);
        endpoints.deinit(alloc);
    }

    var candidates: std.ArrayList(upstream_mod.Upstream) = .empty;
    defer {
        for (candidates.items) |candidate| candidate.deinit(alloc);
        candidates.deinit(alloc);
    }

    for (endpoints.items) |endpoint| {
        const port: u16 = if (endpoint.port < 0) 0 else @intCast(endpoint.port);
        try candidates.append(alloc, .{
            .service = try alloc.dupe(u8, service_name),
            .endpoint_id = try alloc.dupe(u8, endpoint.endpoint_id),
            .address = try alloc.dupe(u8, endpoint.ip_address),
            .port = port,
            .eligible = endpoint.eligible,
        });
    }

    const selected = upstream_mod.selectFirstEligible(candidates.items) orelse return error.NoHealthyUpstream;
    return .{
        .service = try alloc.dupe(u8, selected.service),
        .endpoint_id = try alloc.dupe(u8, selected.endpoint_id),
        .address = try alloc.dupe(u8, selected.address),
        .port = selected.port,
        .eligible = selected.eligible,
    };
}

fn cloneRouteSnapshot(alloc: std.mem.Allocator, route: router.Route) !RouteSnapshot {
    return .{
        .name = try alloc.dupe(u8, route.name),
        .service = try alloc.dupe(u8, route.service),
        .vip_address = try alloc.dupe(u8, route.vip_address),
        .host = try alloc.dupe(u8, route.match.host orelse ""),
        .path_prefix = try alloc.dupe(u8, route.match.path_prefix),
        .eligible_endpoints = route.eligible_endpoints,
        .healthy_endpoints = route.healthy_endpoints,
        .degraded = route.degraded,
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
            .eligible_endpoints = @intCast(service.eligible_endpoints),
            .healthy_endpoints = @intCast(service.healthy_endpoints),
            .degraded = service.degraded,
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
    try std.testing.expectEqual(@as(u32, 0), routes_snapshot.items[0].eligible_endpoints);
    try std.testing.expect(routes_snapshot.items[0].degraded);
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

test "materialized routes include service endpoint readiness counts" {
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
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "ctr-1:0",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "10.42.0.9",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });

    bootstrapIfEnabled();

    var routes_snapshot = try snapshotServiceRoutes(std.testing.allocator, "api");
    defer {
        for (routes_snapshot.items) |route| route.deinit(std.testing.allocator);
        routes_snapshot.deinit(std.testing.allocator);
    }

    try std.testing.expectEqual(@as(usize, 1), routes_snapshot.items.len);
    try std.testing.expectEqual(@as(u32, 1), routes_snapshot.items[0].eligible_endpoints);
    try std.testing.expectEqual(@as(u32, 0), routes_snapshot.items[0].healthy_endpoints);
    try std.testing.expect(!routes_snapshot.items[0].degraded);
}

test "resolveRoute matches by host and path" {
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

    bootstrapIfEnabled();

    const route = try resolveRoute(std.testing.allocator, "api.internal", "/v1/users");
    defer route.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("api", route.service);
    try std.testing.expectEqualStrings("/v1", route.path_prefix);
}

test "resolveUpstream returns the first eligible endpoint" {
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
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-1",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "10.42.0.9",
        .port = 8080,
        .weight = 1,
        .admin_state = "draining",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-2",
        .container_id = "ctr-2",
        .node_id = null,
        .ip_address = "10.42.0.10",
        .port = 8081,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1001,
        .last_seen_at = 1001,
    });

    const upstream = try resolveUpstream(std.testing.allocator, "api");
    defer upstream.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("api-2", upstream.endpoint_id);
    try std.testing.expectEqualStrings("10.42.0.10", upstream.address);
    try std.testing.expectEqual(@as(u16, 8081), upstream.port);
}

test "snapshot exposes L7 proxy observability counters" {
    resetForTest();
    defer resetForTest();

    recordRequestStart();
    recordRequestStart();
    recordResponse(.ok);
    recordResponse(.bad_request);
    recordResponse(.bad_gateway);
    recordRetry();
    recordLoopRejection();
    recordUpstreamFailure(.connect);
    recordUpstreamFailure(.receive);
    recordUpstreamFailure(.other);

    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 2), state.requests_total);
    try std.testing.expectEqual(@as(u64, 1), state.responses_2xx_total);
    try std.testing.expectEqual(@as(u64, 1), state.responses_4xx_total);
    try std.testing.expectEqual(@as(u64, 1), state.responses_5xx_total);
    try std.testing.expectEqual(@as(u64, 1), state.retries_total);
    try std.testing.expectEqual(@as(u64, 1), state.loop_rejections_total);
    try std.testing.expectEqual(@as(u64, 1), state.upstream_connect_failures_total);
    try std.testing.expectEqual(@as(u64, 0), state.upstream_send_failures_total);
    try std.testing.expectEqual(@as(u64, 1), state.upstream_receive_failures_total);
    try std.testing.expectEqual(@as(u64, 1), state.upstream_other_failures_total);
}
