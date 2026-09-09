const std = @import("std");
const spec = @import("../spec.zig");
const store = @import("../../state/store.zig");

/// owns the converted arrays; strings remain borrowed from the manifest.
pub const RouteInputs = struct {
    items: []store.ServiceHttpRouteInput,

    pub fn init(alloc: std.mem.Allocator, routes: []const spec.HttpProxyRoute, target_port: ?u16) !RouteInputs {
        const items = try alloc.alloc(store.ServiceHttpRouteInput, routes.len);
        errdefer alloc.free(items);

        var initialized: usize = 0;
        errdefer for (items[0..initialized]) |item| freeRoute(alloc, item);
        for (routes, items) |route, *item| {
            item.* = try convertRoute(alloc, route, target_port);
            initialized += 1;
        }
        return .{ .items = items };
    }

    pub fn deinit(self: RouteInputs, alloc: std.mem.Allocator) void {
        for (self.items) |item| freeRoute(alloc, item);
        alloc.free(self.items);
    }
};

fn freeRoute(alloc: std.mem.Allocator, route: store.ServiceHttpRouteInput) void {
    alloc.free(route.match_methods);
    alloc.free(route.match_headers);
    alloc.free(route.backend_services);
}

fn convertRoute(alloc: std.mem.Allocator, route: spec.HttpProxyRoute, target_port: ?u16) !store.ServiceHttpRouteInput {
    const methods = try alloc.alloc(store.ServiceHttpRouteMethodInput, route.match_methods.len);
    errdefer alloc.free(methods);
    for (route.match_methods, methods) |source, *target| target.* = .{ .method = source.method };

    const headers = try alloc.alloc(store.ServiceHttpRouteHeaderInput, route.match_headers.len);
    errdefer alloc.free(headers);
    for (route.match_headers, headers) |source, *target| {
        target.* = .{ .header_name = source.name, .header_value = source.value };
    }

    const backends = try alloc.alloc(store.ServiceHttpRouteBackendInput, route.backend_services.len);
    errdefer alloc.free(backends);
    for (route.backend_services, backends) |source, *target| {
        target.* = .{ .backend_service = source.service_name, .weight = source.weight };
    }

    return .{
        .route_name = route.name,
        .host = route.host,
        .path_prefix = route.path_prefix,
        .rewrite_prefix = route.rewrite_prefix,
        .match_methods = methods,
        .match_headers = headers,
        .backend_services = backends,
        .mirror_service = route.mirror_service,
        .retries = route.retries,
        .connect_timeout_ms = route.connect_timeout_ms,
        .request_timeout_ms = route.request_timeout_ms,
        .http2_idle_timeout_ms = route.http2_idle_timeout_ms,
        .target_port = if (target_port) |port| port else null,
        .preserve_host = route.preserve_host,
        .retry_on_5xx = route.retry_on_5xx,
        .circuit_breaker_threshold = route.circuit_breaker_threshold,
        .circuit_breaker_timeout_ms = route.circuit_breaker_timeout_ms,
    };
}

fn checkRouteInputs(alloc: std.mem.Allocator) !void {
    const routes = [_]spec.HttpProxyRoute{
        .{
            .name = "api",
            .host = "api.example.test",
            .path_prefix = "/v1",
            .rewrite_prefix = "/",
            .match_methods = &.{ .{ .method = "GET" }, .{ .method = "POST" } },
            .match_headers = &.{.{ .name = "x-env", .value = "test" }},
            .backend_services = &.{ .{ .service_name = "stable", .weight = 90 }, .{ .service_name = "canary", .weight = 10 } },
            .mirror_service = "shadow",
            .retries = 2,
            .connect_timeout_ms = 1234,
            .request_timeout_ms = 5678,
            .http2_idle_timeout_ms = 45000,
            .preserve_host = false,
            .retry_on_5xx = false,
            .circuit_breaker_threshold = 7,
            .circuit_breaker_timeout_ms = 9000,
        },
        .{ .name = "fallback", .host = "fallback.example.test", .match_methods = &.{.{ .method = "HEAD" }} },
    };
    const inputs = try RouteInputs.init(alloc, &routes, 8080);
    defer inputs.deinit(alloc);
    const first = inputs.items[0];
    try std.testing.expectEqual(@as(usize, 2), inputs.items.len);
    try std.testing.expectEqualStrings("POST", first.match_methods[1].method);
    try std.testing.expectEqualStrings("x-env", first.match_headers[0].header_name);
    try std.testing.expectEqualStrings("test", first.match_headers[0].header_value);
    try std.testing.expectEqualStrings("canary", first.backend_services[1].backend_service);
    try std.testing.expectEqual(@as(i64, 10), first.backend_services[1].weight);
    try std.testing.expectEqualStrings("/", first.rewrite_prefix.?);
    try std.testing.expectEqualStrings("shadow", first.mirror_service.?);
    try std.testing.expectEqual(@as(?i64, 8080), first.target_port);
    try std.testing.expectEqual(@as(i64, 2), first.retries);
    try std.testing.expectEqual(@as(i64, 1234), first.connect_timeout_ms);
    try std.testing.expectEqual(@as(i64, 5678), first.request_timeout_ms);
    try std.testing.expectEqual(@as(i64, 45000), first.http2_idle_timeout_ms);
    try std.testing.expectEqual(@as(i64, 7), first.circuit_breaker_threshold);
    try std.testing.expectEqual(@as(i64, 9000), first.circuit_breaker_timeout_ms);
    try std.testing.expect(!first.preserve_host and !first.retry_on_5xx);
    try std.testing.expectEqualStrings("HEAD", inputs.items[1].match_methods[0].method);
    try std.testing.expectEqual(@as(usize, 0), inputs.items[1].backend_services.len);
}

test "route inputs preserve routing fields and release every partial allocation" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkRouteInputs, .{});
}

test "route inputs support empty routes and services without ports" {
    const alloc = std.testing.allocator;
    const empty = try RouteInputs.init(alloc, &.{}, null);
    defer empty.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 0), empty.items.len);
    const inputs = try RouteInputs.init(alloc, &.{.{ .name = "default", .host = "example.test" }}, null);
    defer inputs.deinit(alloc);
    try std.testing.expectEqual(@as(?i64, null), inputs.items[0].target_port);
}

test "route inputs persist configured http2 idle timeouts" {
    const common = @import("../../state/store/common.zig");
    try common.initTestDb();
    defer common.deinitTestDb();
    const alloc = std.testing.allocator;
    for ([_]u32{ 45000, 1, std.math.maxInt(u32), 30000 }) |timeout| {
        const inputs = try RouteInputs.init(alloc, &.{.{
            .name = "default",
            .host = "api.example.test",
            .http2_idle_timeout_ms = timeout,
        }}, 8080);
        defer inputs.deinit(alloc);
        const synced = try store.syncServiceConfig(alloc, "api", "consistent_hash", "off", inputs.items);
        defer synced.deinit(alloc);
        const stored = try store.getService(alloc, "api");
        defer stored.deinit(alloc);
        try std.testing.expectEqual(@as(usize, 1), stored.http_routes.len);
        try std.testing.expectEqual(@as(i64, timeout), stored.http_routes[0].http2_idle_timeout_ms);
        try std.testing.expectEqual(@as(?i64, timeout), stored.http_proxy_http2_idle_timeout_ms);
    }
}
