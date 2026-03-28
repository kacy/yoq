const std = @import("std");
const http = @import("../http.zig");
const common = @import("common.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const proxy_control_plane = @import("../../network/proxy/control_plane.zig");
const proxy_runtime = @import("../../network/proxy/runtime.zig");
const steering_runtime = @import("../../network/proxy/steering_runtime.zig");
const service_registry_runtime = @import("../../network/service_registry_runtime.zig");
const store = @import("../../state/store.zig");

const Response = common.Response;

pub fn route(request: http.Request, alloc: std.mem.Allocator) ?Response {
    const path = request.path_only;

    if (request.method == .GET and std.mem.eql(u8, path, "/v1/services")) {
        return handleListServices(alloc);
    }

    if (path.len <= "/v1/services/".len or !std.mem.startsWith(u8, path, "/v1/services/")) {
        return null;
    }

    const rest = path["/v1/services/".len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const service_name = rest[0..slash];
    if (!isValidSegment(service_name)) return common.badRequest("invalid service name");

    const after = rest[slash..];
    if (after.len == 0) {
        if (request.method != .GET) return common.methodNotAllowed();
        return handleGetService(alloc, service_name);
    }

    if (std.mem.eql(u8, after, "/endpoints")) {
        if (request.method != .GET) return common.methodNotAllowed();
        return handleListServiceEndpoints(alloc, service_name);
    }

    if (std.mem.eql(u8, after, "/proxy-routes")) {
        if (request.method != .GET) return common.methodNotAllowed();
        return handleListServiceProxyRoutes(alloc, service_name);
    }

    if (std.mem.eql(u8, after, "/reconcile")) {
        if (request.method != .POST) return common.methodNotAllowed();
        return handleRequestReconcile(service_name);
    }

    const endpoint_prefix = "/endpoints/";
    if (!std.mem.startsWith(u8, after, endpoint_prefix)) return common.notFound();

    const endpoint_rest = after[endpoint_prefix.len..];
    const endpoint_slash = std.mem.indexOfScalar(u8, endpoint_rest, '/') orelse endpoint_rest.len;
    const endpoint_id = endpoint_rest[0..endpoint_slash];
    if (!isValidSegment(endpoint_id)) return common.badRequest("invalid endpoint id");

    const endpoint_after = endpoint_rest[endpoint_slash..];
    if (endpoint_after.len == 0) {
        if (request.method != .DELETE) return common.methodNotAllowed();
        return handleDeleteEndpoint(service_name, endpoint_id);
    }

    if (std.mem.eql(u8, endpoint_after, "/drain")) {
        if (request.method != .POST) return common.methodNotAllowed();
        return handleDrainEndpoint(service_name, endpoint_id);
    }

    return common.notFound();
}

fn handleListServices(alloc: std.mem.Allocator) Response {
    var services = service_registry_runtime.snapshotServices(alloc) catch return common.internalError();
    defer {
        for (services.items) |service| service.deinit(alloc);
        services.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return common.internalError();
    for (services.items, 0..) |service, idx| {
        if (idx > 0) writer.writeByte(',') catch return common.internalError();
        writeServiceJson(writer, alloc, service) catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleGetService(alloc: std.mem.Allocator, service_name: []const u8) Response {
    const service = service_registry_runtime.snapshotService(alloc, service_name) catch |err| switch (err) {
        error.ServiceNotFound => return common.notFound(),
        else => return common.internalError(),
    };
    defer service.deinit(alloc);

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);
    writeServiceJson(writer, alloc, service) catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleListServiceEndpoints(alloc: std.mem.Allocator, service_name: []const u8) Response {
    var endpoints = service_registry_runtime.snapshotServiceEndpoints(alloc, service_name) catch |err| switch (err) {
        error.ServiceNotFound => return common.notFound(),
        else => return common.internalError(),
    };
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(alloc);
        endpoints.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return common.internalError();
    for (endpoints.items, 0..) |endpoint, idx| {
        if (idx > 0) writer.writeByte(',') catch return common.internalError();
        writeEndpointJson(writer, endpoint) catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleListServiceProxyRoutes(alloc: std.mem.Allocator, service_name: []const u8) Response {
    var proxy_routes = proxy_runtime.snapshotServiceRoutes(alloc, service_name) catch |err| switch (err) {
        error.ServiceNotFound => return common.notFound(),
        else => return common.internalError(),
    };
    defer {
        for (proxy_routes.items) |proxy_route| proxy_route.deinit(alloc);
        proxy_routes.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return common.internalError();
    for (proxy_routes.items, 0..) |proxy_route, idx| {
        if (idx > 0) writer.writeByte(',') catch return common.internalError();
        writeProxyRouteJson(writer, proxy_route) catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleRequestReconcile(service_name: []const u8) Response {
    service_registry_runtime.requestReconcile(service_name) catch |err| switch (err) {
        error.ServiceNotFound => return common.notFound(),
        else => return common.internalError(),
    };
    return .{ .status = .ok, .body = "{\"status\":\"queued\"}", .allocated = false };
}

fn handleDrainEndpoint(service_name: []const u8, endpoint_id: []const u8) Response {
    service_registry_runtime.drainEndpoint(service_name, endpoint_id) catch |err| switch (err) {
        error.ServiceNotFound, error.EndpointNotFound => return common.notFound(),
        else => return common.internalError(),
    };
    proxy_control_plane.refreshIfEnabled();
    return .{ .status = .ok, .body = "{\"status\":\"draining\"}", .allocated = false };
}

fn handleDeleteEndpoint(service_name: []const u8, endpoint_id: []const u8) Response {
    service_registry_runtime.deleteEndpoint(service_name, endpoint_id) catch |err| switch (err) {
        error.ServiceNotFound, error.EndpointNotFound => return common.notFound(),
        else => return common.internalError(),
    };
    proxy_control_plane.refreshIfEnabled();
    return .{ .status = .ok, .body = "{\"status\":\"removed\"}", .allocated = false };
}

fn writeServiceJson(writer: anytype, alloc: std.mem.Allocator, service: service_registry_runtime.ServiceSnapshot) !void {
    const steering = if (service.http_proxy_host != null) try steering_runtime.snapshotServiceStatus(alloc, service.service_name) else null;

    try writer.writeAll("{\"service_name\":\"");
    try json_helpers.writeJsonEscaped(writer, service.service_name);
    try writer.writeAll("\",\"vip_address\":\"");
    try json_helpers.writeJsonEscaped(writer, service.vip_address);
    try writer.writeAll("\",\"lb_policy\":\"");
    try json_helpers.writeJsonEscaped(writer, service.lb_policy);
    try writer.writeAll("\",\"http_proxy\":");
    if (service.http_proxy_host) |host| {
        try writer.writeAll("{\"host\":\"");
        try json_helpers.writeJsonEscaped(writer, host);
        try writer.writeAll("\",\"path_prefix\":\"");
        try json_helpers.writeJsonEscaped(writer, service.http_proxy_path_prefix orelse "/");
        try writer.print(
            "\",\"retries\":{d},\"connect_timeout_ms\":{d},\"request_timeout_ms\":{d},\"preserve_host\":{}}}",
            .{
                service.http_proxy_retries orelse 0,
                service.http_proxy_connect_timeout_ms orelse 1000,
                service.http_proxy_request_timeout_ms orelse 5000,
                service.http_proxy_preserve_host orelse true,
            },
        );
    } else {
        try writer.writeAll("null");
    }
    try writer.print(
        "\",\"total_endpoints\":{d},\"eligible_endpoints\":{d},\"healthy_endpoints\":{d},\"draining_endpoints\":{d},\"last_reconcile_status\":\"",
        .{
            service.total_endpoints,
            service.eligible_endpoints,
            service.healthy_endpoints,
            service.draining_endpoints,
        },
    );
    try json_helpers.writeJsonEscaped(writer, service.last_reconcile_status);
    try writer.writeAll("\",\"last_reconcile_error\":");
    if (service.last_reconcile_error) |message| {
        try writer.writeByte('"');
        try json_helpers.writeJsonEscaped(writer, message);
        try writer.writeByte('"');
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"last_reconcile_requested_at\":");
    if (service.last_reconcile_requested_at) |requested_at| {
        try writer.print("{d}", .{requested_at});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"steering\":");
    if (steering) |state| {
        try writer.print(
            "{{\"desired_ports\":{d},\"applied_ports\":{d},\"ready\":{},\"blocked_reason\":\"{s}\"}}",
            .{
                state.desired_ports,
                state.applied_ports,
                state.ready,
                state.blocked_reason.label(),
            },
        );
    } else {
        try writer.writeAll("null");
    }
    try writer.print(",\"overflow\":{},\"degraded\":{}}}", .{
        service.overflow,
        service.degraded,
    });
}

fn writeEndpointJson(writer: anytype, endpoint: service_registry_runtime.EndpointSnapshot) !void {
    try writer.writeAll("{\"endpoint_id\":\"");
    try json_helpers.writeJsonEscaped(writer, endpoint.endpoint_id);
    try writer.writeAll("\",\"container_id\":\"");
    try json_helpers.writeJsonEscaped(writer, endpoint.container_id);
    try writer.writeAll("\",\"node_id\":");
    if (endpoint.node_id) |node_id| {
        try writer.print("{d}", .{node_id});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"ip_address\":\"");
    try json_helpers.writeJsonEscaped(writer, endpoint.ip_address);
    try writer.print(
        "\",\"port\":{d},\"weight\":{d},\"admin_state\":\"",
        .{ endpoint.port, endpoint.weight },
    );
    try json_helpers.writeJsonEscaped(writer, endpoint.admin_state);
    try writer.print(
        "\",\"generation\":{d},\"registered_at\":{d},\"last_seen_at\":{d},\"observed_health\":\"",
        .{ endpoint.generation, endpoint.registered_at, endpoint.last_seen_at },
    );
    try json_helpers.writeJsonEscaped(writer, endpoint.observed_health);
    try writer.print("\",\"eligible\":{},\"readiness_required\":{},\"last_transition_at\":", .{
        endpoint.eligible,
        endpoint.readiness_required,
    });
    if (endpoint.last_transition_at) |last_transition_at| {
        try writer.print("{d}", .{last_transition_at});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeByte('}');
}

fn writeProxyRouteJson(writer: anytype, proxy_route: proxy_runtime.RouteSnapshot) !void {
    try writer.writeAll("{\"name\":\"");
    try json_helpers.writeJsonEscaped(writer, proxy_route.name);
    try writer.writeAll("\",\"service\":\"");
    try json_helpers.writeJsonEscaped(writer, proxy_route.service);
    try writer.writeAll("\",\"vip_address\":\"");
    try json_helpers.writeJsonEscaped(writer, proxy_route.vip_address);
    try writer.writeAll("\",\"host\":\"");
    try json_helpers.writeJsonEscaped(writer, proxy_route.host);
    try writer.writeAll("\",\"path_prefix\":\"");
    try json_helpers.writeJsonEscaped(writer, proxy_route.path_prefix);
    try writer.print(
        "\",\"eligible_endpoints\":{d},\"healthy_endpoints\":{d},\"degraded\":{},\"degraded_reason\":\"{s}\",\"retries\":{d},\"connect_timeout_ms\":{d},\"request_timeout_ms\":{d},\"preserve_host\":{},\"steering_desired_ports\":{d},\"steering_applied_ports\":{d},\"steering_ready\":{},\"steering_blocked_reason\":\"{s}\",\"last_failure_kind\":",
        .{
            proxy_route.eligible_endpoints,
            proxy_route.healthy_endpoints,
            proxy_route.degraded,
            proxy_route.degraded_reason.label(),
            proxy_route.retries,
            proxy_route.connect_timeout_ms,
            proxy_route.request_timeout_ms,
            proxy_route.preserve_host,
            proxy_route.steering_desired_ports,
            proxy_route.steering_applied_ports,
            proxy_route.steering_ready,
            proxy_route.steering_blocked_reason.label(),
        },
    );
    if (proxy_route.last_failure_kind) |kind| {
        try writer.print("\"{s}\"", .{kind.label()});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"last_failure_at\":");
    if (proxy_route.last_failure_at) |timestamp| {
        try writer.print("{d}", .{timestamp});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeByte('}');
}

fn isValidSegment(value: []const u8) bool {
    if (value.len == 0) return false;
    if (std.mem.indexOfScalar(u8, value, '/')) |_| return false;
    return common.validateClusterInput(value);
}

fn testRequest(method: http.Method, path: []const u8) http.Request {
    return .{
        .method = method,
        .path = path,
        .path_only = path,
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };
}

test "route handles GET /v1/services" {
    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/v1",
        .http_proxy_retries = 2,
        .http_proxy_connect_timeout_ms = 1500,
        .http_proxy_request_timeout_ms = 5000,
        .http_proxy_preserve_host = false,
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "ctr-1:0",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "10.42.0.9",
        .port = 0,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });

    const response = route(testRequest(.GET, "/v1/services"), std.testing.allocator).?;
    defer if (response.allocated) std.testing.allocator.free(response.body);

    try std.testing.expectEqual(http.StatusCode.ok, response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"service_name\":\"api\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"vip_address\":\"10.43.0.2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"http_proxy\":{\"host\":\"api.internal\",\"path_prefix\":\"/v1\",\"retries\":2,\"connect_timeout_ms\":1500,\"request_timeout_ms\":5000,\"preserve_host\":false}") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering\":{\"desired_ports\":0,\"applied_ports\":0,\"ready\":false,\"blocked_reason\":\"rollout_disabled\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"eligible_endpoints\":1") != null);
}

test "route handles GET /v1/services/{name}" {
    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();

    try store.createService(.{
        .service_name = "web",
        .vip_address = "10.43.0.3",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });

    const response = route(testRequest(.GET, "/v1/services/web"), std.testing.allocator).?;
    defer if (response.allocated) std.testing.allocator.free(response.body);

    try std.testing.expectEqual(http.StatusCode.ok, response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"service_name\":\"web\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"degraded\":true") != null);
}

test "route handles GET /v1/services/{name}/endpoints" {
    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "ctr-1:0",
        .container_id = "ctr-1",
        .node_id = null,
        .ip_address = "10.42.0.9",
        .port = 0,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });

    const response = route(testRequest(.GET, "/v1/services/api/endpoints"), std.testing.allocator).?;
    defer if (response.allocated) std.testing.allocator.free(response.body);

    try std.testing.expectEqual(http.StatusCode.ok, response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"endpoint_id\":\"ctr-1:0\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"observed_health\":\"unknown\"") != null);
}

test "route handles GET /v1/services/{name}/proxy-routes" {
    const service_rollout = @import("../../network/service_rollout.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/v1",
        .http_proxy_retries = 2,
        .http_proxy_connect_timeout_ms = 1500,
        .http_proxy_request_timeout_ms = 5000,
        .http_proxy_preserve_host = false,
        .created_at = 1000,
        .updated_at = 1000,
    });
    proxy_runtime.bootstrapIfEnabled();

    const response = route(testRequest(.GET, "/v1/services/api/proxy-routes"), std.testing.allocator).?;
    defer if (response.allocated) std.testing.allocator.free(response.body);

    try std.testing.expectEqual(http.StatusCode.ok, response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"service\":\"api\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"vip_address\":\"10.43.0.2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"host\":\"api.internal\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"path_prefix\":\"/v1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"eligible_endpoints\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"degraded\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"degraded_reason\":\"service_state\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_desired_ports\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_applied_ports\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_ready\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_blocked_reason\":\"rollout_disabled\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"last_failure_kind\":null") != null);
}

test "route handles GET /v1/services/{name}/proxy-routes with steering degradation" {
    const service_rollout = @import("../../network/service_rollout.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .dns_returns_vip = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();

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
    proxy_runtime.bootstrapIfEnabled();

    const response = route(testRequest(.GET, "/v1/services/api/proxy-routes"), std.testing.allocator).?;
    defer if (response.allocated) std.testing.allocator.free(response.body);

    try std.testing.expectEqual(http.StatusCode.ok, response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"degraded\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"degraded_reason\":\"steering_not_ready\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_desired_ports\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_applied_ports\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_ready\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_blocked_reason\":\"listener_not_running\"") != null);
}

test "route handles POST drain and DELETE endpoint" {
    const service_rollout = @import("../../network/service_rollout.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/",
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
    service_registry_runtime.syncServiceFromStore("api");
    proxy_runtime.bootstrapIfEnabled();

    {
        var routes_before = try proxy_runtime.snapshotServiceRoutes(std.testing.allocator, "api");
        defer {
            for (routes_before.items) |route_snapshot| route_snapshot.deinit(std.testing.allocator);
            routes_before.deinit(std.testing.allocator);
        }
        try std.testing.expectEqual(@as(usize, 1), routes_before.items.len);
        try std.testing.expectEqual(@as(u32, 1), routes_before.items[0].eligible_endpoints);
    }

    const drain_response = route(testRequest(.POST, "/v1/services/api/endpoints/ctr-1:0/drain"), std.testing.allocator).?;
    try std.testing.expectEqual(http.StatusCode.ok, drain_response.status);
    try std.testing.expectEqualStrings("{\"status\":\"draining\"}", drain_response.body);

    var drained = try store.listServiceEndpoints(std.testing.allocator, "api");
    defer {
        for (drained.items) |endpoint| endpoint.deinit(std.testing.allocator);
        drained.deinit(std.testing.allocator);
    }
    try std.testing.expectEqualStrings("draining", drained.items[0].admin_state);
    {
        var routes_after_drain = try proxy_runtime.snapshotServiceRoutes(std.testing.allocator, "api");
        defer {
            for (routes_after_drain.items) |route_snapshot| route_snapshot.deinit(std.testing.allocator);
            routes_after_drain.deinit(std.testing.allocator);
        }
        try std.testing.expectEqual(@as(usize, 1), routes_after_drain.items.len);
        try std.testing.expectEqual(@as(u32, 0), routes_after_drain.items[0].eligible_endpoints);
    }

    const delete_response = route(testRequest(.DELETE, "/v1/services/api/endpoints/ctr-1:0"), std.testing.allocator).?;
    try std.testing.expectEqual(http.StatusCode.ok, delete_response.status);
    try std.testing.expectEqualStrings("{\"status\":\"removed\"}", delete_response.body);

    var remaining = try store.listServiceEndpoints(std.testing.allocator, "api");
    defer {
        for (remaining.items) |endpoint| endpoint.deinit(std.testing.allocator);
        remaining.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 0), remaining.items.len);
    {
        var routes_after_delete = try proxy_runtime.snapshotServiceRoutes(std.testing.allocator, "api");
        defer {
            for (routes_after_delete.items) |route_snapshot| route_snapshot.deinit(std.testing.allocator);
            routes_after_delete.deinit(std.testing.allocator);
        }
        try std.testing.expectEqual(@as(usize, 1), routes_after_delete.items.len);
        try std.testing.expectEqual(@as(u32, 0), routes_after_delete.items[0].eligible_endpoints);
    }
}

test "route handles POST /v1/services/{name}/reconcile" {
    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });

    const response = route(testRequest(.POST, "/v1/services/api/reconcile"), std.testing.allocator).?;
    try std.testing.expectEqual(http.StatusCode.ok, response.status);
    try std.testing.expectEqualStrings("{\"status\":\"queued\"}", response.body);

    const service = try service_registry_runtime.snapshotService(std.testing.allocator, "api");
    defer service.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("pending", service.last_reconcile_status);
}
