const std = @import("std");
const http = @import("../http.zig");
const common = @import("common.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const route_traffic_json = @import("route_traffic_json.zig");
const proxy_control_plane = @import("../../network/proxy/control_plane.zig");
const proxy_runtime = @import("../../network/proxy/runtime.zig");
const service_rollout = @import("../../network/service_rollout.zig");
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
    var route_traffic = proxy_runtime.snapshotRouteTraffic(alloc) catch return common.internalError();
    defer {
        for (route_traffic.items) |entry| entry.deinit(alloc);
        route_traffic.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return common.internalError();
    for (proxy_routes.items, 0..) |proxy_route, idx| {
        if (idx > 0) writer.writeByte(',') catch return common.internalError();
        writeProxyRouteJson(writer, proxy_route, route_traffic.items) catch return common.internalError();
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
        if (service.http_proxy_rewrite_prefix) |rewrite_prefix| {
            try writer.writeAll("\",\"rewrite_prefix\":\"");
            try json_helpers.writeJsonEscaped(writer, rewrite_prefix);
        }
        try writer.print(
            "\",\"retries\":{d},\"connect_timeout_ms\":{d},\"request_timeout_ms\":{d},\"http2_idle_timeout_ms\":{d},\"preserve_host\":{}",
            .{
                service.http_proxy_retries orelse 0,
                service.http_proxy_connect_timeout_ms orelse 1000,
                service.http_proxy_request_timeout_ms orelse 5000,
                service.http_proxy_http2_idle_timeout_ms orelse 30000,
                service.http_proxy_preserve_host orelse true,
            },
        );
        if (service.http_routes.len > 0 and service.http_routes[0].match_methods.len > 0) {
            try writer.writeAll(",\"match_methods\":");
            try writeMethodMatchesJson(writer, service.http_routes[0].match_methods);
        }
        if (service.http_routes.len > 0 and service.http_routes[0].match_headers.len > 0) {
            try writer.writeAll(",\"match_headers\":");
            try writeHeaderMatchesJson(writer, service.http_routes[0].match_headers);
        }
        if (service.http_routes.len > 0 and service.http_routes[0].backend_services.len > 0) {
            try writer.writeAll(",\"backend_services\":");
            try writeBackendServicesJson(writer, service.http_routes[0].backend_services);
        }
        if (service.http_routes.len > 0) {
            if (service.http_routes[0].mirror_service) |mirror_service| {
                try writer.writeAll(",\"mirror_service\":\"");
                try json_helpers.writeJsonEscaped(writer, mirror_service);
                try writer.writeByte('"');
            }
        }
        try writer.writeByte('}');
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"http_routes\":[");
    for (service.http_routes, 0..) |http_route, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":\"");
        try json_helpers.writeJsonEscaped(writer, http_route.route_name);
        try writer.writeAll("\",\"host\":\"");
        try json_helpers.writeJsonEscaped(writer, http_route.host);
        try writer.writeAll("\",\"path_prefix\":\"");
        try json_helpers.writeJsonEscaped(writer, http_route.path_prefix);
        if (http_route.rewrite_prefix) |rewrite_prefix| {
            try writer.writeAll("\",\"rewrite_prefix\":\"");
            try json_helpers.writeJsonEscaped(writer, rewrite_prefix);
        }
        try writer.print(
            "\",\"retries\":{d},\"connect_timeout_ms\":{d},\"request_timeout_ms\":{d},\"http2_idle_timeout_ms\":{d},\"preserve_host\":{}",
            .{
                http_route.retries,
                http_route.connect_timeout_ms,
                http_route.request_timeout_ms,
                http_route.http2_idle_timeout_ms,
                http_route.preserve_host,
            },
        );
        if (http_route.match_methods.len > 0) {
            try writer.writeAll(",\"match_methods\":");
            try writeMethodMatchesJson(writer, http_route.match_methods);
        }
        if (http_route.match_headers.len > 0) {
            try writer.writeAll(",\"match_headers\":");
            try writeHeaderMatchesJson(writer, http_route.match_headers);
        }
        if (http_route.backend_services.len > 0) {
            try writer.writeAll(",\"backend_services\":");
            try writeBackendServicesJson(writer, http_route.backend_services);
        }
        if (http_route.mirror_service) |mirror_service| {
            try writer.writeAll(",\"mirror_service\":\"");
            try json_helpers.writeJsonEscaped(writer, mirror_service);
            try writer.writeByte('"');
        }
        try writer.writeByte('}');
    }
    try writer.writeByte(']');
    try writer.print(
        ",\"total_endpoints\":{d},\"eligible_endpoints\":{d},\"healthy_endpoints\":{d},\"draining_endpoints\":{d},\"last_reconcile_status\":\"",
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
        const vip_traffic_mode: proxy_runtime.VipTrafficMode = if (state.ready)
            .l7_proxy
        else
            .l4_fallback;
        try writer.print(
            "{{\"desired_ports\":{d},\"applied_ports\":{d},\"ready\":{},\"blocked\":{},\"drifted\":{},\"blocked_reason\":\"{s}\",\"vip_traffic_mode\":\"{s}\"}}",
            .{
                state.desired_ports,
                state.applied_ports,
                state.ready,
                state.blocked,
                state.drifted,
                state.blocked_reason.label(),
                vip_traffic_mode.label(),
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

fn writeProxyRouteJson(writer: anytype, proxy_route: proxy_runtime.RouteSnapshot, route_traffic: []const proxy_runtime.RouteTrafficSnapshot) !void {
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
    if (proxy_route.rewrite_prefix) |rewrite_prefix| {
        try writer.writeAll("\",\"rewrite_prefix\":\"");
        try json_helpers.writeJsonEscaped(writer, rewrite_prefix);
    }
    try writer.print(
        "\",\"eligible_endpoints\":{d},\"healthy_endpoints\":{d},\"degraded\":{},\"degraded_reason\":\"{s}\",\"retries\":{d},\"connect_timeout_ms\":{d},\"request_timeout_ms\":{d},\"http2_idle_timeout_ms\":{d},\"preserve_host\":{},\"vip_traffic_mode\":\"{s}\",\"steering_desired_ports\":{d},\"steering_applied_ports\":{d},\"steering_ready\":{},\"steering_blocked\":{},\"steering_drifted\":{},\"steering_blocked_reason\":\"{s}\",\"last_failure_kind\":",
        .{
            proxy_route.eligible_endpoints,
            proxy_route.healthy_endpoints,
            proxy_route.degraded,
            proxy_route.degraded_reason.label(),
            proxy_route.retries,
            proxy_route.connect_timeout_ms,
            proxy_route.request_timeout_ms,
            proxy_route.http2_idle_timeout_ms,
            proxy_route.preserve_host,
            proxy_route.vip_traffic_mode.label(),
            proxy_route.steering_desired_ports,
            proxy_route.steering_applied_ports,
            proxy_route.steering_ready,
            proxy_route.steering_blocked,
            proxy_route.steering_drifted,
            proxy_route.steering_blocked_reason.label(),
        },
    );
    if (proxy_route.last_failure_kind) |kind| {
        try writer.print("\"{s}\"", .{kind.label()});
    } else {
        try writer.writeAll("null");
    }
    if (proxy_route.method_matches.len > 0) {
        try writer.writeAll(",\"match_methods\":");
        try writeMethodMatchesJson(writer, proxy_route.method_matches);
    }
    if (proxy_route.header_matches.len > 0) {
        try writer.writeAll(",\"match_headers\":");
        try writeHeaderMatchesJson(writer, proxy_route.header_matches);
    }
    if (proxy_route.backend_services.len > 0) {
        try writer.writeAll(",\"backend_services\":");
        try writeBackendServicesJson(writer, proxy_route.backend_services);
    }
    if (proxy_route.mirror_service) |mirror_service| {
        try writer.writeAll(",\"mirror_service\":\"");
        try json_helpers.writeJsonEscaped(writer, mirror_service);
        try writer.writeByte('"');
    }
    try writer.writeAll(",\"last_failure_at\":");
    if (proxy_route.last_failure_at) |timestamp| {
        try writer.print("{d}", .{timestamp});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"traffic\":");
    try route_traffic_json.writeRouteTrafficSummaryJson(writer, .primary, proxy_route.name, route_traffic);
    try writer.writeAll(",\"backend_traffic\":");
    try route_traffic_json.writeRouteBackendTrafficJson(writer, .primary, proxy_route.name, route_traffic);
    try writer.writeAll(",\"mirror_traffic\":");
    try route_traffic_json.writeRouteTrafficSummaryJson(writer, .mirror, proxy_route.name, route_traffic);
    try writer.writeAll(",\"mirror_backend_traffic\":");
    try route_traffic_json.writeRouteBackendTrafficJson(writer, .mirror, proxy_route.name, route_traffic);
    try writer.writeByte('}');
}

fn writeMethodMatchesJson(writer: anytype, method_matches: anytype) !void {
    try writer.writeByte('[');
    for (method_matches, 0..) |method_match, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeByte('"');
        try json_helpers.writeJsonEscaped(writer, method_match.method);
        try writer.writeByte('"');
    }
    try writer.writeByte(']');
}

fn writeHeaderMatchesJson(writer: anytype, header_matches: anytype) !void {
    try writer.writeByte('[');
    for (header_matches, 0..) |header_match, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":\"");
        try json_helpers.writeJsonEscaped(writer, header_match.name);
        try writer.writeAll("\",\"value\":\"");
        try json_helpers.writeJsonEscaped(writer, header_match.value);
        try writer.writeAll("\"}");
    }
    try writer.writeByte(']');
}

fn writeBackendServicesJson(writer: anytype, backend_services: anytype) !void {
    try writer.writeByte('[');
    for (backend_services, 0..) |backend, idx| {
        if (idx > 0) try writer.writeByte(',');
        try writer.writeAll("{\"service\":\"");
        try json_helpers.writeJsonEscaped(writer, backend.service_name);
        try writer.print("\",\"weight\":{d}}}", .{backend.weight});
    }
    try writer.writeByte(']');
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
    const listener_runtime = @import("../../network/proxy/listener_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
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
        .http_proxy_http2_idle_timeout_ms = 45000,
        .http_proxy_target_port = 8080,
        .http_proxy_preserve_host = false,
        .http_proxy_mirror_service = "api-shadow",
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
    service_registry_runtime.syncServiceFromStore("api");

    const response = route(testRequest(.GET, "/v1/services"), std.testing.allocator).?;
    defer if (response.allocated) std.testing.allocator.free(response.body);

    try std.testing.expectEqual(http.StatusCode.ok, response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"service_name\":\"api\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"vip_address\":\"10.43.0.2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"http_proxy\":{\"host\":\"api.internal\",\"path_prefix\":\"/v1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"retries\":2,\"connect_timeout_ms\":1500,\"request_timeout_ms\":5000,\"http2_idle_timeout_ms\":45000,\"preserve_host\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"backend_services\":[{\"service\":\"api\",\"weight\":100}]") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"mirror_service\":\"api-shadow\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"http_routes\":[{\"name\":\"default\",\"host\":\"api.internal\",\"path_prefix\":\"/v1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering\":{\"desired_ports\":1,\"applied_ports\":0,\"ready\":false,\"blocked\":true,\"drifted\":false,\"blocked_reason\":\"listener_not_running\",\"vip_traffic_mode\":\"l4_fallback\"}") != null);
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

test "route handles GET /v1/services with route method matches" {
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
        .http_routes = &.{
            .{
                .service_name = "api",
                .route_name = "write",
                .host = "api.internal",
                .path_prefix = "/v1",
                .match_methods = &.{
                    .{
                        .service_name = "api",
                        .route_name = "write",
                        .method = "POST",
                        .match_order = 0,
                        .created_at = 1000,
                        .updated_at = 1000,
                    },
                    .{
                        .service_name = "api",
                        .route_name = "write",
                        .method = "PUT",
                        .match_order = 1,
                        .created_at = 1000,
                        .updated_at = 1000,
                    },
                },
                .match_headers = &.{},
                .backend_services = &.{},
                .retries = 0,
                .connect_timeout_ms = 1000,
                .request_timeout_ms = 5000,
                .http2_idle_timeout_ms = 30000,
                .route_order = 0,
                .created_at = 1000,
                .updated_at = 1000,
            },
        },
    });

    const response = route(testRequest(.GET, "/v1/services"), std.testing.allocator).?;
    defer if (response.allocated) std.testing.allocator.free(response.body);

    try std.testing.expectEqual(http.StatusCode.ok, response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"match_methods\":[\"POST\",\"PUT\"]") != null);
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
    const listener_runtime = @import("../../network/proxy/listener_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
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
        .http_proxy_http2_idle_timeout_ms = 45000,
        .http_proxy_target_port = 8080,
        .http_proxy_preserve_host = false,
        .http_proxy_mirror_service = "api-shadow",
        .created_at = 1000,
        .updated_at = 1000,
    });
    service_registry_runtime.syncServiceFromStore("api");
    proxy_runtime.bootstrapIfEnabled();
    proxy_runtime.recordRouteRequestStart("api:default", "api", "api");
    proxy_runtime.recordRouteResponseCode("api:default", "api", "api", 200);
    proxy_runtime.recordRouteRetry("api:default", "api", "api");
    proxy_runtime.recordRouteUpstreamFailure("api:default", "api", "api");
    proxy_runtime.recordMirrorRouteRequestStart("api:default", "api", "api-shadow");
    proxy_runtime.recordMirrorRouteResponseCode("api:default", "api", "api-shadow", 202);
    proxy_runtime.recordMirrorRouteUpstreamFailure("api:default", "api", "api-shadow");

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
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"vip_traffic_mode\":\"l4_fallback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_desired_ports\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_applied_ports\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_ready\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_blocked\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_drifted\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_blocked_reason\":\"listener_not_running\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"last_failure_kind\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"mirror_service\":\"api-shadow\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"traffic\":{\"requests_total\":1,\"responses_2xx_total\":1,\"responses_4xx_total\":0,\"responses_5xx_total\":0,\"retries_total\":1,\"upstream_failures_total\":1}") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"backend_traffic\":[{\"backend_service\":\"api\",\"requests_total\":1,\"responses_2xx_total\":1,\"responses_4xx_total\":0,\"responses_5xx_total\":0,\"retries_total\":1,\"upstream_failures_total\":1}]") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"mirror_traffic\":{\"requests_total\":1,\"responses_2xx_total\":1,\"responses_4xx_total\":0,\"responses_5xx_total\":0,\"retries_total\":0,\"upstream_failures_total\":1}") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"mirror_backend_traffic\":[{\"backend_service\":\"api-shadow\",\"requests_total\":1,\"responses_2xx_total\":1,\"responses_4xx_total\":0,\"responses_5xx_total\":0,\"retries_total\":0,\"upstream_failures_total\":1}]") != null);
}

test "route handles GET /v1/services/{name}/proxy-routes with steering degradation" {
    const listener_runtime = @import("../../network/proxy/listener_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
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
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"vip_traffic_mode\":\"l4_fallback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_desired_ports\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_applied_ports\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_ready\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_blocked\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_drifted\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_blocked_reason\":\"listener_not_running\"") != null);
}

test "route handles GET /v1/services/{name}/proxy-routes with weighted backend traffic breakdown" {
    const listener_runtime = @import("../../network/proxy/listener_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
        .http_routes = &.{
            .{
                .service_name = "api",
                .route_name = "canary",
                .host = "api.internal",
                .path_prefix = "/v1",
                .match_methods = &.{},
                .match_headers = &.{},
                .backend_services = &.{
                    .{
                        .service_name = "api",
                        .route_name = "canary",
                        .backend_service = "api",
                        .weight = 90,
                        .backend_order = 0,
                        .created_at = 1000,
                        .updated_at = 1000,
                    },
                    .{
                        .service_name = "api",
                        .route_name = "canary",
                        .backend_service = "api-canary",
                        .weight = 10,
                        .backend_order = 1,
                        .created_at = 1000,
                        .updated_at = 1000,
                    },
                },
                .retries = 1,
                .connect_timeout_ms = 1000,
                .request_timeout_ms = 5000,
                .http2_idle_timeout_ms = 30000,
                .route_order = 0,
                .created_at = 1000,
                .updated_at = 1000,
            },
        },
    });

    proxy_runtime.bootstrapIfEnabled();
    proxy_runtime.recordRouteRequestStart("api:canary", "api", "api");
    proxy_runtime.recordRouteResponseCode("api:canary", "api", "api", 200);
    proxy_runtime.recordRouteRequestStart("api:canary", "api", "api-canary");
    proxy_runtime.recordRouteResponseCode("api:canary", "api", "api-canary", 503);
    proxy_runtime.recordRouteUpstreamFailure("api:canary", "api", "api-canary");

    const response = route(testRequest(.GET, "/v1/services/api/proxy-routes"), std.testing.allocator).?;
    defer if (response.allocated) std.testing.allocator.free(response.body);

    try std.testing.expectEqual(http.StatusCode.ok, response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"traffic\":{\"requests_total\":2,\"responses_2xx_total\":1,\"responses_4xx_total\":0,\"responses_5xx_total\":1,\"retries_total\":0,\"upstream_failures_total\":1}") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"backend_traffic\":[{\"backend_service\":\"api\",\"requests_total\":1,\"responses_2xx_total\":1,\"responses_4xx_total\":0,\"responses_5xx_total\":0,\"retries_total\":0,\"upstream_failures_total\":0},{\"backend_service\":\"api-canary\",\"requests_total\":1,\"responses_2xx_total\":0,\"responses_4xx_total\":0,\"responses_5xx_total\":1,\"retries_total\":0,\"upstream_failures_total\":1}]") != null);
}

test "route handles GET /v1/services/{name} with steering drift details" {
    const listener_runtime = @import("../../network/proxy/listener_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .dns_returns_vip = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/",
        .http_proxy_target_port = 8080,
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "ctr-1:8080",
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
    steering_runtime.setPortMapperAvailableForTest(true);
    steering_runtime.setBridgeIpForTest(.{ 10, 42, 0, 1 });
    try listener_runtime.startOrSkipForTest(std.testing.allocator, 0);
    try steering_runtime.setActualMappingsForTest(&.{});

    const response = route(testRequest(.GET, "/v1/services/api"), std.testing.allocator).?;
    defer if (response.allocated) std.testing.allocator.free(response.body);

    try std.testing.expectEqual(http.StatusCode.ok, response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering\":{\"desired_ports\":1,\"applied_ports\":0,\"ready\":false,\"blocked\":false,\"drifted\":true,\"blocked_reason\":\"none\",\"vip_traffic_mode\":\"l4_fallback\"}") != null);
}

test "route handles GET /v1/services/{name}/proxy-routes with steering drift details" {
    const listener_runtime = @import("../../network/proxy/listener_runtime.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    steering_runtime.resetForTest();
    defer steering_runtime.resetForTest();
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
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
        .http_proxy_target_port = 8080,
        .created_at = 1000,
        .updated_at = 1000,
    });
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "ctr-1:8080",
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
    steering_runtime.setPortMapperAvailableForTest(true);
    steering_runtime.setBridgeIpForTest(.{ 10, 42, 0, 1 });
    try listener_runtime.startOrSkipForTest(std.testing.allocator, 0);
    try steering_runtime.setActualMappingsForTest(&.{});

    const response = route(testRequest(.GET, "/v1/services/api/proxy-routes"), std.testing.allocator).?;
    defer if (response.allocated) std.testing.allocator.free(response.body);

    try std.testing.expectEqual(http.StatusCode.ok, response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"degraded_reason\":\"steering_not_ready\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"vip_traffic_mode\":\"l4_fallback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_blocked\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_drifted\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"steering_blocked_reason\":\"none\"") != null);
}

test "route handles POST drain and DELETE endpoint" {
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
