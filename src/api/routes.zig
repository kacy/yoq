// routes — API dispatch/auth shell with concern-specific route modules

const std = @import("std");
const http = @import("http.zig");
const store = @import("../state/store.zig");
const cluster_node = @import("../cluster/node.zig");
const json_helpers = @import("../lib/json_helpers.zig");
const common = @import("routes/common.zig");
const containers_images = @import("routes/containers_images.zig");
const cluster_agents = @import("routes/cluster_agents.zig");
const status_metrics = @import("routes/status_metrics.zig");
const security = @import("routes/security.zig");
const s3_gateway = @import("routes/s3_gateway.zig");

pub var cluster: ?*cluster_node.Node = null;
pub var join_token: ?[]const u8 = null;
pub var api_token: ?[]const u8 = null;

pub const Response = common.Response;

pub fn dispatch(request: http.Request, alloc: std.mem.Allocator) Response {
    const is_public = std.mem.eql(u8, request.path_only, "/health") or
        std.mem.eql(u8, request.path_only, "/version");
    const is_join_route = isJoinTokenRoute(&request);
    const has_any_auth = api_token != null or join_token != null;
    const has_api_auth = if (api_token) |expected_token|
        common.hasValidBearerToken(&request, expected_token)
    else
        false;
    const has_join_auth = if (join_token) |expected_join_token|
        is_join_route and common.hasValidBearerToken(&request, expected_join_token)
    else
        false;

    if (has_any_auth and !is_public and !has_api_auth and !has_join_auth) {
        return common.unauthorized();
    }

    if (has_any_auth and !is_public and !is_join_route and !has_api_auth) {
        return common.unauthorized();
    }

    if (request.method == .GET) {
        if (std.mem.eql(u8, request.path_only, "/health")) {
            return .{ .status = .ok, .body = "{\"status\":\"ok\"}", .allocated = false };
        }
        if (std.mem.eql(u8, request.path_only, "/version")) {
            return .{ .status = .ok, .body = "{\"version\":\"0.1.0\"}", .allocated = false };
        }
    }

    if (s3_gateway.route(request, alloc)) |resp| return resp;
    if (containers_images.route(request, alloc)) |resp| return resp;

    const ctx: common.RouteContext = .{
        .cluster = cluster,
        .join_token = join_token,
    };

    if (cluster_agents.route(request, alloc, ctx)) |resp| return resp;
    if (status_metrics.route(request, alloc)) |resp| return resp;
    if (security.route(request, alloc)) |resp| return resp;

    return common.notFound();
}

fn isJoinTokenRoute(request: *const http.Request) bool {
    if (request.method == .GET and std.mem.eql(u8, request.path_only, "/wireguard/peers")) {
        return true;
    }

    if (request.method == .POST and std.mem.eql(u8, request.path_only, "/agents/register")) {
        return true;
    }

    if (request.path_only.len <= "/agents/".len or !std.mem.startsWith(u8, request.path_only, "/agents/")) {
        return false;
    }

    const rest = request.path_only["/agents/".len..];

    if (common.matchSubpath(rest, "/heartbeat") != null) {
        return request.method == .POST;
    }
    if (common.matchSubpath(rest, "/assignments") != null) {
        return request.method == .GET;
    }
    if (common.matchAssignmentStatusPath(rest) != null) {
        return request.method == .POST;
    }

    return false;
}

// -- tests --

test "dispatch health" {
    const req = (try http.parseRequest("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expectEqualStrings("{\"status\":\"ok\"}", resp.body);
    try std.testing.expect(!resp.allocated);
}

test "dispatch version" {
    const req = (try http.parseRequest("GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expectEqualStrings("{\"version\":\"0.1.0\"}", resp.body);
}

test "dispatch not found" {
    const req = (try http.parseRequest("GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.not_found, resp.status);
}

test "dispatch method not allowed on health" {
    const req = (try http.parseRequest("POST /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.not_found, resp.status);
}

test "dispatch POST to container stop" {
    const req = (try http.parseRequest(
        "POST /containers/abc123/stop HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "dispatch GET on container stop returns method not allowed" {
    const req = (try http.parseRequest(
        "GET /containers/abc123/stop HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
}

test "dispatch DELETE container" {
    store.initTestDb() catch return error.SkipZigTest;
    defer store.deinitTestDb();

    const record = store.ContainerRecord{
        .id = "abc123def456",
        .hostname = "test-container",
        .rootfs = "/tmp/rootfs",
        .status = "stopped",
        .command = "sleep 100",
        .created_at = 1234567890,
        .pid = null,
        .exit_code = null,
    };
    try store.save(record);

    const req = (try http.parseRequest(
        "DELETE /containers/abc123def456 HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
}

test "dispatch DELETE image" {
    store.initTestDb() catch return error.SkipZigTest;
    defer store.deinitTestDb();

    const req = (try http.parseRequest(
        "DELETE /images/sha256:abc HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "dispatch GET agents without cluster returns empty" {
    cluster = null;
    const req = (try http.parseRequest("GET /agents HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expectEqualStrings("[]", resp.body);
}

test "dispatch POST register without cluster returns error" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/register HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch agent heartbeat routing" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/abc123/heartbeat HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch assignment status update routing" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/abc123/assignments/def456/status HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\n\r\n{\"status\":\"running\"}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch agent drain routing" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/abc123/drain HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch deploy without cluster returns error" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /deploy HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch rejects non-hex container id" {
    const req = (try http.parseRequest(
        "GET /containers/INVALID! HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch rejects non-hex agent id" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/NOT-HEX!/heartbeat HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch GET /v1/secrets routes correctly" {
    const req = (try http.parseRequest("GET /v1/secrets HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expect(resp.status == .ok or resp.status == .internal_server_error);
}

test "dispatch POST /v1/secrets with missing body returns bad request" {
    const req = (try http.parseRequest(
        "POST /v1/secrets HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch GET /v1/secrets/mykey routes correctly" {
    const req = (try http.parseRequest(
        "GET /v1/secrets/mykey HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
}

test "dispatch DELETE /v1/secrets/mykey routes correctly" {
    const req = (try http.parseRequest(
        "DELETE /v1/secrets/mykey HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "dispatch PUT /v1/secrets returns method not allowed" {
    const req = (try http.parseRequest(
        "PUT /v1/secrets HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
}

test "dispatch returns 401 for missing auth on protected endpoint when api_token is set" {
    const saved = api_token;
    defer api_token = saved;
    api_token = "test-secret-token";

    const req = (try http.parseRequest(
        "GET /containers HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
}

test "dispatch returns 401 for wrong token on protected endpoint" {
    const saved = api_token;
    defer api_token = saved;
    api_token = "correct-token";

    const req = (try http.parseRequest(
        "GET /containers HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong-token\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
}

test "dispatch allows unauthenticated /health when api_token is set" {
    const saved = api_token;
    defer api_token = saved;
    api_token = "test-secret-token";

    const req = (try http.parseRequest(
        "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
}

test "dispatch allows unauthenticated /version when api_token is set" {
    const saved = api_token;
    defer api_token = saved;
    api_token = "test-secret-token";

    const req = (try http.parseRequest(
        "GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
}

test "dispatch allows join token on agent heartbeat route" {
    const saved_api = api_token;
    const saved_join = join_token;
    defer {
        api_token = saved_api;
        join_token = saved_join;
    }
    api_token = "api-secret";
    join_token = "join-secret";

    const req = (try http.parseRequest(
        "POST /agents/abc123def456/heartbeat HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer join-secret\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch rejects join token on operator-only agent list route" {
    const saved_api = api_token;
    const saved_join = join_token;
    defer {
        api_token = saved_api;
        join_token = saved_join;
    }
    api_token = "api-secret";
    join_token = "join-secret";

    const req = (try http.parseRequest(
        "GET /agents HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer join-secret\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
}

test "dispatch rejects protected operator route when only join token is configured" {
    const saved_api = api_token;
    const saved_join = join_token;
    defer {
        api_token = saved_api;
        join_token = saved_join;
    }
    api_token = null;
    join_token = "join-secret";

    const req = (try http.parseRequest(
        "GET /agents HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.unauthorized, resp.status);
}

test "dispatch allows join route when only join token is configured" {
    const saved_api = api_token;
    const saved_join = join_token;
    const saved_cluster = cluster;
    defer {
        api_token = saved_api;
        join_token = saved_join;
        cluster = saved_cluster;
    }
    api_token = null;
    join_token = "join-secret";
    cluster = null;

    const req = (try http.parseRequest(
        "POST /agents/abc123def456/heartbeat HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer join-secret\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch allows unauthenticated public route when only join token is configured" {
    const saved_api = api_token;
    const saved_join = join_token;
    defer {
        api_token = saved_api;
        join_token = saved_join;
    }
    api_token = null;
    join_token = "join-secret";

    const req = (try http.parseRequest(
        "GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
}
