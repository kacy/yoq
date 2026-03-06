// routes — API dispatch/auth shell with concern-specific route modules

const std = @import("std");
const http = @import("http.zig");
const cluster_node = @import("../cluster/node.zig");
const json_helpers = @import("../lib/json_helpers.zig");
const common = @import("routes/common.zig");
const containers_images = @import("routes/containers_images.zig");
const cluster_agents = @import("routes/cluster_agents.zig");
const status_metrics = @import("routes/status_metrics.zig");
const security = @import("routes/security.zig");

pub var cluster: ?*cluster_node.Node = null;
pub var join_token: ?[]const u8 = null;
pub var api_token: ?[]const u8 = null;

pub const Response = common.Response;
const AssignmentIds = common.AssignmentIds;

pub fn dispatch(request: http.Request, alloc: std.mem.Allocator) Response {
    if (api_token) |expected_token| {
        const is_public = std.mem.eql(u8, request.path_only, "/health") or
            std.mem.eql(u8, request.path_only, "/version");

        if (!is_public and !common.hasValidBearerToken(&request, expected_token)) {
            return common.unauthorized();
        }
    }

    if (request.method == .GET) {
        if (std.mem.eql(u8, request.path_only, "/health")) {
            return .{ .status = .ok, .body = "{\"status\":\"ok\"}", .allocated = false };
        }
        if (std.mem.eql(u8, request.path_only, "/version")) {
            return .{ .status = .ok, .body = "{\"version\":\"0.0.1\"}", .allocated = false };
        }
    }

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

fn notFound() Response {
    return common.notFound();
}

fn unauthorized() Response {
    return common.unauthorized();
}

fn methodNotAllowed() Response {
    return common.methodNotAllowed();
}

fn internalError() Response {
    return common.internalError();
}

fn badRequest(comptime message: []const u8) Response {
    return common.badRequest(message);
}

pub fn extractBearerToken(request: *const http.Request) ?[]const u8 {
    return common.extractBearerToken(request);
}

fn validateClusterInput(value: []const u8) bool {
    return common.validateClusterInput(value);
}

fn validateContainerId(id: []const u8) bool {
    return common.validateContainerId(id);
}

fn matchAssignmentStatusPath(rest: []const u8) ?AssignmentIds {
    return common.matchAssignmentStatusPath(rest);
}

fn matchSubpath(rest: []const u8, suffix: []const u8) ?[]const u8 {
    return common.matchSubpath(rest, suffix);
}

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
    try std.testing.expectEqualStrings("{\"version\":\"0.0.1\"}", resp.body);
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

    // will return not found or internal error since no DB is configured
    // but it exercises the routing path correctly
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
    const req = (try http.parseRequest(
        "DELETE /containers/abc123 HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    // will fail because no DB, but routing is correct
    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "dispatch DELETE image" {
    const req = (try http.parseRequest(
        "DELETE /images/sha256:abc HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    // no DB configured, so this will error
    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "matchSubpath" {
    try std.testing.expectEqualStrings("abc123", matchSubpath("abc123/logs", "/logs").?);
    try std.testing.expectEqualStrings("def456", matchSubpath("def456/stop", "/stop").?);
    try std.testing.expect(matchSubpath("abc123", "/logs") == null);
    try std.testing.expect(matchSubpath("abc123/other", "/logs") == null);
    try std.testing.expect(matchSubpath("/logs", "/logs") == null); // empty id
}

test "writeJsonEscaped" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    try json_helpers.writeJsonEscaped(writer, "hello \"world\"\nline2");
    try std.testing.expectEqualStrings("hello \\\"world\\\"\\nline2", buf.items);
}

test "writeJsonEscaped with backslash" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    try json_helpers.writeJsonEscaped(writer, "path\\to\\file");
    try std.testing.expectEqualStrings("path\\\\to\\\\file", buf.items);
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

test "validateClusterInput accepts normal values" {
    try std.testing.expect(validateClusterInput("10.0.0.5:7701"));
    try std.testing.expect(validateClusterInput("nginx:latest"));
    try std.testing.expect(validateClusterInput("/bin/sh -c echo hello"));
}

test "validateClusterInput rejects dangerous values" {
    try std.testing.expect(!validateClusterInput("'; DROP TABLE agents; --"));
    try std.testing.expect(!validateClusterInput("image\"name"));
    try std.testing.expect(!validateClusterInput("cmd;rm -rf /"));
    try std.testing.expect(!validateClusterInput("path\\to\\thing"));
    try std.testing.expect(!validateClusterInput("")); // empty
    try std.testing.expect(!validateClusterInput("a" ** 257)); // too long
}

test "validateClusterInput rejects control characters" {
    try std.testing.expect(!validateClusterInput("hello\x00world"));
    try std.testing.expect(!validateClusterInput("line\nbreak"));
}

test "matchAssignmentStatusPath" {
    const result = matchAssignmentStatusPath("abc123/assignments/def456/status");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("abc123", result.?.agent_id);
    try std.testing.expectEqualStrings("def456", result.?.assignment_id);

    // missing /status suffix
    try std.testing.expect(matchAssignmentStatusPath("abc123/assignments/def456") == null);
    // no assignment id
    try std.testing.expect(matchAssignmentStatusPath("abc123/assignments//status") == null);
    // no agent id
    try std.testing.expect(matchAssignmentStatusPath("/assignments/def456/status") == null);
    // wrong prefix
    try std.testing.expect(matchAssignmentStatusPath("abc123/other/def456/status") == null);
}

test "dispatch assignment status update routing" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/abc123/assignments/def456/status HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\n\r\n{\"status\":\"running\"}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    // no cluster configured, so returns bad_request
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

test "validateContainerId accepts valid hex ids" {
    try std.testing.expect(validateContainerId("abc123def456"));
    try std.testing.expect(validateContainerId("0123456789ab"));
    try std.testing.expect(validateContainerId("deadbeef"));
}

test "validateContainerId rejects invalid ids" {
    try std.testing.expect(!validateContainerId("")); // empty
    try std.testing.expect(!validateContainerId("ABCDEF")); // uppercase
    try std.testing.expect(!validateContainerId("abc-123")); // hyphen
    try std.testing.expect(!validateContainerId("abc_123")); // underscore
    try std.testing.expect(!validateContainerId("../etc")); // path traversal
    try std.testing.expect(!validateContainerId("abc;rm")); // injection
    try std.testing.expect(!validateContainerId("a" ** 65)); // too long
}

test "dispatch rejects non-hex container id" {
    const req = (try http.parseRequest(
        "GET /containers/INVALID! HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "validateContainerId accepts exactly 64 chars" {
    const id_64 = "a" ** 64;
    try std.testing.expect(validateContainerId(id_64));
}

test "validateClusterInput rejects tab character" {
    try std.testing.expect(!validateClusterInput("hello\tworld"));
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

    // will return internal_server_error because no DB is configured,
    // but it proves the routing reached the handler
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
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    // will fail to open DB, but routing is correct
    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "dispatch DELETE /v1/secrets/mykey routes correctly" {
    const req = (try http.parseRequest(
        "DELETE /v1/secrets/mykey HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    // will fail to open DB, but routing is correct
    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "dispatch PUT /v1/secrets returns method not allowed" {
    const req = (try http.parseRequest(
        "PUT /v1/secrets HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
}

// -- bearer token authentication tests --

test "dispatch returns 401 for missing auth on protected endpoint when api_token is set" {
    // save and restore api_token
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

test "extractBearerToken parses valid bearer token" {
    const req = (try http.parseRequest(
        "GET /test HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer my-token\r\n\r\n",
    )).?;
    const token = extractBearerToken(&req);
    try std.testing.expect(token != null);
    try std.testing.expectEqualStrings("my-token", token.?);
}

test "extractBearerToken returns null for missing header" {
    const req = (try http.parseRequest(
        "GET /test HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    try std.testing.expect(extractBearerToken(&req) == null);
}

test "extractBearerToken returns null for non-bearer auth" {
    const req = (try http.parseRequest(
        "GET /test HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic abc123\r\n\r\n",
    )).?;
    try std.testing.expect(extractBearerToken(&req) == null);
}
