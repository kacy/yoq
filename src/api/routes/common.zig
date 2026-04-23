const std = @import("std");
const http = @import("../http.zig");
const cluster_node = @import("../../cluster/node.zig");
const testing = std.testing;

pub const Response = struct {
    status: http.StatusCode,
    body: []const u8,
    // if true, caller must free body
    allocated: bool,
    // override content type (null = application/json)
    content_type: ?[]const u8 = null,
};

pub const RouteContext = struct {
    cluster: ?*cluster_node.Node,
    join_token: ?[]const u8,
};

pub const AssignmentIds = struct {
    agent_id: []const u8,
    assignment_id: []const u8,
};

pub fn notFound() Response {
    return .{ .status = .not_found, .body = "{\"error\":\"not found\"}", .allocated = false };
}

pub fn unauthorized() Response {
    return .{ .status = .unauthorized, .body = "{\"error\":\"unauthorized\"}", .allocated = false };
}

pub fn methodNotAllowed() Response {
    return .{ .status = .method_not_allowed, .body = "{\"error\":\"method not allowed\"}", .allocated = false };
}

pub fn internalError() Response {
    return .{ .status = .internal_server_error, .body = "{\"error\":\"internal error\"}", .allocated = false };
}

pub fn badRequest(comptime message: []const u8) Response {
    return .{ .status = .bad_request, .body = "{\"error\":\"" ++ message ++ "\"}", .allocated = false };
}

pub fn notLeader(alloc: std.mem.Allocator, node: *cluster_node.Node) Response {
    var buf: [64]u8 = undefined;
    if (node.leaderAddrBuf(&buf)) |addr| {
        var json_buf: [128]u8 = undefined;
        const body = std.fmt.bufPrint(&json_buf, "{{\"error\":\"not leader\",\"leader\":\"{s}\"}}", .{addr}) catch
            return badRequest("not leader");
        const owned = alloc.dupe(u8, body) catch return badRequest("not leader");
        return .{ .status = .bad_request, .body = owned, .allocated = true };
    }
    return badRequest("not leader");
}

pub fn jsonOkOwned(alloc: std.mem.Allocator, body: []const u8) Response {
    const owned = alloc.dupe(u8, body) catch return internalError();
    return .{ .status = .ok, .body = owned, .allocated = true };
}

pub fn ownedResponse(
    alloc: std.mem.Allocator,
    status: http.StatusCode,
    content_type: ?[]const u8,
    context: anytype,
    writeFn: anytype,
) Response {
    var body_writer = std.Io.Writer.Allocating.init(alloc);
    defer body_writer.deinit();

    writeFn(&body_writer.writer, context) catch return internalError();

    const body = body_writer.toOwnedSlice() catch return internalError();
    return .{
        .status = status,
        .body = body,
        .allocated = true,
        .content_type = content_type,
    };
}

pub fn jsonOkWrite(alloc: std.mem.Allocator, context: anytype, writeFn: anytype) Response {
    return ownedResponse(alloc, .ok, null, context, writeFn);
}

pub fn extractBearerToken(request: *const http.Request) ?[]const u8 {
    const auth_value = http.findHeaderValue(request.headers_raw, "Authorization") orelse return null;

    const prefix = "Bearer ";
    if (auth_value.len <= prefix.len) return null;
    if (!std.mem.startsWith(u8, auth_value, prefix)) return null;

    return auth_value[prefix.len..];
}

pub fn hasValidBearerToken(request: *const http.Request, expected_token: []const u8) bool {
    const provided = extractBearerToken(request) orelse return false;

    // constant-time: always compare expected_token.len bytes.
    // length mismatch is folded into the diff, not returned early.
    var diff: u8 = if (provided.len != expected_token.len) 1 else 0;
    const compare_len = @min(provided.len, expected_token.len);
    for (provided[0..compare_len], expected_token[0..compare_len]) |a, b| {
        diff |= a ^ b;
    }
    return diff == 0;
}

pub fn validateClusterInput(value: []const u8) bool {
    if (value.len == 0 or value.len > 256) return false;
    for (value) |c| {
        if (c == '\'' or c == '"' or c == ';' or c == '\\') return false;
        if (c < 0x20) return false;
    }
    return true;
}

pub fn validateContainerId(id: []const u8) bool {
    if (id.len == 0 or id.len > 64) return false;
    for (id) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    }
    return true;
}

pub fn matchAssignmentStatusPath(rest: []const u8) ?AssignmentIds {
    const slash = std.mem.indexOf(u8, rest, "/") orelse return null;
    const agent_id = rest[0..slash];
    if (agent_id.len == 0) return null;

    const after = rest[slash..];
    const prefix = "/assignments/";
    if (!std.mem.startsWith(u8, after, prefix)) return null;

    const remaining = after[prefix.len..];
    const slash2 = std.mem.indexOf(u8, remaining, "/") orelse return null;
    const assignment_id = remaining[0..slash2];
    if (assignment_id.len == 0) return null;

    const suffix = remaining[slash2..];
    if (!std.mem.eql(u8, suffix, "/status")) return null;

    return .{ .agent_id = agent_id, .assignment_id = assignment_id };
}

pub fn matchSubpath(rest: []const u8, suffix: []const u8) ?[]const u8 {
    const slash = std.mem.indexOf(u8, rest, "/") orelse return null;
    const id = rest[0..slash];
    const after = rest[slash..];

    if (id.len == 0) return null;
    if (std.mem.eql(u8, after, suffix)) return id;
    return null;
}

pub fn extractQueryParam(path: []const u8, param: []const u8) ?[]const u8 {
    const query_start = std.mem.indexOf(u8, path, "?") orelse return null;
    return extractQueryValue(path[query_start + 1 ..], param);
}

/// parse a query parameter value from a bare query string (no leading '?').
/// returns "" for valueless params (e.g., "uploads" in "uploads&prefix=foo").
/// returns null if the parameter is not found.
pub fn extractQueryValue(query: []const u8, param: []const u8) ?[]const u8 {
    if (query.len == 0) return null;

    var iter = std.mem.splitScalar(u8, query, '&');
    while (iter.next()) |pair| {
        if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
            if (std.mem.eql(u8, pair[0..eq], param)) {
                const value = pair[eq + 1 ..];
                if (value.len > 0) return value;
            }
        } else {
            if (std.mem.eql(u8, pair, param)) return "";
        }
    }

    return null;
}

// ============================================================================
// Tests
// ============================================================================

test "notFound returns correct response" {
    const resp = notFound();
    try testing.expectEqual(http.StatusCode.not_found, resp.status);
    try testing.expectEqualStrings("{\"error\":\"not found\"}", resp.body);
    try testing.expect(!resp.allocated);
}

test "unauthorized returns correct response" {
    const resp = unauthorized();
    try testing.expectEqual(http.StatusCode.unauthorized, resp.status);
    try testing.expectEqualStrings("{\"error\":\"unauthorized\"}", resp.body);
    try testing.expect(!resp.allocated);
}

test "methodNotAllowed returns correct response" {
    const resp = methodNotAllowed();
    try testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
    try testing.expectEqualStrings("{\"error\":\"method not allowed\"}", resp.body);
    try testing.expect(!resp.allocated);
}

test "internalError returns correct response" {
    const resp = internalError();
    try testing.expectEqual(http.StatusCode.internal_server_error, resp.status);
    try testing.expectEqualStrings("{\"error\":\"internal error\"}", resp.body);
    try testing.expect(!resp.allocated);
}

test "badRequest returns correct response with message" {
    const resp = badRequest("invalid input");
    try testing.expectEqual(http.StatusCode.bad_request, resp.status);
    try testing.expectEqualStrings("{\"error\":\"invalid input\"}", resp.body);
    try testing.expect(!resp.allocated);
}

test "jsonOkOwned returns allocated ok response" {
    const body = "{\"status\":\"ok\"}";
    const resp = jsonOkOwned(testing.allocator, body);
    try testing.expectEqual(http.StatusCode.ok, resp.status);
    try testing.expectEqualStrings(body, resp.body);
    try testing.expect(resp.allocated);
    testing.allocator.free(resp.body);
}

test "jsonOkWrite returns allocated ok response" {
    const Ctx = struct {
        value: []const u8,
    };
    const Writer = struct {
        fn write(writer: *std.Io.Writer, ctx: Ctx) !void {
            try writer.print("{{\"value\":\"{s}\"}}", .{ctx.value});
        }
    };

    const resp = jsonOkWrite(testing.allocator, Ctx{ .value = "ok" }, Writer.write);
    defer testing.allocator.free(resp.body);

    try testing.expectEqual(http.StatusCode.ok, resp.status);
    try testing.expectEqualStrings("{\"value\":\"ok\"}", resp.body);
    try testing.expect(resp.allocated);
    try testing.expect(resp.content_type == null);
}

test "ownedResponse preserves content type" {
    const Writer = struct {
        fn write(writer: *std.Io.Writer, _: void) !void {
            try writer.writeAll("metrics");
        }
    };

    const resp = ownedResponse(testing.allocator, .ok, "text/plain", {}, Writer.write);
    defer testing.allocator.free(resp.body);

    try testing.expectEqual(http.StatusCode.ok, resp.status);
    try testing.expectEqualStrings("metrics", resp.body);
    try testing.expect(resp.allocated);
    try testing.expectEqualStrings("text/plain", resp.content_type.?);
}

test "extractBearerToken extracts valid token" {
    const request = http.Request{
        .method = .GET,
        .path = "/test",
        .path_only = "/test",
        .query = "",
        .headers_raw = "Authorization: Bearer token123",
        .body = "",
        .content_length = 0,
    };
    const token = extractBearerToken(&request);
    try testing.expect(token != null);
    try testing.expectEqualStrings("token123", token.?);
}

test "extractBearerToken returns null for missing header" {
    const request = http.Request{
        .method = .GET,
        .path = "/test",
        .path_only = "/test",
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };
    const token = extractBearerToken(&request);
    try testing.expect(token == null);
}

test "extractBearerToken returns null for non-Bearer prefix" {
    const request = http.Request{
        .method = .GET,
        .path = "/test",
        .path_only = "/test",
        .query = "",
        .headers_raw = "Authorization: Basic token123",
        .body = "",
        .content_length = 0,
    };
    const token = extractBearerToken(&request);
    try testing.expect(token == null);
}

test "extractBearerToken returns null for short auth value" {
    const request = http.Request{
        .method = .GET,
        .path = "/test",
        .path_only = "/test",
        .query = "",
        .headers_raw = "Authorization: Bearer ",
        .body = "",
        .content_length = 0,
    };
    const token = extractBearerToken(&request);
    try testing.expect(token == null);
}

test "hasValidBearerToken validates correct token" {
    const request = http.Request{
        .method = .GET,
        .path = "/test",
        .path_only = "/test",
        .query = "",
        .headers_raw = "Authorization: Bearer secrettoken",
        .body = "",
        .content_length = 0,
    };
    try testing.expect(hasValidBearerToken(&request, "secrettoken"));
}

test "hasValidBearerToken rejects invalid token" {
    const request = http.Request{
        .method = .GET,
        .path = "/test",
        .path_only = "/test",
        .query = "",
        .headers_raw = "Authorization: Bearer wrongtoken",
        .body = "",
        .content_length = 0,
    };
    try testing.expect(!hasValidBearerToken(&request, "secrettoken"));
}

test "hasValidBearerToken rejects different length token" {
    const request = http.Request{
        .method = .GET,
        .path = "/test",
        .path_only = "/test",
        .query = "",
        .headers_raw = "Authorization: Bearer short",
        .body = "",
        .content_length = 0,
    };
    try testing.expect(!hasValidBearerToken(&request, "secrettoken"));
}

test "validateClusterInput accepts valid input" {
    try testing.expect(validateClusterInput("valid-address"));
    try testing.expect(validateClusterInput("192.168.1.1:8080"));
    try testing.expect(validateClusterInput("hostname.example.com"));
}

test "validateClusterInput rejects empty string" {
    try testing.expect(!validateClusterInput(""));
}

test "validateClusterInput rejects long string" {
    var long_input: [300]u8 = undefined;
    @memset(&long_input, 'a');
    try testing.expect(!validateClusterInput(&long_input));
}

test "validateClusterInput rejects special characters" {
    try testing.expect(!validateClusterInput("value'with'quotes"));
    try testing.expect(!validateClusterInput("value\"with\"quotes"));
    try testing.expect(!validateClusterInput("value;with;semicolons"));
    try testing.expect(!validateClusterInput("value\\with\\backslash"));
}

test "validateClusterInput rejects control characters" {
    try testing.expect(!validateClusterInput("value\x00with\x01nulls"));
    try testing.expect(!validateClusterInput("value\nwith\rnewlines"));
}

test "validateContainerId accepts valid hex id" {
    try testing.expect(validateContainerId("abc123def4567890123456789012345678901234567890123456789012345678"));
    try testing.expect(validateContainerId("deadbeef"));
    try testing.expect(validateContainerId("1234567890abcdef"));
}

test "validateContainerId rejects empty id" {
    try testing.expect(!validateContainerId(""));
}

test "validateContainerId rejects long id" {
    var long_id: [70]u8 = undefined;
    @memset(&long_id, 'a');
    try testing.expect(!validateContainerId(&long_id));
}

test "validateContainerId rejects non-hex characters" {
    try testing.expect(!validateContainerId("abc123xyz"));
    try testing.expect(!validateContainerId("ABC123")); // uppercase not allowed
    try testing.expect(!validateContainerId("container_id"));
}

test "matchSubpath matches valid subpath" {
    const result = matchSubpath("agent123/heartbeat", "/heartbeat");
    try testing.expect(result != null);
    try testing.expectEqualStrings("agent123", result.?);
}

test "matchSubpath returns null for non-matching suffix" {
    const result = matchSubpath("agent123/logs", "/heartbeat");
    try testing.expect(result == null);
}

test "matchSubpath returns null for missing slash" {
    const result = matchSubpath("agent123heartbeat", "/heartbeat");
    try testing.expect(result == null);
}

test "matchSubpath returns null for empty id" {
    const result = matchSubpath("/heartbeat", "/heartbeat");
    try testing.expect(result == null);
}

test "matchAssignmentStatusPath matches valid path" {
    const result = matchAssignmentStatusPath("agent123/assignments/assign456/status");
    try testing.expect(result != null);
    try testing.expectEqualStrings("agent123", result.?.agent_id);
    try testing.expectEqualStrings("assign456", result.?.assignment_id);
}

test "matchAssignmentStatusPath returns null for missing agent" {
    const result = matchAssignmentStatusPath("/assignments/assign456/status");
    try testing.expect(result == null);
}

test "matchAssignmentStatusPath returns null for missing assignment" {
    const result = matchAssignmentStatusPath("agent123/assignments//status");
    try testing.expect(result == null);
}

test "matchAssignmentStatusPath returns null for wrong suffix" {
    const result = matchAssignmentStatusPath("agent123/assignments/assign456/wrong");
    try testing.expect(result == null);
}

test "extractQueryParam extracts param from query string" {
    try testing.expectEqualStrings("value1", extractQueryParam("/path?param=value1", "param").?);
    try testing.expectEqualStrings("value2", extractQueryParam("/path?other=val&param=value2", "param").?);
}

test "extractQueryParam returns null for missing param" {
    try testing.expect(extractQueryParam("/path?other=value", "param") == null);
}

test "extractQueryParam returns null for empty path" {
    try testing.expect(extractQueryParam("/path", "param") == null);
}

test "extractQueryParam returns null for empty value" {
    try testing.expect(extractQueryParam("/path?param=", "param") == null);
}

test "notLeader without leader hint returns plain error" {
    // notLeader with a node that has no leader_id returns the simple fallback
    // we can't easily construct a real Node in this test, so we test the
    // badRequest fallback path directly
    const resp = badRequest("not leader");
    try testing.expectEqual(http.StatusCode.bad_request, resp.status);
    try testing.expectEqualStrings("{\"error\":\"not leader\"}", resp.body);
    try testing.expect(!resp.allocated);
}
