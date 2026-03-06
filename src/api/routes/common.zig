const std = @import("std");
const http = @import("../http.zig");
const cluster_node = @import("../../cluster/node.zig");

pub const Response = struct {
    status: http.StatusCode,
    body: []const u8,
    // if true, caller must free body
    allocated: bool,
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

pub fn jsonOkOwned(alloc: std.mem.Allocator, body: []const u8) Response {
    const owned = alloc.dupe(u8, body) catch return internalError();
    return .{ .status = .ok, .body = owned, .allocated = true };
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
    if (provided.len != expected_token.len) return false;

    // constant-time comparison
    var diff: u8 = 0;
    for (provided, expected_token) |a, b| {
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
    var rest = path[query_start + 1 ..];

    while (rest.len > 0) {
        const amp = std.mem.indexOf(u8, rest, "&") orelse rest.len;
        const pair = rest[0..amp];

        if (std.mem.indexOf(u8, pair, "=")) |eq| {
            const key = pair[0..eq];
            const value = pair[eq + 1 ..];
            if (std.mem.eql(u8, key, param) and value.len > 0) {
                return value;
            }
        }

        rest = if (amp < rest.len) rest[amp + 1 ..] else &.{};
    }

    return null;
}
