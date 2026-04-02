const std = @import("std");
const http = @import("../../api/http.zig");

pub const trusted_forwarded_proto_ip: [4]u8 = .{ 127, 0, 0, 1 };

pub fn normalizeHost(host_header: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, host_header, ':')) |port_sep| {
        return host_header[0..port_sep];
    }
    return host_header;
}

pub fn methodString(method: http.Method) []const u8 {
    return switch (method) {
        .GET => "GET",
        .HEAD => "HEAD",
        .POST => "POST",
        .PUT => "PUT",
        .DELETE => "DELETE",
    };
}

pub fn parseMethodString(method: []const u8) ?http.Method {
    if (std.mem.eql(u8, method, "GET")) return .GET;
    if (std.mem.eql(u8, method, "HEAD")) return .HEAD;
    if (std.mem.eql(u8, method, "POST")) return .POST;
    if (std.mem.eql(u8, method, "PUT")) return .PUT;
    if (std.mem.eql(u8, method, "DELETE")) return .DELETE;
    return null;
}

pub fn buildOutboundPath(
    alloc: std.mem.Allocator,
    original_path: []const u8,
    matched_prefix: []const u8,
    rewrite_prefix: ?[]const u8,
) ![]u8 {
    const replacement = rewrite_prefix orelse return alloc.dupe(u8, original_path);
    const query_start = std.mem.indexOfScalar(u8, original_path, '?');
    const path_only = if (query_start) |start| original_path[0..start] else original_path;
    const query = if (query_start) |start| original_path[start..] else "";
    const suffix = if (std.mem.eql(u8, matched_prefix, "/"))
        path_only
    else if (path_only.len >= matched_prefix.len)
        path_only[matched_prefix.len..]
    else
        "";

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.appendSlice(alloc, replacement);
    if (suffix.len > 0) {
        if (std.mem.eql(u8, replacement, "/")) {
            if (suffix[0] == '/') {
                try out.appendSlice(alloc, suffix[1..]);
            } else {
                try out.appendSlice(alloc, suffix);
            }
        } else {
            if (suffix[0] != '/') try out.append(alloc, '/');
            try out.appendSlice(alloc, suffix);
        }
    }
    if (out.items.len == 0) try out.append(alloc, '/');
    try out.appendSlice(alloc, query);
    return out.toOwnedSlice(alloc);
}

test "normalizeHost strips port" {
    try std.testing.expectEqualStrings("example.com", normalizeHost("example.com:8080"));
}

test "normalizeHost preserves bare host" {
    try std.testing.expectEqualStrings("example.com", normalizeHost("example.com"));
}

test "methodString round-trips through parseMethodString" {
    inline for (.{ .GET, .HEAD, .POST, .PUT, .DELETE }) |m| {
        try std.testing.expectEqual(m, parseMethodString(methodString(m)).?);
    }
}

test "parseMethodString returns null for unknown method" {
    try std.testing.expectEqual(null, parseMethodString("PATCH"));
}

test "buildOutboundPath preserves path when no rewrite" {
    const alloc = std.testing.allocator;
    const path = try buildOutboundPath(alloc, "/v1/users", "/v1", null);
    defer alloc.free(path);
    try std.testing.expectEqualStrings("/v1/users", path);
}

test "buildOutboundPath rewrites prefix" {
    const alloc = std.testing.allocator;
    const path = try buildOutboundPath(alloc, "/v1/users?q=1", "/v1", "/api");
    defer alloc.free(path);
    try std.testing.expectEqualStrings("/api/users?q=1", path);
}
