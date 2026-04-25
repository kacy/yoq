const std = @import("std");
const http = @import("../../api/http.zig");
const hpack = @import("hpack.zig");
const http2 = @import("http2.zig");
const proxy_helpers = @import("proxy_helpers.zig");
const router = @import("router.zig");

pub const switching_protocols_response =
    "HTTP/1.1 101 Switching Protocols\r\n" ++
    "Connection: Upgrade\r\n" ++
    "Upgrade: h2c\r\n" ++
    "\r\n";

pub const ParseError = error{
    MissingHostHeader,
    InvalidUpgrade,
    InvalidSettings,
    UnsupportedBody,
} || std.mem.Allocator.Error;

pub const ParsedUpgrade = struct {
    method: []const u8,
    authority: []const u8,
    path: []const u8,
    request_headers: []const router.RequestHeader,

    pub fn deinit(self: ParsedUpgrade, alloc: std.mem.Allocator) void {
        alloc.free(self.request_headers);
    }
};

pub fn parseUpgradeRequest(alloc: std.mem.Allocator, raw_request: []const u8) ParseError!?ParsedUpgrade {
    const request = (http.parseRequest(raw_request) catch return null) orelse return null;
    if (!isHttp11Request(raw_request)) return error.InvalidUpgrade;

    const upgrade_value = http.findHeaderValue(request.headers_raw, "Upgrade");
    const connection_value = http.findHeaderValue(request.headers_raw, "Connection");
    const settings_value = http.findHeaderValue(request.headers_raw, "HTTP2-Settings");

    if (upgrade_value == null and settings_value == null and !tokenListContains(connection_value, "upgrade")) {
        return null;
    }

    if (upgrade_value == null or !tokenListContains(upgrade_value, "h2c")) {
        return error.InvalidUpgrade;
    }

    if (request.content_length != 0 or request.body.len != 0) {
        return error.UnsupportedBody;
    }

    if (settings_value) |encoded| {
        try validateSettingsHeader(encoded);
    }

    const host_header = http.findHeaderValue(request.headers_raw, "Host") orelse return error.MissingHostHeader;

    return .{
        .method = proxy_helpers.methodString(request.method),
        .authority = host_header,
        .path = request.path,
        .request_headers = try router.collectHttp1Headers(alloc, request.headers_raw),
    };
}

pub fn buildStream1HeadersFrame(
    alloc: std.mem.Allocator,
    authority: []const u8,
    method: []const u8,
    path: []const u8,
    request_headers: []const router.RequestHeader,
    forwarded_proto: ?[]const u8,
) ![]u8 {
    var headers: std.ArrayList(hpack.HeaderField) = .empty;
    defer {
        for (headers.items) |header| header.deinit(alloc);
        headers.deinit(alloc);
    }

    try appendHeader(&headers, alloc, ":method", method);
    try appendHeader(&headers, alloc, ":scheme", "http");
    try appendHeader(&headers, alloc, ":authority", authority);
    try appendHeader(&headers, alloc, ":path", path);

    for (request_headers) |header| {
        if (shouldSkipRequestHeader(header.name, request_headers, forwarded_proto != null)) continue;
        const lower_name = try asciiLowerDup(alloc, header.name);
        errdefer alloc.free(lower_name);
        try headers.append(alloc, .{
            .name = lower_name,
            .value = try alloc.dupe(u8, header.value),
        });
    }

    if (forwarded_proto) |proto| {
        try appendHeader(&headers, alloc, "x-forwarded-proto", proto);
    }

    const header_block = try hpack.encodeHeaderBlockLiteral(alloc, headers.items);
    defer alloc.free(header_block);

    return http2.buildFrame(alloc, .{
        .length = @intCast(header_block.len),
        .frame_type = .headers,
        .flags = 0x5,
        .stream_id = 1,
    }, header_block);
}

fn validateSettingsHeader(value: []const u8) ParseError!void {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(value) catch return error.InvalidSettings;
    if (decoded_len % 6 != 0) return error.InvalidSettings;

    var buf: [256]u8 = undefined;
    if (decoded_len > buf.len) return error.InvalidSettings;
    decoder.decode(buf[0..decoded_len], value) catch return error.InvalidSettings;
}

fn isHttp11Request(raw_request: []const u8) bool {
    const line_end = std.mem.indexOf(u8, raw_request, "\r\n") orelse return false;
    return std.mem.endsWith(u8, raw_request[0..line_end], " HTTP/1.1");
}

fn tokenListContains(value: ?[]const u8, needle: []const u8) bool {
    const raw = value orelse return false;
    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |token| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), needle)) return true;
    }
    return false;
}

fn shouldSkipRequestHeader(name: []const u8, request_headers: []const router.RequestHeader, rewriting_forwarded_proto: bool) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "upgrade") or
        std.ascii.eqlIgnoreCase(name, "http2-settings") or
        std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        (rewriting_forwarded_proto and std.ascii.eqlIgnoreCase(name, "x-forwarded-proto")) or
        headerListedInConnection(name, request_headers);
}

fn headerListedInConnection(name: []const u8, request_headers: []const router.RequestHeader) bool {
    for (request_headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;

        var it = std.mem.splitScalar(u8, header.value, ',');
        while (it.next()) |token| {
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, token, " \t"), name)) return true;
        }
    }
    return false;
}

fn appendHeader(headers: *std.ArrayList(hpack.HeaderField), alloc: std.mem.Allocator, name: []const u8, value: []const u8) !void {
    try headers.append(alloc, .{
        .name = try alloc.dupe(u8, name),
        .value = try alloc.dupe(u8, value),
    });
}

fn asciiLowerDup(alloc: std.mem.Allocator, value: []const u8) ![]u8 {
    const out = try alloc.alloc(u8, value.len);
    for (value, 0..) |char, idx| {
        out[idx] = std.ascii.toLower(char);
    }
    return out;
}

test "parseUpgradeRequest ignores non-upgrade http1 request" {
    try std.testing.expectEqual(null, try parseUpgradeRequest(
        std.testing.allocator,
        "GET / HTTP/1.1\r\nHost: api.internal\r\n\r\n",
    ));
}

test "parseUpgradeRequest accepts h2c upgrade without http2-settings" {
    const parsed = (try parseUpgradeRequest(
        std.testing.allocator,
        "GET /pkg.Service/Call HTTP/1.1\r\nHost: grpc.internal\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n",
    )).?;
    defer parsed.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("GET", parsed.method);
    try std.testing.expectEqualStrings("grpc.internal", parsed.authority);
    try std.testing.expectEqualStrings("/pkg.Service/Call", parsed.path);
}

test "parseUpgradeRequest rejects non-http11 upgrade request" {
    try std.testing.expectError(error.InvalidUpgrade, parseUpgradeRequest(
        std.testing.allocator,
        "GET /pkg.Service/Call HTTP/1.0\r\nHost: grpc.internal\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n",
    ));
}

test "parseUpgradeRequest rejects malformed settings header" {
    try std.testing.expectError(error.InvalidSettings, parseUpgradeRequest(
        std.testing.allocator,
        "GET /pkg.Service/Call HTTP/1.1\r\nHost: grpc.internal\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nHTTP2-Settings: invalid!\r\n\r\n",
    ));
}

test "parseUpgradeRequest rejects request body" {
    try std.testing.expectError(error.UnsupportedBody, parseUpgradeRequest(
        std.testing.allocator,
        "POST /pkg.Service/Call HTTP/1.1\r\nHost: grpc.internal\r\nUpgrade: h2c\r\nConnection: Upgrade\r\nContent-Length: 5\r\n\r\nhello",
    ));
}

test "buildStream1HeadersFrame strips hop-by-hop headers and preserves app headers" {
    const alloc = std.testing.allocator;
    const request_headers = [_]router.RequestHeader{
        .{ .name = "Host", .value = "grpc.internal" },
        .{ .name = "Upgrade", .value = "h2c" },
        .{ .name = "Connection", .value = "Upgrade, HTTP2-Settings, X-Hop" },
        .{ .name = "HTTP2-Settings", .value = "AAEAAQAAAAIAAAAB" },
        .{ .name = "X-Forwarded-Proto", .value = "https" },
        .{ .name = "X-Hop", .value = "remove-me" },
        .{ .name = "X-Env", .value = "canary" },
    };

    const frame = try buildStream1HeadersFrame(
        alloc,
        "grpc.internal",
        "GET",
        "/pkg.Service/Call",
        &request_headers,
        "http",
    );
    defer alloc.free(frame);

    const parsed = http2.parseFrameHeader(frame[0..http2.frame_header_len]).?;
    try std.testing.expectEqual(http2.FrameType.headers, parsed.frame_type);

    var headers = try hpack.decodeHeaderBlock(alloc, frame[http2.frame_header_len .. http2.frame_header_len + parsed.length]);
    defer {
        for (headers.items) |header| header.deinit(alloc);
        headers.deinit(alloc);
    }

    var saw_env = false;
    var saw_upgrade = false;
    var saw_forwarded_proto = false;
    var saw_hop = false;
    for (headers.items) |header| {
        if (std.mem.eql(u8, header.name, "x-env")) saw_env = std.mem.eql(u8, header.value, "canary");
        if (std.mem.eql(u8, header.name, "upgrade")) saw_upgrade = true;
        if (std.mem.eql(u8, header.name, "x-hop")) saw_hop = true;
        if (std.mem.eql(u8, header.name, "x-forwarded-proto")) saw_forwarded_proto = std.mem.eql(u8, header.value, "http");
    }

    try std.testing.expect(saw_env);
    try std.testing.expect(!saw_upgrade);
    try std.testing.expect(!saw_hop);
    try std.testing.expect(saw_forwarded_proto);
}
