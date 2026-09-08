const std = @import("std");
const common = @import("common.zig");

const posix = std.posix;

/// initialize the client clock and trust bundle before applying socket timeouts.
pub fn requestWithTimeout(
    client: *std.http.Client,
    method: std.http.Method,
    uri: std.Uri,
    options: std.http.Client.RequestOptions,
) !std.http.Client.Request {
    const request = try client.request(method, uri, options);
    setSocketTimeouts(request.connection.?);
    return request;
}

/// copy the location into caller storage so it outlives the response head.
/// registry-relative locations use the registry's https endpoint.
pub fn parseLocationHeader(host: []const u8, head: std.http.Client.Response.Head, buf: []u8) ?[]const u8 {
    var it = head.iterateHeaders();
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "location")) continue;

        const value = header.value;
        if (value.len == 0) continue;

        if (std.mem.startsWith(u8, value, "http://") or
            std.mem.startsWith(u8, value, "https://"))
        {
            return std.fmt.bufPrint(buf, "{s}", .{value}) catch null;
        }

        return std.fmt.bufPrint(buf, "https://{s}{s}", .{ host, value }) catch null;
    }
    return null;
}

fn setSocketTimeouts(conn: *std.http.Client.Connection) void {
    const stream = conn.stream_reader.stream;
    const tv = posix.timeval{ .sec = common.registry_timeout_sec, .usec = 0 };
    const opt_bytes = std.mem.asBytes(&tv);
    posix.setsockopt(stream.socket.handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, opt_bytes) catch {};
    posix.setsockopt(stream.socket.handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, opt_bytes) catch {};
}

/// stop at the cap, including chunked responses and those without a length.
/// read at most one extra byte to detect an oversized body.
pub fn readBody(alloc: std.mem.Allocator, reader: *std.Io.Reader, limit: usize) error{ NetworkError, ResponseTooLarge }![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(alloc);
    var chunk: [8192]u8 = undefined;
    while (true) {
        const remaining = limit - body.items.len;
        const count = reader.readSliceShort(chunk[0..@min(chunk.len, remaining + 1)]) catch return error.NetworkError;
        if (count == 0) break;
        if (count > remaining) return error.ResponseTooLarge;
        body.appendSlice(alloc, chunk[0..count]) catch return error.NetworkError;
    }
    return body.toOwnedSlice(alloc) catch return error.NetworkError;
}

test "registry transfer bounded reader accepts the limit and stops at one extra byte" {
    const alloc = std.testing.allocator;
    var exact = std.Io.Reader.fixed("abcd");
    const body = try readBody(alloc, &exact, 4);
    defer alloc.free(body);
    try std.testing.expectEqualStrings("abcd", body);
    var oversized = std.Io.Reader.fixed("abcdefghi");
    try std.testing.expectError(error.ResponseTooLarge, readBody(alloc, &oversized, 4));
    try std.testing.expectEqual(@as(usize, 5), oversized.seek);
}

test "parseLocationHeader copies absolute locations" {
    const response_bytes = "HTTP/1.1 202 Accepted\r\n" ++
        "Location: https://registry.example.io/v2/myrepo/blobs/uploads/uuid-123\r\n" ++
        "Content-Length: 0\r\n\r\n";

    var location_buf: [8192]u8 = undefined;
    const head = std.http.Client.Response.Head.parse(response_bytes) catch unreachable;
    const location = parseLocationHeader("registry.example.io", head, &location_buf).?;
    try std.testing.expectEqualStrings(
        "https://registry.example.io/v2/myrepo/blobs/uploads/uuid-123",
        location,
    );
}

test "parseLocationHeader — relative URL gets host prepended" {
    const response_bytes = "HTTP/1.1 202 Accepted\r\n" ++
        "Location: /v2/myrepo/blobs/uploads/uuid-456\r\n" ++
        "Content-Length: 0\r\n\r\n";

    var location_buf: [8192]u8 = undefined;
    const head = std.http.Client.Response.Head.parse(response_bytes) catch unreachable;
    const location = parseLocationHeader("registry.example.io", head, &location_buf).?;
    try std.testing.expectEqualStrings(
        "https://registry.example.io/v2/myrepo/blobs/uploads/uuid-456",
        location,
    );
}

test "parseLocationHeader — missing header returns null" {
    const response_bytes = "HTTP/1.1 202 Accepted\r\n" ++
        "Content-Length: 0\r\n\r\n";

    var location_buf: [8192]u8 = undefined;
    const head = std.http.Client.Response.Head.parse(response_bytes) catch unreachable;
    try std.testing.expect(parseLocationHeader("registry.example.io", head, &location_buf) == null);
}

test "parseLocationHeader keeps locations after response storage is reused" {
    var response_bytes = ("HTTP/1.1 202 Accepted\r\n" ++
        "Location: https://registry.example.io/upload?id=123\r\n" ++
        "Content-Length: 0\r\n\r\n").*;
    const head = try std.http.Client.Response.Head.parse(&response_bytes);
    var location_buf: [128]u8 = undefined;
    const location = parseLocationHeader("registry.example.io", head, &location_buf).?;
    @memset(&response_bytes, 'x');
    try std.testing.expectEqualStrings("https://registry.example.io/upload?id=123", location);
}

test "parseLocationHeader keeps concurrent locations in separate caller buffers" {
    const head = try std.http.Client.Response.Head.parse("HTTP/1.1 202 Accepted\r\nLocation: /upload\r\n\r\n");
    var first_buf: [128]u8 = undefined;
    var second_buf: [128]u8 = undefined;
    const first = parseLocationHeader("first.example.io", head, &first_buf).?;
    const second = parseLocationHeader("second.example.io", head, &second_buf).?;
    try std.testing.expectEqualStrings("https://first.example.io/upload", first);
    try std.testing.expectEqualStrings("https://second.example.io/upload", second);
}

test "parseLocationHeader rejects locations that do not fit caller storage" {
    for ([_][]const u8{
        "HTTP/1.1 202 Accepted\r\nLocation: https://registry.example.io/upload\r\n\r\n",
        "HTTP/1.1 202 Accepted\r\nLocation: /upload\r\n\r\n",
    }) |response_bytes| {
        const head = try std.http.Client.Response.Head.parse(response_bytes);
        var buf: [4]u8 = undefined;
        try std.testing.expect(parseLocationHeader("registry.example.io", head, &buf) == null);
    }
}
