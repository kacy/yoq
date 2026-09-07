const std = @import("std");
const common = @import("common.zig");

const posix = std.posix;

/// Let the HTTP client initialize its clock and system trust bundle before TLS.
/// Socket timeouts apply to subsequent request/response I/O, as before.
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

pub fn parseLocationHeader(host: []const u8, head: std.http.Client.Response.Head) ?[]const u8 {
    var it = head.iterateHeaders();
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "location")) continue;

        const value = header.value;
        if (value.len == 0) continue;

        if (std.mem.startsWith(u8, value, "http://") or
            std.mem.startsWith(u8, value, "https://"))
        {
            return value;
        }

        const static = struct {
            threadlocal var buf: [8192]u8 = undefined;
        };
        const full_url = std.fmt.bufPrint(&static.buf, "https://{s}{s}", .{ host, value }) catch
            return null;
        return full_url;
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

/// Stop before appending bytes beyond the cap, even when a response is
/// chunked or has no Content-Length. At most one extra byte is requested.
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
