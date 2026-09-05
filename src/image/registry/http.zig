const std = @import("std");
const common = @import("common.zig");

const posix = std.posix;

pub fn connectWithTimeout(
    client: *std.http.Client,
    uri: std.Uri,
) !*std.http.Client.Connection {
    const protocol = std.http.Client.Protocol.fromUri(uri) orelse
        return error.UnsupportedUriScheme;
    var host_buf: [255]u8 = undefined;
    const host_name = uri.getHost(&host_buf) catch return error.NetworkError;
    const default_port: u16 = if (protocol == .tls) 443 else 80;
    const port = uri.port orelse default_port;

    const conn = client.connectTcp(host_name, port, protocol) catch
        return error.NetworkError;
    setSocketTimeouts(conn);
    return conn;
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
