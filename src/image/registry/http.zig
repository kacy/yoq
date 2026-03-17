const std = @import("std");
const common = @import("common.zig");

const posix = std.posix;

pub fn connectWithTimeout(
    client: *std.http.Client,
    uri: std.Uri,
) !*std.http.Client.Connection {
    const protocol = std.http.Client.Protocol.fromUri(uri) orelse
        return error.UnsupportedUriScheme;
    var host_buf: [std.Uri.host_name_max]u8 = undefined;
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
    const stream = conn.stream_reader.getStream();
    const tv = posix.timeval{ .sec = common.registry_timeout_sec, .usec = 0 };
    const opt_bytes = std.mem.asBytes(&tv);
    posix.setsockopt(stream.handle, posix.SOL.SOCKET, posix.SO.RCVTIMEO, opt_bytes) catch {};
    posix.setsockopt(stream.handle, posix.SOL.SOCKET, posix.SO.SNDTIMEO, opt_bytes) catch {};
}
