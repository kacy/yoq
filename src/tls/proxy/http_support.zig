const std = @import("std");
const posix = std.posix;

pub fn extractHost(request: []const u8) ?[]const u8 {
    const marker = "Host: ";
    const pos = std.mem.indexOf(u8, request, marker) orelse {
        const lower = "host: ";
        const lpos = std.mem.indexOf(u8, request, lower) orelse return null;
        const start = lpos + lower.len;
        const end = std.mem.indexOfPos(u8, request, start, "\r") orelse request.len;
        const host = request[start..end];
        return if (host.len > 0) host else null;
    };
    const start = pos + marker.len;
    const end = std.mem.indexOfPos(u8, request, start, "\r") orelse request.len;
    const host = request[start..end];
    return if (host.len > 0) host else null;
}

pub fn sendCloseNotify(fd: posix.fd_t) void {
    const close_notify = [_]u8{
        0x15,
        0x03,
        0x03,
        0x00,
        0x02,
        0x01,
        0x00,
    };
    _ = posix.write(fd, &close_notify) catch {};
}

pub fn sendHttpResponse(fd: posix.fd_t, status: []const u8, body: []const u8) void {
    var buf: [512]u8 = undefined;
    const response = std.fmt.bufPrint(&buf, "HTTP/1.1 {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status, body.len, body }) catch return;
    _ = posix.write(fd, response) catch {};
}
