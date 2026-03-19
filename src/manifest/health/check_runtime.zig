const std = @import("std");
const posix = std.posix;
const types = @import("types.zig");

pub fn runCheck(container_ip: [4]u8, config: anytype) bool {
    return switch (config.check_type) {
        .http => |http| runHttpCheck(container_ip, http.port, http.path, config.timeout),
        .tcp => |tcp| runTcpCheck(container_ip, tcp.port, config.timeout),
        .exec => false,
    };
}

pub fn runHttpCheck(container_ip: [4]u8, port: u16, path: []const u8, timeout: u32) bool {
    const sock = tcpConnect(container_ip, port, timeout) orelse return false;
    defer posix.close(sock);

    var request_buf: [512]u8 = undefined;
    const request = std.fmt.bufPrint(
        &request_buf,
        "GET {s} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        .{path},
    ) catch return false;

    _ = posix.write(sock, request) catch return false;

    var response_buf: [256]u8 = undefined;
    const bytes_read = posix.read(sock, &response_buf) catch return false;
    if (bytes_read < 12) return false;

    return isHttp2xx(response_buf[0..bytes_read]);
}

pub fn isHttp2xx(response: []const u8) bool {
    if (response.len < 12) return false;
    if (!std.mem.startsWith(u8, response, "HTTP/1.")) return false;
    return response[9] == '2';
}

pub fn runTcpCheck(container_ip: [4]u8, port: u16, timeout: u32) bool {
    const sock = tcpConnect(container_ip, port, timeout) orelse return false;
    posix.close(sock);
    return true;
}

fn tcpConnect(container_ip: [4]u8, port: u16, timeout: u32) ?posix.socket_t {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch return null;
    errdefer posix.close(sock);

    const tv = posix.timeval{
        .sec = @intCast(timeout),
        .usec = 0,
    };
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};

    const addr = posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(container_ip),
    };

    posix.connect(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch return null;
    return sock;
}
