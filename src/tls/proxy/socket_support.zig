const std = @import("std");
const posix = std.posix;
const backend_mod = @import("../backend.zig");

pub fn createListenSocket(port: u16) !posix.fd_t {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);
    errdefer posix.close(fd);

    const reuseaddr: i32 = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuseaddr)) catch {};

    const addr = posix.sockaddr.in{
        .port = std.mem.nativeTo(u16, port, .big),
        .addr = 0,
    };

    try posix.bind(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
    try posix.listen(fd, 128);

    return fd;
}

pub fn connectToBackend(backend: backend_mod.Backend) !posix.fd_t {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);

    const ip_addr = parseIpv4(backend.ip) orelse return error.InvalidBackendAddress;

    const addr = posix.sockaddr.in{
        .port = std.mem.nativeTo(u16, backend.port, .big),
        .addr = ip_addr,
    };

    posix.connect(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch
        return error.BackendConnectFailed;

    return fd;
}

pub fn parseIpv4(ip: []const u8) ?u32 {
    var parts: [4]u8 = undefined;
    var part_idx: usize = 0;
    var current: u16 = 0;
    var has_digit = false;

    for (ip) |c| {
        if (c == '.') {
            if (!has_digit or part_idx >= 3) return null;
            if (current > 255) return null;
            parts[part_idx] = @intCast(current);
            part_idx += 1;
            current = 0;
            has_digit = false;
        } else if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
            has_digit = true;
        } else {
            return null;
        }
    }

    if (!has_digit or part_idx != 3) return null;
    if (current > 255) return null;
    parts[part_idx] = @intCast(current);

    return std.mem.bytesToValue(u32, &parts);
}

pub fn readWithTimeout(fd: posix.fd_t, buf: []u8, timeout_ms: i32) !usize {
    const tv = posix.timeval{
        .sec = @divTrunc(timeout_ms, 1000),
        .usec = @rem(timeout_ms, 1000) * 1000,
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};

    return posix.read(fd, buf) catch return error.ReadFailed;
}
