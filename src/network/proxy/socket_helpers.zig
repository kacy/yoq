const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const ip = @import("../ip.zig");
const log = @import("../../lib/log.zig");
const upstream_mod = @import("upstream.zig");

pub fn clampPollTimeout(timeout_ms: u32) i32 {
    return @intCast(@min(timeout_ms, @as(u32, @intCast(std.math.maxInt(i32)))));
}

pub fn waitForConnect(fd: linux_platform.posix.socket_t, timeout_ms: u32) !void {
    var poll_fds = [_]posix.pollfd{
        .{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 },
    };
    const timeout = clampPollTimeout(timeout_ms);
    const ready = posix.poll(&poll_fds, timeout) catch return error.ConnectFailed;
    if (ready == 0) return error.ConnectTimedOut;
    if (poll_fds[0].revents & posix.POLL.OUT == 0 and poll_fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP) == 0) {
        return error.ConnectFailed;
    }

    linux_platform.posix.getsockoptError(fd) catch |err| switch (err) {
        error.ConnectionTimedOut => return error.ConnectTimedOut,
        else => return error.ConnectFailed,
    };
}

pub fn setSocketBlocking(fd: linux_platform.posix.socket_t) !void {
    const flags = linux_platform.posix.fcntl(fd, posix.F.GETFL, 0) catch return error.ConnectFailed;
    const nonblock: usize = @intCast(@as(u32, @bitCast(posix.O{ .NONBLOCK = true })));
    _ = linux_platform.posix.fcntl(fd, posix.F.SETFL, flags & ~nonblock) catch return error.ConnectFailed;
}

pub fn setSocketTimeoutMs(fd: linux_platform.posix.socket_t, timeout_ms: u32) void {
    const tv = posix.timeval{
        .sec = @divTrunc(timeout_ms, 1000),
        .usec = @as(i64, @intCast(@rem(timeout_ms, 1000))) * 1000,
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch |e| {
        log.warn("l7 proxy failed to set SO_RCVTIMEO: {}", .{e});
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch |e| {
        log.warn("l7 proxy failed to set SO_SNDTIMEO: {}", .{e});
    };
}

pub fn writeAll(fd: linux_platform.posix.socket_t, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const bytes_written = linux_platform.posix.write(fd, data[written..]) catch return error.WriteFailed;
        if (bytes_written == 0) return error.WriteFailed;
        written += bytes_written;
    }
}

pub fn connectToUpstream(connect_timeout_ms: u32, request_timeout_ms: u32, upstream: *const upstream_mod.Upstream) !linux_platform.posix.socket_t {
    const upstream_ip = ip.parseIp(upstream.address) orelse return error.InvalidUpstreamAddress;

    const fd = linux_platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0) catch
        return error.ConnectFailed;
    errdefer linux_platform.posix.close(fd);

    const addr = linux_platform.net.Address.initIp4(upstream_ip, upstream.port);
    linux_platform.posix.connect(fd, &addr.any, addr.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock, error.ConnectionPending => try waitForConnect(fd, connect_timeout_ms),
        error.ConnectionTimedOut => return error.ConnectTimedOut,
        else => return error.ConnectFailed,
    };
    try setSocketBlocking(fd);
    setSocketTimeoutMs(fd, request_timeout_ms);
    return fd;
}

test "clampPollTimeout clamps large values" {
    try std.testing.expectEqual(@as(i32, std.math.maxInt(i32)), clampPollTimeout(std.math.maxInt(u32)));
}

test "clampPollTimeout preserves small values" {
    try std.testing.expectEqual(@as(i32, 5000), clampPollTimeout(5000));
}
