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

/// probe a pooled, idle upstream socket without consuming any data.
///
/// returns true when the socket still looks reusable: nothing is waiting to be
/// read and the peer has not closed. returns false when the peer sent a FIN
/// (recv == 0), when unexpected bytes are already queued (a desynced
/// connection we must not reuse), or on any socket error. callers discard the
/// connection on false rather than handing it back out.
pub fn peekConnAlive(fd: linux_platform.posix.socket_t) bool {
    var probe: [1]u8 = undefined;
    const flags = posix.MSG.PEEK | posix.MSG.DONTWAIT;
    _ = linux_platform.posix.recv(fd, &probe, flags) catch |err| switch (err) {
        // nothing to read: a healthy connection sitting idle.
        error.WouldBlock => return true,
        // reset or anything unexpected: treat as dead.
        else => return false,
    };
    // a successful peek means either the peer closed (recv == 0) or stale bytes
    // are queued from a previous exchange (recv > 0). neither is safe to reuse.
    return false;
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

fn testConnectedPair() ![2]i32 {
    var fds: [2]i32 = undefined;
    const rc = std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SkipZigTest;
    return fds;
}

test "peekConnAlive reports an idle connection as reusable" {
    const fds = try testConnectedPair();
    defer linux_platform.posix.close(fds[0]);
    defer linux_platform.posix.close(fds[1]);

    try std.testing.expect(peekConnAlive(fds[0]));
}

test "peekConnAlive rejects a connection with queued bytes" {
    const fds = try testConnectedPair();
    defer linux_platform.posix.close(fds[0]);
    defer linux_platform.posix.close(fds[1]);

    try writeAll(fds[1], "leftover");
    try std.testing.expect(!peekConnAlive(fds[0]));
}

test "peekConnAlive rejects a connection whose peer has closed" {
    const fds = try testConnectedPair();
    defer linux_platform.posix.close(fds[0]);

    linux_platform.posix.close(fds[1]);
    try std.testing.expect(!peekConnAlive(fds[0]));
}
