const std = @import("std");
const posix = std.posix;

pub fn clampPollTimeout(timeout_ms: u32) i32 {
    return @intCast(@min(timeout_ms, @as(u32, @intCast(std.math.maxInt(i32)))));
}

pub fn waitForConnect(fd: posix.socket_t, timeout_ms: u32) !void {
    var poll_fds = [_]posix.pollfd{
        .{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 },
    };
    const timeout = clampPollTimeout(timeout_ms);
    const ready = posix.poll(&poll_fds, timeout) catch return error.ConnectFailed;
    if (ready == 0) return error.ConnectTimedOut;
    if (poll_fds[0].revents & posix.POLL.OUT == 0 and poll_fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP) == 0) {
        return error.ConnectFailed;
    }

    posix.getsockoptError(fd) catch |err| switch (err) {
        error.ConnectionTimedOut => return error.ConnectTimedOut,
        else => return error.ConnectFailed,
    };
}

pub fn setSocketBlocking(fd: posix.socket_t) !void {
    const flags = posix.fcntl(fd, posix.F.GETFL, 0) catch return error.ConnectFailed;
    const nonblock: usize = @intCast(@as(u32, @bitCast(posix.O{ .NONBLOCK = true })));
    _ = posix.fcntl(fd, posix.F.SETFL, flags & ~nonblock) catch return error.ConnectFailed;
}

pub fn setSocketTimeoutMs(fd: posix.socket_t, timeout_ms: u32) void {
    const tv = posix.timeval{
        .sec = @divTrunc(timeout_ms, 1000),
        .usec = @as(i64, @intCast(@rem(timeout_ms, 1000))) * 1000,
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};
}

pub fn writeAll(fd: posix.socket_t, data: []const u8) !void {
    var written: usize = 0;
    while (written < data.len) {
        const bytes_written = posix.write(fd, data[written..]) catch return error.WriteFailed;
        if (bytes_written == 0) return error.WriteFailed;
        written += bytes_written;
    }
}

test "clampPollTimeout clamps large values" {
    try std.testing.expectEqual(@as(i32, std.math.maxInt(i32)), clampPollTimeout(std.math.maxInt(u32)));
}

test "clampPollTimeout preserves small values" {
    try std.testing.expectEqual(@as(i32, 5000), clampPollTimeout(5000));
}
