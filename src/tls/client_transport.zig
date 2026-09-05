const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;

pub const Error = error{ TimedOut, ReadFailed, WriteFailed, UnexpectedEof };

/// One monotonic budget, shared across every syscall in an operation.
pub const Deadline = struct {
    expires_ns: i96,

    pub fn afterMilliseconds(ms: u32) Deadline {
        return .{ .expires_ns = now() + @as(i96, ms) * std.time.ns_per_ms };
    }

    fn now() i96 {
        return std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds();
    }

    pub fn remaining(self: Deadline) Error!i32 {
        const ns = self.expires_ns - now();
        if (ns <= 0) return error.TimedOut;
        return @intCast(@min(@divTrunc(ns + std.time.ns_per_ms - 1, std.time.ns_per_ms), std.math.maxInt(i32)));
    }
};

pub const Stream = struct {
    fd: posix.fd_t,
    deadline: ?Deadline = null,

    pub fn wait(self: Stream, events: i16) Error!void {
        while (true) {
            const timeout = if (self.deadline) |d| try d.remaining() else -1;
            var fds = [_]posix.pollfd{.{ .fd = self.fd, .events = events, .revents = 0 }};
            const ready = posix.poll(&fds, timeout) catch return error.ReadFailed;
            if (ready == 0) return error.TimedOut;
            if (fds[0].revents & (events | posix.POLL.HUP | posix.POLL.ERR) != 0) return;
            if (fds[0].revents & posix.POLL.NVAL != 0) return error.ReadFailed;
        }
    }

    pub fn read(self: Stream, buf: []u8) Error!usize {
        while (true) {
            if (self.deadline) |d| _ = try d.remaining();
            return linux_platform.posix.recv(self.fd, buf, posix.MSG.DONTWAIT) catch |err| switch (err) {
                error.WouldBlock => {
                    try self.wait(posix.POLL.IN);
                    continue;
                },
                else => return error.ReadFailed,
            };
        }
    }

    pub fn write(self: Stream, bytes: []const u8) Error!usize {
        while (true) {
            if (self.deadline) |d| _ = try d.remaining();
            return linux_platform.posix.send(self.fd, bytes, posix.MSG.DONTWAIT | posix.MSG.NOSIGNAL) catch |err| switch (err) {
                error.WouldBlock => {
                    try self.wait(posix.POLL.OUT);
                    continue;
                },
                else => return error.WriteFailed,
            };
        }
    }

    pub fn writeAll(self: Stream, bytes: []const u8) Error!void {
        try writeAllWith(self, bytes);
    }
};

pub fn stream(value: anytype) Stream {
    return if (@TypeOf(value) == Stream) value else .{ .fd = value };
}

fn writeAllWith(writer: anytype, bytes: []const u8) Error!void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const n = try writer.write(bytes[sent..]);
        if (n == 0) return error.WriteFailed;
        sent += n;
    }
}

test "TLS transport completes short writes and stops on incomplete records" {
    const Writer = struct {
        bytes: [32]u8 = undefined,
        len: usize = 0,
        fail_at: ?usize = null,
        fn write(self: *@This(), data: []const u8) Error!usize {
            if (self.fail_at) |limit| if (self.len >= limit) return error.TimedOut;
            const n = @min(data.len, 3);
            @memcpy(self.bytes[self.len..][0..n], data[0..n]);
            self.len += n;
            return n;
        }
    };
    var writer = Writer{};
    try writeAllWith(&writer, "complete TLS record");
    try std.testing.expectEqualStrings("complete TLS record", writer.bytes[0..writer.len]);
    var failing = Writer{ .fail_at = 6 };
    try std.testing.expectError(error.TimedOut, writeAllWith(&failing, "incomplete TLS record"));
    try std.testing.expectEqualStrings("incomp", failing.bytes[0..failing.len]);
}
