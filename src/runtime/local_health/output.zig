const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const platform = @import("linux_platform").posix;

pub const max_bytes = 4096;
const drain_budget = 64 * 1024;

pub const Output = struct {
    bytes: [max_bytes]u8 = undefined,
    len: usize = 0,
    truncated: bool = false,

    pub fn text(self: *const Output) []const u8 {
        return self.bytes[0..self.len];
    }

    fn append(self: *Output, bytes: []const u8) void {
        const count = @min(bytes.len, self.bytes.len - self.len);
        @memcpy(self.bytes[self.len..][0..count], bytes[0..count]);
        self.len += count;
        self.truncated = self.truncated or count < bytes.len;
    }

    // arbitrary command bytes become valid utf-8 before storage or json output.
    // replacement characters also count toward the rendered diagnostic limit.
    fn utf8(self: *const Output) Output {
        var result: Output = .{ .truncated = self.truncated };
        var index: usize = 0;
        while (index < self.len) {
            const width = std.unicode.utf8ByteSequenceLength(self.bytes[index]) catch 0;
            const valid = width != 0 and index + width <= self.len and std.unicode.utf8ValidateSlice(self.bytes[index..][0..width]);
            const bytes = if (valid) self.bytes[index..][0..width] else "\xef\xbf\xbd";
            if (result.bytes.len - result.len < bytes.len) {
                result.truncated = true;
                break;
            }
            result.append(bytes);
            index += if (valid) width else 1;
        }
        return result;
    }
};

// capture owns both read ends. retained bytes are bounded independently from
// draining, so a noisy check can still exit or reach its cancellation deadline.
pub const Capture = struct {
    fds: [2]posix.fd_t = .{ -1, -1 },
    output: Output = .{},

    pub fn take(child: *std.process.Child) !Capture {
        var self: Capture = .{};
        if (child.stdout) |file| self.fds[0] = file.handle;
        if (child.stderr) |file| self.fds[1] = file.handle;
        child.stdout = null;
        child.stderr = null;
        errdefer self.deinit();
        for (self.fds) |fd| {
            if (fd < 0) continue;
            const flags = linux.fcntl(fd, linux.F.GETFL, 0);
            if (linux.errno(flags) != .SUCCESS) return error.OutputSetupFailed;
            const nonblocking = flags | @as(u32, @bitCast(linux.O{ .NONBLOCK = true }));
            if (linux.errno(linux.fcntl(fd, linux.F.SETFL, nonblocking)) != .SUCCESS) return error.OutputSetupFailed;
        }
        return self;
    }

    pub fn deinit(self: *Capture) void {
        for (&self.fds) |*fd| close(fd);
    }

    // each stream gets a budget so stdout cannot starve stderr or the next
    // ownership/deadline check. the wait below wakes immediately if more remains.
    pub fn drain(self: *Capture) !void {
        var buffer: [4096]u8 = undefined;
        for (&self.fds) |*fd| {
            var remaining: usize = drain_budget;
            var reads: usize = 0;
            while (fd.* >= 0 and remaining > 0 and reads < 16) : (reads += 1) {
                const count = platform.read(fd.*, buffer[0..@min(buffer.len, remaining)]) catch |err| switch (err) {
                    error.WouldBlock => break,
                    error.Interrupted => continue,
                    else => return err,
                };
                if (count == 0) {
                    close(fd);
                    break;
                }
                self.output.append(buffer[0..count]);
                remaining -= count;
            }
        }
    }

    pub fn wait(self: *const Capture, delay_ns: u64) void {
        var polls = [_]linux.pollfd{
            .{ .fd = self.fds[0], .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = self.fds[1], .events = linux.POLL.IN, .revents = 0 },
        };
        const milliseconds: i32 = @intCast(@min(std.math.divCeil(u64, delay_ns, std.time.ns_per_ms) catch 1, 50));
        _ = linux.poll(&polls, polls.len, milliseconds);
    }

    pub fn finish(self: *Capture) !Output {
        // cleanup has killed and reaped the writers. take one final bounded
        // batch; never wait for eof from a descriptor inherited elsewhere.
        try self.drain();
        if (self.fds[0] >= 0 or self.fds[1] >= 0) self.output.truncated = true;
        return self.output.utf8();
    }
};

fn close(fd: *posix.fd_t) void {
    if (fd.* < 0) return;
    platform.close(fd.*);
    fd.* = -1;
}

test "health output keeps valid utf8 within its rendered byte limit" {
    var raw: Output = .{};
    raw.append("ok\x00\xff\xe2");
    raw.append("\x82\xac\n");
    const text = raw.utf8();
    try std.testing.expectEqualStrings("ok\x00\xef\xbf\xbd\xe2\x82\xac\n", text.text());
    try std.testing.expect(!text.truncated);

    raw = .{};
    raw.append(&([_]u8{'x'} ** (max_bytes - 2)));
    raw.append("\xe2\x82\xac");
    const cut = raw.utf8();
    try std.testing.expect(cut.truncated);
    try std.testing.expectEqual(@as(usize, max_bytes - 2), cut.len);
    try std.testing.expect(std.unicode.utf8ValidateSlice(cut.text()));

    raw = .{};
    raw.append(&([_]u8{0xff} ** max_bytes));
    const expanded = raw.utf8();
    try std.testing.expect(expanded.truncated);
    try std.testing.expect(expanded.len <= max_bytes);
    try std.testing.expect(std.unicode.utf8ValidateSlice(expanded.text()));
}

test "health output drains both streams beyond its retained bytes" {
    const stdout = try platform.pipe();
    const stderr = try platform.pipe();
    var child: std.process.Child = .{
        .id = null,
        .thread_handle = {},
        .stdin = null,
        .stdout = .{ .handle = stdout[0], .flags = .{ .nonblocking = false } },
        .stderr = .{ .handle = stderr[0], .flags = .{ .nonblocking = false } },
        .request_resource_usage_statistics = false,
    };
    var capture = try Capture.take(&child);
    defer capture.deinit();
    const bytes = [_]u8{'x'} ** max_bytes;
    for (0..16) |_| {
        try std.testing.expectEqual(bytes.len, try platform.write(stdout[1], &bytes));
        try std.testing.expectEqual(bytes.len, try platform.write(stderr[1], &bytes));
        try capture.drain();
    }
    platform.close(stdout[1]);
    platform.close(stderr[1]);
    const result = try capture.finish();
    try std.testing.expect(result.truncated);
    try std.testing.expectEqual(@as(usize, max_bytes), result.len);
    try std.testing.expectEqual(@as(posix.fd_t, -1), capture.fds[0]);
    try std.testing.expectEqual(@as(posix.fd_t, -1), capture.fds[1]);
    try std.testing.expect(child.stdout == null and child.stderr == null);
}
