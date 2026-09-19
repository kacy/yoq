const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const platform = @import("linux_platform").posix;
const process = @import("../process.zig");
const process_io = @import("process_io.zig");
const terminal = @import("terminal.zig");
const protocol = @import("protocol.zig");

var signal_target = std.atomic.Value(i32).init(0);
fn forward(sig: linux.SIG) callconv(.c) void {
    if (sig == .PIPE) return;
    const pid = signal_target.load(.acquire);
    if (pid > 0) _ = linux.kill(pid, sig);
}

pub const Signals = struct {
    previous: [4]posix.Sigaction,
    const signals = [_]linux.SIG{ .INT, .TERM, .HUP, .PIPE };

    pub fn install(pid: posix.pid_t) Signals {
        var self: Signals = undefined;
        signal_target.store(pid, .release);
        const action: posix.Sigaction = .{ .handler = .{ .handler = forward }, .mask = posix.sigemptyset(), .flags = 0 };
        for (signals, 0..) |sig, i| posix.sigaction(sig, &action, &self.previous[i]);
        return self;
    }

    pub fn deinit(self: Signals) void {
        for (signals, 0..) |sig, i| posix.sigaction(sig, &self.previous[i], null);
        signal_target.store(0, .release);
    }
};

pub fn writeAll(fd: posix.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const written = platform.write(fd, bytes[offset..]) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };
        if (written == 0) return error.WriteFailed;
        offset += written;
    }
}

/// a foreground exec owns its process. disconnect closes pipe stdin; terminal
/// detach keys are reserved for the durable supervisor client.
pub fn run(channels: *process_io.ProcessIo, pid: posix.pid_t) !u8 {
    const signals = Signals.install(pid);
    defer signals.deinit();
    const raw = if (channels.tty and channels.interactive) terminal.Raw.enter(posix.STDIN_FILENO) catch null else null;
    defer if (raw) |value| value.deinit();
    var input = try PendingInput.init(channels);
    var buffer: [protocol.max_payload]u8 = undefined;
    var result: ?u8 = null;
    while (true) {
        var polls = [_]linux.pollfd{
            .{ .fd = if (input.canRead()) posix.STDIN_FILENO else -1, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = channels.stdout, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = channels.stderr, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = if (input.len > 0) channels.input else -1, .events = linux.POLL.OUT, .revents = 0 },
        };
        const rc = linux.poll(&polls, polls.len, 100);
        if (linux.errno(rc) != .SUCCESS and linux.errno(rc) != .INTR) return error.PollFailed;
        var saw_output = false;
        for (polls[1..3], 0..) |poll, stream| {
            if (poll.fd < 0 or poll.revents == 0) continue;
            const count = platform.read(poll.fd, &buffer) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => 0, // a closed pty returns EIO.
            };
            if (count == 0) {
                if (stream == 0) process_io.close(&channels.stdout) else process_io.close(&channels.stderr);
            } else {
                saw_output = true;
                try writeAll(if (stream == 0) posix.STDOUT_FILENO else posix.STDERR_FILENO, buffer[0..count]);
            }
        }
        if (input.open and polls[0].revents != 0) try input.readStdin(channels.tty);
        input.flush(channels);
        if (channels.tty) if (terminal.size(posix.STDIN_FILENO)) |size| terminal.resize(channels.input, size);
        if (result == null) {
            const waited = try process.wait(pid, true);
            result = switch (waited.status) {
                .exited => |code| code,
                .signaled => |sig| @intCast(128 + sig),
                .running, .stopped => null,
            };
            if (result != null) signal_target.store(0, .release);
        }
        if (result) |code| {
            if (!saw_output) return code;
        }
    }
}

// stdin is queued separately so a child can drain its output before it reads
// more input. the process channels own the fd; this buffer only owns bytes.
const PendingInput = struct {
    open: bool,
    eof: bool = false,
    bytes: [64 * 1024]u8 = undefined,
    len: usize = 0,

    fn init(channels: *process_io.ProcessIo) !PendingInput {
        if (channels.input >= 0) {
            const flags = linux.fcntl(channels.input, linux.F.GETFL, 0);
            if (linux.errno(flags) != .SUCCESS) return error.InputSetupFailed;
            const nonblocking = flags | @as(u32, @bitCast(linux.O{ .NONBLOCK = true }));
            if (linux.errno(linux.fcntl(channels.input, linux.F.SETFL, nonblocking)) != .SUCCESS)
                return error.InputSetupFailed;
        }
        return .{ .open = channels.interactive };
    }

    fn canRead(self: *const PendingInput) bool {
        return self.open and self.bytes.len - self.len >= protocol.max_payload;
    }

    fn readStdin(self: *PendingInput, tty: bool) !void {
        const count = try platform.read(posix.STDIN_FILENO, self.bytes[self.len..][0..protocol.max_payload]);
        self.len += count;
        if (count != 0) return;

        self.open = false;
        self.eof = true;
        if (tty) {
            // a terminal uses the EOF character; closing its master would
            // also discard the output we still need to read.
            self.bytes[self.len] = 4;
            self.len += 1;
        }
    }

    fn flush(self: *PendingInput, channels: *process_io.ProcessIo) void {
        if (self.len > 0 and channels.input >= 0) {
            const count = platform.write(channels.input, self.bytes[0..self.len]) catch |err| {
                if (err != error.WouldBlock and err != error.Interrupted) {
                    self.open = false;
                    self.len = 0;
                    process_io.close(&channels.input);
                }
                return;
            };
            std.mem.copyForwards(u8, &self.bytes, self.bytes[count..self.len]);
            self.len -= count;
        }
        // pipe EOF follows all queued bytes, including a final partial write.
        if (self.eof and self.len == 0 and !channels.tty) process_io.close(&channels.input);
    }
};

test "foreground relay drains output while a child delays reading large stdin" {
    const source = try platform.pipe();
    const sink = try platform.pipe();
    const relay_fork = linux.fork();
    if (linux.errno(relay_fork) != .SUCCESS) return error.ForkFailed;
    if (relay_fork == 0) {
        platform.close(source[1]);
        platform.close(sink[0]);
        platform.dup2(source[0], posix.STDIN_FILENO) catch linux.exit_group(125);
        platform.dup2(sink[1], posix.STDOUT_FILENO) catch linux.exit_group(124);
        platform.close(source[0]);
        platform.close(sink[1]);
        var channels = process_io.ProcessIo.init(true, false) catch linux.exit_group(123);
        const relay_pid = linux.getpid();
        const command_fork = linux.fork();
        if (linux.errno(command_fork) != .SUCCESS) linux.exit_group(122);
        if (command_fork == 0) {
            if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @intFromEnum(linux.SIG.KILL), 0, 0, 0)) != .SUCCESS or linux.getppid() != relay_pid)
                linux.exit_group(114);
            channels.applyChild() catch linux.exit_group(121);
            const output = [_]u8{'o'} ** 4096;
            for (0..64) |_| writeAll(posix.STDOUT_FILENO, &output) catch linux.exit_group(120);
            var input: [4096]u8 = undefined;
            var total: usize = 0;
            while (true) {
                const count = platform.read(posix.STDIN_FILENO, &input) catch linux.exit_group(119);
                if (count == 0) break;
                for (input[0..count]) |byte| if (byte != 'i') linux.exit_group(118);
                total += count;
            }
            linux.exit_group(if (total == 64 * 4096) 7 else 117);
        }
        channels.closeChild();
        const code = run(&channels, @intCast(command_fork)) catch linux.exit_group(116);
        channels.deinit();
        linux.exit_group(code);
    }
    platform.close(source[0]);
    platform.close(sink[1]);
    defer platform.close(sink[0]);
    const relay: posix.pid_t = @intCast(relay_fork);
    defer {
        process.kill(relay) catch {};
        _ = process.waitForExit(relay) catch {};
    }
    const feeder_fork = linux.fork();
    if (linux.errno(feeder_fork) != .SUCCESS) return error.ForkFailed;
    if (feeder_fork == 0) {
        platform.close(sink[0]);
        const input = [_]u8{'i'} ** 4096;
        for (0..64) |_| writeAll(source[1], &input) catch linux.exit_group(115);
        platform.close(source[1]);
        linux.exit_group(0);
    }
    platform.close(source[1]);
    const feeder: posix.pid_t = @intCast(feeder_fork);
    defer {
        process.kill(feeder) catch {};
        _ = process.waitForExit(feeder) catch {};
    }
    var total: usize = 0;
    var output: [4096]u8 = undefined;
    while (true) {
        var poll = [_]linux.pollfd{.{ .fd = sink[0], .events = linux.POLL.IN, .revents = 0 }};
        try std.testing.expectEqual(@as(usize, 1), linux.poll(&poll, 1, 2000));
        const count = try platform.read(sink[0], &output);
        if (count == 0) break;
        for (output[0..count]) |byte| try std.testing.expectEqual(@as(u8, 'o'), byte);
        total += count;
    }
    try std.testing.expectEqual(@as(usize, 64 * 4096), total);
    try std.testing.expectEqual(process.ExitStatus{ .exited = 7 }, (try process.waitForExit(relay)).status);
    try std.testing.expectEqual(process.ExitStatus{ .exited = 0 }, (try process.waitForExit(feeder)).status);
}
