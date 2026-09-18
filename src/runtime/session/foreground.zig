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

/// A foreground exec owns its process. Disconnect closes pipe stdin; terminal
/// detach keys are reserved for the durable supervisor client.
pub fn run(channels: *process_io.ProcessIo, pid: posix.pid_t) !u8 {
    const signals = Signals.install(pid);
    defer signals.deinit();
    const raw = if (channels.tty and channels.interactive) terminal.Raw.enter(posix.STDIN_FILENO) catch null else null;
    defer if (raw) |value| value.deinit();
    var stdin_open = channels.interactive;
    var buffer: [protocol.max_payload]u8 = undefined;
    var result: ?u8 = null;
    while (true) {
        var polls = [_]linux.pollfd{
            .{ .fd = if (stdin_open) posix.STDIN_FILENO else -1, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = channels.stdout, .events = linux.POLL.IN, .revents = 0 },
            .{ .fd = channels.stderr, .events = linux.POLL.IN, .revents = 0 },
        };
        const rc = linux.poll(&polls, polls.len, 100);
        if (linux.errno(rc) != .SUCCESS and linux.errno(rc) != .INTR) return error.PollFailed;
        var saw_output = false;
        for (polls[1..], 0..) |poll, stream| {
            if (poll.fd < 0 or poll.revents == 0) continue;
            const count = platform.read(poll.fd, &buffer) catch 0; // A closed PTY returns EIO.
            if (count == 0) {
                if (stream == 0) process_io.close(&channels.stdout) else process_io.close(&channels.stderr);
            } else {
                saw_output = true;
                try writeAll(if (stream == 0) posix.STDOUT_FILENO else posix.STDERR_FILENO, buffer[0..count]);
            }
        }
        if (stdin_open and polls[0].revents != 0) {
            const count = try platform.read(posix.STDIN_FILENO, &buffer);
            if (count == 0) {
                stdin_open = false;
                if (channels.tty) {
                    try writeAll(channels.input, "\x04");
                } else process_io.close(&channels.input);
            } else writeAll(channels.input, buffer[0..count]) catch {
                stdin_open = false;
                process_io.close(&channels.input);
            };
        }
        if (channels.tty) if (terminal.size(posix.STDIN_FILENO)) |size| terminal.resize(channels.input, size);
        if (result == null) {
            const waited = try process.wait(pid, true);
            result = switch (waited.status) {
                .exited => |code| code,
                .signaled => |sig| @intCast(128 + sig),
                .running, .stopped => null,
            };
        }
        if (result) |code| {
            if (!saw_output) return code;
        }
    }
}
