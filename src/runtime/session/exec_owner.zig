const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const process = @import("../process.zig");
const foreground = @import("foreground.zig");

var child_target = std.atomic.Value(i32).init(0);

fn cancel(_: linux.SIG) callconv(.c) void {
    const pid = child_target.load(.acquire);
    if (pid > 0) {
        // ordinary children inherit this group. the direct child is also
        // killed if cancellation arrived before it established its group.
        _ = linux.kill(-pid, .KILL);
        _ = linux.kill(pid, .KILL);
    }
}

pub const CancellationMask = struct {
    previous: posix.sigset_t,

    // block before fork so cancellation cannot take the helper's default
    // action before it has installed its handler and recorded the child.
    pub fn block() CancellationMask {
        var mask = posix.sigemptyset();
        posix.sigaddset(&mask, .USR2);
        var self: CancellationMask = undefined;
        posix.sigprocmask(posix.SIG.BLOCK, &mask, &self.previous);
        return self;
    }

    pub fn restore(self: CancellationMask) void {
        posix.sigprocmask(posix.SIG.SETMASK, &self.previous, null);
    }
};

pub fn installHelper(child: posix.pid_t, mask: CancellationMask) void {
    _ = foreground.Signals.install(child);
    child_target.store(child, .release);
    const action: posix.Sigaction = .{ .handler = .{ .handler = cancel }, .mask = posix.sigemptyset(), .flags = 0 };
    posix.sigaction(.USR2, &action, null);
    mask.restore();
}

pub fn parentHandle() !posix.fd_t {
    const fd = linux.pidfd_open(linux.getpid(), 0);
    if (linux.errno(fd) != .SUCCESS) return error.ParentHandleFailed;
    return @intCast(fd);
}

// setting credentials clears PDEATHSIG, so arm it again after identity setup.
// the pidfd closes the race where the helper died before prctl took effect.
pub fn armChild(parent: posix.fd_t) !void {
    if (linux.errno(linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @intFromEnum(linux.SIG.KILL), 0, 0, 0)) != .SUCCESS)
        return error.ParentWatchFailed;
    var poll = [_]linux.pollfd{.{ .fd = parent, .events = linux.POLL.IN, .revents = 0 }};
    const rc = linux.poll(&poll, 1, 0);
    if (linux.errno(rc) != .SUCCESS or poll[0].revents != 0) return error.ParentExited;
}

pub fn abort(helper: posix.pid_t) void {
    // the relay may already have reaped the helper before an output error.
    // do not signal a recycled PID in that case.
    if (!stillOwned(helper)) return;
    process.sendSignal(helper, linux.SIG.USR2) catch {};
    process.sendSignal(helper, linux.SIG.CONT) catch {};
    if (waitBounded(helper, 40)) return;
    process.kill(helper) catch {};
    _ = waitBounded(helper, 40);
}

fn stillOwned(pid: posix.pid_t) bool {
    const result = process.wait(pid, true) catch return false;
    return result.status == .running or result.status == .stopped;
}

fn waitBounded(pid: posix.pid_t, attempts: usize) bool {
    for (0..attempts) |_| {
        if (!stillOwned(pid)) return true;
        std.Io.sleep(std.Options.debug_io, .fromMilliseconds(25), .awake) catch break;
    }
    return false;
}

test "exec cancellation kills a term-ignoring child and reaps its helper" {
    const platform = @import("linux_platform").posix;
    const ready = try platform.pipe();
    defer platform.close(ready[0]);
    const mask = CancellationMask.block();
    const forked = linux.fork();
    if (linux.errno(forked) != .SUCCESS) {
        mask.restore();
        platform.close(ready[1]);
        return error.ForkFailed;
    }
    if (forked == 0) {
        platform.close(ready[0]);
        const parent = parentHandle() catch linux.exit_group(125);
        const child = linux.fork();
        if (linux.errno(child) != .SUCCESS) linux.exit_group(124);
        if (child == 0) {
            armChild(parent) catch linux.exit_group(123);
            mask.restore();
            if (linux.errno(linux.setpgid(0, 0)) != .SUCCESS) linux.exit_group(122);
            const ignored: posix.Sigaction = .{ .handler = .{ .handler = posix.SIG.IGN }, .mask = posix.sigemptyset(), .flags = 0 };
            posix.sigaction(.TERM, &ignored, null);
            const pid = linux.getpid();
            foreground.writeAll(ready[1], std.mem.asBytes(&pid)) catch linux.exit_group(121);
            while (true) _ = linux.pause();
        }
        platform.close(parent);
        platform.close(ready[1]);
        installHelper(@intCast(child), mask);
        _ = process.waitForExit(@intCast(child)) catch linux.exit_group(120);
        linux.exit_group(0);
    }
    mask.restore();
    platform.close(ready[1]);
    const helper: posix.pid_t = @intCast(forked);
    defer abort(helper);
    var poll = [_]linux.pollfd{.{ .fd = ready[0], .events = linux.POLL.IN, .revents = 0 }};
    try std.testing.expectEqual(@as(usize, 1), linux.poll(&poll, 1, 2000));
    var child: posix.pid_t = undefined;
    try std.testing.expectEqual(@sizeOf(posix.pid_t), try platform.read(ready[0], std.mem.asBytes(&child)));
    abort(helper);
    try std.testing.expect(process.hasExited(helper));
    try std.testing.expect(process.hasExited(child));
    try std.testing.expectError(error.WaitFailed, process.wait(helper, true));
}
