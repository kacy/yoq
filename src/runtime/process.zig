// process — process supervision and management for containers
//
// handles waiting on child processes, detecting exits, and
// reparenting. the container's init process is the one we
// spawned via clone3(), and we monitor it here.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const syscall_util = @import("../lib/syscall.zig");

pub const ProcessError = error{
    /// wait4 syscall failed (process may not exist or is not a child)
    WaitFailed,
    /// kill syscall failed when sending a signal to the process
    KillFailed,
    /// generic signal delivery failure
    SignalFailed,
};

/// result of waiting on a process
pub const WaitResult = struct {
    pid: posix.pid_t,
    status: ExitStatus,
};

/// how a process exited
pub const ExitStatus = union(enum) {
    /// process exited normally with this code
    exited: u8,
    /// process was killed by this signal
    signaled: u32,
    /// process was stopped (e.g., by SIGSTOP)
    stopped: u32,
    /// process is still running
    running,
};

/// wait for a specific process to change state.
/// returns immediately if the process has already exited.
/// if `no_hang` is true, returns `.running` if still alive.
/// retries automatically on EINTR (signal interrupted the wait),
/// up to a limit to prevent spinning under signal storms.
pub fn wait(pid: posix.pid_t, no_hang: bool) ProcessError!WaitResult {
    var status: u32 = 0;
    var flags: u32 = linux.W.UNTRACED; // report stopped children too
    if (no_hang) flags |= linux.W.NOHANG;

    const max_eintr_retries: u32 = 1000;
    var eintr_count: u32 = 0;

    while (eintr_count < max_eintr_retries) {
        const rc = linux.syscall4(
            .wait4,
            @as(usize, @bitCast(@as(isize, pid))),
            @intFromPtr(&status),
            flags,
            0, // rusage
        );

        if (syscall_util.isError(rc)) {
            if (syscall_util.getErrno(rc) == @intFromEnum(linux.E.INTR)) {
                eintr_count += 1;
                continue;
            }
            return ProcessError.WaitFailed;
        }

        const result_pid: isize = @bitCast(rc);

        // WNOHANG and process hasn't changed state
        if (result_pid == 0) {
            return .{ .pid = pid, .status = .running };
        }

        return .{
            .pid = @intCast(result_pid),
            .status = parseStatus(status),
        };
    }

    return ProcessError.WaitFailed;
}

/// send a signal to a process.
pub fn sendSignal(pid: posix.pid_t, sig: u32) ProcessError!void {
    const rc = linux.syscall2(
        .kill,
        @as(usize, @bitCast(@as(isize, pid))),
        sig,
    );
    if (syscall_util.isError(rc)) return ProcessError.KillFailed;
}

/// send SIGTERM, giving the process a chance to clean up.
pub fn terminate(pid: posix.pid_t) ProcessError!void {
    return sendSignal(pid, linux.SIG.TERM);
}

/// send SIGKILL, forcing immediate termination.
pub fn kill(pid: posix.pid_t) ProcessError!void {
    return sendSignal(pid, linux.SIG.KILL);
}

/// parse the raw status value from wait4.
/// follows the waitpid(2) status macros.
fn parseStatus(status: u32) ExitStatus {
    // WIFEXITED: (status & 0x7f) == 0
    if (status & 0x7f == 0) {
        // WEXITSTATUS: (status >> 8) & 0xff
        return .{ .exited = @intCast((status >> 8) & 0xff) };
    }

    // WIFSTOPPED: (status & 0xff) == 0x7f
    // Must check this BEFORE signaled because stopped status (0x7f) passes signaled check too
    if (status & 0xff == 0x7f) {
        // WSTOPSIG: (status >> 8) & 0xff
        const stop_sig = (status >> 8) & 0xff;
        return .{ .stopped = stop_sig };
    }

    // WIFSIGNALED: ((status & 0x7f) + 1) >> 1 > 0
    const sig = status & 0x7f;
    if (((sig + 1) >> 1) > 0) {
        return .{ .signaled = sig };
    }

    return .running;
}

// -- tests --

test "parse exit status: normal exit 0" {
    // exit(0) produces status 0x0000
    const result = parseStatus(0x0000);
    try std.testing.expectEqual(ExitStatus{ .exited = 0 }, result);
}

test "parse exit status: normal exit 1" {
    // exit(1) produces status 0x0100
    const result = parseStatus(0x0100);
    try std.testing.expectEqual(ExitStatus{ .exited = 1 }, result);
}

test "parse exit status: normal exit 42" {
    // exit(42) produces status (42 << 8)
    const result = parseStatus(42 << 8);
    try std.testing.expectEqual(ExitStatus{ .exited = 42 }, result);
}

test "parse exit status: killed by SIGKILL" {
    // SIGKILL (9) produces status 0x0009
    const result = parseStatus(0x0009);
    try std.testing.expectEqual(ExitStatus{ .signaled = 9 }, result);
}

test "parse exit status: killed by SIGTERM" {
    // SIGTERM (15) produces status 0x000f
    const result = parseStatus(0x000f);
    try std.testing.expectEqual(ExitStatus{ .signaled = 15 }, result);
}

test "parse exit status: stopped by SIGSTOP" {
    // stopped status: signal << 8 | 0x7f
    // SIGSTOP (19) stopped produces status 0x137f
    const result = parseStatus(0x137f);
    try std.testing.expectEqual(ExitStatus{ .stopped = 19 }, result);
}

test "parse exit status: stopped by SIGTSTP" {
    // SIGTSTP (20) stopped produces status 0x147f
    const result = parseStatus(0x147f);
    try std.testing.expectEqual(ExitStatus{ .stopped = 20 }, result);
}
