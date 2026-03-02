// process — process supervision and management for containers
//
// handles waiting on child processes, detecting exits, and
// reparenting. the container's init process is the one we
// spawned via clone3(), and we monitor it here.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

pub const ProcessError = error{
    WaitFailed,
    KillFailed,
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
    /// process is still running
    running,
};

/// wait for a specific process to change state.
/// returns immediately if the process has already exited.
/// if `no_hang` is true, returns `.running` if still alive.
pub fn wait(pid: posix.pid_t, no_hang: bool) ProcessError!WaitResult {
    var status: u32 = 0;
    var flags: u32 = 0;
    if (no_hang) flags |= 1; // WNOHANG

    const rc = linux.syscall4(
        .wait4,
        @as(usize, @bitCast(@as(isize, pid))),
        @intFromPtr(&status),
        flags,
        0, // rusage
    );

    const result_pid: isize = @bitCast(rc);
    if (result_pid < 0) return ProcessError.WaitFailed;

    // WNOHANG and process hasn't changed state
    if (result_pid == 0) {
        return .{ .pid = pid, .status = .running };
    }

    return .{
        .pid = @intCast(result_pid),
        .status = parseStatus(status),
    };
}

/// send a signal to a process.
pub fn sendSignal(pid: posix.pid_t, sig: u32) ProcessError!void {
    const rc = linux.syscall2(
        .kill,
        @as(usize, @bitCast(@as(isize, pid))),
        sig,
    );
    const signed: isize = @bitCast(rc);
    if (signed < 0) return ProcessError.KillFailed;
}

/// send SIGTERM, giving the process a chance to clean up.
pub fn terminate(pid: posix.pid_t) ProcessError!void {
    return sendSignal(pid, 15); // SIGTERM
}

/// send SIGKILL, forcing immediate termination.
pub fn kill(pid: posix.pid_t) ProcessError!void {
    return sendSignal(pid, 9); // SIGKILL
}

/// parse the raw status value from wait4.
/// follows the waitpid(2) status macros.
fn parseStatus(status: u32) ExitStatus {
    // WIFEXITED: (status & 0x7f) == 0
    if (status & 0x7f == 0) {
        // WEXITSTATUS: (status >> 8) & 0xff
        return .{ .exited = @intCast((status >> 8) & 0xff) };
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
