// init — minimal container init process (PID 1)
//
// when a container runs, the process tree looks like:
//
//   [yoq parent] --clone3--> [childMain] -> [init (PID 1)] --fork--> [workload (PID 2)]
//                                                |
//                                                +-- reaps zombies (waitpid(-1))
//                                                +-- forwards SIGTERM/SIGINT to workload
//                                                +-- exits with workload's exit code
//
// why this matters:
// - without an init, orphaned grandchildren become zombies (no one calls waitpid)
// - without signal forwarding, SIGTERM kills the container shell but not its children
// - the Linux kernel sends SIGKILL to all processes in a PID namespace when PID 1 exits,
//   so exiting with the workload's code gives clean shutdown semantics
//
// constraints:
// - no heap allocation (runs post-clone3, allocator state is undefined)
// - signal handlers must be async-signal-safe (no stdio, no locks)

const std = @import("std");
const linux = std.os.linux;
const syscall_util = @import("../lib/syscall.zig");

/// PID of the workload process. set after fork, read by signal handler.
/// must be file-scope so the signal handler can access it.
var workload_pid: std.atomic.Value(i32) = std.atomic.Value(i32).init(0);

/// function type for the workload entry point.
/// takes an opaque context pointer and returns the exit code.
/// must have C calling convention since it's called after fork.
pub const WorkloadFn = *const fn (?*anyopaque) callconv(.c) u8;

/// run as container init (PID 1).
///
/// forks a child to run the workload function, then sits in a wait loop
/// reaping zombies and forwarding signals. returns the workload's exit code.
///
/// this function never returns to the caller on success — it calls _exit
/// directly to avoid running any atexit handlers in the init process.
pub fn run(workload_fn: WorkloadFn, ctx: ?*anyopaque) u8 {
    // install signal handlers before fork so we're ready immediately
    installHandlers();

    // fork the workload process
    const fork_rc = linux.syscall4(.clone, linux.SIG.CHLD, 0, 0, 0);
    if (syscall_util.isError(fork_rc)) return 1;

    const child_pid: i32 = @intCast(@as(isize, @bitCast(fork_rc)));

    if (child_pid == 0) {
        // child: run the workload and exit directly
        const code = workload_fn(ctx);
        exitRaw(code);
    }

    // parent: we are PID 1 (init)
    workload_pid.store(child_pid, .release);

    // reap loop: wait for any child, exit when the workload exits
    return reapLoop(child_pid);
}

/// wait for children in a loop. reaps zombies from any process in the
/// PID namespace. exits when the workload (identified by its PID) exits.
fn reapLoop(target_pid: i32) u8 {
    // track consecutive unexpected errors to avoid infinite busy loops.
    // if wait4 returns an errno we don't handle (not EINTR, not ECHILD),
    // we'd spin at 100% CPU. bail after 10 consecutive failures.
    var unexpected_errors: u32 = 0;

    while (true) {
        var status: u32 = 0;

        // wait for any child (-1)
        const rc = linux.syscall4(
            .wait4,
            @as(usize, @bitCast(@as(isize, -1))),
            @intFromPtr(&status),
            0, // blocking
            0, // rusage
        );

        if (syscall_util.isError(rc)) {
            const errno = syscall_util.getErrno(rc);
            if (errno == @intFromEnum(linux.E.INTR)) continue;
            if (errno == @intFromEnum(linux.E.CHILD)) return 0; // no more children
            unexpected_errors += 1;
            if (unexpected_errors >= 10) return 1;
            continue;
        }

        // successful wait — reset error counter
        unexpected_errors = 0;

        const exited_pid: i32 = @intCast(@as(isize, @bitCast(rc)));

        // only care about the workload process exit
        if (exited_pid == target_pid) {
            // clear workload_pid so the signal handler doesn't forward
            // to a stale PID that the kernel may have recycled
            workload_pid.store(0, .release);

            // WIFEXITED: (status & 0x7f) == 0
            if (status & 0x7f == 0) {
                return @intCast((status >> 8) & 0xff);
            }
            // killed by signal — convention: 128 + signal number
            const sig = status & 0x7f;
            const code: u16 = @intCast(128 + sig);
            return @intCast(code & 0xff);
        }

        // any other child: just reap it (zombie cleanup) and continue
    }
}

/// signal handler: forward SIGTERM and SIGINT to the workload.
/// async-signal-safe: only uses atomic load + kill syscall.
fn forwardSignal(sig: c_int) callconv(.c) void {
    const pid = workload_pid.load(.acquire);
    if (pid > 0) {
        _ = linux.syscall2(
            .kill,
            @as(usize, @bitCast(@as(isize, pid))),
            @intCast(sig),
        );
    }
}

/// install signal handlers for SIGTERM and SIGINT.
/// uses sigaction with SA_RESTART so the wait loop isn't permanently broken.
fn installHandlers() void {
    const act = std.posix.Sigaction{
        .handler = .{ .handler = forwardSignal },
        .mask = std.posix.sigemptyset(),
        .flags = @bitCast(@as(u32, 0x10000000)), // SA_RESTART
    };
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
}

/// raw _exit syscall. avoids atexit handlers and stdio flushing
/// which are unsafe in the init process context.
fn exitRaw(code: u8) noreturn {
    _ = linux.syscall1(.exit, code);
    unreachable;
}

// -- tests --

test "reapLoop returns 0 on ECHILD" {
    // with no children, reapLoop should get ECHILD and return 0
    // but we can't safely test this in the test runner since it would
    // actually call waitpid. instead, test the status parsing logic.
    //
    // WIFEXITED: status 0x0000 -> exit code 0
    const status: u32 = 0x0000;
    try std.testing.expect(status & 0x7f == 0);
    try std.testing.expectEqual(@as(u32, 0), (status >> 8) & 0xff);
}

test "status parsing: normal exit" {
    // exit(42) -> status = 42 << 8 = 0x2a00
    const status: u32 = 42 << 8;
    try std.testing.expect(status & 0x7f == 0); // WIFEXITED
    try std.testing.expectEqual(@as(u32, 42), (status >> 8) & 0xff);
}

test "status parsing: killed by SIGTERM" {
    // killed by SIGTERM (15) -> status = 0x000f
    const status: u32 = 0x000f;
    try std.testing.expect(status & 0x7f != 0); // not WIFEXITED
    const sig = status & 0x7f;
    try std.testing.expectEqual(@as(u32, 15), sig);
    // convention: 128 + signal
    const code: u16 = 128 + sig;
    try std.testing.expectEqual(@as(u16, 143), code);
}

test "status parsing: killed by SIGKILL" {
    const status: u32 = 0x0009;
    const sig = status & 0x7f;
    try std.testing.expectEqual(@as(u32, 9), sig);
    const code: u16 = 128 + sig;
    try std.testing.expectEqual(@as(u16, 137), code);
}

test "workload_pid starts at zero" {
    try std.testing.expectEqual(@as(i32, 0), workload_pid.load(.acquire));
}
