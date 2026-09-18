const std = @import("std");
const runtime_wait = @import("../lib/runtime_wait.zig");

pub const Cancellation = struct {
    flag: *const std.atomic.Value(bool),
    when: bool = true,
    shutdown: ?*const std.atomic.Value(bool) = null,

    pub fn requested(self: Cancellation) bool {
        return self.flag.load(.acquire) == self.when or
            (if (self.shutdown) |flag| flag.load(.acquire) else false);
    }
};

pub const grace_ns = 2 * std.time.ns_per_s;

/// the caller owns the child until it is reaped. cancellation first gives it
/// time to exit, then kills it so normal container cleanup can finish.
pub fn wait(child: anytype, cancellation: ?Cancellation) u8 {
    return waitWithGrace(child, cancellation, grace_ns);
}

fn waitWithGrace(child: anytype, cancellation: ?Cancellation, grace: i96) u8 {
    var deadline: ?i96 = null;
    while (true) {
        child.poll() catch {};
        if (child.status != .running) return child.exit_code orelse 255;
        const now = std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds();
        if (deadline) |until| {
            if (now >= until) {
                child.forceStop() catch {};
                return child.wait() catch 255;
            }
        } else if (if (cancellation) |token| token.requested() else false) {
            child.stop() catch {};
            deadline = now + grace;
        }
        if (!runtime_wait.sleep(.fromMilliseconds(20), "waiting for workload exit")) {
            child.forceStop() catch {};
            return child.wait() catch 255;
        }
    }
}

const TestChild = struct {
    pid: std.posix.pid_t,
    fd: std.posix.fd_t,
    status: enum { running, stopped } = .running,
    exit_code: ?u8 = null,
    term_sent: bool = false,
    killed: bool = false,
    cleaned: bool = false,

    fn init() !TestChild {
        const linux = std.os.linux;
        const forked = linux.fork();
        if (linux.errno(forked) != .SUCCESS) return error.ForkFailed;
        if (forked == 0) {
            const action = std.posix.Sigaction{ .handler = .{ .handler = std.posix.SIG.IGN }, .mask = std.posix.sigemptyset(), .flags = 0 };
            std.posix.sigaction(std.posix.SIG.TERM, &action, null);
            _ = linux.kill(linux.getpid(), .STOP);
            while (true) _ = linux.syscall0(.pause);
        }
        const pid: std.posix.pid_t = @intCast(forked);
        const fd = linux.pidfd_open(pid, 0);
        if (linux.errno(fd) != .SUCCESS) {
            _ = linux.kill(pid, .KILL);
            _ = @import("../runtime/process.zig").waitForExit(pid) catch {};
            return error.PidFdFailed;
        }
        var child: TestChild = .{ .pid = pid, .fd = @intCast(fd) };
        errdefer child.deinit();
        var status: u32 = 0;
        if (linux.errno(linux.wait4(pid, &status, linux.W.UNTRACED, null)) != .SUCCESS) return error.WaitFailed;
        _ = linux.pidfd_send_signal(child.fd, .CONT, null, 0);
        return child;
    }

    fn deinit(self: *TestChild) void {
        _ = std.os.linux.pidfd_send_signal(self.fd, .KILL, null, 0);
        if (!self.cleaned) _ = @import("../runtime/process.zig").waitForExit(self.pid) catch {};
        _ = std.os.linux.close(self.fd);
    }

    pub fn poll(self: *TestChild) !void {
        const result = try @import("../runtime/process.zig").wait(self.pid, true);
        switch (result.status) {
            .exited => |code| self.finish(code),
            .signaled => self.finish(128),
            .running, .stopped => {},
        }
    }

    fn finish(self: *TestChild, code: u8) void {
        self.status = .stopped;
        self.exit_code = code;
        self.cleaned = true;
    }

    pub fn stop(self: *TestChild) !void {
        self.term_sent = true;
        _ = std.os.linux.pidfd_send_signal(self.fd, .TERM, null, 0);
    }

    pub fn forceStop(self: *TestChild) !void {
        self.killed = true;
        _ = std.os.linux.pidfd_send_signal(self.fd, .KILL, null, 0);
    }

    pub fn wait(self: *TestChild) !u8 {
        const result = try @import("../runtime/process.zig").waitForExit(self.pid);
        const code: u8 = switch (result.status) {
            .exited => |code| code,
            .signaled => 128,
            else => unreachable,
        };
        self.finish(code);
        return code;
    }
};

test "child wait cancels an active cron and reaps a term ignoring process" {
    var child = try TestChild.init();
    defer child.deinit();
    var scheduler = try @import("cron_scheduler.zig").CronScheduler.init(std.testing.allocator, &.{}, &.{}, "cancel-test");
    defer scheduler.deinit();
    scheduler.running.store(true, .release);
    const Cron = struct {
        fn run(active: *TestChild, flag: *const std.atomic.Value(bool)) void {
            _ = waitWithGrace(active, .{ .flag = flag, .when = false }, 40 * std.time.ns_per_ms);
        }
    };
    scheduler.thread = try std.Thread.spawn(.{}, Cron.run, .{ &child, &scheduler.running });
    scheduler.stop();
    try std.testing.expect(scheduler.thread == null);
    try std.testing.expect(child.term_sent);
    try std.testing.expect(child.killed);
    try std.testing.expect(child.cleaned);
    try std.testing.expectEqual(@as(?u8, 128), child.exit_code);
}

test "service shutdown cancels every replica before joining and reaps stubborn children" {
    const orchestration = @import("orchestrator.zig");
    const spec = @import("spec.zig");
    var children = [_]TestChild{ try TestChild.init(), try TestChild.init() };
    defer for (&children) |*child| child.deinit();
    const services = [_]spec.Service{.{ .name = "service", .image = "scratch", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{}, .replicas = 2 }};
    var states = [_]orchestration.ServiceState{
        .{ .container_id = "canceltest01".*, .status = .running, .thread = null },
        .{ .container_id = "canceltest02".*, .status = .pending, .thread = null },
    };
    const Fixture = struct { manifest: struct { services: []const spec.Service }, states: []orchestration.ServiceState };
    var fixture: Fixture = .{ .manifest = .{ .services = &services }, .states = &states };
    const Worker = struct {
        fn run(child: *TestChild, state: *orchestration.ServiceState) void {
            _ = waitWithGrace(child, .{ .flag = &state.stop_requested }, 40 * std.time.ns_per_ms);
        }
    };
    for (&children, &states) |*child, *state| state.thread = try std.Thread.spawn(.{}, Worker.run, .{ child, state });
    @import("orchestrator/lifecycle_support.zig").stopServiceInstances(&fixture, 0);
    for (children, &states) |child, *state| {
        try std.testing.expect(child.term_sent and child.killed and child.cleaned);
        try std.testing.expectEqual(orchestration.ServiceState.Status.stopped, state.getStatus());
        try std.testing.expect(state.thread == null);
    }
}
