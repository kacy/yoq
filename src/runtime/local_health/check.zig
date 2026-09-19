const std = @import("std");
const cgroups = @import("../cgroups.zig");
const process = @import("../process.zig");
const runtime_wait = @import("../../lib/runtime_wait.zig");

pub const Group = struct {
    cgroup: cgroups.Cgroup,

    pub fn create(id: []const u8, pid: i32, generation: i64, limits: cgroups.ResourceLimits) !Group {
        if (!@import("../container.zig").isValidContainerId(id)) return error.InvalidId;
        var group: Group = .{ .cgroup = .{ .path_buf = undefined, .path_len = 0 } };
        const path = try std.fmt.bufPrint(&group.cgroup.path_buf, "/sys/fs/cgroup/yoq/health-{s}-{d}-{d}", .{ id, generation, pid });
        group.cgroup.path_len = path.len;
        try std.Io.Dir.cwd().createDir(std.Options.debug_io, path, .default_dir);
        errdefer std.Io.Dir.cwd().deleteDir(std.Options.debug_io, path) catch {};
        // The check is a sibling so ordinary container teardown does not race
        // deletion of its cgroup. Apply the container's configured bounds here.
        try group.cgroup.setLimits(limits);
        return group;
    }

    pub fn cleanup(self: *const Group) !void {
        try self.cgroup.destroy();
    }
};

/// Call only with the container owner lock held and no active monitor. Recovery
/// removes groups left by a supervisor that could not run its normal cleanup.
pub fn cleanupOrphans(id: []const u8) !void {
    if (!@import("../container.zig").isValidContainerId(id)) return error.InvalidId;
    const io = std.Options.debug_io;
    var directory = std.Io.Dir.cwd().openDir(io, "/sys/fs/cgroup/yoq", .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer directory.close(io);
    var prefix_buffer: [32]u8 = undefined;
    const prefix = try std.fmt.bufPrint(&prefix_buffer, "health-{s}-", .{id});
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .directory or !std.mem.startsWith(u8, entry.name, prefix)) continue;
        var group: Group = .{ .cgroup = .{ .path_buf = undefined, .path_len = 0 } };
        const path = try std.fmt.bufPrint(&group.cgroup.path_buf, "/sys/fs/cgroup/yoq/{s}", .{entry.name});
        group.cgroup.path_len = path.len;
        try group.cleanup();
    }
}

pub const Outcome = union(enum) { exited: u8, timed_out, cancelled };

/// The injected runner owns the helper and all check descendants. Every return
/// path calls cleanup before returning the result to the monitor.
pub fn awaitCheck(runner: anytype, timeout_ns: u64) !Outcome {
    errdefer runner.cleanup() catch {};
    const deadline = runner.now() + @as(i96, timeout_ns);
    while (true) {
        if (runner.cancelled()) {
            try runner.cleanup();
            return .cancelled;
        }
        if (try runner.poll()) |code| {
            try runner.cleanup();
            return .{ .exited = code };
        }
        const remaining = @max(0, deadline - runner.now());
        if (remaining == 0) {
            try runner.cleanup();
            return .timed_out;
        }
        const delay: u64 = @intCast(@min(remaining, 50 * std.time.ns_per_ms));
        runner.sleep(delay);
    }
}

pub fn run(monitor: anytype, timeout_ns: u64) !Outcome {
    var helper_io = @import("../helper_io.zig").init();
    defer helper_io.deinit();
    const io = helper_io.io();
    var group = try Group.create(monitor.id, monitor.pid, monitor.generation, monitor.cfg.limits);
    var group_owned = true;
    defer if (group_owned) {
        group.cleanup() catch {
            monitor.failed_group = group;
        };
    };
    var exe_buffer: [4096]u8 = undefined;
    const exe_len = try std.Io.Dir.readLinkAbsolute(io, "/proc/self/exe", &exe_buffer);
    var pid_buffer: [32]u8 = undefined;
    var generation_buffer: [32]u8 = undefined;
    const pid = try std.fmt.bufPrint(&pid_buffer, "{d}", .{monitor.pid});
    const generation = try std.fmt.bufPrint(&generation_buffer, "{d}", .{monitor.generation});
    var child = try std.process.spawn(io, .{
        .argv = &.{ exe_buffer[0..exe_len], "__healthcheck", monitor.id, pid, generation },
        .stdin = .pipe,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer child.kill(io);
    const helper_pid = child.id.?;
    try group.cgroup.addProcess(helper_pid);
    // No check process can fork before its helper has joined the owned group.
    try child.stdin.?.writeStreamingAll(io, "1");
    child.stdin.?.close(io);
    child.stdin = null;
    const Runner = struct {
        owner: @TypeOf(monitor),
        helper: *std.process.Child,
        group: *Group,
        cleaned: bool = false,
        group_destroyed: bool = false,

        fn cancelled(self: *@This()) bool {
            return self.owner.cancelled.load(.acquire) or !self.owner.isCurrent() or self.owner.isPaused();
        }
        fn poll(self: *@This()) !?u8 {
            const current = self.helper.id orelse return null;
            const result = try process.wait(current, true);
            return switch (result.status) {
                .exited => |code| blk: {
                    self.helper.id = null;
                    break :blk code;
                },
                .signaled => |signal| blk: {
                    self.helper.id = null;
                    break :blk @intCast(@min(128 + signal, 255));
                },
                .running, .stopped => null,
            };
        }
        fn now(_: *@This()) i96 {
            return std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds();
        }
        fn sleep(_: *@This(), delay: u64) void {
            _ = runtime_wait.sleep(std.Io.Duration.fromNanoseconds(@intCast(delay)), "container healthcheck wait");
        }
        fn cleanup(self: *@This()) !void {
            if (self.cleaned) return;
            if (self.helper.id) |current| process.kill(current) catch {};
            // cgroup.kill also reaches children that change session or detach.
            if (!self.group_destroyed) {
                try self.group.cleanup();
                self.group_destroyed = true;
            }
            if (self.helper.id) |current| {
                _ = try process.waitForExit(current);
                self.helper.id = null;
            }
            self.cleaned = true;
        }
    };
    var runner: Runner = .{ .owner = monitor, .helper = &child, .group = &group };
    defer group_owned = !runner.group_destroyed;
    const outcome = try awaitCheck(&runner, timeout_ns);
    group_owned = !runner.group_destroyed;
    return outcome;
}

test "local health timeout and cancellation clean up every check" {
    const Fake = struct {
        remaining: usize = 3,
        cancel: bool = false,
        cleaned: bool = false,
        group_destroyed: bool = false,
        time: i96 = 0,
        fn now(self: *@This()) i96 {
            return self.time;
        }
        fn cancelled(self: *@This()) bool {
            return self.cancel;
        }
        fn poll(self: *@This()) !?u8 {
            return if (self.remaining == 0) @as(u8, 0) else null;
        }
        fn sleep(self: *@This(), delay: u64) void {
            self.remaining -= 1;
            self.time += delay;
        }
        fn cleanup(self: *@This()) !void {
            self.cleaned = true;
        }
    };
    var runner: Fake = .{};
    try std.testing.expectEqual(Outcome.timed_out, try awaitCheck(&runner, std.time.ns_per_ms));
    try std.testing.expect(runner.cleaned);
    runner = .{ .cancel = true };
    try std.testing.expectEqual(Outcome.cancelled, try awaitCheck(&runner, std.time.ns_per_s));
    try std.testing.expect(runner.cleaned);
    runner = .{ .remaining = 0 };
    try std.testing.expectEqual(Outcome{ .exited = 0 }, try awaitCheck(&runner, std.time.ns_per_s));
    try std.testing.expect(runner.cleaned);
}

test "local health polling failures clean up and cleanup failures propagate" {
    const Fake = struct {
        fail_poll: bool = false,
        cleanups: usize = 0,
        fn now(_: *@This()) i96 {
            return 0;
        }
        fn cancelled(_: *@This()) bool {
            return false;
        }
        fn poll(self: *@This()) !?u8 {
            if (self.fail_poll) return error.PollFailed;
            return 0;
        }
        fn sleep(_: *@This(), _: u64) void {}
        fn cleanup(self: *@This()) !void {
            self.cleanups += 1;
            if (!self.fail_poll) return error.CleanupFailed;
        }
    };
    var runner: Fake = .{ .fail_poll = true };
    try std.testing.expectError(error.PollFailed, awaitCheck(&runner, std.time.ns_per_s));
    try std.testing.expectEqual(@as(usize, 1), runner.cleanups);
    runner = .{};
    try std.testing.expectError(error.CleanupFailed, awaitCheck(&runner, std.time.ns_per_s));
    try std.testing.expect(runner.cleanups > 0);
}
