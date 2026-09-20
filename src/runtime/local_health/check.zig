const std = @import("std");
const cgroups = @import("../cgroups.zig");
const process = @import("../process.zig");
const output = @import("output.zig");

pub const Group = struct {
    cgroup: cgroups.Cgroup,

    pub fn create(id: []const u8, pid: i32, generation: i64, limits: cgroups.ResourceLimits) !Group {
        if (!@import("../container.zig").isValidContainerId(id)) return error.InvalidId;
        var group: Group = .{ .cgroup = .{ .path_buf = undefined, .path_len = 0 } };
        const path = try std.fmt.bufPrint(&group.cgroup.path_buf, "/sys/fs/cgroup/yoq/health-{s}-{d}-{d}", .{ id, generation, pid });
        group.cgroup.path_len = path.len;
        try std.Io.Dir.cwd().createDir(std.Options.debug_io, path, .default_dir);
        errdefer std.Io.Dir.cwd().deleteDir(std.Options.debug_io, path) catch {};
        // the check is a sibling so ordinary container teardown does not race
        // deletion of its cgroup. reserve the helper processes separately from
        // the command's configured process budget.
        try group.cgroup.setLimits(checkLimits(limits));
        return group;
    }

    pub fn cleanup(self: *const Group) !void {
        try self.cgroup.destroy();
    }
};

fn checkLimits(configured: cgroups.ResourceLimits) cgroups.ResourceLimits {
    var limits = configured;
    // __healthcheck relays io while the namespace helper waits for the command.
    // both live beside the command in this group and each needs one pid slot.
    if (configured.pids_max) |count| limits.pids_max = count +| 2;
    return limits;
}

/// call only with the container owner lock held and no active monitor. recovery
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
pub const Result = struct { outcome: Outcome, output: output.Output };

/// the injected runner owns the helper and all check descendants. every return
/// path calls cleanup before returning the result to the monitor.
pub fn awaitCheck(runner: anytype, timeout_ns: u64) !Outcome {
    const outcome = pollCheck(runner, timeout_ns) catch |err| {
        try runner.cleanup();
        return err;
    };
    try runner.cleanup();
    return outcome;
}

fn pollCheck(runner: anytype, timeout_ns: u64) !Outcome {
    const deadline = runner.now() + @as(i96, timeout_ns);
    while (true) {
        if (try runner.cancelled()) return .cancelled;
        if (try runner.poll()) |code| return .{ .exited = code };
        const remaining = @max(0, deadline - runner.now());
        if (remaining == 0) return .timed_out;
        const delay: u64 = @intCast(@min(remaining, 50 * std.time.ns_per_ms));
        runner.sleep(delay);
    }
}

pub fn run(monitor: anytype, timeout_ns: u64) !Result {
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
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer child.kill(io);
    var capture = try output.Capture.take(&child);
    defer capture.deinit();
    const helper_pid = child.id.?;
    try group.cgroup.addProcess(helper_pid);
    // no check process can fork before its helper has joined the owned group.
    try child.stdin.?.writeStreamingAll(io, "1");
    child.stdin.?.close(io);
    child.stdin = null;
    const Runner = struct {
        owner: @TypeOf(monitor),
        helper: *std.process.Child,
        group: *Group,
        capture: *output.Capture,

        fn cancelled(self: *@This()) !bool {
            if (self.owner.cancelled.load(.acquire)) return true;
            return try self.owner.availability() != .ready;
        }
        fn poll(self: *@This()) !?u8 {
            try self.capture.drain();
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
        fn sleep(self: *@This(), delay: u64) void {
            self.capture.wait(delay);
        }
        fn cleanup(self: *@This()) !void {
            if (self.helper.id) |current| process.kill(current) catch {};
            // cgroup.kill also reaches children that change session or detach.
            // retain a failed group for stop/recovery instead of repeating its
            // full destruction deadline while unwinding this check.
            self.group.cleanup() catch |err| {
                self.owner.failed_group = self.group.*;
                return err;
            };
            if (self.helper.id) |current| {
                _ = try process.waitForExit(current);
                self.helper.id = null;
            }
        }
    };
    var runner: Runner = .{ .owner = monitor, .helper = &child, .group = &group, .capture = &capture };
    // awaitCheck now owns the single cleanup attempt, including error returns.
    group_owned = false;
    const outcome = try awaitCheck(&runner, timeout_ns);
    return .{ .outcome = outcome, .output = try capture.finish() };
}

test "local health timeout and cancellation clean up every check" {
    const Fake = struct {
        remaining: usize = 3,
        cancel: bool = false,
        cleanups: usize = 0,
        time: i96 = 0,
        fn now(self: *@This()) i96 {
            return self.time;
        }
        fn cancelled(self: *@This()) !bool {
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
            self.cleanups += 1;
        }
    };
    var runner: Fake = .{};
    try std.testing.expectEqual(Outcome.timed_out, try awaitCheck(&runner, std.time.ns_per_ms));
    try std.testing.expectEqual(@as(usize, 1), runner.cleanups);
    runner = .{ .cancel = true };
    try std.testing.expectEqual(Outcome.cancelled, try awaitCheck(&runner, std.time.ns_per_s));
    try std.testing.expectEqual(@as(usize, 1), runner.cleanups);
    runner = .{ .remaining = 0 };
    try std.testing.expectEqual(Outcome{ .exited = 0 }, try awaitCheck(&runner, std.time.ns_per_s));
    try std.testing.expectEqual(@as(usize, 1), runner.cleanups);
}

test "local health polling failures clean up and cleanup failures propagate" {
    const Fake = struct {
        fail_poll: bool = false,
        fail_ownership: bool = false,
        cleanups: usize = 0,
        fn now(_: *@This()) i96 {
            return 0;
        }
        fn cancelled(self: *@This()) !bool {
            if (self.fail_ownership) return error.OwnershipUnknown;
            return false;
        }
        fn poll(self: *@This()) !?u8 {
            if (self.fail_poll) return error.PollFailed;
            return 0;
        }
        fn sleep(_: *@This(), _: u64) void {}
        fn cleanup(self: *@This()) !void {
            self.cleanups += 1;
            if (!self.fail_poll and !self.fail_ownership) return error.CleanupFailed;
        }
    };
    var runner: Fake = .{ .fail_poll = true };
    try std.testing.expectError(error.PollFailed, awaitCheck(&runner, std.time.ns_per_s));
    try std.testing.expectEqual(@as(usize, 1), runner.cleanups);
    runner = .{ .fail_ownership = true };
    try std.testing.expectError(error.OwnershipUnknown, awaitCheck(&runner, std.time.ns_per_s));
    try std.testing.expectEqual(@as(usize, 1), runner.cleanups);
    runner = .{};
    try std.testing.expectError(error.CleanupFailed, awaitCheck(&runner, std.time.ns_per_s));
    try std.testing.expectEqual(@as(usize, 1), runner.cleanups);
}

test "healthcheck pid limits reserve helpers without exhausting small command budgets" {
    try std.testing.expectEqual(@as(?u32, 3), checkLimits(.{ .pids_max = 1 }).pids_max);
    try std.testing.expectEqual(@as(?u32, 4), checkLimits(.{ .pids_max = 2 }).pids_max);
    try std.testing.expectEqual(@as(?u32, 4098), checkLimits(.{ .pids_max = 4096 }).pids_max);
    try std.testing.expectEqual(@as(?u32, std.math.maxInt(u32)), checkLimits(.{ .pids_max = std.math.maxInt(u32) }).pids_max);
    try std.testing.expect(checkLimits(cgroups.ResourceLimits.unlimited).pids_max == null);
    try std.testing.expectEqual(@as(?u64, 16 * 1024 * 1024), checkLimits(.{ .pids_max = 1, .memory_max = 16 * 1024 * 1024 }).memory_max);
}

test {
    _ = output;
}
