const std = @import("std");
const log = @import("../../lib/log.zig");
const deployment_store = @import("deployment_store.zig");
const common = @import("common.zig");

fn nowAwakeSeconds() u64 {
    return @intCast(@max(0, std.Io.Clock.awake.now(std.Options.debug_io).toSeconds()));
}

pub fn pausedFailureStatus(progress: *const common.UpdateProgress) common.DeploymentStatus {
    return if (progress.replaced > 0) .partially_failed else .failed;
}

pub fn handleBatchFailure(
    strategy: common.UpdateStrategy,
    context: *const common.UpdateContext,
    deployment_id: ?[]const u8,
    new_container_ids: *std.ArrayList([12]u8),
    progress: *common.UpdateProgress,
    reason: []const u8,
) common.UpdateError {
    log.warn("update: batch failed for {s}: {s}", .{ context.service_name, reason });

    const status: common.DeploymentStatus = switch (strategy.failure_action) {
        .rollback => blk: {
            log.info("update: rolling back — stopping {d} new containers", .{new_container_ids.items.len});

            for (new_container_ids.items) |new_id| {
                _ = context.callbacks.stopContainer(&new_id);
            }

            break :blk .rolled_back;
        },
        .pause => pausedFailureStatus(progress),
    };

    progress.status = status;
    progress.message = reason;

    if (deployment_id) |id| {
        deployment_store.updateDeploymentStatus(id, status, reason) catch |err| {
            log.warn("failed to update deployment status to {s}: {}", .{ status.toString(), err });
        };
    }

    return switch (strategy.failure_action) {
        .rollback => common.UpdateError.BatchFailed,
        .pause => common.UpdateError.UpdatePaused,
    };
}

pub fn waitForHealth(
    container_ids: *const std.ArrayList([12]u8),
    callbacks: common.UpdateCallbacks,
    timeout: u32,
) bool {
    return waitForHealthWithSleep(container_ids, callbacks, timeout, sleepHealthPoll);
}

fn waitForHealthWithSleep(
    container_ids: *const std.ArrayList([12]u8),
    callbacks: common.UpdateCallbacks,
    timeout: u32,
    sleepFn: *const fn () anyerror!void,
) bool {
    const deadline = nowAwakeSeconds() + timeout;

    while (nowAwakeSeconds() < deadline) {
        if (allHealthy(container_ids.items, callbacks)) return true;
        sleepFn() catch |err| {
            log.warn("update: health wait interrupted: {}", .{err});
            return false;
        };
    }

    return false;
}

fn allHealthy(container_ids: []const [12]u8, callbacks: common.UpdateCallbacks) bool {
    for (container_ids) |id| {
        if (!callbacks.isHealthy(&id)) return false;
    }
    return true;
}

fn sleepHealthPoll() !void {
    try std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromSeconds(1), .awake);
}

fn testStopContainer(_: []const u8) bool {
    return true;
}

fn testStartContainer(_: []const u8, _: usize) ?[12]u8 {
    return null;
}

fn testIsUnhealthy(_: []const u8) bool {
    return false;
}

fn failHealthSleep() !void {
    return error.SleepFailed;
}

test "waitForHealth returns false when the health wait sleep fails" {
    var ids: std.ArrayList([12]u8) = .empty;
    defer ids.deinit(std.testing.allocator);
    try ids.append(std.testing.allocator, "container001".*);

    const callbacks = common.UpdateCallbacks{
        .stopContainer = testStopContainer,
        .startContainer = testStartContainer,
        .isHealthy = testIsUnhealthy,
    };

    try std.testing.expect(!waitForHealthWithSleep(&ids, callbacks, 1, failHealthSleep));
}

test "batch rollback stops new containers in order before recording failure" {
    const State = struct {
        var stopped: [2][12]u8 = undefined;
        var stop_count: usize = 0;
        var progress: *common.UpdateProgress = undefined;
        var stopped_before_status_change: bool = true;

        fn stop(id: []const u8) bool {
            @memcpy(&stopped[stop_count], id);
            stop_count += 1;
            stopped_before_status_change = stopped_before_status_change and progress.status == .in_progress;
            return false;
        }
    };
    var ids: std.ArrayList([12]u8) = .empty;
    defer ids.deinit(std.testing.allocator);
    try ids.appendSlice(std.testing.allocator, &.{ "container001".*, "container002".* });
    const context = common.UpdateContext{
        .service_name = "web",
        .manifest_hash = "hash",
        .config_snapshot = "{}",
        .old_container_ids = &.{"oldcontainer"},
        .callbacks = .{ .stopContainer = State.stop, .startContainer = testStartContainer, .isHealthy = testIsUnhealthy },
    };

    for ([_]common.FailureAction{ .rollback, .pause }) |action| {
        var progress = common.UpdateProgress{
            .total_containers = 3,
            .replaced = 1,
            .failed = 1,
            .status = .in_progress,
            .message = null,
        };
        State.stop_count = 0;
        State.progress = &progress;
        State.stopped_before_status_change = true;

        const result = handleBatchFailure(.{ .failure_action = action }, &context, null, &ids, &progress, "batch failed");
        if (action == .rollback) {
            // a failed stop must not prevent the remaining stop attempts.
            try std.testing.expectEqual(common.UpdateError.BatchFailed, result);
            try std.testing.expectEqual(common.DeploymentStatus.rolled_back, progress.status);
            try std.testing.expectEqual(@as(usize, 2), State.stop_count);
            for (ids.items, State.stopped) |expected, stopped| {
                try std.testing.expectEqualStrings(&expected, &stopped);
            }
            try std.testing.expect(State.stopped_before_status_change);
        } else {
            try std.testing.expectEqual(common.UpdateError.UpdatePaused, result);
            try std.testing.expectEqual(common.DeploymentStatus.partially_failed, progress.status);
            try std.testing.expectEqual(@as(usize, 0), State.stop_count);
        }
        try std.testing.expectEqualStrings("batch failed", progress.message.?);
        try std.testing.expectEqual(@as(usize, 1), progress.replaced);
        try std.testing.expectEqual(@as(usize, 1), progress.failed);
        try std.testing.expectEqual(@as(usize, 2), ids.items.len);
    }
}

test "health polling retries in order and skips callbacks at zero timeout" {
    const State = struct {
        var checked: [3][12]u8 = undefined;
        var check_count: usize = 0;
        var sleep_count: usize = 0;

        fn healthy(id: []const u8) bool {
            @memcpy(&checked[check_count], id);
            check_count += 1;
            return check_count > 1;
        }

        fn sleep() !void {
            sleep_count += 1;
        }
    };
    State.check_count = 0;
    State.sleep_count = 0;
    var ids: std.ArrayList([12]u8) = .empty;
    defer ids.deinit(std.testing.allocator);
    try ids.appendSlice(std.testing.allocator, &.{ "container001".*, "container002".* });
    const callbacks = common.UpdateCallbacks{
        .stopContainer = testStopContainer,
        .startContainer = testStartContainer,
        .isHealthy = State.healthy,
    };

    try std.testing.expect(!waitForHealthWithSleep(&ids, callbacks, 0, State.sleep));
    try std.testing.expectEqual(@as(usize, 0), State.check_count);
    try std.testing.expectEqual(@as(usize, 0), State.sleep_count);

    // the first unhealthy container ends the scan. the next poll starts over.
    try std.testing.expect(waitForHealthWithSleep(&ids, callbacks, 60, State.sleep));
    try std.testing.expectEqual(@as(usize, 3), State.check_count);
    try std.testing.expectEqual(@as(usize, 1), State.sleep_count);
    const expected_ids = [_][]const u8{ "container001", "container001", "container002" };
    for (expected_ids, State.checked) |expected, checked| {
        try std.testing.expectEqualStrings(expected, &checked);
    }

    ids.clearRetainingCapacity();
    try std.testing.expect(waitForHealthWithSleep(&ids, callbacks, 60, State.sleep));
    try std.testing.expect(!waitForHealthWithSleep(&ids, callbacks, 0, State.sleep));
    try std.testing.expectEqual(@as(usize, 3), State.check_count);
    try std.testing.expectEqual(@as(usize, 1), State.sleep_count);
}
