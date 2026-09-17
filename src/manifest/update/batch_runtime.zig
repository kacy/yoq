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
