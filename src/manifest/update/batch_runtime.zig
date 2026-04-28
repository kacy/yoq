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

    switch (strategy.failure_action) {
        .rollback => {
            log.info("update: rolling back — stopping {d} new containers", .{new_container_ids.items.len});

            for (new_container_ids.items) |new_id| {
                _ = context.callbacks.stopContainer(&new_id);
            }

            progress.status = .rolled_back;
            progress.message = reason;

            if (deployment_id) |id| {
                deployment_store.updateDeploymentStatus(id, .rolled_back, reason) catch |e| {
                    log.warn("failed to update deployment status to rolled_back: {}", .{e});
                };
            }

            return common.UpdateError.BatchFailed;
        },
        .pause => {
            const status = pausedFailureStatus(progress);
            progress.status = status;
            progress.message = reason;

            if (deployment_id) |id| {
                deployment_store.updateDeploymentStatus(id, status, reason) catch |e| {
                    log.warn("failed to update deployment status to {s}: {}", .{ status.toString(), e });
                };
            }

            return common.UpdateError.UpdatePaused;
        },
    }
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
        var all_healthy = true;

        for (container_ids.items) |id| {
            if (!callbacks.isHealthy(&id)) {
                all_healthy = false;
                break;
            }
        }

        if (all_healthy) return true;
        sleepFn() catch |err| {
            log.warn("update: health wait interrupted: {}", .{err});
            return false;
        };
    }

    return false;
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
