const std = @import("std");
const log = @import("../../lib/log.zig");
const deployment_store = @import("deployment_store.zig");
const common = @import("common.zig");

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
    const now = std.time.timestamp();
    const deadline = @as(u64, @intCast(@max(0, now))) + timeout;

    while (@as(u64, @intCast(@max(0, std.time.timestamp()))) < deadline) {
        var all_healthy = true;

        for (container_ids.items) |id| {
            if (!callbacks.isHealthy(&id)) {
                all_healthy = false;
                break;
            }
        }

        if (all_healthy) return true;
        std.Thread.sleep(1 * std.time.ns_per_s);
    }

    return false;
}
