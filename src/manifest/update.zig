// update — rolling update engine
//
// replaces containers in batches during a service deployment.
// each batch waits for health checks (if configured) before
// proceeding to the next batch. on failure, either rolls back
// to the previous config or pauses for manual intervention.
//
// the engine is intentionally decoupled from the orchestrator's
// container lifecycle — it operates on abstract "old container"
// and "new container config" concepts, delegating actual
// start/stop to callback functions. this makes it testable
// without real containers.
//
// usage:
//   const strategy = UpdateStrategy{};
//   const result = performRollingUpdate(alloc, strategy, &context);

const std = @import("std");
const store = @import("../state/store.zig");
const log = @import("../lib/log.zig");
const common = @import("update/common.zig");
const deployment_store = @import("update/deployment_store.zig");
const batch_runtime = @import("update/batch_runtime.zig");

pub const FailureAction = common.FailureAction;
pub const DeploymentStatus = common.DeploymentStatus;
pub const UpdateStrategy = common.UpdateStrategy;
pub const Deployment = common.Deployment;
pub const UpdateProgress = common.UpdateProgress;
pub const UpdateError = common.UpdateError;
pub const UpdateCallbacks = common.UpdateCallbacks;
pub const UpdateContext = common.UpdateContext;

// -- core engine --

/// perform a rolling update, replacing old containers with new ones
/// in batches according to the strategy.
///
/// the flow:
///   1. record a new deployment as "in_progress"
///   2. split old containers into batches of size `parallelism`
///   3. for each batch:
///      a. start new containers
///      b. wait for health checks (if configured)
///      c. stop old containers
///      d. on failure: rollback or pause based on strategy
///   4. mark deployment as completed (or failed/rolled_back)
///
/// returns the final progress state.
pub fn performRollingUpdate(
    alloc: std.mem.Allocator,
    strategy: UpdateStrategy,
    context: *const UpdateContext,
) UpdateError!UpdateProgress {
    const total = context.old_container_ids.len;

    // handle edge case: no old containers means this is a fresh deploy,
    // not a rolling update. just start the new containers.
    if (total == 0) {
        return UpdateProgress{
            .total_containers = 0,
            .replaced = 0,
            .failed = 0,
            .status = .completed,
            .message = null,
        };
    }

    // record deployment start (best-effort — the update proceeds even if
    // we can't write to the store, since the actual container work matters
    // more than the audit trail)
    const deployment_id = deployment_store.generateDeploymentId(alloc) catch null;
    defer if (deployment_id) |did| alloc.free(did);

    if (deployment_id) |did| {
        deployment_store.recordDeployment(
            did,
            null,
            context.service_name,
            context.manifest_hash,
            context.config_snapshot,
            .in_progress,
            null,
        ) catch {
            log.warn("update: failed to record deployment start", .{});
        };
    }

    log.info("update: starting rolling update for {s} ({d} containers, parallelism={d})", .{
        context.service_name,
        total,
        strategy.parallelism,
    });

    // track new containers we've started (for rollback if needed)
    var new_container_ids = std.ArrayList([12]u8).empty;
    defer new_container_ids.deinit(alloc);

    var progress = UpdateProgress{
        .total_containers = total,
        .replaced = 0,
        .failed = 0,
        .status = .in_progress,
        .message = null,
    };

    // process in batches
    var batch_start: usize = 0;
    while (batch_start < total) {
        const batch_end = @min(batch_start + strategy.parallelism, total);
        const batch_size = batch_end - batch_start;

        log.info("update: batch {d}-{d} of {d}", .{ batch_start, batch_end - 1, total });

        // step 1: start new containers for this batch
        var batch_new_ids = std.ArrayList([12]u8).empty;
        defer batch_new_ids.deinit(alloc);

        var start_failures: usize = 0;
        for (0..batch_size) |i| {
            if (context.callbacks.startContainer(context.config_snapshot, batch_start + i)) |new_id| {
                batch_new_ids.append(alloc, new_id) catch {
                    start_failures += 1;
                    continue;
                };
                new_container_ids.append(alloc, new_id) catch {
                    log.warn("update: failed to track new container ID for rollback (possible orphan on failure)", .{});
                };
            } else {
                start_failures += 1;
            }
        }

        if (start_failures > 0) {
            log.warn("update: {d}/{d} containers failed to start in batch", .{ start_failures, batch_size });
            progress.failed += start_failures;
            return batch_runtime.handleBatchFailure(
                strategy,
                context,
                deployment_id,
                &new_container_ids,
                &progress,
                "one or more containers failed to start",
            );
        }

        // step 2: wait for health checks on new containers
        if (strategy.health_check_timeout > 0) {
            const all_healthy = batch_runtime.waitForHealth(
                &batch_new_ids,
                context.callbacks,
                strategy.health_check_timeout,
            );

            if (!all_healthy) {
                return batch_runtime.handleBatchFailure(
                    strategy,
                    context,
                    deployment_id,
                    &new_container_ids,
                    &progress,
                    "health checks failed for new containers",
                );
            }
        }

        // step 3: stop old containers in this batch
        for (batch_start..batch_end) |i| {
            const old_id = context.old_container_ids[i];
            if (!context.callbacks.stopContainer(old_id)) {
                log.warn("update: failed to stop old container {s}", .{old_id});
                // not fatal — the new container is already running
            }
            progress.replaced += 1;
        }

        // step 4: delay between batches (if configured and not the last batch)
        if (strategy.delay_between_batches > 0 and batch_end < total) {
            log.info("update: waiting {d}s before next batch", .{strategy.delay_between_batches});
            std.Thread.sleep(@as(u64, strategy.delay_between_batches) * std.time.ns_per_s);
        }

        batch_start = batch_end;
    }

    // all batches succeeded
    progress.status = .completed;
    progress.message = null;

    if (deployment_id) |did| {
        deployment_store.updateDeploymentStatus(did, .completed, null) catch {};
    }

    log.info("update: rolling update completed for {s} ({d} containers replaced)", .{
        context.service_name,
        progress.replaced,
    });

    return progress;
}

/// look up the previous successful deployment and re-deploy that config.
/// returns the config snapshot of the deployment being rolled back to.
pub fn rollback(
    alloc: std.mem.Allocator,
    service_name: []const u8,
) UpdateError![]const u8 {
    const prev = store.getLastSuccessfulDeployment(alloc, service_name) catch {
        return UpdateError.NoPreviousDeployment;
    };
    defer prev.deinit(alloc);

    // duplicate the config snapshot so the caller owns it
    const config = alloc.dupe(u8, prev.config_snapshot) catch {
        return UpdateError.StoreFailed;
    };

    log.info("update: rolling back {s} to deployment {s}", .{ service_name, prev.id });

    return config;
}

// -- tests --

// test callbacks that simulate container operations without needing
// a real runtime. controlled by module-level state so the test can
// set up expected behaviors.

var test_start_should_fail: bool = false;
var test_fail_start_call: ?u32 = null;
var test_health_should_fail: bool = false;
var test_stops: u32 = 0;
var test_starts: u32 = 0;
var test_start_calls: u32 = 0;

fn resetTestState() void {
    test_start_should_fail = false;
    test_fail_start_call = null;
    test_health_should_fail = false;
    test_stops = 0;
    test_starts = 0;
    test_start_calls = 0;
}

fn testStopContainer(_: []const u8) bool {
    test_stops += 1;
    return true;
}

fn testStartContainer(_: []const u8, _: usize) ?[12]u8 {
    defer test_start_calls += 1;
    if (test_start_should_fail) return null;
    if (test_fail_start_call) |call| {
        if (test_start_calls == call) return null;
    }
    test_starts += 1;
    return "newcontainer".*;
}

fn testIsHealthy(_: []const u8) bool {
    return !test_health_should_fail;
}

const test_callbacks = UpdateCallbacks{
    .stopContainer = testStopContainer,
    .startContainer = testStartContainer,
    .isHealthy = testIsHealthy,
};

test "deployment status round-trip" {
    try std.testing.expectEqualStrings("pending", DeploymentStatus.pending.toString());
    try std.testing.expectEqualStrings("in_progress", DeploymentStatus.in_progress.toString());
    try std.testing.expectEqualStrings("partially_failed", DeploymentStatus.partially_failed.toString());
    try std.testing.expectEqualStrings("completed", DeploymentStatus.completed.toString());
    try std.testing.expectEqualStrings("failed", DeploymentStatus.failed.toString());
    try std.testing.expectEqualStrings("rolled_back", DeploymentStatus.rolled_back.toString());

    try std.testing.expectEqual(DeploymentStatus.pending, DeploymentStatus.fromString("pending").?);
    try std.testing.expectEqual(DeploymentStatus.partially_failed, DeploymentStatus.fromString("partially_failed").?);
    try std.testing.expectEqual(DeploymentStatus.completed, DeploymentStatus.fromString("completed").?);
    try std.testing.expect(DeploymentStatus.fromString("unknown") == null);
}

test "update strategy defaults" {
    const s = UpdateStrategy{};
    try std.testing.expectEqual(@as(u32, 1), s.parallelism);
    try std.testing.expectEqual(@as(u32, 0), s.delay_between_batches);
    try std.testing.expectEqual(FailureAction.rollback, s.failure_action);
    try std.testing.expectEqual(@as(u32, 60), s.health_check_timeout);
}

test "empty container list completes immediately" {
    resetTestState();
    const alloc = std.testing.allocator;

    const empty: []const []const u8 = &.{};
    const context = UpdateContext{
        .service_name = "web",
        .manifest_hash = "sha256:abc",
        .config_snapshot = "{}",
        .old_container_ids = empty,
        .callbacks = test_callbacks,
    };

    const result = try performRollingUpdate(alloc, .{}, &context);
    try std.testing.expectEqual(DeploymentStatus.completed, result.status);
    try std.testing.expectEqual(@as(usize, 0), result.replaced);
    try std.testing.expectEqual(@as(usize, 0), result.total_containers);
}

test "single container replacement" {
    resetTestState();
    const alloc = std.testing.allocator;

    const old_ids: []const []const u8 = &.{"old-container1"};
    const context = UpdateContext{
        .service_name = "web",
        .manifest_hash = "sha256:abc",
        .config_snapshot = "{\"image\":\"nginx:2.0\"}",
        .old_container_ids = old_ids,
        .callbacks = test_callbacks,
    };

    // skip health checks for this test
    const strategy = UpdateStrategy{ .health_check_timeout = 0 };
    const result = try performRollingUpdate(alloc, strategy, &context);

    try std.testing.expectEqual(DeploymentStatus.completed, result.status);
    try std.testing.expectEqual(@as(usize, 1), result.replaced);
    try std.testing.expectEqual(@as(u32, 1), test_starts);
    try std.testing.expectEqual(@as(u32, 1), test_stops);
}

test "batch replacement with parallelism" {
    resetTestState();
    const alloc = std.testing.allocator;

    const old_ids: []const []const u8 = &.{ "c1", "c2", "c3", "c4" };
    const context = UpdateContext{
        .service_name = "api",
        .manifest_hash = "sha256:def",
        .config_snapshot = "{}",
        .old_container_ids = old_ids,
        .callbacks = test_callbacks,
    };

    const strategy = UpdateStrategy{
        .parallelism = 2,
        .health_check_timeout = 0,
    };
    const result = try performRollingUpdate(alloc, strategy, &context);

    try std.testing.expectEqual(DeploymentStatus.completed, result.status);
    try std.testing.expectEqual(@as(usize, 4), result.replaced);
    try std.testing.expectEqual(@as(u32, 4), test_starts);
    try std.testing.expectEqual(@as(u32, 4), test_stops);
}

test "start failure triggers rollback" {
    resetTestState();
    test_start_should_fail = true;
    const alloc = std.testing.allocator;

    const old_ids: []const []const u8 = &.{"old-1"};
    const context = UpdateContext{
        .service_name = "web",
        .manifest_hash = "sha256:bad",
        .config_snapshot = "{}",
        .old_container_ids = old_ids,
        .callbacks = test_callbacks,
    };

    const strategy = UpdateStrategy{
        .failure_action = .rollback,
        .health_check_timeout = 0,
    };

    const result = performRollingUpdate(alloc, strategy, &context);
    try std.testing.expectError(UpdateError.BatchFailed, result);
}

test "start failure triggers pause when configured" {
    resetTestState();
    test_start_should_fail = true;
    const alloc = std.testing.allocator;

    const old_ids: []const []const u8 = &.{"old-1"};
    const context = UpdateContext{
        .service_name = "web",
        .manifest_hash = "sha256:bad",
        .config_snapshot = "{}",
        .old_container_ids = old_ids,
        .callbacks = test_callbacks,
    };

    const strategy = UpdateStrategy{
        .failure_action = .pause,
        .health_check_timeout = 0,
    };

    const result = performRollingUpdate(alloc, strategy, &context);
    try std.testing.expectError(UpdateError.UpdatePaused, result);
}

test "partial batch start failure rolls back before stopping old containers" {
    resetTestState();
    test_fail_start_call = 1;
    const alloc = std.testing.allocator;

    const old_ids: []const []const u8 = &.{ "old-1", "old-2" };
    const context = UpdateContext{
        .service_name = "web",
        .manifest_hash = "sha256:partial",
        .config_snapshot = "{}",
        .old_container_ids = old_ids,
        .callbacks = test_callbacks,
    };

    const strategy = UpdateStrategy{
        .parallelism = 2,
        .failure_action = .rollback,
        .health_check_timeout = 0,
    };

    const result = performRollingUpdate(alloc, strategy, &context);
    try std.testing.expectError(UpdateError.BatchFailed, result);
    try std.testing.expectEqual(@as(u32, 1), test_starts);
    try std.testing.expectEqual(@as(u32, 1), test_stops);
}

test "failure action enum values" {
    try std.testing.expectEqual(FailureAction.rollback, FailureAction.rollback);
    try std.testing.expectEqual(FailureAction.pause, FailureAction.pause);
    try std.testing.expect(FailureAction.rollback != FailureAction.pause);
}

test "update progress tracking" {
    var progress = UpdateProgress{
        .total_containers = 4,
        .replaced = 0,
        .failed = 0,
        .status = .in_progress,
        .message = null,
    };

    progress.replaced = 2;
    progress.failed = 1;

    try std.testing.expectEqual(@as(usize, 4), progress.total_containers);
    try std.testing.expectEqual(@as(usize, 2), progress.replaced);
    try std.testing.expectEqual(@as(usize, 1), progress.failed);
}

test "generate deployment id produces 12-char hex" {
    const alloc = std.testing.allocator;
    const id = try deployment_store.generateDeploymentId(alloc);
    defer alloc.free(id);

    try std.testing.expectEqual(@as(usize, 12), id.len);

    // verify all chars are hex
    for (id) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "two generated ids are different" {
    const alloc = std.testing.allocator;
    const id1 = try deployment_store.generateDeploymentId(alloc);
    defer alloc.free(id1);
    const id2 = try deployment_store.generateDeploymentId(alloc);
    defer alloc.free(id2);

    try std.testing.expect(!std.mem.eql(u8, id1, id2));
}
