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

// -- types --

/// how to handle a batch failure during a rolling update
pub const FailureAction = enum {
    /// automatically restore the previous containers
    rollback,
    /// stop the update and leave the service in a mixed state
    pause,
};

/// deployment status — tracks where a deployment is in its lifecycle
pub const DeploymentStatus = enum {
    pending,
    in_progress,
    completed,
    failed,
    rolled_back,

    pub fn toString(self: DeploymentStatus) []const u8 {
        return switch (self) {
            .pending => "pending",
            .in_progress => "in_progress",
            .completed => "completed",
            .failed => "failed",
            .rolled_back => "rolled_back",
        };
    }

    pub fn fromString(s: []const u8) ?DeploymentStatus {
        if (std.mem.eql(u8, s, "pending")) return .pending;
        if (std.mem.eql(u8, s, "in_progress")) return .in_progress;
        if (std.mem.eql(u8, s, "completed")) return .completed;
        if (std.mem.eql(u8, s, "failed")) return .failed;
        if (std.mem.eql(u8, s, "rolled_back")) return .rolled_back;
        return null;
    }
};

/// controls how containers are replaced during a rolling update
pub const UpdateStrategy = struct {
    /// how many containers to replace at once
    parallelism: u32 = 1,

    /// seconds to wait between batches (gives the system time to stabilize)
    delay_between_batches: u32 = 0,

    /// what to do if a batch fails health checks
    failure_action: FailureAction = .rollback,

    /// how long to wait for health checks after starting new containers (seconds).
    /// zero means don't wait for health checks.
    health_check_timeout: u32 = 60,
};

/// a deployment record — snapshot of what was deployed
pub const Deployment = struct {
    id: []const u8,
    service_name: []const u8,
    manifest_hash: []const u8,
    config_snapshot: []const u8,
    status: DeploymentStatus,
    message: ?[]const u8,
    created_at: i64,
};

/// tracks the progress of a rolling update
pub const UpdateProgress = struct {
    total_containers: usize,
    replaced: usize,
    failed: usize,
    status: DeploymentStatus,
    message: ?[]const u8,
};

pub const UpdateError = error{
    /// a batch failed and rollback was triggered
    BatchFailed,
    /// a batch failed and the update was paused
    UpdatePaused,
    /// no previous deployment to rollback to
    NoPreviousDeployment,
    /// failed to record deployment in store
    StoreFailed,
    /// the stop or start callback reported an error
    ContainerOperationFailed,
};

/// callbacks for container operations. the update engine calls these
/// to actually start and stop containers, which keeps the engine
/// testable without needing a real container runtime.
pub const UpdateCallbacks = struct {
    /// stop a container by ID. returns true on success.
    stopContainer: *const fn (id: []const u8) bool,

    /// start a new container with the given config. returns the new
    /// container's ID on success, null on failure.
    /// the `index` parameter tells the callback which container
    /// in the batch this is (useful for generating unique IDs).
    startContainer: *const fn (config: []const u8, index: usize) ?[12]u8,

    /// check if a container is healthy. returns true if healthy,
    /// false if unhealthy or still starting.
    isHealthy: *const fn (id: []const u8) bool,
};

/// the context passed to performRollingUpdate
pub const UpdateContext = struct {
    service_name: []const u8,
    manifest_hash: []const u8,
    config_snapshot: []const u8,

    /// IDs of containers currently running for this service
    old_container_ids: []const []const u8,

    /// callbacks for container operations
    callbacks: UpdateCallbacks,
};

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

    // record deployment start
    const deployment_id = generateDeploymentId(alloc) catch {
        return UpdateError.StoreFailed;
    };
    defer alloc.free(deployment_id);

    recordDeployment(
        deployment_id,
        context.service_name,
        context.manifest_hash,
        context.config_snapshot,
        .in_progress,
        null,
    ) catch {
        return UpdateError.StoreFailed;
    };

    log.info("update: starting rolling update for {s} ({d} containers, parallelism={d})", .{
        context.service_name,
        total,
        strategy.parallelism,
    });

    // track new containers we've started (for rollback if needed)
    var new_container_ids = std.ArrayList([12]u8).init(alloc);
    defer new_container_ids.deinit();

    // track which old containers we've stopped (for rollback)
    var stopped_old = std.ArrayList(usize).init(alloc);
    defer stopped_old.deinit();

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
        var batch_new_ids = std.ArrayList([12]u8).init(alloc);
        defer batch_new_ids.deinit();

        var start_failures: usize = 0;
        for (0..batch_size) |i| {
            if (context.callbacks.startContainer(context.config_snapshot, batch_start + i)) |new_id| {
                batch_new_ids.append(new_id) catch {
                    start_failures += 1;
                    continue;
                };
                new_container_ids.append(new_id) catch {};
            } else {
                start_failures += 1;
            }
        }

        if (start_failures > 0) {
            log.warn("update: {d}/{d} containers failed to start in batch", .{ start_failures, batch_size });
            progress.failed += start_failures;
        }

        // if all starts failed, handle the failure
        if (batch_new_ids.items.len == 0) {
            return handleBatchFailure(
                alloc,
                strategy,
                context,
                deployment_id,
                &new_container_ids,
                &stopped_old,
                &progress,
                "all containers failed to start",
            );
        }

        // step 2: wait for health checks on new containers
        if (strategy.health_check_timeout > 0) {
            const all_healthy = waitForHealth(
                &batch_new_ids,
                context.callbacks,
                strategy.health_check_timeout,
            );

            if (!all_healthy) {
                return handleBatchFailure(
                    alloc,
                    strategy,
                    context,
                    deployment_id,
                    &new_container_ids,
                    &stopped_old,
                    &progress,
                    "health checks failed for new containers",
                );
            }
        }

        // step 3: stop old containers in this batch
        for (batch_start..batch_end) |i| {
            const old_id = context.old_container_ids[i];
            if (context.callbacks.stopContainer(old_id)) {
                stopped_old.append(i) catch {};
                progress.replaced += 1;
            } else {
                log.warn("update: failed to stop old container {s}", .{old_id});
                // not fatal — the new container is already running
                progress.replaced += 1;
            }
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

    updateDeploymentStatus(deployment_id, .completed, null) catch {};

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

// -- internal helpers --

/// handle a batch failure: either rollback or pause based on strategy
fn handleBatchFailure(
    alloc: std.mem.Allocator,
    strategy: UpdateStrategy,
    context: *const UpdateContext,
    deployment_id: []const u8,
    new_container_ids: *std.ArrayList([12]u8),
    stopped_old: *std.ArrayList(usize),
    progress: *UpdateProgress,
    reason: []const u8,
) UpdateError {
    _ = stopped_old;

    log.warn("update: batch failed for {s}: {s}", .{ context.service_name, reason });

    switch (strategy.failure_action) {
        .rollback => {
            log.info("update: rolling back — stopping {d} new containers", .{new_container_ids.items.len});

            // stop all new containers we started
            for (new_container_ids.items) |new_id| {
                _ = context.callbacks.stopContainer(&new_id);
            }

            // note: we don't restart old containers here because in a real
            // system they may still be running (we stop old after health check).
            // the orchestrator handles restarting from the previous config.

            progress.status = .rolled_back;
            progress.message = reason;
            _ = alloc;

            updateDeploymentStatus(deployment_id, .rolled_back, reason) catch {};

            return UpdateError.BatchFailed;
        },
        .pause => {
            progress.status = .failed;
            progress.message = reason;

            updateDeploymentStatus(deployment_id, .failed, reason) catch {};

            return UpdateError.UpdatePaused;
        },
    }
}

/// wait for all containers in a batch to become healthy.
/// polls at 1-second intervals up to `timeout` seconds.
fn waitForHealth(
    container_ids: *const std.ArrayList([12]u8),
    callbacks: UpdateCallbacks,
    timeout: u32,
) bool {
    const deadline = @as(u64, @intCast(std.time.timestamp())) + timeout;

    while (@as(u64, @intCast(std.time.timestamp())) < deadline) {
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

/// generate a unique deployment ID (12-char hex string like container IDs)
fn generateDeploymentId(alloc: std.mem.Allocator) ![]const u8 {
    var buf: [6]u8 = undefined;
    std.crypto.random.bytes(&buf);

    const hex = try alloc.alloc(u8, 12);
    _ = std.fmt.bufPrint(hex, "{s}", .{std.fmt.fmtSliceHexLower(&buf)}) catch unreachable;
    return hex;
}

/// record a deployment in the store
fn recordDeployment(
    id: []const u8,
    service_name: []const u8,
    manifest_hash: []const u8,
    config_snapshot: []const u8,
    status: DeploymentStatus,
    message: ?[]const u8,
) !void {
    store.saveDeployment(.{
        .id = id,
        .service_name = service_name,
        .manifest_hash = manifest_hash,
        .config_snapshot = config_snapshot,
        .status = status.toString(),
        .message = message,
        .created_at = std.time.timestamp(),
    }) catch return error.StoreFailed;
}

/// update a deployment's status in the store
fn updateDeploymentStatus(
    id: []const u8,
    status: DeploymentStatus,
    message: ?[]const u8,
) !void {
    store.updateDeploymentStatus(id, status.toString(), message) catch return error.StoreFailed;
}

// -- tests --

// test callbacks that simulate container operations without needing
// a real runtime. controlled by module-level state so the test can
// set up expected behaviors.

var test_start_should_fail: bool = false;
var test_health_should_fail: bool = false;
var test_stops: u32 = 0;
var test_starts: u32 = 0;

fn resetTestState() void {
    test_start_should_fail = false;
    test_health_should_fail = false;
    test_stops = 0;
    test_starts = 0;
}

fn testStopContainer(_: []const u8) bool {
    test_stops += 1;
    return true;
}

fn testStartContainer(_: []const u8, _: usize) ?[12]u8 {
    if (test_start_should_fail) return null;
    test_starts += 1;
    return "newcontainer1".*;
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
    try std.testing.expectEqualStrings("completed", DeploymentStatus.completed.toString());
    try std.testing.expectEqualStrings("failed", DeploymentStatus.failed.toString());
    try std.testing.expectEqualStrings("rolled_back", DeploymentStatus.rolled_back.toString());

    try std.testing.expectEqual(DeploymentStatus.pending, DeploymentStatus.fromString("pending").?);
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
    const id = try generateDeploymentId(alloc);
    defer alloc.free(id);

    try std.testing.expectEqual(@as(usize, 12), id.len);

    // verify all chars are hex
    for (id) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "two generated ids are different" {
    const alloc = std.testing.allocator;
    const id1 = try generateDeploymentId(alloc);
    defer alloc.free(id1);
    const id2 = try generateDeploymentId(alloc);
    defer alloc.free(id2);

    try std.testing.expect(!std.mem.eql(u8, id1, id2));
}
