const std = @import("std");
const sqlite = @import("sqlite");

const scheduler = @import("../../../cluster/scheduler.zig");
const cluster_node = @import("../../../cluster/node.zig");
const apply_release = @import("../../../manifest/apply_release.zig");
const apply_request = @import("apply_request.zig");
const rollout_targets_mod = @import("rollout_targets.zig");
const readiness = @import("cluster_readiness.zig");
const rollback = @import("cluster_rollback.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const rollout_spec = @import("../../../manifest/spec.zig");
const store = @import("../../../state/store.zig");
const runtime_wait = @import("../../../lib/runtime_wait.zig");

const FailureDetailBuilder = rollout_targets_mod.FailureDetailBuilder;
const RolloutTargetBuilder = rollout_targets_mod.RolloutTargetBuilder;
const ScheduledTarget = rollout_targets_mod.ScheduledTarget;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

const ResumeSeed = struct {
    completed_targets: usize = 0,
    failed_targets: usize = 0,
    rollout_targets_json: ?[]u8 = null,

    fn deinit(self: ResumeSeed, alloc: std.mem.Allocator) void {
        if (self.rollout_targets_json) |json| alloc.free(json);
    }
};

const ApplyCounters = struct {
    placed: usize,
    failed: usize,
    completed_targets: usize,
    failed_targets: usize,

    fn fromResumeSeed(seed: ResumeSeed) ApplyCounters {
        return .{
            .placed = seed.completed_targets,
            .failed = seed.failed_targets,
            .completed_targets = seed.completed_targets,
            .failed_targets = seed.failed_targets,
        };
    }
};

pub const ClusterApplyError = rollback.ApplyError;
pub const RollbackState = rollback.RollbackState;
pub const TargetReadiness = readiness.TargetReadiness;
pub const queryTargetReadiness = readiness.queryTargetReadiness;
pub const resolveTargetReadinessStates = readiness.resolveTargetReadinessStates;
pub const ClusterApplyBackend = struct {
    alloc: std.mem.Allocator,
    node: *cluster_node.Node,
    requests: []apply_request.ServiceRequest,
    agents: []agent_registry.AgentRecord,
    progress: ?apply_release.ProgressRecorder = null,

    pub fn attachProgressRecorder(self: *@This(), recorder: apply_release.ProgressRecorder) void {
        self.progress = recorder;
    }

    pub fn apply(self: *const ClusterApplyBackend) ClusterApplyError!apply_release.ApplyOutcome {
        const strategy = effectiveClusterRollout(self.requests);
        const resume_seed = loadResumeSeed(self.alloc, self.node.stateMachineDb(), self.progress);
        defer resume_seed.deinit(self.alloc);
        var failure_details = FailureDetailBuilder.init(self.alloc);
        defer failure_details.deinit();
        var rollout_targets = RolloutTargetBuilder.init(self.alloc);
        defer rollout_targets.deinit();
        rollout_targets.appendRequests(self.requests) catch return ClusterApplyError.InternalError;
        rollout_targets.restoreFromJson(resume_seed.rollout_targets_json);
        var rollback_state_storage: RollbackState = undefined;
        var rollback_state: ?*RollbackState = null;
        if (strategy.failure_action == .rollback) {
            rollback_state_storage = try RollbackState.capture(self.alloc, self.node.stateMachineDb(), self.requests);
            rollback_state = &rollback_state_storage;
        }
        defer if (rollback_state) |state| state.deinit();

        var counters = ApplyCounters.fromResumeSeed(resume_seed);

        var batch_start: usize = 0;
        var first_batch = true;
        while (batch_start < self.requests.len) {
            if (self.awaitControl()) {
                if (strategy.failure_action == .rollback) {
                    if (rollback_state) |state| {
                        try state.rollbackActivatedTargets(self.node);
                        state.markActivatedTargets(&rollout_targets, "rolled_back", "rollback_reverted");
                        counters.completed_targets = 0;
                        counters.placed = 0;
                    }
                }
                return .{
                    .status = if (counters.placed > 0 or counters.failed_targets > 0) .partially_failed else .failed,
                    .message = "rollout canceled by operator",
                    .failure_details_json = failure_details.toOwnedJson() catch return ClusterApplyError.InternalError,
                    .rollout_targets_json = rollout_targets.toOwnedJson() catch return ClusterApplyError.InternalError,
                    .placed = counters.placed,
                    .failed = counters.failed,
                    .completed_targets = counters.completed_targets,
                    .failed_targets = counters.failed_targets,
                };
            }
            const batch_end = nextClusterBatchEnd(strategy, batch_start, self.requests.len, first_batch);
            const batch = self.requests[batch_start..batch_end];
            const batch_failed_before = counters.failed_targets;

            try self.applyBatch(batch, batch_start, batch_end, strategy, rollback_state, &failure_details, &rollout_targets, &counters);

            if (counters.failed_targets > batch_failed_before) break;
            if (strategy.delay_between_batches > 0 and batch_end < self.requests.len) {
                if (!runtime_wait.sleep(std.Io.Duration.fromSeconds(@intCast(strategy.delay_between_batches)), "cluster rollout batch delay")) return ClusterApplyError.InternalError;
            }
            batch_start = batch_end;
            first_batch = false;
        }

        return .{
            .status = if (counters.failed_targets == 0)
                .completed
            else if (counters.completed_targets > 0)
                .partially_failed
            else
                .failed,
            .message = if (counters.failed_targets > 0 and counters.failed == 0)
                "one or more rollout targets failed readiness checks"
            else if (counters.failed == 0)
                "all placements succeeded"
            else
                "one or more placements failed",
            .failure_details_json = failure_details.toOwnedJson() catch return ClusterApplyError.InternalError,
            .rollout_targets_json = rollout_targets.toOwnedJson() catch return ClusterApplyError.InternalError,
            .placed = counters.placed,
            .failed = counters.failed,
            .completed_targets = counters.completed_targets,
            .failed_targets = counters.failed_targets,
        };
    }

    fn applyBatch(
        self: *const ClusterApplyBackend,
        batch: []const apply_request.ServiceRequest,
        batch_start: usize,
        batch_end: usize,
        strategy: rollout_spec.RolloutPolicy,
        rollback_state: ?*RollbackState,
        failure_details: *FailureDetailBuilder,
        rollout_targets: *RolloutTargetBuilder,
        counters: *ApplyCounters,
    ) ClusterApplyError!void {
        const batch_failed_before = counters.failed_targets;
        var scheduled_targets: std.ArrayListUnmanaged(ScheduledTarget) = .empty;
        defer {
            for (scheduled_targets.items) |*target| target.deinit(self.alloc);
            scheduled_targets.deinit(self.alloc);
        }

        for (batch) |req| {
            if (req.request.gang_world_size > 0) {
                try self.applyGangRequest(req, batch_start, batch_end, failure_details, rollout_targets, counters, &scheduled_targets);
            } else {
                try self.applySingleRequest(req, batch_start, batch_end, failure_details, rollout_targets, counters, &scheduled_targets);
            }
        }

        if (scheduled_targets.items.len == 0) return;

        if (strategy.failure_action == .rollback and counters.failed_targets > batch_failed_before) {
            for (scheduled_targets.items) |target| try rollback.discardTarget(self.node, target);
            if (rollback_state) |state| {
                try state.rollbackActivatedTargets(self.node);
                counters.completed_targets = 0;
                counters.placed = 0;
                self.reportProgress("schedule", batch_start, batch_end, counters.*, failure_details, rollout_targets);
            }
            return;
        }

        if (strategy.health_check_timeout > 0) {
            try self.finalizeBatchTargets(
                scheduled_targets.items,
                strategy.failure_action,
                rollback_state,
                failure_details,
                rollout_targets,
                strategy.health_check_timeout,
                counters,
                batch_start,
                batch_end,
            );
            return;
        }

        for (scheduled_targets.items) |target| {
            try rollback.activateTarget(self.node, target);
            if (rollback_state) |state| try state.recordActivatedTarget(target);
            rollout_targets.setTargetState(target, "ready", null);
            counters.placed += target.placement_count;
            counters.completed_targets += 1;
            self.reportProgress("cutover", batch_start, batch_end, counters.*, failure_details, rollout_targets);
        }
    }

    fn applyGangRequest(
        self: *const ClusterApplyBackend,
        req: apply_request.ServiceRequest,
        batch_start: usize,
        batch_end: usize,
        failure_details: *FailureDetailBuilder,
        rollout_targets: *RolloutTargetBuilder,
        counters: *ApplyCounters,
        scheduled_targets: *std.ArrayListUnmanaged(ScheduledTarget),
    ) ClusterApplyError!void {
        if (isTerminalRolloutTargetState(rollout_targets.stateForRequest(req.request))) return;
        const gang_placements = scheduler.scheduleGang(self.alloc, req.request, self.agents) catch {
            counters.failed += 1;
            counters.failed_targets += 1;
            failure_details.appendRequest(req, "placement_failed") catch return ClusterApplyError.InternalError;
            rollout_targets.setRequestState(req.request, "failed", "placement_failed");
            self.reportProgress("schedule", batch_start, batch_end, counters.*, failure_details, rollout_targets);
            return;
        };

        if (gang_placements) |gps| {
            defer self.alloc.free(gps);

            var keep_ids = std.ArrayList([]const u8).empty;
            errdefer {
                for (keep_ids.items) |id| self.alloc.free(id);
                keep_ids.deinit(self.alloc);
            }

            for (gps) |gp| {
                const owned_id = generateOwnedAssignmentId(self.alloc) catch return ClusterApplyError.InternalError;
                errdefer self.alloc.free(owned_id);
                keep_ids.append(self.alloc, owned_id) catch return ClusterApplyError.InternalError;

                var sql_buf: [2048]u8 = undefined;
                const sql = scheduler.assignmentSqlGang(
                    &sql_buf,
                    owned_id,
                    gp.agent_id,
                    req.request,
                    nowRealSeconds(),
                    gp,
                ) catch return ClusterApplyError.InternalError;

                _ = self.node.propose(sql) catch return ClusterApplyError.NotLeader;
            }

            scheduled_targets.append(self.alloc, .{
                .request = req.request,
                .assignment_ids = keep_ids.toOwnedSlice(self.alloc) catch return ClusterApplyError.InternalError,
                .placement_count = gps.len,
            }) catch return ClusterApplyError.InternalError;
            rollout_targets.setRequestState(req.request, "starting", null);
            keep_ids.deinit(self.alloc);
            return;
        }

        counters.failed += req.request.gang_world_size;
        counters.failed_targets += 1;
        failure_details.appendRequest(req, "placement_failed") catch return ClusterApplyError.InternalError;
        rollout_targets.setRequestState(req.request, "failed", "placement_failed");
        self.reportProgress("schedule", batch_start, batch_end, counters.*, failure_details, rollout_targets);
    }

    fn applySingleRequest(
        self: *const ClusterApplyBackend,
        req: apply_request.ServiceRequest,
        batch_start: usize,
        batch_end: usize,
        failure_details: *FailureDetailBuilder,
        rollout_targets: *RolloutTargetBuilder,
        counters: *ApplyCounters,
        scheduled_targets: *std.ArrayListUnmanaged(ScheduledTarget),
    ) ClusterApplyError!void {
        if (isTerminalRolloutTargetState(rollout_targets.stateForRequest(req.request))) return;
        const placements = scheduler.schedule(self.alloc, &[_]scheduler.PlacementRequest{req.request}, self.agents) catch {
            return ClusterApplyError.InternalError;
        };
        defer self.alloc.free(placements);

        if (placements.len == 0 or placements[0] == null) {
            counters.failed += 1;
            counters.failed_targets += 1;
            failure_details.appendRequest(req, "placement_failed") catch return ClusterApplyError.InternalError;
            rollout_targets.setRequestState(req.request, "failed", "placement_failed");
            self.reportProgress("schedule", batch_start, batch_end, counters.*, failure_details, rollout_targets);
            return;
        }

        const placement = placements[0].?;
        const owned_id = generateOwnedAssignmentId(self.alloc) catch return ClusterApplyError.InternalError;
        errdefer self.alloc.free(owned_id);

        var sql_buf: [1024]u8 = undefined;
        const sql = scheduler.assignmentSql(
            &sql_buf,
            owned_id,
            placement.agent_id,
            req.request,
            nowRealSeconds(),
        ) catch return ClusterApplyError.InternalError;

        _ = self.node.propose(sql) catch return ClusterApplyError.NotLeader;

        const assignment_ids = self.alloc.alloc([]const u8, 1) catch return ClusterApplyError.InternalError;
        assignment_ids[0] = owned_id;
        errdefer {
            self.alloc.free(owned_id);
            self.alloc.free(assignment_ids);
        }

        scheduled_targets.append(self.alloc, .{
            .request = req.request,
            .assignment_ids = assignment_ids,
            .placement_count = 1,
        }) catch return ClusterApplyError.InternalError;
        rollout_targets.setRequestState(req.request, "starting", null);
    }

    fn reportProgress(
        self: *const ClusterApplyBackend,
        phase: []const u8,
        batch_start: usize,
        batch_end: usize,
        counters: ApplyCounters,
        failure_details: *FailureDetailBuilder,
        rollout_targets: *RolloutTargetBuilder,
    ) void {
        if (self.progress) |progress| {
            const failure_details_json = failure_details.toOwnedJson() catch return;
            defer if (failure_details_json) |json| self.alloc.free(json);
            const rollout_targets_json = rollout_targets.toOwnedJson() catch return;
            defer if (rollout_targets_json) |json| self.alloc.free(json);
            const checkpoint_json = apply_release.buildRolloutCheckpointJson(
                self.alloc,
                "cluster",
                phase,
                batch_start,
                batch_end,
                self.requests.len,
                counters.completed_targets,
                counters.failed_targets,
                progress.controlState(),
            ) catch return;
            defer self.alloc.free(checkpoint_json);
            progress.markDetails(.in_progress, null, counters.completed_targets, counters.failed_targets, failure_details_json, rollout_targets_json, checkpoint_json) catch {};
        }
    }

    fn awaitControl(self: *const ClusterApplyBackend) bool {
        if (self.progress) |progress| {
            return progress.waitWhilePaused() catch false;
        }
        return false;
    }

    pub fn failureMessage(_: *const ClusterApplyBackend, err: ClusterApplyError) ?[]const u8 {
        return switch (err) {
            error.NotLeader => "leadership changed during apply",
            error.InternalError => "scheduler error during apply",
        };
    }

    pub fn finalizeBatchTargets(
        self: *const ClusterApplyBackend,
        targets: []ScheduledTarget,
        failure_action: rollout_spec.RolloutFailureAction,
        rollback_state: ?*RollbackState,
        failure_details: *FailureDetailBuilder,
        rollout_targets: *RolloutTargetBuilder,
        timeout_secs: u32,
        counters: *ApplyCounters,
        batch_start: usize,
        batch_end: usize,
    ) ClusterApplyError!void {
        const db = self.node.stateMachineDb();
        const states = readiness.resolveTargetReadinessStates(self.alloc, db, targets, timeout_secs, self.progress) catch return ClusterApplyError.InternalError;
        defer self.alloc.free(states);

        if (self.awaitControl()) {
            for (targets) |target| {
                rollout_targets.setTargetState(target, "failed", "canceled_by_operator");
                try rollback.discardTarget(self.node, target);
            }
            counters.failed_targets += targets.len;
            self.reportProgress("cutover", batch_start, batch_end, counters.*, failure_details, rollout_targets);
            return;
        }

        const batch_has_failure = blk: {
            for (states) |state| {
                if (state != .ready) break :blk true;
            }
            break :blk false;
        };

        if (failure_action == .rollback and batch_has_failure) {
            for (targets, states) |target, state| {
                if (state != .ready) {
                    failure_details.appendTarget(target, readiness.failureReason(state)) catch return ClusterApplyError.InternalError;
                    rollout_targets.setTargetState(target, "failed", readiness.failureReason(state));
                } else {
                    rollout_targets.setTargetState(target, "rolled_back", "rollback_reverted");
                }
                try rollback.discardTarget(self.node, target);
            }
            counters.failed_targets += targets.len;
            if (rollback_state) |state| {
                try state.rollbackActivatedTargets(self.node);
                state.markActivatedTargets(rollout_targets, "rolled_back", "rollback_reverted");
                counters.completed_targets = 0;
                counters.placed = 0;
            }
            self.reportProgress("cutover", batch_start, batch_end, counters.*, failure_details, rollout_targets);
            return;
        }

        for (targets, states) |target, state| {
            switch (state) {
                .ready => {
                    try rollback.activateTarget(self.node, target);
                    if (rollback_state) |state_tracker| try state_tracker.recordActivatedTarget(target);
                    rollout_targets.setTargetState(target, "ready", null);
                    counters.placed += target.placement_count;
                    counters.completed_targets += 1;
                    self.reportProgress("cutover", batch_start, batch_end, counters.*, failure_details, rollout_targets);
                },
                .pending,
                .missing,
                .image_pull_failed,
                .rootfs_assemble_failed,
                .container_id_failed,
                .container_record_failed,
                .start_failed,
                .readiness_timeout,
                .readiness_failed,
                .readiness_invalid,
                .process_failed,
                .failed,
                => {
                    const reason = readiness.failureReason(state);
                    failure_details.appendTarget(target, reason) catch return ClusterApplyError.InternalError;
                    rollout_targets.setTargetState(target, "failed", reason);
                    switch (failure_action) {
                        .rollback, .pause => try rollback.discardTarget(self.node, target),
                    }
                    counters.failed_targets += 1;
                    self.reportProgress("cutover", batch_start, batch_end, counters.*, failure_details, rollout_targets);
                },
            }
        }
    }
};

fn loadResumeSeed(
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    progress: ?apply_release.ProgressRecorder,
) ResumeSeed {
    const recorder = progress orelse return .{};
    const dep = store.getDeploymentInDb(db, alloc, recorder.release_id) catch return .{};
    defer dep.deinit(alloc);

    return .{
        .completed_targets = dep.completed_targets,
        .failed_targets = dep.failed_targets,
        .rollout_targets_json = if (dep.rollout_targets_json) |json| alloc.dupe(u8, json) catch null else null,
    };
}

fn isTerminalRolloutTargetState(state: []const u8) bool {
    return rollout_targets_mod.isTerminalState(state);
}

pub fn effectiveClusterRollout(requests: []const apply_request.ServiceRequest) rollout_spec.RolloutPolicy {
    var strategy: rollout_spec.RolloutPolicy = .{};
    if (requests.len == 0) return strategy;

    strategy = requests[0].rollout;
    for (requests[1..]) |req| {
        strategy.strategy = mergeClusterRolloutStrategy(strategy.strategy, req.rollout.strategy);
        strategy.parallelism = @min(strategy.parallelism, req.rollout.parallelism);
        strategy.delay_between_batches = @max(strategy.delay_between_batches, req.rollout.delay_between_batches);
        strategy.health_check_timeout = @max(strategy.health_check_timeout, req.rollout.health_check_timeout);
        if (req.rollout.failure_action == .pause) strategy.failure_action = .pause;
    }
    return strategy;
}

fn mergeClusterRolloutStrategy(
    left: rollout_spec.RolloutStrategy,
    right: rollout_spec.RolloutStrategy,
) rollout_spec.RolloutStrategy {
    return switch (left) {
        .blue_green => .blue_green,
        .canary => if (right == .blue_green) .blue_green else .canary,
        .rolling => right,
    };
}

pub fn nextClusterBatchEnd(
    strategy: rollout_spec.RolloutPolicy,
    start: usize,
    total: usize,
    first_batch: bool,
) usize {
    if (start >= total) return total;
    return switch (strategy.strategy) {
        .blue_green => total,
        .canary => if (first_batch)
            @min(start + 1, total)
        else
            @min(start + @max(@as(usize, 1), @as(usize, strategy.parallelism)), total),
        .rolling => @min(start + @max(@as(usize, 1), @as(usize, strategy.parallelism)), total),
    };
}

fn generateOwnedAssignmentId(alloc: std.mem.Allocator) ![]u8 {
    var id_buf: [12]u8 = undefined;
    scheduler.generateAssignmentId(&id_buf);
    return alloc.dupe(u8, id_buf[0..]);
}

const RolloutNodeHarness = struct {
    alloc: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    node: *cluster_node.Node,

    fn init(alloc: std.mem.Allocator) !RolloutNodeHarness {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var path_buf: [512]u8 = undefined;
        const tmp_path_len = tmp.dir.realPathFile(std.testing.io, ".", &path_buf) catch return error.SkipZigTest;
        const tmp_path = path_buf[0..tmp_path_len];

        const node = try alloc.create(cluster_node.Node);
        errdefer alloc.destroy(node);

        node.* = cluster_node.Node.init(alloc, .{
            .id = 1,
            .port = 0,
            .peers = &.{},
            .data_dir = tmp_path,
        }) catch return error.SkipZigTest;
        errdefer node.deinit();
        node.fixPointers();

        node.raft.role = .leader;
        node.leader_id = node.config.id;

        return .{
            .alloc = alloc,
            .tmp = tmp,
            .node = node,
        };
    }

    fn deinit(self: *RolloutNodeHarness) void {
        self.node.deinit();
        self.alloc.destroy(self.node);
        self.tmp.cleanup();
    }

    fn applyCommitted(self: *RolloutNodeHarness) void {
        self.node.state_machine.applyUpTo(&self.node.log, self.alloc, self.node.log.lastIndex());
        self.node.raft.role = .leader;
        self.node.leader_id = self.node.config.id;
    }
};

fn makeTestProgressRecorder(release_id: []const u8) apply_release.ProgressRecorder {
    const Dummy = struct {
        fn mark(
            _: *anyopaque,
            _: []const u8,
            _: @import("../../../manifest/update/common.zig").DeploymentStatus,
            _: ?[]const u8,
            _: usize,
            _: usize,
            _: ?[]const u8,
            _: ?[]const u8,
            _: ?[]const u8,
        ) anyerror!void {}
    };

    return .{
        .ctx = @ptrFromInt(1),
        .release_id = release_id,
        .markFn = Dummy.mark,
    };
}
test "effectiveClusterRollout chooses conservative service rollout settings" {
    const requests = [_]apply_request.ServiceRequest{
        .{
            .request = .{
                .image = "nginx:1",
                .command = "echo first",
                .cpu_limit = 1000,
                .memory_limit_mb = 256,
            },
            .rollout = .{
                .strategy = .canary,
                .parallelism = 3,
                .delay_between_batches = 2,
                .health_check_timeout = 5,
            },
        },
        .{
            .request = .{
                .image = "nginx:2",
                .command = "echo second",
                .cpu_limit = 1000,
                .memory_limit_mb = 256,
            },
            .rollout = .{
                .strategy = .blue_green,
                .parallelism = 2,
                .delay_between_batches = 4,
                .failure_action = .pause,
                .health_check_timeout = 12,
            },
        },
    };

    const rollout = effectiveClusterRollout(&requests);
    try std.testing.expectEqual(rollout_spec.RolloutStrategy.blue_green, rollout.strategy);
    try std.testing.expectEqual(@as(u32, 2), rollout.parallelism);
    try std.testing.expectEqual(@as(u32, 4), rollout.delay_between_batches);
    try std.testing.expectEqual(@as(u32, 12), rollout.health_check_timeout);
    try std.testing.expectEqual(rollout_spec.RolloutFailureAction.pause, rollout.failure_action);
}

test "nextClusterBatchEnd uses canary first batch then configured parallelism" {
    const rollout: rollout_spec.RolloutPolicy = .{
        .strategy = .canary,
        .parallelism = 3,
    };

    try std.testing.expectEqual(@as(usize, 1), nextClusterBatchEnd(rollout, 0, 5, true));
    try std.testing.expectEqual(@as(usize, 4), nextClusterBatchEnd(rollout, 1, 5, false));
}

test "nextClusterBatchEnd uses full batch for blue green" {
    const rollout: rollout_spec.RolloutPolicy = .{
        .strategy = .blue_green,
        .parallelism = 1,
    };

    try std.testing.expectEqual(@as(usize, 5), nextClusterBatchEnd(rollout, 0, 5, true));
}

test "queryTargetReadiness returns ready when all assignments are running" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    try db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, created_at) VALUES (?, ?, ?, ?, ?), (?, ?, ?, ?, ?);",
        .{},
        .{
            "a1", "agent1", "nginx:1", "running", @as(i64, 1),
            "a2", "agent1", "nginx:1", "running", @as(i64, 1),
        },
    );

    try std.testing.expectEqual(
        TargetReadiness.ready,
        try queryTargetReadiness(std.testing.allocator, &db, &.{ "a1", "a2" }),
    );
}

test "queryTargetReadiness returns pending when assignments are not ready yet" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    try db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, created_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "pending", @as(i64, 1) },
    );

    try std.testing.expectEqual(
        TargetReadiness.pending,
        try queryTargetReadiness(std.testing.allocator, &db, &.{"a1"}),
    );
}

test "queryTargetReadiness returns failed when any assignment is terminal" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    try db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, created_at) VALUES (?, ?, ?, ?, ?), (?, ?, ?, ?, ?);",
        .{},
        .{
            "a1", "agent1", "nginx:1", "running", @as(i64, 1),
            "a2", "agent1", "nginx:1", "failed",  @as(i64, 1),
        },
    );

    try std.testing.expectEqual(
        TargetReadiness.failed,
        try queryTargetReadiness(std.testing.allocator, &db, &.{ "a1", "a2" }),
    );
}

test "queryTargetReadiness uses explicit status reason from agent" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    try db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, status_reason, created_at) VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "failed", "readiness_failed", @as(i64, 1) },
    );

    try std.testing.expectEqual(
        TargetReadiness.readiness_failed,
        try queryTargetReadiness(std.testing.allocator, &db, &.{"a1"}),
    );
}

test "queryTargetReadiness preserves exact startup failure reason from agent" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    try db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, status_reason, created_at) VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "failed", "image_pull_failed", @as(i64, 1) },
    );

    try std.testing.expectEqual(
        TargetReadiness.image_pull_failed,
        try queryTargetReadiness(std.testing.allocator, &db, &.{"a1"}),
    );
}

test "queryTargetReadiness preserves process failure reason from agent" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    try db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, status_reason, created_at) VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "failed", "process_failed", @as(i64, 1) },
    );

    try std.testing.expectEqual(
        TargetReadiness.process_failed,
        try queryTargetReadiness(std.testing.allocator, &db, &.{"a1"}),
    );
}

test "queryTargetReadiness returns missing when assignment row disappears" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    try std.testing.expectEqual(
        TargetReadiness.missing,
        try queryTargetReadiness(std.testing.allocator, &db, &.{"missing"}),
    );
}

test "resolveTargetReadinessStates leaves pending targets pending when timeout elapses" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    try db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, created_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "pending", @as(i64, 1) },
    );

    const ids = [_][]const u8{"a1"};
    const targets = [_]ScheduledTarget{
        .{
            .request = .{
                .image = "nginx:1",
                .command = "echo hi",
                .cpu_limit = 1000,
                .memory_limit_mb = 256,
            },
            .assignment_ids = ids[0..],
            .placement_count = 1,
        },
    };

    const states = try resolveTargetReadinessStates(std.testing.allocator, &db, &targets, 0, null);
    defer std.testing.allocator.free(states);

    try std.testing.expectEqual(@as(usize, 1), states.len);
    try std.testing.expectEqual(TargetReadiness.pending, states[0]);
}

test "resolveTargetReadinessStates waits for paused rollout control to resume" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();

    try store.saveDeployment(.{
        .id = "dep-pause",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:pause",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "in_progress",
        .message = "apply in progress",
        .created_at = 100,
        .rollout_control_state = "paused",
    });

    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    try db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, created_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "running", @as(i64, 1) },
    );

    const ids = [_][]const u8{"a1"};
    const targets = [_]ScheduledTarget{
        .{
            .request = .{
                .image = "nginx:1",
                .command = "echo hi",
                .cpu_limit = 1000,
                .memory_limit_mb = 256,
            },
            .assignment_ids = ids[0..],
            .placement_count = 1,
        },
    };

    const Dummy = struct {
        fn mark(
            _: *anyopaque,
            _: []const u8,
            _: @import("../../../manifest/update/common.zig").DeploymentStatus,
            _: ?[]const u8,
            _: usize,
            _: usize,
            _: ?[]const u8,
            _: ?[]const u8,
            _: ?[]const u8,
        ) anyerror!void {}
    };
    const recorder: apply_release.ProgressRecorder = .{
        .ctx = @ptrFromInt(1),
        .release_id = "dep-pause",
        .markFn = Dummy.mark,
    };

    const Resumer = struct {
        fn run() void {
            std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(150), .awake) catch return;
            store.updateDeploymentRolloutControlState("dep-pause", "active") catch {};
        }
    };

    const thread = try std.Thread.spawn(.{}, Resumer.run, .{});
    defer thread.join();

    const states = try resolveTargetReadinessStates(alloc, &db, &targets, 1, recorder);
    defer alloc.free(states);

    try std.testing.expectEqual(@as(usize, 1), states.len);
    try std.testing.expectEqual(TargetReadiness.ready, states[0]);
}

test "resolveTargetReadinessStates exits when paused rollout is canceled" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();

    try store.saveDeployment(.{
        .id = "dep-cancel",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:cancel",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "in_progress",
        .message = "apply in progress",
        .created_at = 100,
        .rollout_control_state = "paused",
    });

    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    try db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, created_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "pending", @as(i64, 1) },
    );

    const ids = [_][]const u8{"a1"};
    const targets = [_]ScheduledTarget{
        .{
            .request = .{
                .image = "nginx:1",
                .command = "echo hi",
                .cpu_limit = 1000,
                .memory_limit_mb = 256,
            },
            .assignment_ids = ids[0..],
            .placement_count = 1,
        },
    };

    const Dummy = struct {
        fn mark(
            _: *anyopaque,
            _: []const u8,
            _: @import("../../../manifest/update/common.zig").DeploymentStatus,
            _: ?[]const u8,
            _: usize,
            _: usize,
            _: ?[]const u8,
            _: ?[]const u8,
            _: ?[]const u8,
        ) anyerror!void {}
    };
    const recorder: apply_release.ProgressRecorder = .{
        .ctx = @ptrFromInt(1),
        .release_id = "dep-cancel",
        .markFn = Dummy.mark,
    };

    const Canceler = struct {
        fn run() void {
            std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(150), .awake) catch return;
            store.updateDeploymentRolloutControlState("dep-cancel", "cancel_requested") catch {};
        }
    };

    const thread = try std.Thread.spawn(.{}, Canceler.run, .{});
    defer thread.join();

    const states = try resolveTargetReadinessStates(alloc, &db, &targets, 5, recorder);
    defer alloc.free(states);

    try std.testing.expectEqual(@as(usize, 1), states.len);
    try std.testing.expectEqual(TargetReadiness.pending, states[0]);
}

test "finalizeBatchTargets honors paused rollout resume before cutover" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();

    var harness = try RolloutNodeHarness.init(alloc);
    defer harness.deinit();

    try store.saveDeployment(.{
        .id = "dep-resume",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:resume",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "in_progress",
        .message = "apply in progress",
        .created_at = 100,
        .rollout_control_state = "paused",
    });

    harness.node.stateMachineDb().exec(
        "INSERT INTO assignments (id, agent_id, image, command, status, created_at, app_name, workload_kind, workload_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "new-web", "agent1", "alpine", "echo web", "pending", @as(i64, 1), "demo-app", "service", "web" },
    ) catch return error.SkipZigTest;

    const ids = [_][]const u8{"new-web"};
    var targets = [_]ScheduledTarget{
        .{
            .request = .{
                .image = "alpine",
                .command = "echo web",
                .cpu_limit = 1000,
                .memory_limit_mb = 256,
                .app_name = "demo-app",
                .workload_kind = "service",
                .workload_name = "web",
            },
            .assignment_ids = ids[0..],
            .placement_count = 1,
        },
    };

    var backend = ClusterApplyBackend{
        .alloc = alloc,
        .node = harness.node,
        .requests = &.{},
        .agents = &.{},
        .progress = makeTestProgressRecorder("dep-resume"),
    };
    var failure_details = FailureDetailBuilder.init(alloc);
    defer failure_details.deinit();
    var rollout_targets = RolloutTargetBuilder.init(alloc);
    defer rollout_targets.deinit();
    try rollout_targets.appendRequests(&.{.{
        .request = targets[0].request,
        .rollout = .{},
    }});

    var counters = ApplyCounters{
        .placed = 0,
        .failed = 0,
        .completed_targets = 0,
        .failed_targets = 0,
    };

    const Resumer = struct {
        fn run(db: *sqlite.Db) void {
            std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(150), .awake) catch return;
            db.exec("UPDATE assignments SET status = 'running' WHERE id = 'new-web';", .{}, .{}) catch {};
            store.updateDeploymentRolloutControlState("dep-resume", "active") catch {};
        }
    };

    const thread = try std.Thread.spawn(.{}, Resumer.run, .{harness.node.stateMachineDb()});
    defer thread.join();

    try backend.finalizeBatchTargets(
        targets[0..],
        .pause,
        null,
        &failure_details,
        &rollout_targets,
        5,
        &counters,
        0,
        1,
    );
    harness.applyCommitted();

    try std.testing.expectEqual(@as(usize, 1), counters.placed);
    try std.testing.expectEqual(@as(usize, 0), counters.failed);
    try std.testing.expectEqual(@as(usize, 1), counters.completed_targets);
    try std.testing.expectEqual(@as(usize, 0), counters.failed_targets);

    const assignments = try agent_registry.listAssignmentsForWorkload(
        alloc,
        harness.node.stateMachineDb(),
        "demo-app",
        "service",
        "web",
    );
    defer {
        for (assignments) |assignment| assignment.deinit(alloc);
        alloc.free(assignments);
    }
    try std.testing.expectEqual(@as(usize, 1), assignments.len);
    try std.testing.expectEqualStrings("new-web", assignments[0].id);
    try std.testing.expectEqualStrings("running", assignments[0].status);
}
test "finalizeBatchTargets discards scheduled targets when paused rollout is canceled" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();

    var harness = try RolloutNodeHarness.init(alloc);
    defer harness.deinit();

    try store.saveDeployment(.{
        .id = "dep-cancel-finalize",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:cancel-finalize",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "in_progress",
        .message = "apply in progress",
        .created_at = 100,
        .rollout_control_state = "paused",
    });

    harness.node.stateMachineDb().exec(
        "INSERT INTO assignments (id, agent_id, image, command, status, created_at, app_name, workload_kind, workload_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "new-web", "agent1", "alpine", "echo web", "pending", @as(i64, 1), "demo-app", "service", "web" },
    ) catch return error.SkipZigTest;

    const ids = [_][]const u8{"new-web"};
    var targets = [_]ScheduledTarget{
        .{
            .request = .{
                .image = "alpine",
                .command = "echo web",
                .cpu_limit = 1000,
                .memory_limit_mb = 256,
                .app_name = "demo-app",
                .workload_kind = "service",
                .workload_name = "web",
            },
            .assignment_ids = ids[0..],
            .placement_count = 1,
        },
    };

    var backend = ClusterApplyBackend{
        .alloc = alloc,
        .node = harness.node,
        .requests = &.{},
        .agents = &.{},
        .progress = makeTestProgressRecorder("dep-cancel-finalize"),
    };
    var failure_details = FailureDetailBuilder.init(alloc);
    defer failure_details.deinit();
    var rollout_targets = RolloutTargetBuilder.init(alloc);
    defer rollout_targets.deinit();
    try rollout_targets.appendRequests(&.{.{
        .request = targets[0].request,
        .rollout = .{},
    }});

    var counters = ApplyCounters{
        .placed = 0,
        .failed = 0,
        .completed_targets = 0,
        .failed_targets = 0,
    };

    const Canceler = struct {
        fn run() void {
            std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(150), .awake) catch return;
            store.updateDeploymentRolloutControlState("dep-cancel-finalize", "cancel_requested") catch {};
        }
    };

    const thread = try std.Thread.spawn(.{}, Canceler.run, .{});
    defer thread.join();

    try backend.finalizeBatchTargets(
        targets[0..],
        .pause,
        null,
        &failure_details,
        &rollout_targets,
        5,
        &counters,
        0,
        1,
    );
    harness.applyCommitted();

    try std.testing.expectEqual(@as(usize, 0), counters.placed);
    try std.testing.expectEqual(@as(usize, 0), counters.failed);
    try std.testing.expectEqual(@as(usize, 0), counters.completed_targets);
    try std.testing.expectEqual(@as(usize, 1), counters.failed_targets);

    const assignments = try agent_registry.listAssignmentsForWorkload(
        alloc,
        harness.node.stateMachineDb(),
        "demo-app",
        "service",
        "web",
    );
    defer {
        for (assignments) |assignment| assignment.deinit(alloc);
        alloc.free(assignments);
    }
    try std.testing.expectEqual(@as(usize, 0), assignments.len);

    const rollout_json = try rollout_targets.toOwnedJson();
    defer if (rollout_json) |json| alloc.free(json);
    try std.testing.expect(rollout_json != null);
    try std.testing.expect(std.mem.indexOf(u8, rollout_json.?, "\"reason\":\"canceled_by_operator\"") != null);
}

test "rollback state restores prior assignments after cutover" {
    const alloc = std.testing.allocator;
    var harness = try RolloutNodeHarness.init(alloc);
    defer harness.deinit();

    const request: scheduler.PlacementRequest = .{
        .image = "alpine",
        .command = "echo web",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
        .app_name = "demo-app",
        .workload_kind = "service",
        .workload_name = "web",
    };

    harness.node.stateMachineDb().exec(
        "INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, app_name, workload_kind, workload_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "old-web", "agent1", "alpine", "echo old", "running", @as(i64, 1000), @as(i64, 256), "demo-app", "service", "web", @as(i64, 1) },
    ) catch return error.SkipZigTest;

    var rollback_state = try RollbackState.capture(alloc, harness.node.stateMachineDb(), &.{.{ .request = request, .rollout = .{} }});
    defer rollback_state.deinit();

    harness.node.stateMachineDb().exec("DELETE FROM assignments WHERE app_name = ? AND workload_kind = ? AND workload_name = ?;", .{}, .{ "demo-app", "service", "web" }) catch return error.SkipZigTest;
    harness.node.stateMachineDb().exec(
        "INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, app_name, workload_kind, workload_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "new-web", "agent1", "alpine", "echo new", "running", @as(i64, 1000), @as(i64, 256), "demo-app", "service", "web", @as(i64, 2) },
    ) catch return error.SkipZigTest;

    try rollback_state.recordActivatedTarget(.{
        .request = request,
        .assignment_ids = &.{"new-web"},
        .placement_count = 1,
    });
    try rollback_state.rollbackActivatedTargets(harness.node);
    harness.applyCommitted();

    const assignments = try agent_registry.listAssignmentsForWorkload(
        alloc,
        harness.node.stateMachineDb(),
        "demo-app",
        "service",
        "web",
    );
    defer {
        for (assignments) |assignment| assignment.deinit(alloc);
        alloc.free(assignments);
    }

    try std.testing.expectEqual(@as(usize, 1), assignments.len);
    try std.testing.expectEqualStrings("old-web", assignments[0].id);
    try std.testing.expectEqualStrings("pending", assignments[0].status);
}
