const std = @import("std");
const platform = @import("platform");
const sqlite = @import("sqlite");
const gpu_scheduler = @import("../../../gpu/scheduler.zig");
const scheduler = @import("../../../cluster/scheduler.zig");
const cluster_node = @import("../../../cluster/node.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const apply_release = @import("../../../manifest/apply_release.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const apply_request = @import("apply_request.zig");
const volumes_mod = @import("../../../state/volumes.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const deployment_store = @import("../../../manifest/update/deployment_store.zig");
const rollout_spec = @import("../../../manifest/spec.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

var active_rollout_mu: platform.Mutex = .{};
var active_rollouts: std.StringHashMapUnmanaged(void) = .empty;

const ResumeSeed = struct {
    completed_targets: usize = 0,
    failed_targets: usize = 0,
    rollout_targets_json: ?[]u8 = null,

    fn deinit(self: ResumeSeed, alloc: std.mem.Allocator) void {
        if (self.rollout_targets_json) |json| alloc.free(json);
    }
};

const ResponseMode = enum {
    legacy,
    app,
};

pub const ClusterApplyError = error{
    NotLeader,
    InternalError,
};

const ClusterReleaseTracker = struct {
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    app_name: ?[]const u8,
    config_snapshot: []const u8,
    context: apply_release.ApplyContext = .{},

    pub fn begin(self: *const ClusterReleaseTracker) !?[]const u8 {
        if (self.context.continue_release_id) |existing_id| {
            const resumed_id = self.alloc.dupe(u8, existing_id) catch return ClusterApplyError.InternalError;
            errdefer self.alloc.free(resumed_id);
            markClusterRolloutActive(existing_id) catch return ClusterApplyError.InternalError;
            return resumed_id;
        }
        const name = self.app_name orelse return null;
        const manifest_hash = deployment_store.computeManifestHash(self.alloc, self.config_snapshot) catch return ClusterApplyError.InternalError;
        defer self.alloc.free(manifest_hash);

        const id = deployment_store.generateDeploymentId(self.alloc) catch return ClusterApplyError.InternalError;
        errdefer self.alloc.free(id);

        deployment_store.recordDeploymentInDb(
            self.db,
            id,
            name,
            name,
            self.context.trigger.toString(),
            self.context.source_release_id,
            self.context.resumed_from_release_id,
            manifest_hash,
            self.config_snapshot,
            0,
            0,
            .pending,
            null,
            null,
            null,
            null,
        ) catch return ClusterApplyError.InternalError;

        markClusterRolloutActive(id) catch return ClusterApplyError.InternalError;

        return id;
    }

    pub fn mark(self: *const ClusterReleaseTracker, id: []const u8, status: @import("../../../manifest/update/common.zig").DeploymentStatus, message: ?[]const u8) !void {
        try self.markProgressDetails(id, status, message, 0, 0, null, null, null);
    }

    pub fn markProgress(
        self: *const ClusterReleaseTracker,
        id: []const u8,
        status: @import("../../../manifest/update/common.zig").DeploymentStatus,
        message: ?[]const u8,
        completed_targets: usize,
        failed_targets: usize,
    ) !void {
        try self.markProgressDetails(id, status, message, completed_targets, failed_targets, null, null, null);
    }

    pub fn markProgressDetails(
        self: *const ClusterReleaseTracker,
        id: []const u8,
        status: @import("../../../manifest/update/common.zig").DeploymentStatus,
        message: ?[]const u8,
        completed_targets: usize,
        failed_targets: usize,
        failure_details_json: ?[]const u8,
        rollout_targets_json: ?[]const u8,
        rollout_checkpoint_json: ?[]const u8,
    ) !void {
        const resolved_message = apply_release.materializeMessage(self.alloc, self.context, status, message) catch return ClusterApplyError.InternalError;
        defer if (resolved_message) |msg| self.alloc.free(msg);
        deployment_store.updateDeploymentProgressInDb(
            self.db,
            id,
            status,
            resolved_message,
            completed_targets,
            failed_targets,
            failure_details_json,
            rollout_targets_json,
            rollout_checkpoint_json,
        ) catch return ClusterApplyError.InternalError;
        if (isTerminalStatus(status)) {
            markClusterRolloutInactive(id);
        }
    }

    pub fn freeReleaseId(self: *const ClusterReleaseTracker, id: []const u8) void {
        self.alloc.free(id);
    }
};

fn isTerminalStatus(status: @import("../../../manifest/update/common.zig").DeploymentStatus) bool {
    return switch (status) {
        .pending, .in_progress => false,
        .completed, .partially_failed, .failed, .superseded, .rolled_back => true,
    };
}

fn markClusterRolloutActive(id: []const u8) !void {
    active_rollout_mu.lock();
    defer active_rollout_mu.unlock();

    const entry = try active_rollouts.getOrPut(std.heap.page_allocator, id);
    if (!entry.found_existing) {
        entry.key_ptr.* = try std.heap.page_allocator.dupe(u8, id);
    }
}

fn markClusterRolloutInactive(id: []const u8) void {
    active_rollout_mu.lock();
    defer active_rollout_mu.unlock();

    if (active_rollouts.fetchRemove(id)) |entry| {
        std.heap.page_allocator.free(entry.key);
    }
}

pub fn isClusterRolloutActive(id: []const u8) bool {
    active_rollout_mu.lock();
    defer active_rollout_mu.unlock();
    return active_rollouts.contains(id);
}

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

        var placed: usize = resume_seed.completed_targets;
        var failed: usize = resume_seed.failed_targets;
        var completed_targets: usize = resume_seed.completed_targets;
        var failed_targets: usize = resume_seed.failed_targets;

        var batch_start: usize = 0;
        var first_batch = true;
        while (batch_start < self.requests.len) {
            if (self.awaitControl()) {
                if (strategy.failure_action == .rollback) {
                    if (rollback_state) |state| {
                        try state.rollbackActivatedTargets(self.node);
                        state.markActivatedTargets(&rollout_targets, "rolled_back", "rollback_reverted");
                        completed_targets = 0;
                        placed = 0;
                    }
                }
                return .{
                    .status = if (placed > 0 or failed_targets > 0) .partially_failed else .failed,
                    .message = "rollout canceled by operator",
                    .failure_details_json = failure_details.toOwnedJson() catch return ClusterApplyError.InternalError,
                    .rollout_targets_json = rollout_targets.toOwnedJson() catch return ClusterApplyError.InternalError,
                    .placed = placed,
                    .failed = failed,
                    .completed_targets = completed_targets,
                    .failed_targets = failed_targets,
                };
            }
            const batch_end = nextClusterBatchEnd(strategy, batch_start, self.requests.len, first_batch);
            const batch = self.requests[batch_start..batch_end];
            const batch_failed_before = failed_targets;

            try self.applyBatch(batch, batch_start, batch_end, strategy, rollback_state, &failure_details, &rollout_targets, &placed, &failed, &completed_targets, &failed_targets);

            if (failed_targets > batch_failed_before) break;
            if (strategy.delay_between_batches > 0 and batch_end < self.requests.len) {
                platform.sleep(@as(u64, strategy.delay_between_batches) * std.time.ns_per_s);
            }
            batch_start = batch_end;
            first_batch = false;
        }

        return .{
            .status = if (failed_targets == 0)
                .completed
            else if (completed_targets > 0)
                .partially_failed
            else
                .failed,
            .message = if (failed_targets > 0 and failed == 0)
                "one or more rollout targets failed readiness checks"
            else if (failed == 0)
                "all placements succeeded"
            else
                "one or more placements failed",
            .failure_details_json = failure_details.toOwnedJson() catch return ClusterApplyError.InternalError,
            .rollout_targets_json = rollout_targets.toOwnedJson() catch return ClusterApplyError.InternalError,
            .placed = placed,
            .failed = failed,
            .completed_targets = completed_targets,
            .failed_targets = failed_targets,
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
        placed: *usize,
        failed: *usize,
        completed_targets: *usize,
        failed_targets: *usize,
    ) ClusterApplyError!void {
        const batch_failed_before = failed_targets.*;
        var scheduled_targets: std.ArrayListUnmanaged(ScheduledTarget) = .empty;
        defer {
            for (scheduled_targets.items) |*target| target.deinit(self.alloc);
            scheduled_targets.deinit(self.alloc);
        }

        for (batch) |req| {
            if (req.request.gang_world_size > 0) {
                try self.applyGangRequest(req, batch_start, batch_end, failure_details, rollout_targets, failed, completed_targets, failed_targets, &scheduled_targets);
            } else {
                try self.applySingleRequest(req, batch_start, batch_end, failure_details, rollout_targets, failed, completed_targets, failed_targets, &scheduled_targets);
            }
        }

        if (scheduled_targets.items.len == 0) return;

        if (strategy.failure_action == .rollback and failed_targets.* > batch_failed_before) {
            for (scheduled_targets.items) |target| try discardTarget(self, target);
            if (rollback_state) |state| {
                try state.rollbackActivatedTargets(self.node);
                completed_targets.* = 0;
                placed.* = 0;
                self.reportProgress("schedule", batch_start, batch_end, completed_targets.*, failed_targets.*, failure_details, rollout_targets);
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
                placed,
                failed,
                completed_targets,
                failed_targets,
                batch_start,
                batch_end,
            );
            return;
        }

        for (scheduled_targets.items) |target| {
            try activateTarget(self, target);
            if (rollback_state) |state| try state.recordActivatedTarget(target);
            rollout_targets.setTargetState(target, "ready", null);
            placed.* += target.placement_count;
            completed_targets.* += 1;
            self.reportProgress("cutover", batch_start, batch_end, completed_targets.*, failed_targets.*, failure_details, rollout_targets);
        }
    }

    fn applyGangRequest(
        self: *const ClusterApplyBackend,
        req: apply_request.ServiceRequest,
        batch_start: usize,
        batch_end: usize,
        failure_details: *FailureDetailBuilder,
        rollout_targets: *RolloutTargetBuilder,
        failed: *usize,
        completed_targets: *usize,
        failed_targets: *usize,
        scheduled_targets: *std.ArrayListUnmanaged(ScheduledTarget),
    ) ClusterApplyError!void {
        if (isTerminalRolloutTargetState(rollout_targets.stateForRequest(req.request))) return;
        const gang_placements = scheduler.scheduleGang(self.alloc, req.request, self.agents) catch {
            failed.* += 1;
            failed_targets.* += 1;
            failure_details.appendRequest(req, "placement_failed") catch return ClusterApplyError.InternalError;
            rollout_targets.setRequestState(req.request, "failed", "placement_failed");
            self.reportProgress("schedule", batch_start, batch_end, completed_targets.*, failed_targets.*, failure_details, rollout_targets);
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
                    platform.timestamp(),
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

        failed.* += req.request.gang_world_size;
        failed_targets.* += 1;
        failure_details.appendRequest(req, "placement_failed") catch return ClusterApplyError.InternalError;
        rollout_targets.setRequestState(req.request, "failed", "placement_failed");
        self.reportProgress("schedule", batch_start, batch_end, completed_targets.*, failed_targets.*, failure_details, rollout_targets);
    }

    fn applySingleRequest(
        self: *const ClusterApplyBackend,
        req: apply_request.ServiceRequest,
        batch_start: usize,
        batch_end: usize,
        failure_details: *FailureDetailBuilder,
        rollout_targets: *RolloutTargetBuilder,
        failed: *usize,
        completed_targets: *usize,
        failed_targets: *usize,
        scheduled_targets: *std.ArrayListUnmanaged(ScheduledTarget),
    ) ClusterApplyError!void {
        if (isTerminalRolloutTargetState(rollout_targets.stateForRequest(req.request))) return;
        const placements = scheduler.schedule(self.alloc, &[_]scheduler.PlacementRequest{req.request}, self.agents) catch {
            return ClusterApplyError.InternalError;
        };
        defer self.alloc.free(placements);

        if (placements.len == 0 or placements[0] == null) {
            failed.* += 1;
            failed_targets.* += 1;
            failure_details.appendRequest(req, "placement_failed") catch return ClusterApplyError.InternalError;
            rollout_targets.setRequestState(req.request, "failed", "placement_failed");
            self.reportProgress("schedule", batch_start, batch_end, completed_targets.*, failed_targets.*, failure_details, rollout_targets);
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
            platform.timestamp(),
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
        completed_targets: usize,
        failed_targets: usize,
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
                completed_targets,
                failed_targets,
                progress.controlState(),
            ) catch return;
            defer self.alloc.free(checkpoint_json);
            progress.markDetails(.in_progress, null, completed_targets, failed_targets, failure_details_json, rollout_targets_json, checkpoint_json) catch {};
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

    fn finalizeBatchTargets(
        self: *const ClusterApplyBackend,
        targets: []ScheduledTarget,
        failure_action: rollout_spec.RolloutFailureAction,
        rollback_state: ?*RollbackState,
        failure_details: *FailureDetailBuilder,
        rollout_targets: *RolloutTargetBuilder,
        timeout_secs: u32,
        placed: *usize,
        failed: *usize,
        completed_targets: *usize,
        failed_targets: *usize,
        batch_start: usize,
        batch_end: usize,
    ) ClusterApplyError!void {
        const db = self.node.stateMachineDb();
        const states = resolveTargetReadinessStates(self.alloc, db, targets, timeout_secs, self.progress) catch return ClusterApplyError.InternalError;
        defer self.alloc.free(states);

        if (self.awaitControl()) {
            for (targets) |target| {
                rollout_targets.setTargetState(target, "failed", "canceled_by_operator");
                try discardTarget(self, target);
            }
            failed_targets.* += targets.len;
            self.reportProgress("cutover", batch_start, batch_end, completed_targets.*, failed_targets.*, failure_details, rollout_targets);
            _ = failed;
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
                    failure_details.appendTarget(target, targetFailureReason(state)) catch return ClusterApplyError.InternalError;
                    rollout_targets.setTargetState(target, "failed", targetFailureReason(state));
                } else {
                    rollout_targets.setTargetState(target, "rolled_back", "rollback_reverted");
                }
                try discardTarget(self, target);
            }
            failed_targets.* += targets.len;
            if (rollback_state) |state| {
                try state.rollbackActivatedTargets(self.node);
                state.markActivatedTargets(rollout_targets, "rolled_back", "rollback_reverted");
                completed_targets.* = 0;
                placed.* = 0;
            }
            self.reportProgress("cutover", batch_start, batch_end, completed_targets.*, failed_targets.*, failure_details, rollout_targets);
            _ = failed;
            return;
        }

        for (targets, states) |target, state| {
            switch (state) {
                .ready => {
                    try activateTarget(self, target);
                    if (rollback_state) |state_tracker| try state_tracker.recordActivatedTarget(target);
                    rollout_targets.setTargetState(target, "ready", null);
                    placed.* += target.placement_count;
                    completed_targets.* += 1;
                    self.reportProgress("cutover", batch_start, batch_end, completed_targets.*, failed_targets.*, failure_details, rollout_targets);
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
                    const reason = targetFailureReason(state);
                    failure_details.appendTarget(target, reason) catch return ClusterApplyError.InternalError;
                    rollout_targets.setTargetState(target, "failed", reason);
                    switch (failure_action) {
                        .rollback, .pause => try discardTarget(self, target),
                    }
                    failed_targets.* += 1;
                    self.reportProgress("cutover", batch_start, batch_end, completed_targets.*, failed_targets.*, failure_details, rollout_targets);
                },
            }
        }
        _ = failed;
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

const FailureDetail = struct {
    workload_kind: []const u8,
    workload_name: []const u8,
    reason: []const u8,
};

const RolloutTarget = struct {
    workload_kind: []const u8,
    workload_name: []const u8,
    state: []const u8,
    reason: ?[]const u8 = null,
};

const FailureDetailBuilder = struct {
    alloc: std.mem.Allocator,
    items: std.ArrayListUnmanaged(FailureDetail) = .empty,

    fn init(alloc: std.mem.Allocator) FailureDetailBuilder {
        return .{ .alloc = alloc };
    }

    fn deinit(self: *FailureDetailBuilder) void {
        self.items.deinit(self.alloc);
    }

    fn appendRequest(self: *FailureDetailBuilder, req: apply_request.ServiceRequest, reason: []const u8) !void {
        try self.append(req.request.workload_kind orelse "service", req.request.workload_name orelse req.request.image, reason);
    }

    fn appendTarget(self: *FailureDetailBuilder, target: ScheduledTarget, reason: []const u8) !void {
        try self.append(target.request.workload_kind orelse "service", target.request.workload_name orelse target.request.image, reason);
    }

    fn append(self: *FailureDetailBuilder, workload_kind: []const u8, workload_name: []const u8, reason: []const u8) !void {
        try self.items.append(self.alloc, .{
            .workload_kind = workload_kind,
            .workload_name = workload_name,
            .reason = reason,
        });
    }

    fn toOwnedJson(self: *FailureDetailBuilder) !?[]u8 {
        if (self.items.items.len == 0) return null;

        var json_buf: std.ArrayList(u8) = .empty;
        errdefer json_buf.deinit(self.alloc);
        const writer = platform.arrayListWriter(&json_buf, self.alloc);

        try writer.writeByte('[');
        for (self.items.items, 0..) |detail, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('{');
            try json_helpers.writeJsonStringField(writer, "workload_kind", detail.workload_kind);
            try writer.writeByte(',');
            try json_helpers.writeJsonStringField(writer, "workload_name", detail.workload_name);
            try writer.writeByte(',');
            try json_helpers.writeJsonStringField(writer, "reason", detail.reason);
            try writer.writeByte('}');
        }
        try writer.writeByte(']');
        const owned = try json_buf.toOwnedSlice(self.alloc);
        return owned;
    }
};

const RolloutTargetBuilder = struct {
    alloc: std.mem.Allocator,
    items: std.ArrayListUnmanaged(RolloutTarget) = .empty,

    fn init(alloc: std.mem.Allocator) RolloutTargetBuilder {
        return .{ .alloc = alloc };
    }

    fn deinit(self: *RolloutTargetBuilder) void {
        self.items.deinit(self.alloc);
    }

    fn appendRequests(self: *RolloutTargetBuilder, requests: []const apply_request.ServiceRequest) !void {
        for (requests) |req| {
            try self.items.append(self.alloc, .{
                .workload_kind = req.request.workload_kind orelse "service",
                .workload_name = req.request.workload_name orelse req.request.image,
                .state = "pending",
                .reason = null,
            });
        }
    }

    fn setRequestState(
        self: *RolloutTargetBuilder,
        request: scheduler.PlacementRequest,
        state: []const u8,
        reason: ?[]const u8,
    ) void {
        self.set(
            request.workload_kind orelse "service",
            request.workload_name orelse request.image,
            state,
            reason,
        );
    }

    fn setTargetState(
        self: *RolloutTargetBuilder,
        target: ScheduledTarget,
        state: []const u8,
        reason: ?[]const u8,
    ) void {
        self.set(
            target.request.workload_kind orelse "service",
            target.request.workload_name orelse target.request.image,
            state,
            reason,
        );
    }

    fn setActivatedState(
        self: *RolloutTargetBuilder,
        target: ActivatedTarget,
        state: []const u8,
        reason: ?[]const u8,
    ) void {
        self.set(
            target.request.workload_kind orelse "service",
            target.request.workload_name orelse target.request.image,
            state,
            reason,
        );
    }

    fn set(
        self: *RolloutTargetBuilder,
        workload_kind: []const u8,
        workload_name: []const u8,
        state: []const u8,
        reason: ?[]const u8,
    ) void {
        for (self.items.items) |*item| {
            if (std.mem.eql(u8, item.workload_kind, workload_kind) and std.mem.eql(u8, item.workload_name, workload_name)) {
                item.state = state;
                item.reason = reason;
                return;
            }
        }
    }

    fn stateFor(
        self: *const RolloutTargetBuilder,
        workload_kind: []const u8,
        workload_name: []const u8,
    ) []const u8 {
        for (self.items.items) |item| {
            if (std.mem.eql(u8, item.workload_kind, workload_kind) and std.mem.eql(u8, item.workload_name, workload_name)) {
                return item.state;
            }
        }
        return "pending";
    }

    fn stateForRequest(self: *const RolloutTargetBuilder, request: scheduler.PlacementRequest) []const u8 {
        return self.stateFor(
            request.workload_kind orelse "service",
            request.workload_name orelse request.image,
        );
    }

    fn restoreFromJson(self: *RolloutTargetBuilder, rollout_targets_json: ?[]const u8) void {
        const json = rollout_targets_json orelse return;
        var iter = json_helpers.extractJsonObjects(json);
        while (iter.next()) |obj| {
            const workload_kind = json_helpers.extractJsonString(obj, "workload_kind") orelse continue;
            const workload_name = json_helpers.extractJsonString(obj, "workload_name") orelse continue;
            const state = json_helpers.extractJsonString(obj, "state") orelse continue;
            const reason = json_helpers.extractJsonString(obj, "reason");
            self.set(workload_kind, workload_name, state, reason);
        }
    }

    fn toOwnedJson(self: *RolloutTargetBuilder) !?[]u8 {
        if (self.items.items.len == 0) return null;

        var json_buf: std.ArrayList(u8) = .empty;
        errdefer json_buf.deinit(self.alloc);
        const writer = platform.arrayListWriter(&json_buf, self.alloc);

        try writer.writeByte('[');
        for (self.items.items, 0..) |target, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('{');
            try json_helpers.writeJsonStringField(writer, "workload_kind", target.workload_kind);
            try writer.writeByte(',');
            try json_helpers.writeJsonStringField(writer, "workload_name", target.workload_name);
            try writer.writeByte(',');
            try json_helpers.writeJsonStringField(writer, "state", target.state);
            try writer.writeByte(',');
            try json_helpers.writeNullableJsonStringField(writer, "reason", target.reason);
            try writer.writeByte('}');
        }
        try writer.writeByte(']');
        return try json_buf.toOwnedSlice(self.alloc);
    }
};

fn isTerminalRolloutTargetState(state: []const u8) bool {
    return std.mem.eql(u8, state, "ready") or
        std.mem.eql(u8, state, "failed") or
        std.mem.eql(u8, state, "rolled_back");
}

const ScheduledTarget = struct {
    request: scheduler.PlacementRequest,
    assignment_ids: []const []const u8,
    placement_count: usize,

    fn deinit(self: *const ScheduledTarget, alloc: std.mem.Allocator) void {
        for (self.assignment_ids) |id| alloc.free(id);
        alloc.free(self.assignment_ids);
    }
};

const ActivatedTarget = struct {
    request: scheduler.PlacementRequest,
    assignment_ids: []const []const u8,

    fn deinit(self: *const ActivatedTarget, alloc: std.mem.Allocator) void {
        for (self.assignment_ids) |id| alloc.free(id);
        alloc.free(self.assignment_ids);
    }
};

const PriorAssignmentSnapshot = struct {
    request: scheduler.PlacementRequest,
    assignments: []agent_registry.Assignment,

    fn deinit(self: *const PriorAssignmentSnapshot, alloc: std.mem.Allocator) void {
        for (self.assignments) |assignment| assignment.deinit(alloc);
        alloc.free(self.assignments);
    }
};

const RollbackState = struct {
    alloc: std.mem.Allocator,
    snapshots: []PriorAssignmentSnapshot,
    activated_targets: std.ArrayListUnmanaged(ActivatedTarget) = .empty,

    fn capture(
        alloc: std.mem.Allocator,
        db: *sqlite.Db,
        requests: []const apply_request.ServiceRequest,
    ) ClusterApplyError!RollbackState {
        var snapshots = std.ArrayListUnmanaged(PriorAssignmentSnapshot).empty;
        errdefer {
            for (snapshots.items) |*snapshot| snapshot.deinit(alloc);
            snapshots.deinit(alloc);
        }

        for (requests) |req| {
            const app_name = req.request.app_name orelse continue;
            const workload_kind = req.request.workload_kind orelse continue;
            const workload_name = req.request.workload_name orelse continue;
            const assignments = agent_registry.listAssignmentsForWorkload(
                alloc,
                db,
                app_name,
                workload_kind,
                workload_name,
            ) catch return ClusterApplyError.InternalError;
            snapshots.append(alloc, .{
                .request = req.request,
                .assignments = assignments,
            }) catch return ClusterApplyError.InternalError;
        }

        return .{
            .alloc = alloc,
            .snapshots = snapshots.toOwnedSlice(alloc) catch return ClusterApplyError.InternalError,
        };
    }

    fn deinit(self: *RollbackState) void {
        for (self.snapshots) |*snapshot| snapshot.deinit(self.alloc);
        self.alloc.free(self.snapshots);
        for (self.activated_targets.items) |*target| target.deinit(self.alloc);
        self.activated_targets.deinit(self.alloc);
    }

    fn recordActivatedTarget(self: *RollbackState, target: ScheduledTarget) ClusterApplyError!void {
        const assignment_ids = copyAssignmentIds(self.alloc, target.assignment_ids) catch return ClusterApplyError.InternalError;
        self.activated_targets.append(self.alloc, .{
            .request = target.request,
            .assignment_ids = assignment_ids,
        }) catch return ClusterApplyError.InternalError;
    }

    fn rollbackActivatedTargets(self: *RollbackState, node: *cluster_node.Node) ClusterApplyError!void {
        for (self.activated_targets.items) |target| {
            try deleteAssignmentsForRequest(node, target.request);
            if (self.findSnapshot(target.request)) |snapshot| {
                for (snapshot.assignments) |assignment| {
                    try restoreAssignment(node, assignment);
                }
            }
        }
    }

    fn markActivatedTargets(
        self: *const RollbackState,
        rollout_targets: *RolloutTargetBuilder,
        state: []const u8,
        reason: ?[]const u8,
    ) void {
        for (self.activated_targets.items) |target| {
            rollout_targets.setActivatedState(target, state, reason);
        }
    }

    fn findSnapshot(self: *const RollbackState, request: scheduler.PlacementRequest) ?*const PriorAssignmentSnapshot {
        const app_name = request.app_name orelse return null;
        const workload_kind = request.workload_kind orelse return null;
        const workload_name = request.workload_name orelse return null;
        for (self.snapshots) |*snapshot| {
            if (std.mem.eql(u8, snapshot.request.app_name orelse return null, app_name) and
                std.mem.eql(u8, snapshot.request.workload_kind orelse return null, workload_kind) and
                std.mem.eql(u8, snapshot.request.workload_name orelse return null, workload_name))
            {
                return snapshot;
            }
        }
        return null;
    }
};

fn activateTarget(self: *const ClusterApplyBackend, target: ScheduledTarget) ClusterApplyError!void {
    try reconcilePriorAssignments(self.node, target.request, target.assignment_ids);
}

fn discardTarget(self: *const ClusterApplyBackend, target: ScheduledTarget) ClusterApplyError!void {
    var sql_buf: [2048]u8 = undefined;
    const sql = agent_registry.deleteAssignmentsByIdsSql(&sql_buf, target.assignment_ids) catch return ClusterApplyError.InternalError;
    _ = self.node.propose(sql) catch return ClusterApplyError.NotLeader;
}

fn deleteAssignmentsForRequest(node: *cluster_node.Node, request: scheduler.PlacementRequest) ClusterApplyError!void {
    const app_name = request.app_name orelse return;
    const workload_kind = request.workload_kind orelse return;
    const workload_name = request.workload_name orelse return;

    var sql_buf: [2048]u8 = undefined;
    const sql = agent_registry.deleteAssignmentsForWorkloadSql(
        &sql_buf,
        app_name,
        workload_kind,
        workload_name,
    ) catch return ClusterApplyError.InternalError;
    _ = node.propose(sql) catch return ClusterApplyError.NotLeader;
}

fn restoreAssignment(node: *cluster_node.Node, assignment: agent_registry.Assignment) ClusterApplyError!void {
    var sql_buf: [2048]u8 = undefined;
    const request: scheduler.PlacementRequest = .{
        .image = assignment.image,
        .command = assignment.command,
        .health_check_json = assignment.health_check_json,
        .cpu_limit = assignment.cpu_limit,
        .memory_limit_mb = assignment.memory_limit_mb,
        .app_name = assignment.app_name,
        .workload_kind = assignment.workload_kind,
        .workload_name = assignment.workload_name,
    };

    const sql = if (assignment.gang_rank != null and assignment.gang_world_size != null and assignment.gang_master_addr != null and assignment.gang_master_port != null)
        scheduler.assignmentSqlGang(
            &sql_buf,
            assignment.id,
            assignment.agent_id,
            request,
            platform.timestamp(),
            .{
                .agent_id = assignment.agent_id,
                .rank = @intCast(assignment.gang_rank.?),
                .gpu_start = 0,
                .gpu_count = 0,
                .world_size = @intCast(assignment.gang_world_size.?),
                .master_addr = assignment.gang_master_addr.?,
                .master_port = @intCast(assignment.gang_master_port.?),
            },
        ) catch return ClusterApplyError.InternalError
    else
        scheduler.assignmentSql(
            &sql_buf,
            assignment.id,
            assignment.agent_id,
            request,
            platform.timestamp(),
        ) catch return ClusterApplyError.InternalError;

    _ = node.propose(sql) catch return ClusterApplyError.NotLeader;
}

fn copyAssignmentIds(alloc: std.mem.Allocator, ids: []const []const u8) ![]const []const u8 {
    const owned = try alloc.alloc([]const u8, ids.len);
    errdefer alloc.free(owned);
    for (ids, 0..) |id, i| {
        owned[i] = try alloc.dupe(u8, id);
        errdefer {
            for (owned[0..i]) |prior| alloc.free(prior);
        }
    }
    return owned;
}

const TargetReadiness = enum {
    pending,
    ready,
    missing,
    image_pull_failed,
    rootfs_assemble_failed,
    container_id_failed,
    container_record_failed,
    start_failed,
    readiness_timeout,
    readiness_failed,
    readiness_invalid,
    process_failed,
    failed,
};

fn targetFailureReason(state: TargetReadiness) []const u8 {
    return switch (state) {
        .pending => "readiness_timeout",
        .missing => "assignment_missing",
        .image_pull_failed => "image_pull_failed",
        .rootfs_assemble_failed => "rootfs_assemble_failed",
        .container_id_failed => "container_id_failed",
        .container_record_failed => "container_record_failed",
        .start_failed => "start_failed",
        .readiness_timeout => "readiness_timeout",
        .readiness_failed => "readiness_failed",
        .readiness_invalid => "readiness_invalid",
        .process_failed => "process_failed",
        .failed => "assignment_failed",
        .ready => unreachable,
    };
}

fn resolveTargetReadinessStates(
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    targets: []const ScheduledTarget,
    timeout_secs: u32,
    progress: ?apply_release.ProgressRecorder,
) ![]TargetReadiness {
    var states = try alloc.alloc(TargetReadiness, targets.len);
    errdefer alloc.free(states);
    @memset(states, .pending);

    const deadline_ns: i128 = platform.nanoTimestamp() + (@as(i128, timeout_secs) * std.time.ns_per_s);
    var remaining = targets.len;

    while (remaining > 0) {
        if (progress) |recorder| {
            if (recorder.waitWhilePaused() catch false) return states;
        }
        for (targets, 0..) |target, i| {
            if (states[i] != .pending) continue;

            const state = try queryTargetReadiness(alloc, db, target.assignment_ids);
            if (state == .pending) continue;

            states[i] = state;
            remaining -= 1;
        }

        if (remaining == 0) return states;
        if (platform.nanoTimestamp() >= deadline_ns) break;
        platform.sleep(100 * std.time.ns_per_ms);
    }

    return states;
}

fn queryTargetReadiness(alloc: std.mem.Allocator, db: *sqlite.Db, assignment_ids: []const []const u8) !TargetReadiness {
    if (assignment_ids.len == 0) return .missing;

    var all_running = true;
    for (assignment_ids) |assignment_id| {
        const row = try loadAssignmentState(alloc, db, assignment_id) orelse {
            return .missing;
        };
        defer {
            alloc.free(row.status);
            if (row.status_reason) |status_reason| alloc.free(status_reason);
        }

        if (std.mem.eql(u8, row.status, "running")) continue;
        if (std.mem.eql(u8, row.status, "failed") or std.mem.eql(u8, row.status, "stopped")) {
            if (row.status_reason) |status_reason| {
                if (std.mem.eql(u8, status_reason, "readiness_timeout")) return .readiness_timeout;
                if (std.mem.eql(u8, status_reason, "readiness_failed")) return .readiness_failed;
                if (std.mem.eql(u8, status_reason, "readiness_invalid")) return .readiness_invalid;
                if (std.mem.eql(u8, status_reason, "process_failed")) return .process_failed;
                if (std.mem.eql(u8, status_reason, "image_pull_failed")) return .image_pull_failed;
                if (std.mem.eql(u8, status_reason, "rootfs_assemble_failed")) return .rootfs_assemble_failed;
                if (std.mem.eql(u8, status_reason, "container_id_failed")) return .container_id_failed;
                if (std.mem.eql(u8, status_reason, "container_record_failed")) return .container_record_failed;
                if (std.mem.eql(u8, status_reason, "start_failed")) return .start_failed;
            }
            return .failed;
        }
        all_running = false;
    }

    return if (all_running) .ready else .pending;
}

fn loadAssignmentState(alloc: std.mem.Allocator, db: *sqlite.Db, assignment_id: []const u8) !?struct {
    status: []const u8,
    status_reason: ?[]const u8,
} {
    const Row = struct {
        status: sqlite.Text,
        status_reason: ?sqlite.Text,
    };
    const row = (db.oneAlloc(
        Row,
        alloc,
        "SELECT status, status_reason FROM assignments WHERE id = ?;",
        .{},
        .{assignment_id},
    ) catch return error.QueryFailed) orelse return null;
    return .{
        .status = row.status.data,
        .status_reason = if (row.status_reason) |status_reason| status_reason.data else null,
    };
}

fn effectiveClusterRollout(requests: []const apply_request.ServiceRequest) rollout_spec.RolloutPolicy {
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

fn nextClusterBatchEnd(
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

fn reconcilePriorAssignments(
    node: *cluster_node.Node,
    request: scheduler.PlacementRequest,
    keep_ids: []const []const u8,
) ClusterApplyError!void {
    const app_name = request.app_name orelse return;
    const workload_kind = request.workload_kind orelse return;
    const workload_name = request.workload_name orelse return;

    var sql_buf: [2048]u8 = undefined;
    const sql = agent_registry.deleteOtherAssignmentsForWorkloadSql(
        &sql_buf,
        app_name,
        workload_kind,
        workload_name,
        keep_ids,
    ) catch return ClusterApplyError.InternalError;
    _ = node.propose(sql) catch return ClusterApplyError.NotLeader;
}

fn handleApply(
    alloc: std.mem.Allocator,
    request: @import("../../http.zig").Request,
    ctx: RouteContext,
    response_mode: ResponseMode,
    apply_context: apply_release.ApplyContext,
) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (request.body.len == 0) return common.badRequest("missing request body");

    var parsed = apply_request.parse(alloc, request.body, response_mode == .app) catch |err| return switch (err) {
        apply_request.ParseError.MissingAppName => common.badRequest("missing app_name"),
        apply_request.ParseError.MissingServicesArray => common.badRequest("missing services array"),
        apply_request.ParseError.NoServices => common.badRequest("no services to deploy"),
        apply_request.ParseError.OutOfMemory => common.internalError(),
        apply_request.ParseError.InvalidRequest => common.badRequest("invalid request body"),
        apply_request.ParseError.InvalidRolloutConfig => common.badRequest("invalid rollout config"),
    };
    defer parsed.deinit(alloc);

    const db = node.stateMachineDb();

    const vol_constraints = if (parsed.app_name) |name|
        volumes_mod.getVolumesByApp(alloc, db, name) catch &[_]volumes_mod.VolumeConstraint{}
    else
        &[_]volumes_mod.VolumeConstraint{};
    defer if (parsed.app_name != null) alloc.free(vol_constraints);

    parsed.setVolumeConstraints(vol_constraints);

    const agents = if (parsed.requests.items.len > 0)
        agent_registry.listAgents(alloc, db) catch return common.internalError()
    else
        alloc.alloc(agent_registry.AgentRecord, 0) catch return common.internalError();
    defer {
        for (agents) |a| a.deinit(alloc);
        alloc.free(agents);
    }

    if (parsed.requests.items.len > 0 and agents.len == 0) {
        return .{ .status = .bad_request, .body = "{\"error\":\"no agents available\"}", .allocated = false };
    }

    var tracker = ClusterReleaseTracker{
        .alloc = alloc,
        .db = db,
        .app_name = parsed.app_name,
        .config_snapshot = request.body,
        .context = apply_context,
    };
    var backend = ClusterApplyBackend{
        .alloc = alloc,
        .node = node,
        .requests = parsed.requests.items,
        .agents = agents,
    };
    const apply_result = apply_release.execute(&tracker, &backend) catch |err| switch (err) {
        ClusterApplyError.NotLeader => return common.notLeader(alloc, node),
        ClusterApplyError.InternalError => return common.internalError(),
    };
    const apply_report = apply_result.toReport(parsed.app_name orelse "", parsed.requests.items.len, apply_context);
    defer apply_report.deinit(alloc);

    if (parsed.app_name) |app_name| {
        if (apply_result.outcome.status != .failed) {
            reconcileCronSchedules(db, alloc, app_name, request.body) catch return common.internalError();
        }
    }

    const body = switch (response_mode) {
        .legacy => formatLegacyApplyResponse(alloc, apply_report.placed, apply_report.failed) catch return common.internalError(),
        .app => formatAppApplyResponse(alloc, apply_report, parsed.summary) catch return common.internalError(),
    };
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn reconcileCronSchedules(db: *sqlite.Db, alloc: std.mem.Allocator, app_name: []const u8, config_snapshot: []const u8) !void {
    var schedules = try app_snapshot.listCronSchedules(alloc, config_snapshot);
    defer {
        for (schedules.items) |schedule| schedule.deinit(alloc);
        schedules.deinit(alloc);
    }

    try store.replaceCronSchedulesForAppInDb(
        db,
        alloc,
        app_name,
        schedules.items,
        platform.timestamp(),
    );
}

pub fn handleAppApply(alloc: std.mem.Allocator, request: @import("../../http.zig").Request, ctx: RouteContext) Response {
    return handleApply(alloc, request, ctx, .app, .{});
}

pub fn handleAppApplyWithContext(
    alloc: std.mem.Allocator,
    request: @import("../../http.zig").Request,
    ctx: RouteContext,
    apply_context: apply_release.ApplyContext,
) Response {
    return handleApply(alloc, request, ctx, .app, apply_context);
}

pub fn handleDeploy(alloc: std.mem.Allocator, request: @import("../../http.zig").Request, ctx: RouteContext) Response {
    return handleApply(alloc, request, ctx, .legacy, .{});
}

pub fn handleAppRollbackApply(
    alloc: std.mem.Allocator,
    request: @import("../../http.zig").Request,
    ctx: RouteContext,
    source_release_id: []const u8,
) Response {
    return handleAppRollbackApplyWithContext(alloc, request, ctx, .{
        .trigger = .rollback,
        .source_release_id = source_release_id,
    });
}

pub fn handleAppRollbackApplyWithContext(
    alloc: std.mem.Allocator,
    request: @import("../../http.zig").Request,
    ctx: RouteContext,
    apply_context: apply_release.ApplyContext,
) Response {
    return handleApply(alloc, request, ctx, .app, apply_context);
}

fn formatLegacyApplyResponse(alloc: std.mem.Allocator, placed: usize, failed: usize) ![]u8 {
    return std.fmt.allocPrint(alloc, "{{\"placed\":{d},\"failed\":{d}}}", .{ placed, failed });
}

fn formatAppApplyResponse(
    alloc: std.mem.Allocator,
    report: apply_release.ApplyReport,
    summary: app_snapshot.Summary,
) ![]u8 {
    var json_buf: std.ArrayList(u8) = .empty;
    errdefer json_buf.deinit(alloc);
    const writer = platform.arrayListWriter(&json_buf, alloc);

    try writer.writeByte('{');
    try json_helpers.writeJsonStringField(writer, "app_name", report.app_name);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "trigger", report.trigger.toString());
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "release_id", report.release_id orelse "");
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "status", report.status.toString());
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "rollout_state", report.rolloutState());
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "rollout_control_state", report.rollout_control_state.toString());
    try writer.print(",\"service_count\":{d},\"worker_count\":{d},\"cron_count\":{d},\"training_job_count\":{d},\"placed\":{d},\"failed\":{d},\"completed_targets\":{d},\"failed_targets\":{d},\"remaining_targets\":{d}", .{
        summary.service_count,
        summary.worker_count,
        summary.cron_count,
        summary.training_job_count,
        report.placed,
        report.failed,
        report.completed_targets,
        report.failed_targets,
        report.remainingTargets(),
    });
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "source_release_id", report.source_release_id);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "resumed_from_release_id", report.resumed_from_release_id);

    const resolved_message = try report.resolvedMessage(alloc);
    defer if (resolved_message) |message| alloc.free(message);

    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "message", resolved_message);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "failure_details", report.failure_details_json);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "rollout_targets", report.rollout_targets_json);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "rollout_checkpoint", report.rollout_checkpoint_json);
    try writer.writeAll(",\"rollout\":{");
    try json_helpers.writeJsonStringField(writer, "state", report.rolloutState());
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "control_state", report.rollout_control_state.toString());
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "resumed_from_release_id", report.resumed_from_release_id);
    try writer.print(",\"completed_targets\":{d},\"failed_targets\":{d},\"remaining_targets\":{d}", .{
        report.completed_targets,
        report.failed_targets,
        report.remainingTargets(),
    });
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "failure_details", report.failure_details_json);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "targets", report.rollout_targets_json);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "checkpoint", report.rollout_checkpoint_json);
    try writer.writeByte('}');
    try writer.writeByte('}');

    return json_buf.toOwnedSlice(alloc);
}

const RolloutNodeHarness = struct {
    alloc: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    node: *cluster_node.Node,

    fn init(alloc: std.mem.Allocator) !RolloutNodeHarness {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var path_buf: [512]u8 = undefined;
        const tmp_path = platform.Dir.from(tmp.dir).realpath(".", &path_buf) catch return error.SkipZigTest;

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

test "formatAppApplyResponse includes app release metadata" {
    const alloc = std.testing.allocator;
    const json = try formatAppApplyResponse(alloc, .{
        .app_name = "demo-app",
        .release_id = "abc123def456",
        .status = .completed,
        .service_count = 2,
        .placed = 2,
        .failed = 0,
        .completed_targets = 2,
        .failed_targets = 0,
        .rollout_checkpoint_json = "{\"engine\":\"cluster\",\"phase\":\"cutover\",\"batch_start\":0,\"batch_end\":2,\"total_targets\":2,\"completed_targets\":2,\"failed_targets\":0,\"remaining_targets\":0,\"control_state\":\"active\"}",
    }, .{ .service_count = 2 });
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"apply\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"abc123def456\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":\"completed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_state\":\"stable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"service_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"worker_count\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"placed\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"completed_targets\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed_targets\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"remaining_targets\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_release_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"apply completed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_checkpoint\":{\"engine\":\"cluster\",\"phase\":\"cutover\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout\":{\"state\":\"stable\",\"control_state\":\"active\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"completed_targets\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed_targets\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"remaining_targets\":0") != null);
}

test "formatAppApplyResponse includes rollback trigger metadata" {
    const alloc = std.testing.allocator;
    const json = try formatAppApplyResponse(alloc, .{
        .app_name = "demo-app",
        .release_id = "dep-2",
        .status = .completed,
        .service_count = 2,
        .placed = 2,
        .failed = 0,
        .completed_targets = 2,
        .failed_targets = 0,
        .message = "all placements succeeded",
        .trigger = .rollback,
        .source_release_id = "dep-1",
    }, .{ .service_count = 2 });
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"rollback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_release_id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_state\":\"stable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"rollback to dep-1 completed: all placements succeeded\"") != null);
}

test "formatAppApplyResponse includes partially failed status" {
    const alloc = std.testing.allocator;
    const json = try formatAppApplyResponse(alloc, .{
        .app_name = "demo-app",
        .release_id = "dep-3",
        .status = .partially_failed,
        .service_count = 2,
        .placed = 1,
        .failed = 1,
        .completed_targets = 1,
        .failed_targets = 1,
        .message = "one or more placements failed",
        .failure_details_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"reason\":\"placement_failed\"}]",
    }, .{ .service_count = 2 });
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":\"partially_failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_state\":\"degraded\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"placed\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"one or more placements failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failure_details\":[{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"reason\":\"placement_failed\"}]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout\":{\"state\":\"degraded\",\"control_state\":\"active\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"completed_targets\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed_targets\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"remaining_targets\":0") != null);
}

test "formatAppApplyResponse includes rollout control state" {
    const alloc = std.testing.allocator;
    const json = try formatAppApplyResponse(alloc, .{
        .app_name = "demo-app",
        .release_id = "dep-7",
        .status = .in_progress,
        .service_count = 1,
        .placed = 0,
        .failed = 0,
        .completed_targets = 0,
        .failed_targets = 0,
        .rollout_control_state = .paused,
    }, .{ .service_count = 1 });
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_control_state\":\"paused\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"control_state\":\"paused\"") != null);
}

test "formatLegacyApplyResponse preserves compact deploy shape" {
    const alloc = std.testing.allocator;
    const json = try formatLegacyApplyResponse(alloc, 1, 1);
    defer alloc.free(json);

    try std.testing.expectEqualStrings("{\"placed\":1,\"failed\":1}", json);
}

test "formatAppApplyResponse includes non-service workload counts" {
    const alloc = std.testing.allocator;
    const json = try formatAppApplyResponse(alloc, .{
        .app_name = "demo-app",
        .release_id = "dep-4",
        .status = .completed,
        .service_count = 0,
        .placed = 0,
        .failed = 0,
        .completed_targets = 0,
        .failed_targets = 0,
    }, .{
        .worker_count = 1,
        .cron_count = 2,
        .training_job_count = 1,
    });
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"worker_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"cron_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"training_job_count\":1") != null);
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

    db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, created_at) VALUES (?, ?, ?, ?, ?), (?, ?, ?, ?, ?);",
        .{},
        .{
            "a1", "agent1", "nginx:1", "running", @as(i64, 1),
            "a2", "agent1", "nginx:1", "running", @as(i64, 1),
        },
    ) catch unreachable;

    try std.testing.expectEqual(
        TargetReadiness.ready,
        try queryTargetReadiness(std.testing.allocator, &db, &.{ "a1", "a2" }),
    );
}

test "queryTargetReadiness returns pending when assignments are not ready yet" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, created_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "pending", @as(i64, 1) },
    ) catch unreachable;

    try std.testing.expectEqual(
        TargetReadiness.pending,
        try queryTargetReadiness(std.testing.allocator, &db, &.{"a1"}),
    );
}

test "queryTargetReadiness returns failed when any assignment is terminal" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, created_at) VALUES (?, ?, ?, ?, ?), (?, ?, ?, ?, ?);",
        .{},
        .{
            "a1", "agent1", "nginx:1", "running", @as(i64, 1),
            "a2", "agent1", "nginx:1", "failed",  @as(i64, 1),
        },
    ) catch unreachable;

    try std.testing.expectEqual(
        TargetReadiness.failed,
        try queryTargetReadiness(std.testing.allocator, &db, &.{ "a1", "a2" }),
    );
}

test "queryTargetReadiness uses explicit status reason from agent" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, status_reason, created_at) VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "failed", "readiness_failed", @as(i64, 1) },
    ) catch unreachable;

    try std.testing.expectEqual(
        TargetReadiness.readiness_failed,
        try queryTargetReadiness(std.testing.allocator, &db, &.{"a1"}),
    );
}

test "queryTargetReadiness preserves exact startup failure reason from agent" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, status_reason, created_at) VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "failed", "image_pull_failed", @as(i64, 1) },
    ) catch unreachable;

    try std.testing.expectEqual(
        TargetReadiness.image_pull_failed,
        try queryTargetReadiness(std.testing.allocator, &db, &.{"a1"}),
    );
}

test "queryTargetReadiness preserves process failure reason from agent" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../../../state/schema.zig").init(&db);

    db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, status_reason, created_at) VALUES (?, ?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "failed", "process_failed", @as(i64, 1) },
    ) catch unreachable;

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

    db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, created_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "pending", @as(i64, 1) },
    ) catch unreachable;

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

    db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, created_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "running", @as(i64, 1) },
    ) catch unreachable;

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
            platform.sleep(150 * std.time.ns_per_ms);
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

    db.exec(
        "INSERT INTO assignments (id, agent_id, image, status, created_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "a1", "agent1", "nginx:1", "pending", @as(i64, 1) },
    ) catch unreachable;

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
            platform.sleep(150 * std.time.ns_per_ms);
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

    var placed: usize = 0;
    var failed: usize = 0;
    var completed_targets: usize = 0;
    var failed_targets: usize = 0;

    const Resumer = struct {
        fn run(db: *sqlite.Db) void {
            platform.sleep(150 * std.time.ns_per_ms);
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
        &placed,
        &failed,
        &completed_targets,
        &failed_targets,
        0,
        1,
    );
    harness.applyCommitted();

    try std.testing.expectEqual(@as(usize, 1), placed);
    try std.testing.expectEqual(@as(usize, 0), failed);
    try std.testing.expectEqual(@as(usize, 1), completed_targets);
    try std.testing.expectEqual(@as(usize, 0), failed_targets);

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

test "rollout target builder restores terminal request state from stored json" {
    const alloc = std.testing.allocator;
    var rollout_targets = RolloutTargetBuilder.init(alloc);
    defer rollout_targets.deinit();

    const request: scheduler.PlacementRequest = .{
        .image = "alpine",
        .command = "echo web",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
        .app_name = "demo-app",
        .workload_kind = "service",
        .workload_name = "web",
    };

    try rollout_targets.appendRequests(&.{.{
        .request = request,
        .rollout = .{},
    }});
    rollout_targets.restoreFromJson(
        "[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"ready\",\"reason\":null}]",
    );

    try std.testing.expectEqualStrings("ready", rollout_targets.stateForRequest(request));
    try std.testing.expect(isTerminalRolloutTargetState(rollout_targets.stateForRequest(request)));
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

    var placed: usize = 0;
    var failed: usize = 0;
    var completed_targets: usize = 0;
    var failed_targets: usize = 0;

    const Canceler = struct {
        fn run() void {
            platform.sleep(150 * std.time.ns_per_ms);
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
        &placed,
        &failed,
        &completed_targets,
        &failed_targets,
        0,
        1,
    );
    harness.applyCommitted();

    try std.testing.expectEqual(@as(usize, 0), placed);
    try std.testing.expectEqual(@as(usize, 0), failed);
    try std.testing.expectEqual(@as(usize, 0), completed_targets);
    try std.testing.expectEqual(@as(usize, 1), failed_targets);

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
