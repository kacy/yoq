const std = @import("std");
const sqlite = @import("sqlite");
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
            manifest_hash,
            self.config_snapshot,
            0,
            0,
            .pending,
            null,
        ) catch return ClusterApplyError.InternalError;

        return id;
    }

    pub fn mark(self: *const ClusterReleaseTracker, id: []const u8, status: @import("../../../manifest/update/common.zig").DeploymentStatus, message: ?[]const u8) !void {
        try self.markProgress(id, status, message, 0, 0);
    }

    pub fn markProgress(
        self: *const ClusterReleaseTracker,
        id: []const u8,
        status: @import("../../../manifest/update/common.zig").DeploymentStatus,
        message: ?[]const u8,
        completed_targets: usize,
        failed_targets: usize,
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
        ) catch return ClusterApplyError.InternalError;
    }

    pub fn freeReleaseId(self: *const ClusterReleaseTracker, id: []const u8) void {
        self.alloc.free(id);
    }
};

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
        var placed: usize = 0;
        var failed: usize = 0;
        var completed_targets: usize = 0;
        var failed_targets: usize = 0;

        const batch_size = @max(@as(usize, 1), @as(usize, strategy.parallelism));
        var batch_start: usize = 0;
        while (batch_start < self.requests.len) {
            const batch_end = @min(batch_start + batch_size, self.requests.len);
            const batch = self.requests[batch_start..batch_end];
            const batch_failed_before = failed_targets;

            try self.applyBatch(batch, strategy, &placed, &failed, &completed_targets, &failed_targets);

            if (failed_targets > batch_failed_before) break;
            if (strategy.delay_between_batches > 0 and batch_end < self.requests.len) {
                std.Thread.sleep(@as(u64, strategy.delay_between_batches) * std.time.ns_per_s);
            }
            batch_start = batch_end;
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
            .placed = placed,
            .failed = failed,
            .completed_targets = completed_targets,
            .failed_targets = failed_targets,
        };
    }

    fn applyBatch(
        self: *const ClusterApplyBackend,
        batch: []const apply_request.ServiceRequest,
        strategy: rollout_spec.RolloutPolicy,
        placed: *usize,
        failed: *usize,
        completed_targets: *usize,
        failed_targets: *usize,
    ) ClusterApplyError!void {
        var scheduled_targets: std.ArrayListUnmanaged(ScheduledTarget) = .empty;
        defer {
            for (scheduled_targets.items) |*target| target.deinit(self.alloc);
            scheduled_targets.deinit(self.alloc);
        }

        for (batch) |req| {
            if (req.request.gang_world_size > 0) {
                try self.applyGangRequest(req, failed, completed_targets, failed_targets, &scheduled_targets);
            } else {
                try self.applySingleRequest(req, failed, completed_targets, failed_targets, &scheduled_targets);
            }
        }

        if (scheduled_targets.items.len == 0) return;

        if (strategy.health_check_timeout > 0) {
            try self.finalizeBatchTargets(
                scheduled_targets.items,
                strategy.health_check_timeout,
                placed,
                failed,
                completed_targets,
                failed_targets,
            );
            return;
        }

        for (scheduled_targets.items) |target| {
            placed.* += target.placement_count;
            completed_targets.* += 1;
            self.reportProgress(completed_targets.*, failed_targets.*);
        }
    }

    fn applyGangRequest(
        self: *const ClusterApplyBackend,
        req: apply_request.ServiceRequest,
        failed: *usize,
        completed_targets: *usize,
        failed_targets: *usize,
        scheduled_targets: *std.ArrayListUnmanaged(ScheduledTarget),
    ) ClusterApplyError!void {
        const gang_placements = scheduler.scheduleGang(self.alloc, req.request, self.agents) catch {
            failed.* += 1;
            failed_targets.* += 1;
            self.reportProgress(completed_targets.*, failed_targets.*);
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
                    std.time.timestamp(),
                    gp,
                ) catch return ClusterApplyError.InternalError;

                _ = self.node.propose(sql) catch return ClusterApplyError.NotLeader;
            }

            try reconcilePriorAssignments(self.node, req.request, keep_ids.items);
            scheduled_targets.append(self.alloc, .{
                .assignment_ids = keep_ids.toOwnedSlice(self.alloc) catch return ClusterApplyError.InternalError,
                .placement_count = gps.len,
            }) catch return ClusterApplyError.InternalError;
            keep_ids.deinit(self.alloc);
            return;
        }

        failed.* += req.request.gang_world_size;
        failed_targets.* += 1;
        self.reportProgress(completed_targets.*, failed_targets.*);
    }

    fn applySingleRequest(
        self: *const ClusterApplyBackend,
        req: apply_request.ServiceRequest,
        failed: *usize,
        completed_targets: *usize,
        failed_targets: *usize,
        scheduled_targets: *std.ArrayListUnmanaged(ScheduledTarget),
    ) ClusterApplyError!void {
        const placements = scheduler.schedule(self.alloc, &[_]scheduler.PlacementRequest{req.request}, self.agents) catch {
            return ClusterApplyError.InternalError;
        };
        defer self.alloc.free(placements);

        if (placements.len == 0 or placements[0] == null) {
            failed.* += 1;
            failed_targets.* += 1;
            self.reportProgress(completed_targets.*, failed_targets.*);
            return;
        }

        const placement = placements[0].?;
        const owned_id = generateOwnedAssignmentId(self.alloc) catch return ClusterApplyError.InternalError;

        var sql_buf: [1024]u8 = undefined;
        const sql = scheduler.assignmentSql(
            &sql_buf,
            owned_id,
            placement.agent_id,
            req.request,
            std.time.timestamp(),
        ) catch return ClusterApplyError.InternalError;

        _ = self.node.propose(sql) catch return ClusterApplyError.NotLeader;
        try reconcilePriorAssignments(self.node, req.request, &.{owned_id});
        errdefer self.alloc.free(owned_id);

        const assignment_ids = self.alloc.alloc([]const u8, 1) catch return ClusterApplyError.InternalError;
        assignment_ids[0] = owned_id;
        errdefer {
            self.alloc.free(owned_id);
            self.alloc.free(assignment_ids);
        }

        scheduled_targets.append(self.alloc, .{
            .assignment_ids = assignment_ids,
            .placement_count = 1,
        }) catch return ClusterApplyError.InternalError;
    }

    fn reportProgress(self: *const ClusterApplyBackend, completed_targets: usize, failed_targets: usize) void {
        if (self.progress) |progress| {
            progress.mark(.in_progress, null, completed_targets, failed_targets) catch {};
        }
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
        timeout_secs: u32,
        placed: *usize,
        failed: *usize,
        completed_targets: *usize,
        failed_targets: *usize,
    ) ClusterApplyError!void {
        const db = self.node.stateMachineDb();
        const states = resolveTargetReadinessStates(self.alloc, db, targets, timeout_secs) catch return ClusterApplyError.InternalError;
        defer self.alloc.free(states);

        for (targets, states) |target, state| {
            switch (state) {
                .ready => {
                    placed.* += target.placement_count;
                    completed_targets.* += 1;
                    self.reportProgress(completed_targets.*, failed_targets.*);
                },
                .failed, .pending => {
                    failed_targets.* += 1;
                    self.reportProgress(completed_targets.*, failed_targets.*);
                },
            }
        }
        _ = failed;
    }
};

const ScheduledTarget = struct {
    assignment_ids: []const []const u8,
    placement_count: usize,

    fn deinit(self: *const ScheduledTarget, alloc: std.mem.Allocator) void {
        for (self.assignment_ids) |id| alloc.free(id);
        alloc.free(self.assignment_ids);
    }
};

const TargetReadiness = enum {
    pending,
    ready,
    failed,
};

fn resolveTargetReadinessStates(
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    targets: []const ScheduledTarget,
    timeout_secs: u32,
) ![]TargetReadiness {
    var states = try alloc.alloc(TargetReadiness, targets.len);
    errdefer alloc.free(states);
    @memset(states, .pending);

    const deadline_ns: i128 = std.time.nanoTimestamp() + (@as(i128, timeout_secs) * std.time.ns_per_s);
    var remaining = targets.len;

    while (remaining > 0) {
        for (targets, 0..) |target, i| {
            if (states[i] != .pending) continue;

            const state = try queryTargetReadiness(alloc, db, target.assignment_ids);
            if (state == .pending) continue;

            states[i] = state;
            remaining -= 1;
        }

        if (remaining == 0) return states;
        if (std.time.nanoTimestamp() >= deadline_ns) break;
        std.Thread.sleep(100 * std.time.ns_per_ms);
    }

    for (states) |*state| {
        if (state.* == .pending) state.* = .failed;
    }
    return states;
}

fn queryTargetReadiness(alloc: std.mem.Allocator, db: *sqlite.Db, assignment_ids: []const []const u8) !TargetReadiness {
    if (assignment_ids.len == 0) return .failed;

    var all_running = true;
    for (assignment_ids) |assignment_id| {
        const status = try loadAssignmentStatus(alloc, db, assignment_id) orelse {
            all_running = false;
            continue;
        };
        defer alloc.free(status);

        if (std.mem.eql(u8, status, "running")) continue;
        if (std.mem.eql(u8, status, "failed") or std.mem.eql(u8, status, "stopped")) return .failed;
        all_running = false;
    }

    return if (all_running) .ready else .pending;
}

fn loadAssignmentStatus(alloc: std.mem.Allocator, db: *sqlite.Db, assignment_id: []const u8) !?[]const u8 {
    const Row = struct { status: sqlite.Text };
    const row = (db.oneAlloc(
        Row,
        alloc,
        "SELECT status FROM assignments WHERE id = ?;",
        .{},
        .{assignment_id},
    ) catch return error.QueryFailed) orelse return null;
    return row.status.data;
}

fn effectiveClusterRollout(requests: []const apply_request.ServiceRequest) rollout_spec.RolloutPolicy {
    var strategy: rollout_spec.RolloutPolicy = .{};
    if (requests.len == 0) return strategy;

    strategy = requests[0].rollout;
    for (requests[1..]) |req| {
        strategy.parallelism = @min(strategy.parallelism, req.rollout.parallelism);
        strategy.delay_between_batches = @max(strategy.delay_between_batches, req.rollout.delay_between_batches);
        strategy.health_check_timeout = @max(strategy.health_check_timeout, req.rollout.health_check_timeout);
        if (req.rollout.failure_action == .pause) strategy.failure_action = .pause;
    }
    return strategy;
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
        std.time.timestamp(),
    );
}

pub fn handleAppApply(alloc: std.mem.Allocator, request: @import("../../http.zig").Request, ctx: RouteContext) Response {
    return handleApply(alloc, request, ctx, .app, .{});
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
    return handleApply(alloc, request, ctx, .app, .{
        .trigger = .rollback,
        .source_release_id = source_release_id,
    });
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
    const writer = json_buf.writer(alloc);

    try writer.writeByte('{');
    try json_helpers.writeJsonStringField(writer, "app_name", report.app_name);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "trigger", report.trigger.toString());
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "release_id", report.release_id orelse "");
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "status", report.status.toString());
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

    const resolved_message = try report.resolvedMessage(alloc);
    defer if (resolved_message) |message| alloc.free(message);

    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "message", resolved_message);
    try writer.writeByte('}');

    return json_buf.toOwnedSlice(alloc);
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
    }, .{ .service_count = 2 });
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"apply\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"abc123def456\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":\"completed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"service_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"worker_count\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"placed\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"completed_targets\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed_targets\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"remaining_targets\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_release_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"apply completed\"") != null);
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
    }, .{ .service_count = 2 });
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":\"partially_failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"placed\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"one or more placements failed\"") != null);
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
                .parallelism = 2,
                .delay_between_batches = 4,
                .failure_action = .pause,
                .health_check_timeout = 12,
            },
        },
    };

    const rollout = effectiveClusterRollout(&requests);
    try std.testing.expectEqual(@as(u32, 2), rollout.parallelism);
    try std.testing.expectEqual(@as(u32, 4), rollout.delay_between_batches);
    try std.testing.expectEqual(@as(u32, 12), rollout.health_check_timeout);
    try std.testing.expectEqual(rollout_spec.RolloutFailureAction.pause, rollout.failure_action);
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
            "a2", "agent1", "nginx:1", "failed", @as(i64, 1),
        },
    ) catch unreachable;

    try std.testing.expectEqual(
        TargetReadiness.failed,
        try queryTargetReadiness(std.testing.allocator, &db, &.{ "a1", "a2" }),
    );
}

test "resolveTargetReadinessStates marks pending targets failed when timeout elapses" {
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
        .{ .assignment_ids = ids[0..], .placement_count = 1 },
    };

    const states = try resolveTargetReadinessStates(std.testing.allocator, &db, &targets, 0);
    defer std.testing.allocator.free(states);

    try std.testing.expectEqual(@as(usize, 1), states.len);
    try std.testing.expectEqual(TargetReadiness.failed, states[0]);
}
