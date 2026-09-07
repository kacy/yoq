const std = @import("std");
const apply_release = @import("../../../manifest/apply_release.zig");
const app_diff = @import("../../../manifest/app_diff.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const apply_lock = @import("../../../manifest/apply_lock.zig");
const apply_backend = @import("apply_backend.zig");
const apply_response = @import("apply_response.zig");
const apply_request = @import("apply_request.zig");
const volumes_mod = @import("../../../state/volumes.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const mutations = @import("../../../cluster/deployment_mutations.zig");
const mutation_session = @import("../../../cluster/mutation_session.zig");
const sql_command = @import("../../../cluster/sql_command.zig");
const deployment_store = @import("../../../manifest/update/deployment_store.zig");
const store = @import("../../../state/store.zig");
const audit = @import("../../../state/audit.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const common = @import("../common.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

var active_rollout_mu: std.Io.Mutex = .init;
var active_rollouts: std.StringHashMapUnmanaged(void) = .empty;

const ResponseMode = enum {
    legacy,
    app,
};

pub const ClusterApplyError = apply_backend.ClusterApplyError;
pub const ClusterApplyBackend = apply_backend.ClusterApplyBackend;

const ClusterReleaseTracker = struct {
    alloc: std.mem.Allocator,
    session: mutation_session.Session,
    app_name: ?[]const u8,
    config_snapshot: []const u8,
    context: apply_release.ApplyContext = .{},

    pub fn begin(self: *const ClusterReleaseTracker) !?[]const u8 {
        if (self.context.continue_release_id) |existing_id| {
            // The caller already holds the app lock. Recheck the durable row
            // now: a recovery request may have waited behind a finishing apply.
            const node = self.session.node;
            node.mu.lockUncancelable(std.Options.debug_io);
            defer node.mu.unlock(std.Options.debug_io);
            try self.session.checkLocked();
            const existing = store.getDeploymentInDb(node.stateMachineDb(), self.alloc, existing_id) catch |err| return switch (err) {
                error.NotFound => error.Conflict,
                else => error.InternalError,
            };
            defer existing.deinit(self.alloc);
            if ((!std.mem.eql(u8, existing.status, "pending") and !std.mem.eql(u8, existing.status, "in_progress")) or
                !std.mem.eql(u8, existing.app_name orelse "", self.app_name orelse "") or
                !std.mem.eql(u8, existing.config_snapshot, self.config_snapshot)) return error.Conflict;
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

        const command = mutations.insert(self.alloc, .{
            .id = id,
            .app_name = name,
            .service_name = name,
            .trigger = self.context.trigger.toString(),
            .source_release_id = self.context.source_release_id,
            .resumed_from_release_id = self.context.resumed_from_release_id,
            .manifest_hash = manifest_hash,
            .config_snapshot = self.config_snapshot,
            .status = "pending",
            .message = null,
            .created_at = nowRealSeconds(),
        }) catch return ClusterApplyError.InternalError;
        defer self.alloc.free(command);
        try self.session.commit(command);

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
        const command = mutations.progress(self.alloc, id, .{
            .status = status.toString(),
            .message = resolved_message,
            .completed_targets = completed_targets,
            .failed_targets = failed_targets,
            .failure_details_json = failure_details_json,
            .rollout_targets_json = rollout_targets_json,
            .rollout_checkpoint_json = rollout_checkpoint_json,
        }) catch return ClusterApplyError.InternalError;
        defer self.alloc.free(command);
        var batch = std.Io.Writer.Allocating.init(self.alloc);
        defer batch.deinit();
        batch.writer.writeAll(command) catch return error.InternalError;
        if (isTerminalStatus(status) and status != .failed) {
            if (self.app_name) |name| appendCronSchedules(&batch.writer, self.alloc, name, self.config_snapshot) catch return error.InternalError;
        }
        try self.session.commit(batch.written());
        if (isTerminalStatus(status)) {
            markClusterRolloutInactive(id);
        }
    }

    pub fn controlState(self: *const ClusterReleaseTracker, id: []const u8) !apply_release.RolloutControlState {
        const node = self.session.node;
        node.mu.lockUncancelable(std.Options.debug_io);
        defer node.mu.unlock(std.Options.debug_io);
        try self.session.checkLocked();
        const dep = try store.getDeploymentInDb(node.stateMachineDb(), self.alloc, id);
        defer dep.deinit(self.alloc);
        const state = dep.rollout_control_state orelse "active";
        if (!std.mem.eql(u8, state, "active") and !std.mem.eql(u8, state, "paused") and !std.mem.eql(u8, state, "cancel_requested")) return error.InternalError;
        return apply_release.RolloutControlState.fromString(state);
    }

    pub fn preserveProgressOnError(_: *const ClusterReleaseTracker) bool {
        return true;
    }

    pub fn isResuming(self: *const ClusterReleaseTracker) bool {
        return self.context.continue_release_id != null;
    }

    pub fn finish(_: *const ClusterReleaseTracker, id: []const u8) void {
        markClusterRolloutInactive(id);
    }

    pub fn freeOutcome(self: *const ClusterReleaseTracker, outcome: apply_release.ApplyOutcome) void {
        outcome.deinit(self.alloc);
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
    active_rollout_mu.lockUncancelable(std.Options.debug_io);
    defer active_rollout_mu.unlock(std.Options.debug_io);

    const entry = try active_rollouts.getOrPut(std.heap.page_allocator, id);
    if (!entry.found_existing) {
        entry.key_ptr.* = std.heap.page_allocator.dupe(u8, id) catch |err| {
            _ = active_rollouts.remove(id);
            return err;
        };
    }
}

fn markClusterRolloutInactive(id: []const u8) void {
    active_rollout_mu.lockUncancelable(std.Options.debug_io);
    defer active_rollout_mu.unlock(std.Options.debug_io);

    if (active_rollouts.fetchRemove(id)) |entry| {
        std.heap.page_allocator.free(entry.key);
    }
}

pub fn isClusterRolloutActive(id: []const u8) bool {
    active_rollout_mu.lockUncancelable(std.Options.debug_io);
    defer active_rollout_mu.unlock(std.Options.debug_io);
    return active_rollouts.contains(id);
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

    const session = mutation_session.Session.begin(node) catch return common.notLeader(alloc, node);
    session.synchronize() catch |err| return mutationFailure(alloc, node, err);
    const db = node.stateMachineDb();

    var app_lock: ?apply_lock.ApplyLock = null;
    if (parsed.app_name) |app_name| {
        app_lock = apply_lock.acquire(alloc, app_name) catch |err| switch (err) {
            apply_lock.ApplyLockError.AlreadyLocked => return common.conflict("apply already in progress"),
            else => return common.internalError(),
        };
    }
    defer if (app_lock) |*lock| lock.release();

    const vol_constraints = if (parsed.app_name) |name|
        volumes_mod.getVolumesByApp(alloc, db, name) catch return common.internalError()
    else
        &[_]volumes_mod.VolumeConstraint{};
    defer if (parsed.app_name != null) alloc.free(vol_constraints);

    parsed.setVolumeConstraints(vol_constraints);

    if (parsed.requests.items.len > 0 and !(agent_registry.hasAgents(db) catch return common.internalError())) {
        return .{ .status = .bad_request, .body = "{\"error\":\"no agents available\"}", .allocated = false };
    }

    var tracker = ClusterReleaseTracker{
        .alloc = alloc,
        .session = session,
        .app_name = parsed.app_name,
        .config_snapshot = request.body,
        .context = apply_context,
    };
    var backend = ClusterApplyBackend{
        .alloc = alloc,
        .session = session,
        .requests = parsed.requests.items,
    };
    const apply_result = apply_release.execute(&tracker, &backend) catch |err| return mutationFailure(alloc, node, err);
    const apply_report = apply_result.toReport(parsed.app_name orelse "", parsed.requests.items.len, apply_context);
    defer apply_report.deinit(alloc);

    const body = switch (response_mode) {
        .legacy => formatLegacyApplyResponse(alloc, apply_report.placed, apply_report.failed) catch return common.internalError(),
        .app => formatAppApplyResponse(alloc, apply_report, parsed.summary) catch return common.internalError(),
    };
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn appendCronSchedules(writer: *std.Io.Writer, alloc: std.mem.Allocator, app_name: []const u8, config_snapshot: []const u8) !void {
    var schedules = try app_snapshot.listCronSchedules(alloc, config_snapshot);
    defer {
        for (schedules.items) |schedule| schedule.deinit(alloc);
        schedules.deinit(alloc);
    }
    try sql_command.write(writer, "DELETE FROM cron_schedules WHERE app_name = ?;", .{app_name});
    const now = nowRealSeconds();
    for (schedules.items) |schedule| try sql_command.write(writer, "INSERT INTO cron_schedules (app_name, name, every, spec_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?);", .{ app_name, schedule.name, schedule.every, schedule.spec_json, now, now });
}

pub fn handleAppApply(alloc: std.mem.Allocator, request: @import("../../http.zig").Request, ctx: RouteContext) Response {
    const resp = handleApply(alloc, request, ctx, .app, .{});
    const app_name = json_helpers.extractJsonString(request.body, "app_name") orelse "";
    audit.record(.app_apply, app_name, if (resp.status.isError()) .failed else .ok);
    return resp;
}

pub fn handleAppDryRun(alloc: std.mem.Allocator, request: @import("../../http.zig").Request, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (request.body.len == 0) return common.badRequest("missing request body");

    var parsed = apply_request.parse(alloc, request.body, true) catch |err| return switch (err) {
        apply_request.ParseError.MissingAppName => common.badRequest("missing app_name"),
        apply_request.ParseError.MissingServicesArray => common.badRequest("missing services array"),
        apply_request.ParseError.NoServices => common.badRequest("no services to deploy"),
        apply_request.ParseError.OutOfMemory => common.internalError(),
        apply_request.ParseError.InvalidRequest => common.badRequest("invalid request body"),
        apply_request.ParseError.InvalidRolloutConfig => common.badRequest("invalid rollout config"),
    };
    defer parsed.deinit(alloc);

    const app_name = parsed.app_name.?;
    const db = node.stateMachineDb();
    const manifest_hash = deployment_store.computeManifestHash(alloc, request.body) catch return common.internalError();
    defer alloc.free(manifest_hash);

    const current = store.getLatestDeploymentByAppInDb(db, alloc, app_name) catch |err| switch (err) {
        error.NotFound => null,
        else => return common.internalError(),
    };
    defer if (current) |dep| dep.deinit(alloc);

    var diff = app_diff.compute(
        alloc,
        app_name,
        manifest_hash,
        if (current) |dep| dep.id else null,
        if (current) |dep| dep.manifest_hash else null,
        if (current) |dep| dep.config_snapshot else null,
        request.body,
    ) catch return common.internalError();
    defer diff.deinit();

    const body = diff.renderJson(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
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
    return apply_response.formatLegacy(alloc, placed, failed);
}

fn formatAppApplyResponse(
    alloc: std.mem.Allocator,
    report: apply_release.ApplyReport,
    summary: app_snapshot.Summary,
) ![]u8 {
    return apply_response.formatApp(alloc, report, summary);
}

test "cluster release progress and control survive replica promotion" {
    const alloc = std.testing.allocator;
    const Node = @import("../../../cluster/node.zig").Node;
    var leader = try Node.initForTests(alloc, .{ .id = 1, .port = 0, .peers = &.{}, .data_dir = "/tmp" });
    defer leader.deinit();
    leader.raft.role = .leader;
    leader.raft.persistent_state.current_term = 1;
    try std.testing.expect(leader.log.setCurrentTerm(1));
    var replica = try Node.initForTests(alloc, .{ .id = 2, .port = 0, .peers = &.{}, .data_dir = "/tmp" });
    defer replica.deinit();
    const snapshot = "{\"app_name\":\"demo\",\"services\":[],\"crons\":[{\"name\":\"cleanup\",\"image\":\"alpine\",\"every\":60}]}";
    var tracker = ClusterReleaseTracker{
        .alloc = alloc,
        .session = try mutation_session.Session.begin(&leader),
        .app_name = "demo",
        .config_snapshot = snapshot,
    };
    const id = (try tracker.begin()).?;
    defer tracker.freeReleaseId(id);
    defer tracker.finish(id);
    try tracker.markProgressDetails(id, .in_progress, "it's progressing", 2, 0, null, "[]", "{\"batch_start\":2}");
    const pause = try mutations.control(alloc, id, "paused");
    defer alloc.free(pause);
    try tracker.session.commit(pause);

    // A conflicting local runtime record must never control a cluster rollout.
    try store.initTestDb();
    defer store.deinitTestDb();
    try store.saveDeployment(.{ .id = id, .service_name = "demo", .manifest_hash = "local", .trigger = "apply", .config_snapshot = snapshot, .status = "in_progress", .message = null, .created_at = 0, .rollout_control_state = "active" });
    var completed: usize = 0;
    var failed: usize = 0;
    const recorder = apply_release.makeProgressRecorder(&tracker, id, &completed, &failed);
    try std.testing.expectEqual(.paused, try recorder.controlState());

    // Replay exactly the acknowledged prefix into an independent node DB.
    replica.state_machine.applyUpTo(&leader.log, alloc, leader.raft.commit_index);
    try std.testing.expectEqual(leader.state_machine.last_applied, replica.state_machine.last_applied);
    const recovered = try store.getDeploymentInDb(replica.stateMachineDb(), alloc, id);
    defer recovered.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), recovered.completed_targets);
    try std.testing.expectEqualStrings("{\"batch_start\":2}", recovered.rollout_checkpoint_json.?);
    try std.testing.expectEqualStrings("it's progressing", recovered.message.?);

    // The promoted replica reads the pause from replicated state. The old
    // operation stays fenced even if its server becomes leader again later.
    replica.raft.role = .leader;
    replica.raft.persistent_state.current_term = 2;
    try std.testing.expect(replica.log.setCurrentTerm(2));
    var promoted = tracker;
    promoted.session = try mutation_session.Session.begin(&replica);
    try std.testing.expectEqual(.paused, try promoted.controlState(id));
    leader.raft.persistent_state.current_term = 2;
    try std.testing.expect(leader.log.setCurrentTerm(2));
    const previous_index = leader.log.lastIndex();
    try std.testing.expectError(error.NotLeader, tracker.mark(id, .completed, null));
    try std.testing.expectEqual(previous_index, leader.log.lastIndex());
    try std.testing.expectError(error.NotLeader, recorder.controlState());

    // Complete on the original server in a new term, then replay the final
    // release and cron registration together to the replica.
    tracker.session = try mutation_session.Session.begin(&leader);
    try tracker.markProgressDetails(id, .completed, null, 3, 0, null, "[]", null);
    replica.state_machine.applyUpTo(&leader.log, alloc, leader.raft.commit_index);
    const final = try store.getDeploymentInDb(replica.stateMachineDb(), alloc, id);
    defer final.deinit(alloc);
    try std.testing.expectEqualStrings("completed", final.status);
    var crons = try store.listCronSchedulesByAppInDb(replica.stateMachineDb(), alloc, "demo");
    defer {
        for (crons.items) |cron| cron.deinit(alloc);
        crons.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 1), crons.items.len);
    try std.testing.expectEqualStrings("cleanup", crons.items[0].name);
    tracker.context.continue_release_id = id;
    const final_index = leader.log.lastIndex();
    try std.testing.expectError(error.Conflict, tracker.begin());
    try std.testing.expectEqual(final_index, leader.log.lastIndex());
}

test "cluster release completion rolls back when cron registration fails" {
    const alloc = std.testing.allocator;
    const Node = @import("../../../cluster/node.zig").Node;
    var node = try Node.initForTests(alloc, .{ .id = 1, .port = 0, .peers = &.{}, .data_dir = "/tmp" });
    defer node.deinit();
    node.raft.role = .leader;
    var tracker = ClusterReleaseTracker{
        .alloc = alloc,
        .session = try mutation_session.Session.begin(&node),
        .app_name = "demo",
        .config_snapshot = "{\"app_name\":\"demo\",\"crons\":[{\"name\":\"duplicate\",\"every\":60},{\"name\":\"duplicate\",\"every\":120}]}",
    };
    const id = (try tracker.begin()).?;
    defer tracker.freeReleaseId(id);
    defer tracker.finish(id);
    try tracker.markProgressDetails(id, .in_progress, null, 1, 0, null, "[]", "checkpoint");
    try std.testing.expectError(error.Conflict, tracker.mark(id, .completed, null));
    const dep = try store.getDeploymentInDb(node.stateMachineDb(), alloc, id);
    defer dep.deinit(alloc);
    try std.testing.expectEqualStrings("in_progress", dep.status);
    try std.testing.expectEqualStrings("checkpoint", dep.rollout_checkpoint_json.?);
    var crons = try store.listCronSchedulesByAppInDb(node.stateMachineDb(), alloc, "demo");
    defer crons.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 0), crons.items.len);
}

pub fn mutationFailure(alloc: std.mem.Allocator, node: *@import("../../../cluster/node.zig").Node, err: mutation_session.Error) Response {
    return switch (err) {
        error.NotLeader => common.notLeader(alloc, node),
        error.CommitUnknown => .{ .status = .service_unavailable, .body = "{\"error\":\"rollout outcome unknown; inspect release state before retrying\"}", .allocated = false },
        error.Conflict => common.conflict("rollout conflicts with cluster state"),
        error.InternalError => common.internalError(),
    };
}
