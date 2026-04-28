const std = @import("std");
const sqlite = @import("sqlite");
const apply_release = @import("../../../manifest/apply_release.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const apply_backend = @import("apply_backend.zig");
const apply_response = @import("apply_response.zig");
const apply_request = @import("apply_request.zig");
const volumes_mod = @import("../../../state/volumes.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const deployment_store = @import("../../../manifest/update/deployment_store.zig");
const store = @import("../../../state/store.zig");
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
    active_rollout_mu.lockUncancelable(std.Options.debug_io);
    defer active_rollout_mu.unlock(std.Options.debug_io);

    const entry = try active_rollouts.getOrPut(std.heap.page_allocator, id);
    if (!entry.found_existing) {
        entry.key_ptr.* = try std.heap.page_allocator.dupe(u8, id);
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
        nowRealSeconds(),
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
    return apply_response.formatLegacy(alloc, placed, failed);
}

fn formatAppApplyResponse(
    alloc: std.mem.Allocator,
    report: apply_release.ApplyReport,
    summary: app_snapshot.Summary,
) ![]u8 {
    return apply_response.formatApp(alloc, report, summary);
}
