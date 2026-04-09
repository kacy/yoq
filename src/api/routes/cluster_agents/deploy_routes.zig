const std = @import("std");
const sqlite = @import("sqlite");
const scheduler = @import("../../../cluster/scheduler.zig");
const cluster_node = @import("../../../cluster/node.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const apply_release = @import("../../../manifest/apply_release.zig");
const apply_request = @import("apply_request.zig");
const volumes_mod = @import("../../../state/volumes.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const deployment_store = @import("../../../manifest/update/deployment_store.zig");
const common = @import("../common.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

const ResponseMode = enum {
    legacy,
    app,
};

const ClusterApplyError = error{
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

const ClusterApplyBackend = struct {
    alloc: std.mem.Allocator,
    node: *cluster_node.Node,
    requests: []scheduler.PlacementRequest,
    agents: []agent_registry.AgentRecord,

    pub fn apply(self: *const ClusterApplyBackend) ClusterApplyError!apply_release.ApplyOutcome {
        var placed: usize = 0;
        var failed: usize = 0;
        var completed_targets: usize = 0;
        var failed_targets: usize = 0;

        for (self.requests) |req| {
            if (req.gang_world_size > 0) {
                const gang_placements = scheduler.scheduleGang(self.alloc, req, self.agents) catch {
                    failed += 1;
                    failed_targets += 1;
                    continue;
                };

                if (gang_placements) |gps| {
                    defer self.alloc.free(gps);

                    var gang_ok = true;
                    for (gps) |gp| {
                        var id_buf: [12]u8 = undefined;
                        scheduler.generateAssignmentId(&id_buf);

                        var sql_buf: [2048]u8 = undefined;
                        const sql = scheduler.assignmentSqlGang(
                            &sql_buf,
                            &id_buf,
                            gp.agent_id,
                            req,
                            std.time.timestamp(),
                            gp,
                        ) catch {
                            gang_ok = false;
                            break;
                        };

                        _ = self.node.propose(sql) catch return ClusterApplyError.NotLeader;
                    }

                    if (gang_ok) {
                        placed += gps.len;
                        completed_targets += 1;
                    } else {
                        failed += req.gang_world_size;
                        failed_targets += 1;
                    }
                } else {
                    failed += req.gang_world_size;
                    failed_targets += 1;
                }
            }
        }

        var normal_requests: std.ArrayListUnmanaged(scheduler.PlacementRequest) = .empty;
        defer normal_requests.deinit(self.alloc);
        for (self.requests) |req| {
            if (req.gang_world_size == 0) {
                normal_requests.append(self.alloc, req) catch {
                    failed += 1;
                    failed_targets += 1;
                    continue;
                };
            }
        }

        if (normal_requests.items.len > 0) {
            const placements = scheduler.schedule(self.alloc, normal_requests.items, self.agents) catch {
                return ClusterApplyError.InternalError;
            };
            defer self.alloc.free(placements);

            for (placements) |maybe_placement| {
                if (maybe_placement) |placement| {
                    var id_buf: [12]u8 = undefined;
                    scheduler.generateAssignmentId(&id_buf);

                    var sql_buf: [1024]u8 = undefined;
                    const sql = scheduler.assignmentSql(
                        &sql_buf,
                        &id_buf,
                        placement.agent_id,
                        normal_requests.items[placement.request_idx],
                        std.time.timestamp(),
                    ) catch {
                        failed += 1;
                        failed_targets += 1;
                        continue;
                    };

                    _ = self.node.propose(sql) catch return ClusterApplyError.NotLeader;
                    placed += 1;
                    completed_targets += 1;
                } else {
                    failed += 1;
                    failed_targets += 1;
                }
            }
        }

        return .{
            .status = if (failed_targets == 0)
                .completed
            else if (completed_targets > 0)
                .partially_failed
            else
                .failed,
            .message = if (failed == 0) "all placements succeeded" else "one or more placements failed",
            .placed = placed,
            .failed = failed,
            .completed_targets = completed_targets,
            .failed_targets = failed_targets,
        };
    }

    pub fn failureMessage(_: *const ClusterApplyBackend, err: ClusterApplyError) ?[]const u8 {
        return switch (err) {
            error.NotLeader => "leadership changed during apply",
            error.InternalError => "scheduler error during apply",
        };
    }
};

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

    const agents = agent_registry.listAgents(alloc, db) catch return common.internalError();
    defer {
        for (agents) |a| a.deinit(alloc);
        alloc.free(agents);
    }

    if (agents.len == 0) {
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

    const body = switch (response_mode) {
        .legacy => formatLegacyApplyResponse(alloc, apply_report.placed, apply_report.failed) catch return common.internalError(),
        .app => formatAppApplyResponse(alloc, apply_report) catch return common.internalError(),
    };
    return .{ .status = .ok, .body = body, .allocated = true };
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

fn formatAppApplyResponse(alloc: std.mem.Allocator, report: apply_release.ApplyReport) ![]u8 {
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
    try writer.print(",\"service_count\":{d},\"placed\":{d},\"failed\":{d},\"completed_targets\":{d},\"failed_targets\":{d},\"remaining_targets\":{d}", .{
        report.service_count,
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
    });
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"apply\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"abc123def456\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":\"completed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"service_count\":2") != null);
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
    });
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
    });
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
