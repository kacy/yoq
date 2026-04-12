const std = @import("std");
const http = @import("../../http.zig");
const sqlite = @import("sqlite");
const cluster_node = @import("../../../cluster/node.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const apply_release = @import("../../../manifest/apply_release.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const schema = @import("../../../state/schema.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const deploy_routes = @import("deploy_routes.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

pub fn route(request: @import("../../http.zig").Request, alloc: std.mem.Allocator, ctx: RouteContext) ?Response {
    if (request.method == .GET and std.mem.eql(u8, request.path_only, "/apps")) {
        return handleListApps(alloc, ctx);
    }
    if (!std.mem.startsWith(u8, request.path_only, "/apps/")) return null;

    const rest = request.path_only["/apps/".len..];
    if (std.mem.eql(u8, rest, "apply")) return null;

    if (common.matchSubpath(rest, "/history")) |app_name| {
        if (!common.validateClusterInput(app_name)) return common.badRequest("invalid app name");
        if (request.method != .GET) return common.methodNotAllowed();
        return handleAppHistory(alloc, app_name, ctx);
    }

    if (common.matchSubpath(rest, "/status")) |app_name| {
        if (!common.validateClusterInput(app_name)) return common.badRequest("invalid app name");
        if (request.method != .GET) return common.methodNotAllowed();
        return handleAppStatus(alloc, app_name, ctx);
    }

    if (common.matchSubpath(rest, "/rollback")) |app_name| {
        if (!common.validateClusterInput(app_name)) return common.badRequest("invalid app name");
        if (request.method != .POST) return common.methodNotAllowed();
        return handleAppRollback(alloc, app_name, request, ctx);
    }

    return null;
}

pub fn handleListApps(alloc: std.mem.Allocator, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    var latest = store.listLatestDeploymentsByAppInDb(node.stateMachineDb(), alloc) catch return common.internalError();
    defer {
        for (latest.items) |dep| dep.deinit(alloc);
        latest.deinit(alloc);
    }

    const body = formatAppsResponse(alloc, node.stateMachineDb(), latest.items) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleAppHistory(alloc: std.mem.Allocator, app_name: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    var deployments = store.listDeploymentsByAppInDb(node.stateMachineDb(), alloc, app_name) catch
        return common.internalError();
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    const body = formatAppHistoryResponse(alloc, deployments.items) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleAppStatus(alloc: std.mem.Allocator, app_name: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const latest = store.getLatestDeploymentByAppInDb(node.stateMachineDb(), alloc, app_name) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        else => common.internalError(),
    };
    defer latest.deinit(alloc);

    const previous_successful = loadPreviousSuccessfulDeployment(
        node.stateMachineDb(),
        alloc,
        app_name,
        latest.id,
    ) catch return common.internalError();
    defer if (previous_successful) |dep| dep.deinit(alloc);

    const body = formatAppStatusResponseFromDeployments(alloc, node.stateMachineDb(), latest, previous_successful) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleAppRollback(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    request: http.Request,
    ctx: RouteContext,
) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const release_id = json_helpers.extractJsonString(request.body, "release_id");
    const print_only = json_helpers.extractJsonBool(request.body, "print") orelse false;
    if (release_id) |id| {
        if (!common.validateContainerId(id)) return common.badRequest("invalid release_id");
    }

    const release = store.getRollbackTargetDeploymentByAppInDb(node.stateMachineDb(), alloc, app_name, release_id) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        else => common.internalError(),
    };
    defer release.deinit(alloc);

    if (print_only) {
        return .{
            .status = .ok,
            .body = alloc.dupe(u8, release.config_snapshot) catch return common.internalError(),
            .allocated = true,
        };
    }

    const apply_request = http.Request{
        .method = .POST,
        .path = "/apps/apply",
        .path_only = "/apps/apply",
        .query = "",
        .headers_raw = request.headers_raw,
        .body = release.config_snapshot,
        .content_length = release.config_snapshot.len,
    };
    return deploy_routes.handleAppRollbackApply(alloc, apply_request, ctx, release.id);
}

fn formatAppsResponse(
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    latest_deployments: []const store.DeploymentRecord,
) ![]u8 {
    var json_buf: std.ArrayList(u8) = .empty;
    errdefer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    try writer.writeByte('[');
    for (latest_deployments, 0..) |latest, i| {
        const previous_successful = try loadPreviousSuccessfulDeployment(db, alloc, latest.app_name.?, latest.id);
        defer if (previous_successful) |dep| dep.deinit(alloc);

        if (i > 0) try writer.writeByte(',');
        const json = try formatAppStatusResponseFromDeployments(alloc, db, latest, previous_successful);
        defer alloc.free(json);
        try writer.writeAll(json);
    }
    try writer.writeByte(']');
    return json_buf.toOwnedSlice(alloc);
}

fn loadPreviousSuccessfulDeployment(
    db: *sqlite.Db,
    alloc: std.mem.Allocator,
    app_name: []const u8,
    exclude_release_id: []const u8,
) !?store.DeploymentRecord {
    return store.getPreviousSuccessfulDeploymentByAppInDb(db, alloc, app_name, exclude_release_id) catch |err| switch (err) {
        error.NotFound => null,
        else => return err,
    };
}

fn formatAppStatusResponseFromDeployments(
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    latest: store.DeploymentRecord,
    previous_successful: ?store.DeploymentRecord,
) ![]u8 {
    return formatAppStatusResponse(
        alloc,
        apply_release.reportFromDeployment(latest),
        if (previous_successful) |dep| apply_release.reportFromDeployment(dep) else null,
        app_snapshot.summarize(latest.config_snapshot),
        store.summarizeTrainingJobsByAppInDb(db, alloc, latest.app_name.?) catch .{},
    );
}

fn formatAppHistoryResponse(alloc: std.mem.Allocator, deployments: []const store.DeploymentRecord) ![]u8 {
    const current_release_id = if (deployments.len > 0) deployments[0].id else null;
    const previous_successful_release_id = findPreviousSuccessfulReleaseId(deployments);

    var json_buf: std.ArrayList(u8) = .empty;
    errdefer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    try writer.writeByte('[');
    for (deployments, 0..) |dep, i| {
        const report = apply_release.reportFromDeployment(dep);
        const summary = app_snapshot.summarize(dep.config_snapshot);
        const is_current = current_release_id != null and std.mem.eql(u8, dep.id, current_release_id.?);
        const is_previous_successful = previous_successful_release_id != null and std.mem.eql(u8, dep.id, previous_successful_release_id.?);
        if (i > 0) try writer.writeByte(',');
        try writer.writeByte('{');
        try json_helpers.writeJsonStringField(writer, "id", report.release_id orelse "");
        try writer.writeByte(',');
        try json_helpers.writeNullableJsonStringField(writer, "app", dep.app_name);
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "service", dep.service_name);
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "trigger", report.trigger.toString());
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "status", report.status.toString());
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "manifest_hash", report.manifest_hash);
        try writer.print(",\"created_at\":{d}", .{report.created_at});
        try writer.print(",\"service_count\":{d},\"worker_count\":{d},\"cron_count\":{d},\"training_job_count\":{d},\"completed_targets\":{d},\"failed_targets\":{d},\"remaining_targets\":{d}", .{
            summary.service_count,
            summary.worker_count,
            summary.cron_count,
            summary.training_job_count,
            report.completed_targets,
            report.failed_targets,
            report.remainingTargets(),
        });
        try writer.writeByte(',');
        try json_helpers.writeNullableJsonStringField(writer, "source_release_id", report.source_release_id);
        try writer.writeByte(',');
        try json_helpers.writeNullableJsonStringField(writer, "message", report.message);
        try writer.print(",\"is_current\":{},\"is_previous_successful\":{}", .{ is_current, is_previous_successful });
        try writer.writeAll(",\"release\":{");
        try json_helpers.writeJsonStringField(writer, "id", report.release_id orelse "");
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "trigger", report.trigger.toString());
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "status", report.status.toString());
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "manifest_hash", report.manifest_hash);
        try writer.print(",\"created_at\":{d},\"completed_targets\":{d},\"failed_targets\":{d},\"remaining_targets\":{d},\"current\":{},\"previous_successful\":{}", .{
            report.created_at,
            report.completed_targets,
            report.failed_targets,
            report.remainingTargets(),
            is_current,
            is_previous_successful,
        });
        try writer.writeByte(',');
        try json_helpers.writeNullableJsonStringField(writer, "source_release_id", report.source_release_id);
        try writer.writeByte(',');
        try json_helpers.writeNullableJsonStringField(writer, "message", report.message);
        try writer.writeByte('}');
        try writer.print(",\"workloads\":{{\"services\":{d},\"workers\":{d},\"crons\":{d},\"training_jobs\":{d}}}", .{
            summary.service_count,
            summary.worker_count,
            summary.cron_count,
            summary.training_job_count,
        });
        try writer.writeByte('}');
    }
    try writer.writeByte(']');
    return json_buf.toOwnedSlice(alloc);
}

fn formatAppStatusResponse(
    alloc: std.mem.Allocator,
    report: apply_release.ApplyReport,
    previous_successful: ?apply_release.ApplyReport,
    summary: app_snapshot.Summary,
    training_summary: store.TrainingJobSummary,
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
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "manifest_hash", report.manifest_hash);
    try writer.print(",\"created_at\":{d},\"service_count\":{d},\"worker_count\":{d},\"cron_count\":{d},\"training_job_count\":{d},\"active_training_jobs\":{d},\"paused_training_jobs\":{d},\"failed_training_jobs\":{d},\"completed_targets\":{d},\"failed_targets\":{d},\"remaining_targets\":{d}", .{
        report.created_at,
        summary.service_count,
        summary.worker_count,
        summary.cron_count,
        summary.training_job_count,
        training_summary.active,
        training_summary.paused,
        training_summary.failed,
        report.completed_targets,
        report.failed_targets,
        report.remainingTargets(),
    });
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "source_release_id", report.source_release_id);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_release_id", if (previous_successful) |prev| prev.release_id else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_trigger", if (previous_successful) |prev| prev.trigger.toString() else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_status", if (previous_successful) |prev| prev.status.toString() else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_manifest_hash", if (previous_successful) |prev| prev.manifest_hash else null);
    if (previous_successful) |prev| {
        try writer.print(",\"previous_successful_created_at\":{d}", .{prev.created_at});
        try writer.print(",\"previous_successful_completed_targets\":{d},\"previous_successful_failed_targets\":{d},\"previous_successful_remaining_targets\":{d}", .{
            prev.completed_targets,
            prev.failed_targets,
            prev.remainingTargets(),
        });
    } else {
        try writer.writeAll(",\"previous_successful_created_at\":null");
        try writer.writeAll(",\"previous_successful_completed_targets\":0,\"previous_successful_failed_targets\":0,\"previous_successful_remaining_targets\":0");
    }
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_source_release_id", if (previous_successful) |prev| prev.source_release_id else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_message", if (previous_successful) |prev| prev.message else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "message", report.message);
    try writer.writeAll(",\"current_release\":{");
    try json_helpers.writeJsonStringField(writer, "id", report.release_id orelse "");
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "trigger", report.trigger.toString());
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "status", report.status.toString());
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "manifest_hash", report.manifest_hash);
    try writer.print(",\"created_at\":{d},\"completed_targets\":{d},\"failed_targets\":{d},\"remaining_targets\":{d}", .{
        report.created_at,
        report.completed_targets,
        report.failed_targets,
        report.remainingTargets(),
    });
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "source_release_id", report.source_release_id);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "message", report.message);
    try writer.writeByte('}');
    try writer.writeAll(",\"previous_successful_release\":");
    if (previous_successful) |prev| {
        try writer.writeByte('{');
        try json_helpers.writeJsonStringField(writer, "id", prev.release_id orelse "");
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "trigger", prev.trigger.toString());
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "status", prev.status.toString());
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "manifest_hash", prev.manifest_hash);
        try writer.print(",\"created_at\":{d},\"completed_targets\":{d},\"failed_targets\":{d},\"remaining_targets\":{d}", .{
            prev.created_at,
            prev.completed_targets,
            prev.failed_targets,
            prev.remainingTargets(),
        });
        try writer.writeByte(',');
        try json_helpers.writeNullableJsonStringField(writer, "source_release_id", prev.source_release_id);
        try writer.writeByte(',');
        try json_helpers.writeNullableJsonStringField(writer, "message", prev.message);
        try writer.writeByte('}');
    } else {
        try writer.writeAll("null");
    }
    try writer.print(",\"workloads\":{{\"services\":{d},\"workers\":{d},\"crons\":{d},\"training_jobs\":{d}}}", .{
        summary.service_count,
        summary.worker_count,
        summary.cron_count,
        summary.training_job_count,
    });
    try writer.print(",\"training_runtime\":{{\"active\":{d},\"paused\":{d},\"failed\":{d}}}", .{
        training_summary.active,
        training_summary.paused,
        training_summary.failed,
    });
    try writer.writeByte('}');
    return json_buf.toOwnedSlice(alloc);
}

fn findPreviousSuccessfulReleaseId(deployments: []const store.DeploymentRecord) ?[]const u8 {
    if (deployments.len == 0) return null;
    for (deployments[1..]) |dep| {
        if (std.mem.eql(u8, dep.status, "completed")) return dep.id;
    }
    return null;
}

const RouteFlowHarness = struct {
    alloc: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    node: cluster_node.Node,

    fn init(alloc: std.mem.Allocator) !RouteFlowHarness {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var path_buf: [512]u8 = undefined;
        const tmp_path = tmp.dir.realpath(".", &path_buf) catch return error.SkipZigTest;

        var node = cluster_node.Node.init(alloc, .{
            .id = 1,
            .port = 0,
            .peers = &.{},
            .data_dir = tmp_path,
        }) catch return error.SkipZigTest;
        errdefer node.deinit();

        node.raft.role = .leader;
        node.leader_id = node.config.id;

        var harness = RouteFlowHarness{
            .alloc = alloc,
            .tmp = tmp,
            .node = node,
        };
        try harness.seedActiveAgent();
        return harness;
    }

    fn deinit(self: *RouteFlowHarness) void {
        self.node.deinit();
        self.tmp.cleanup();
    }

    fn ctx(self: *RouteFlowHarness) RouteContext {
        return .{ .cluster = &self.node, .join_token = null };
    }

    fn applyCommitted(self: *RouteFlowHarness) void {
        self.node.state_machine.applyUpTo(&self.node.log, self.alloc, self.node.log.lastIndex());
        self.node.raft.role = .leader;
        self.node.leader_id = self.node.config.id;
    }

    fn seedActiveAgent(self: *RouteFlowHarness) !void {
        self.node.stateMachineDb().exec(
            "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role, labels) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            .{},
            .{ "abc123def456", "10.0.0.2:7701", "active", @as(i64, 4), @as(i64, 8192), @as(i64, 0), @as(i64, 0), @as(i64, 0), @as(i64, 100), @as(i64, 100), "agent", "" },
        ) catch return error.SkipZigTest;
    }

    fn appApply(self: *RouteFlowHarness, body: []const u8) Response {
        return deploy_routes.handleAppApply(self.alloc, makeRequest(.POST, "/apps/apply", body), self.ctx());
    }

    fn rollback(self: *RouteFlowHarness, app_name: []const u8, release_id: []const u8) !Response {
        const body = try std.fmt.allocPrint(self.alloc, "{{\"release_id\":\"{s}\"}}", .{release_id});
        defer self.alloc.free(body);
        const path = try std.fmt.allocPrint(self.alloc, "/apps/{s}/rollback", .{app_name});
        defer self.alloc.free(path);
        return handleAppRollback(self.alloc, app_name, makeRequest(.POST, path, body), self.ctx());
    }

    fn rollbackDefault(self: *RouteFlowHarness, app_name: []const u8) !Response {
        const path = try std.fmt.allocPrint(self.alloc, "/apps/{s}/rollback", .{app_name});
        defer self.alloc.free(path);
        return handleAppRollback(self.alloc, app_name, makeRequest(.POST, path, "{\"print\":false}"), self.ctx());
    }

    fn rollbackPrint(self: *RouteFlowHarness, app_name: []const u8) !Response {
        const path = try std.fmt.allocPrint(self.alloc, "/apps/{s}/rollback", .{app_name});
        defer self.alloc.free(path);
        return handleAppRollback(self.alloc, app_name, makeRequest(.POST, path, "{\"print\":true}"), self.ctx());
    }

    fn status(self: *RouteFlowHarness, app_name: []const u8) Response {
        return handleAppStatus(self.alloc, app_name, self.ctx());
    }

    fn history(self: *RouteFlowHarness, app_name: []const u8) Response {
        return handleAppHistory(self.alloc, app_name, self.ctx());
    }
};

fn makeRequest(method: http.Method, path: []const u8, body: []const u8) http.Request {
    return .{
        .method = method,
        .path = path,
        .path_only = path,
        .query = "",
        .headers_raw = "",
        .body = body,
        .content_length = body.len,
    };
}

fn freeResponse(alloc: std.mem.Allocator, response: Response) void {
    if (response.allocated) alloc.free(response.body);
}

fn expectJsonContains(json: []const u8, needle: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, json, needle) != null);
}

fn expectResponseOk(response: Response) !void {
    try std.testing.expectEqual(http.StatusCode.ok, response.status);
}

test "formatAppHistoryResponse emits release records" {
    const alloc = std.testing.allocator;
    const deployments = [_]store.DeploymentRecord{
        .{
            .id = "dep-2",
            .app_name = "demo-app",
            .service_name = "demo-app",
            .manifest_hash = "sha256:222",
            .config_snapshot = "{}",
            .status = "failed",
            .message = "placement failed",
            .created_at = 200,
        },
        .{
            .id = "dep-1",
            .app_name = "demo-app",
            .service_name = "demo-app",
            .manifest_hash = "sha256:111",
            .config_snapshot = "{}",
            .status = "completed",
            .message = null,
            .created_at = 100,
        },
    };

    const json = try formatAppHistoryResponse(alloc, &deployments);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"app\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"apply\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_release_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"placement failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release\":{\"id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"workloads\":{\"services\":0,\"workers\":0,\"crons\":0,\"training_jobs\":0}") != null);
}

test "formatAppStatusResponse summarizes latest release" {
    const alloc = std.testing.allocator;
    const latest = store.DeploymentRecord{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"},{\"name\":\"db\"}]}",
        .status = "completed",
        .message = null,
        .created_at = 200,
    };

    const json = try formatAppStatusResponse(alloc, apply_release.reportFromDeployment(latest), null, app_snapshot.summarize(latest.config_snapshot), .{});
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"apply\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"service_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"completed_targets\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed_targets\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"remaining_targets\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_release_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"previous_successful_release_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"current_release\":{\"id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"workloads\":{\"services\":2,\"workers\":0,\"crons\":0,\"training_jobs\":0}") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"training_runtime\":{\"active\":0,\"paused\":0,\"failed\":0}") != null);
}

test "formatAppsResponse emits one latest summary per app" {
    const alloc = std.testing.allocator;

    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try store.saveDeploymentInDb(&db, .{
        .id = "dep-1",
        .app_name = "app-a",
        .service_name = "app-a",
        .trigger = "apply",
        .manifest_hash = "sha256:a1",
        .config_snapshot = "{\"app_name\":\"app-a\",\"services\":[{\"name\":\"web\"}],\"workers\":[],\"crons\":[],\"training_jobs\":[]}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 100,
    });
    try store.saveDeploymentInDb(&db, .{
        .id = "dep-2",
        .app_name = "app-b",
        .service_name = "app-b",
        .trigger = "apply",
        .manifest_hash = "sha256:b1",
        .config_snapshot = "{\"app_name\":\"app-b\",\"services\":[{\"name\":\"api\"}],\"workers\":[],\"crons\":[],\"training_jobs\":[]}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 150,
    });
    try store.saveDeploymentInDb(&db, .{
        .id = "dep-3",
        .app_name = "app-a",
        .service_name = "app-a",
        .trigger = "apply",
        .manifest_hash = "sha256:a2",
        .config_snapshot = "{\"app_name\":\"app-a\",\"services\":[{\"name\":\"web\"},{\"name\":\"db\"}],\"workers\":[{\"name\":\"migrate\"}],\"crons\":[{\"name\":\"nightly\"}],\"training_jobs\":[{\"name\":\"finetune\"}]}",
        .status = "failed",
        .message = "scheduler error during apply",
        .created_at = 200,
    });
    try store.saveTrainingJobInDb(&db, .{
        .id = "job-1",
        .name = "finetune-a",
        .app_name = "app-a",
        .state = "running",
        .image = "trainer:v1",
        .gpus = 1,
        .checkpoint_path = null,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = 0,
        .created_at = 210,
        .updated_at = 210,
    });
    try store.saveTrainingJobInDb(&db, .{
        .id = "job-2",
        .name = "finetune-b",
        .app_name = "app-a",
        .state = "paused",
        .image = "trainer:v1",
        .gpus = 1,
        .checkpoint_path = null,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = 0,
        .created_at = 220,
        .updated_at = 220,
    });
    try store.saveTrainingJobInDb(&db, .{
        .id = "job-3",
        .name = "finetune-c",
        .app_name = "app-a",
        .state = "failed",
        .image = "trainer:v1",
        .gpus = 1,
        .checkpoint_path = null,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = 0,
        .created_at = 230,
        .updated_at = 230,
    });

    var latest = try store.listLatestDeploymentsByAppInDb(&db, alloc);
    defer {
        for (latest.items) |dep| dep.deinit(alloc);
        latest.deinit(alloc);
    }

    const json = try formatAppsResponse(alloc, &db, latest.items);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"app-a\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"dep-3\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"previous_successful_release_id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"worker_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"cron_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"training_job_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"active_training_jobs\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"paused_training_jobs\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed_training_jobs\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"app-b\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"dep-2\"") != null);
}

test "formatAppsResponse returns empty array when no app releases exist" {
    const alloc = std.testing.allocator;

    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const json = try formatAppsResponse(alloc, &db, &.{});
    defer alloc.free(json);

    try std.testing.expectEqualStrings("[]", json);
}

test "formatAppStatusResponse includes structured rollback metadata" {
    const alloc = std.testing.allocator;
    const latest = store.DeploymentRecord{
        .id = "dep-3",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "rollback",
        .source_release_id = "dep-1",
        .manifest_hash = "sha256:333",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .completed_targets = 1,
        .failed_targets = 0,
        .status = "completed",
        .message = "rollback to dep-1 completed: all placements succeeded",
        .created_at = 300,
    };

    const json = try formatAppStatusResponse(alloc, apply_release.reportFromDeployment(latest), null, app_snapshot.summarize(latest.config_snapshot), .{});
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"rollback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_release_id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"completed_targets\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"remaining_targets\":0") != null);
}

test "formatAppStatusResponse falls back to rollback metadata inferred from legacy message" {
    const alloc = std.testing.allocator;
    const latest = store.DeploymentRecord{
        .id = "dep-4",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .manifest_hash = "sha256:444",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "completed",
        .message = "rollback to dep-1 completed: all placements succeeded",
        .created_at = 400,
    };

    const json = try formatAppStatusResponse(alloc, apply_release.reportFromDeployment(latest), null, app_snapshot.summarize(latest.config_snapshot), .{});
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"rollback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_release_id\":\"dep-1\"") != null);
}

test "app status and history surface rollback release metadata from persisted rows" {
    const alloc = std.testing.allocator;

    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try store.saveDeploymentInDb(&db, .{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 100,
    });
    try store.saveDeploymentInDb(&db, .{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "rollback",
        .source_release_id = "dep-1",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "completed",
        .message = "rollback to dep-1 completed: all placements succeeded",
        .created_at = 200,
    });

    var deployments = try store.listDeploymentsByAppInDb(&db, alloc, "demo-app");
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    const history_json = try formatAppHistoryResponse(alloc, deployments.items);
    defer alloc.free(history_json);

    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"trigger\":\"rollback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"source_release_id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"trigger\":\"apply\"") != null);

    const latest = try store.getLatestDeploymentByAppInDb(&db, alloc, "demo-app");
    defer latest.deinit(alloc);

    const previous_successful = try store.getPreviousSuccessfulDeploymentByAppInDb(&db, alloc, "demo-app", latest.id);
    defer previous_successful.deinit(alloc);

    const status_json = try formatAppStatusResponse(
        alloc,
        apply_release.reportFromDeployment(latest),
        apply_release.reportFromDeployment(previous_successful),
        app_snapshot.summarize(latest.config_snapshot),
        .{},
    );
    defer alloc.free(status_json);

    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"release_id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"trigger\":\"rollback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"source_release_id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"previous_successful_release_id\":\"dep-1\"") != null);
}

test "app status and history surface failed apply metadata from persisted rows" {
    const alloc = std.testing.allocator;

    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try store.saveDeploymentInDb(&db, .{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 100,
    });
    try store.saveDeploymentInDb(&db, .{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"},{\"name\":\"db\"}]}",
        .status = "failed",
        .message = "scheduler error during apply",
        .created_at = 200,
    });

    var deployments = try store.listDeploymentsByAppInDb(&db, alloc, "demo-app");
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    const history_json = try formatAppHistoryResponse(alloc, deployments.items);
    defer alloc.free(history_json);

    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"trigger\":\"apply\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"status\":\"failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"source_release_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"message\":\"scheduler error during apply\"") != null);

    const latest = try store.getLatestDeploymentByAppInDb(&db, alloc, "demo-app");
    defer latest.deinit(alloc);

    const previous_successful = try store.getPreviousSuccessfulDeploymentByAppInDb(&db, alloc, "demo-app", latest.id);
    defer previous_successful.deinit(alloc);

    const status_json = try formatAppStatusResponse(
        alloc,
        apply_release.reportFromDeployment(latest),
        apply_release.reportFromDeployment(previous_successful),
        app_snapshot.summarize(latest.config_snapshot),
        .{},
    );
    defer alloc.free(status_json);

    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"release_id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"trigger\":\"apply\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"status\":\"failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"service_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"source_release_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"previous_successful_release_id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"message\":\"scheduler error during apply\"") != null);
}

test "app apply then rollback routes preserve release transition metadata" {
    const alloc = std.testing.allocator;
    const apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"alpine","command":["echo","hello"]}]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const apply_response = harness.appApply(apply_body);
    defer freeResponse(alloc, apply_response);

    try expectResponseOk(apply_response);
    try expectJsonContains(apply_response.body, "\"trigger\":\"apply\"");

    const source_release_id = json_helpers.extractJsonString(apply_response.body, "release_id").?;

    const rollback_response = try harness.rollback("demo-app", source_release_id);
    defer freeResponse(alloc, rollback_response);

    try expectResponseOk(rollback_response);
    try expectJsonContains(rollback_response.body, "\"trigger\":\"rollback\"");
    try expectJsonContains(rollback_response.body, "\"source_release_id\":\"");
    try expectJsonContains(rollback_response.body, source_release_id);

    const latest = try store.getLatestDeploymentByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer latest.deinit(alloc);

    try std.testing.expectEqualStrings("rollback", latest.trigger.?);
    try std.testing.expectEqualStrings(source_release_id, latest.source_release_id.?);

    const status_response = harness.status("demo-app");
    defer freeResponse(alloc, status_response);

    try expectResponseOk(status_response);
    try expectJsonContains(status_response.body, "\"trigger\":\"rollback\"");
    try expectJsonContains(status_response.body, "\"source_release_id\":\"");
    try expectJsonContains(status_response.body, source_release_id);

    const history_response = harness.history("demo-app");
    defer freeResponse(alloc, history_response);

    try expectResponseOk(history_response);
    try expectJsonContains(history_response.body, "\"trigger\":\"rollback\"");
    try expectJsonContains(history_response.body, "\"source_release_id\":\"");
    try expectJsonContains(history_response.body, source_release_id);
}

test "app rollback defaults to the previous successful release when release id is omitted" {
    const alloc = std.testing.allocator;
    const first_apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx:1","command":["echo","first"]}]}
    ;
    const second_apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx:2","command":["echo","second"]}]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const first_apply_response = harness.appApply(first_apply_body);
    defer freeResponse(alloc, first_apply_response);
    std.debug.print("first_apply_response={s}\n", .{first_apply_response.body});
    try expectResponseOk(first_apply_response);
    const source_release_id = json_helpers.extractJsonString(first_apply_response.body, "release_id").?;

    const second_apply_response = harness.appApply(second_apply_body);
    defer freeResponse(alloc, second_apply_response);
    try expectResponseOk(second_apply_response);

    const rollback_response = try harness.rollbackDefault("demo-app");
    defer freeResponse(alloc, rollback_response);
    try expectResponseOk(rollback_response);
    try expectJsonContains(rollback_response.body, "\"source_release_id\":\"");
    try expectJsonContains(rollback_response.body, source_release_id);

    const latest = try store.getLatestDeploymentByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer latest.deinit(alloc);
    try std.testing.expectEqualStrings("rollback", latest.trigger.?);
    try std.testing.expectEqualStrings(source_release_id, latest.source_release_id.?);
}

test "app rollback print returns the selected snapshot without creating a new release" {
    const alloc = std.testing.allocator;
    const first_apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx:1","command":["echo","first"]}]}
    ;
    const second_apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx:2","command":["echo","second"]}]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const first_apply_response = harness.appApply(first_apply_body);
    defer freeResponse(alloc, first_apply_response);
    try expectResponseOk(first_apply_response);

    const second_apply_response = harness.appApply(second_apply_body);
    defer freeResponse(alloc, second_apply_response);
    try expectResponseOk(second_apply_response);

    var before = try store.listDeploymentsByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer {
        for (before.items) |dep| dep.deinit(alloc);
        before.deinit(alloc);
    }

    const rollback_response = try harness.rollbackPrint("demo-app");
    defer freeResponse(alloc, rollback_response);
    try expectResponseOk(rollback_response);
    try std.testing.expect(std.mem.indexOf(u8, rollback_response.body, "\"image\":\"nginx:1\"") != null);

    var after = try store.listDeploymentsByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer {
        for (after.items) |dep| dep.deinit(alloc);
        after.deinit(alloc);
    }
    try std.testing.expectEqual(before.items.len, after.items.len);
}

test "app apply registers cluster cron schedules from snapshot" {
    const alloc = std.testing.allocator;
    const apply_body =
        \\{"app_name":"demo-app","services":[],"workers":[],"crons":[{"name":"nightly","image":"alpine","command":["/bin/sh","-c","echo cron"],"every":3600}],"training_jobs":[]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const apply_response = harness.appApply(apply_body);
    defer freeResponse(alloc, apply_response);

    try expectResponseOk(apply_response);
    try expectJsonContains(apply_response.body, "\"cron_count\":1");

    var schedules = try store.listCronSchedulesByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer {
        for (schedules.items) |schedule| schedule.deinit(alloc);
        schedules.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), schedules.items.len);
    try std.testing.expectEqualStrings("nightly", schedules.items[0].name);
    try std.testing.expectEqual(@as(i64, 3600), schedules.items[0].every);
}

test "app rollback restores worker and training workload snapshot" {
    const alloc = std.testing.allocator;
    const first_apply_body =
        \\{"app_name":"demo-app","services":[],"workers":[{"name":"migrate","image":"alpine","command":["/bin/sh","-c","echo first"]}],"crons":[],"training_jobs":[{"name":"finetune","image":"trainer:v1","command":["python","train.py"],"gpus":1}]}
    ;
    const second_apply_body =
        \\{"app_name":"demo-app","services":[],"workers":[{"name":"compact","image":"alpine","command":["/bin/sh","-c","echo second"]}],"crons":[{"name":"nightly","schedule":"0 2 * * *","command":["/bin/sh","-c","echo cron"]}],"training_jobs":[]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const first_apply_response = harness.appApply(first_apply_body);
    defer freeResponse(alloc, first_apply_response);
    try expectResponseOk(first_apply_response);

    const source_release_id = json_helpers.extractJsonString(first_apply_response.body, "release_id").?;

    const second_apply_response = harness.appApply(second_apply_body);
    defer freeResponse(alloc, second_apply_response);
    try expectResponseOk(second_apply_response);

    const rollback_response = try harness.rollback("demo-app", source_release_id);
    defer freeResponse(alloc, rollback_response);
    try expectResponseOk(rollback_response);

    const latest = try store.getLatestDeploymentByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer latest.deinit(alloc);

    try std.testing.expectEqualStrings("rollback", latest.trigger.?);
    try std.testing.expectEqualStrings(source_release_id, latest.source_release_id.?);
    try std.testing.expect(std.mem.indexOf(u8, latest.config_snapshot, "\"workers\":[{\"name\":\"migrate\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, latest.config_snapshot, "\"training_jobs\":[{\"name\":\"finetune\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, latest.config_snapshot, "\"crons\":[]") != null);

    var schedules = try store.listCronSchedulesByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer {
        for (schedules.items) |schedule| schedule.deinit(alloc);
        schedules.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 0), schedules.items.len);

    const status_response = harness.status("demo-app");
    defer freeResponse(alloc, status_response);
    try expectResponseOk(status_response);
    try expectJsonContains(status_response.body, "\"worker_count\":1");
    try expectJsonContains(status_response.body, "\"training_job_count\":1");
    try expectJsonContains(status_response.body, "\"cron_count\":0");
}

test "app rollback restores cluster cron schedules from selected release" {
    const alloc = std.testing.allocator;
    const first_apply_body =
        \\{"app_name":"demo-app","services":[],"workers":[],"crons":[{"name":"cleanup","image":"alpine","command":["/bin/sh","-c","echo first"],"every":60}],"training_jobs":[]}
    ;
    const second_apply_body =
        \\{"app_name":"demo-app","services":[],"workers":[],"crons":[{"name":"backup","image":"alpine","command":["/bin/sh","-c","echo second"],"every":3600}],"training_jobs":[]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const first_apply_response = harness.appApply(first_apply_body);
    defer freeResponse(alloc, first_apply_response);
    try expectResponseOk(first_apply_response);
    const source_release_id = json_helpers.extractJsonString(first_apply_response.body, "release_id").?;

    const second_apply_response = harness.appApply(second_apply_body);
    defer freeResponse(alloc, second_apply_response);
    try expectResponseOk(second_apply_response);

    const rollback_response = try harness.rollback("demo-app", source_release_id);
    defer freeResponse(alloc, rollback_response);
    try expectResponseOk(rollback_response);

    var schedules = try store.listCronSchedulesByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer {
        for (schedules.items) |schedule| schedule.deinit(alloc);
        schedules.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), schedules.items.len);
    try std.testing.expectEqualStrings("cleanup", schedules.items[0].name);
    try std.testing.expectEqual(@as(i64, 60), schedules.items[0].every);
}

test "app apply route preserves failed release metadata across reads" {
    const alloc = std.testing.allocator;
    const apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"alpine","command":["echo","hello"],"cpu_limit":999999,"memory_limit_mb":999999}]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const apply_response = harness.appApply(apply_body);
    defer freeResponse(alloc, apply_response);

    try expectResponseOk(apply_response);
    try expectJsonContains(apply_response.body, "\"trigger\":\"apply\"");
    try expectJsonContains(apply_response.body, "\"status\":\"failed\"");
    try expectJsonContains(apply_response.body, "\"failed\":1");
    try expectJsonContains(apply_response.body, "\"source_release_id\":null");
    try expectJsonContains(apply_response.body, "\"message\":\"one or more placements failed\"");

    const release_id = json_helpers.extractJsonString(apply_response.body, "release_id").?;

    const status_response = harness.status("demo-app");
    defer freeResponse(alloc, status_response);

    try expectResponseOk(status_response);
    try expectJsonContains(status_response.body, "\"release_id\":\"");
    try expectJsonContains(status_response.body, release_id);
    try expectJsonContains(status_response.body, "\"trigger\":\"apply\"");
    try expectJsonContains(status_response.body, "\"status\":\"failed\"");
    try expectJsonContains(status_response.body, "\"source_release_id\":null");
    try expectJsonContains(status_response.body, "\"message\":\"one or more placements failed\"");

    const history_response = harness.history("demo-app");
    defer freeResponse(alloc, history_response);

    try expectResponseOk(history_response);
    try expectJsonContains(history_response.body, "\"id\":\"");
    try expectJsonContains(history_response.body, release_id);
    try expectJsonContains(history_response.body, "\"trigger\":\"apply\"");
    try expectJsonContains(history_response.body, "\"status\":\"failed\"");
    try expectJsonContains(history_response.body, "\"source_release_id\":null");
    try expectJsonContains(history_response.body, "\"message\":\"one or more placements failed\"");
}

test "app apply route preserves partially failed release metadata across reads" {
    const alloc = std.testing.allocator;
    const apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"alpine","command":["echo","hello"]},{"name":"db","image":"alpine","command":["echo","db"],"cpu_limit":999999,"memory_limit_mb":999999}]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const apply_response = harness.appApply(apply_body);
    defer freeResponse(alloc, apply_response);

    try expectResponseOk(apply_response);
    try expectJsonContains(apply_response.body, "\"trigger\":\"apply\"");
    try expectJsonContains(apply_response.body, "\"status\":\"partially_failed\"");
    try expectJsonContains(apply_response.body, "\"placed\":1");
    try expectJsonContains(apply_response.body, "\"failed\":1");
    try expectJsonContains(apply_response.body, "\"source_release_id\":null");
    try expectJsonContains(apply_response.body, "\"message\":\"one or more placements failed\"");

    const release_id = json_helpers.extractJsonString(apply_response.body, "release_id").?;

    const status_response = harness.status("demo-app");
    defer freeResponse(alloc, status_response);

    try expectResponseOk(status_response);
    try expectJsonContains(status_response.body, "\"release_id\":\"");
    try expectJsonContains(status_response.body, release_id);
    try expectJsonContains(status_response.body, "\"trigger\":\"apply\"");
    try expectJsonContains(status_response.body, "\"status\":\"partially_failed\"");
    try expectJsonContains(status_response.body, "\"source_release_id\":null");
    try expectJsonContains(status_response.body, "\"message\":\"one or more placements failed\"");

    const history_response = harness.history("demo-app");
    defer freeResponse(alloc, history_response);

    try expectResponseOk(history_response);
    try expectJsonContains(history_response.body, "\"id\":\"");
    try expectJsonContains(history_response.body, release_id);
    try expectJsonContains(history_response.body, "\"trigger\":\"apply\"");
    try expectJsonContains(history_response.body, "\"status\":\"partially_failed\"");
    try expectJsonContains(history_response.body, "\"source_release_id\":null");
    try expectJsonContains(history_response.body, "\"message\":\"one or more placements failed\"");
}

test "route rejects app rollback without cluster" {
    const body = "{\"release_id\":\"abc123def456\"}";
    const request = http.Request{
        .method = .POST,
        .path = "/apps/demo-app/rollback",
        .path_only = "/apps/demo-app/rollback",
        .query = "",
        .headers_raw = "",
        .body = body,
        .content_length = body.len,
    };
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };

    const response = route(request, std.testing.allocator, ctx).?;
    try std.testing.expectEqual(http.StatusCode.bad_request, response.status);
}
