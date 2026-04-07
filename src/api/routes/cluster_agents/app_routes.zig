const std = @import("std");
const http = @import("../../http.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const apply_release = @import("../../../manifest/apply_release.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const deploy_routes = @import("deploy_routes.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

pub fn route(request: @import("../../http.zig").Request, alloc: std.mem.Allocator, ctx: RouteContext) ?Response {
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

    const body = formatAppStatusResponse(alloc, apply_release.reportFromDeployment(latest)) catch
        return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleAppRollback(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    request: http.Request,
    ctx: RouteContext,
) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const release_id = json_helpers.extractJsonString(request.body, "release_id") orelse
        return common.badRequest("missing release_id");
    if (!common.validateContainerId(release_id)) return common.badRequest("invalid release_id");

    const release = store.getDeploymentInDb(node.stateMachineDb(), alloc, release_id) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        else => common.internalError(),
    };
    defer release.deinit(alloc);

    if (release.app_name == null or !std.mem.eql(u8, release.app_name.?, app_name)) {
        return common.notFound();
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
    return deploy_routes.handleAppRollbackApply(alloc, apply_request, ctx, release_id);
}

fn formatAppHistoryResponse(alloc: std.mem.Allocator, deployments: []const store.DeploymentRecord) ![]u8 {
    var json_buf: std.ArrayList(u8) = .empty;
    errdefer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    try writer.writeByte('[');
    for (deployments, 0..) |dep, i| {
        const report = apply_release.reportFromDeployment(dep);
        if (i > 0) try writer.writeByte(',');
        try writer.writeAll("{\"id\":\"");
        try json_helpers.writeJsonEscaped(writer, report.release_id orelse "");
        if (dep.app_name) |app_name| {
            try writer.writeAll("\",\"app\":\"");
            try json_helpers.writeJsonEscaped(writer, app_name);
            try writer.writeByte('"');
        } else {
            try writer.writeAll("\",\"app\":null");
        }
        try writer.writeAll(",\"service\":\"");
        try json_helpers.writeJsonEscaped(writer, dep.service_name);
        try writer.writeAll("\",\"status\":\"");
        try json_helpers.writeJsonEscaped(writer, report.status.toString());
        try writer.writeAll("\",\"manifest_hash\":\"");
        try json_helpers.writeJsonEscaped(writer, report.manifest_hash);
        try writer.print("\",\"created_at\":{d}", .{report.created_at});
        if (report.message) |message| {
            try writer.writeAll(",\"message\":\"");
            try json_helpers.writeJsonEscaped(writer, message);
            try writer.writeByte('"');
        } else {
            try writer.writeAll(",\"message\":null");
        }
        try writer.writeByte('}');
    }
    try writer.writeByte(']');
    return json_buf.toOwnedSlice(alloc);
}

fn formatAppStatusResponse(
    alloc: std.mem.Allocator,
    report: apply_release.ApplyReport,
) ![]u8 {
    var json_buf: std.ArrayList(u8) = .empty;
    errdefer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    try writer.writeAll("{\"app_name\":\"");
    try json_helpers.writeJsonEscaped(writer, report.app_name);
    try writer.writeAll("\",\"release_id\":\"");
    try json_helpers.writeJsonEscaped(writer, report.release_id orelse "");
    try writer.writeAll("\",\"status\":\"");
    try json_helpers.writeJsonEscaped(writer, report.status.toString());
    try writer.writeAll("\",\"manifest_hash\":\"");
    try json_helpers.writeJsonEscaped(writer, report.manifest_hash);
    try writer.print("\",\"created_at\":{d},\"service_count\":{d}", .{
        report.created_at,
        report.service_count,
    });
    if (report.message) |message| {
        try writer.writeAll(",\"message\":\"");
        try json_helpers.writeJsonEscaped(writer, message);
        try writer.writeByte('"');
    } else {
        try writer.writeAll(",\"message\":null");
    }
    try writer.writeByte('}');
    return json_buf.toOwnedSlice(alloc);
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
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"placement failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":null") != null);
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

    const json = try formatAppStatusResponse(alloc, apply_release.reportFromDeployment(latest));
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"service_count\":2") != null);
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
