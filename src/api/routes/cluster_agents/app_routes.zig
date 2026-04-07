const std = @import("std");
const json_helpers = @import("../../../lib/json_helpers.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");

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

    const body = formatAppStatusResponse(alloc, latest, countServices(latest.config_snapshot)) catch
        return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn countServices(snapshot: []const u8) usize {
    const services = json_helpers.extractJsonArray(snapshot, "services") orelse return 0;
    var iter = json_helpers.extractJsonObjects(services);
    var count: usize = 0;
    while (iter.next() != null) count += 1;
    return count;
}

fn formatAppHistoryResponse(alloc: std.mem.Allocator, deployments: []const store.DeploymentRecord) ![]u8 {
    var json_buf: std.ArrayList(u8) = .empty;
    errdefer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    try writer.writeByte('[');
    for (deployments, 0..) |dep, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.writeAll("{\"id\":\"");
        try json_helpers.writeJsonEscaped(writer, dep.id);
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
        try json_helpers.writeJsonEscaped(writer, dep.status);
        try writer.writeAll("\",\"manifest_hash\":\"");
        try json_helpers.writeJsonEscaped(writer, dep.manifest_hash);
        try writer.print("\",\"created_at\":{d}", .{dep.created_at});
        if (dep.message) |message| {
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
    latest: store.DeploymentRecord,
    service_count: usize,
) ![]u8 {
    var json_buf: std.ArrayList(u8) = .empty;
    errdefer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    try writer.writeAll("{\"app_name\":\"");
    try json_helpers.writeJsonEscaped(writer, latest.app_name orelse latest.service_name);
    try writer.writeAll("\",\"release_id\":\"");
    try json_helpers.writeJsonEscaped(writer, latest.id);
    try writer.writeAll("\",\"status\":\"");
    try json_helpers.writeJsonEscaped(writer, latest.status);
    try writer.writeAll("\",\"manifest_hash\":\"");
    try json_helpers.writeJsonEscaped(writer, latest.manifest_hash);
    try writer.print("\",\"created_at\":{d},\"service_count\":{d}", .{
        latest.created_at,
        service_count,
    });
    if (latest.message) |message| {
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

    const json = try formatAppStatusResponse(alloc, latest, countServices(latest.config_snapshot));
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"service_count\":2") != null);
}
