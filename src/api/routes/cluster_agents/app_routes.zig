const std = @import("std");
const http = @import("../../http.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const app_rollout_control = @import("app_rollout_control.zig");
const app_route_responses = @import("app_route_responses.zig");
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

    if (common.matchSubpath(rest, "/rollout/pause")) |app_name| {
        if (!common.validateClusterInput(app_name)) return common.badRequest("invalid app name");
        if (request.method != .POST) return common.methodNotAllowed();
        return handleRolloutControl(alloc, app_name, "paused", ctx);
    }
    if (common.matchSubpath(rest, "/rollout/resume")) |app_name| {
        if (!common.validateClusterInput(app_name)) return common.badRequest("invalid app name");
        if (request.method != .POST) return common.methodNotAllowed();
        return handleRolloutControl(alloc, app_name, "active", ctx);
    }
    if (common.matchSubpath(rest, "/rollout/cancel")) |app_name| {
        if (!common.validateClusterInput(app_name)) return common.badRequest("invalid app name");
        if (request.method != .POST) return common.methodNotAllowed();
        return handleRolloutControl(alloc, app_name, "cancel_requested", ctx);
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

    const body = app_route_responses.formatApps(alloc, node.stateMachineDb(), latest.items) catch return common.internalError();
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

    const body = app_route_responses.formatHistory(alloc, deployments.items) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleAppStatus(alloc: std.mem.Allocator, app_name: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const latest = store.getLatestDeploymentByAppInDb(node.stateMachineDb(), alloc, app_name) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        else => common.internalError(),
    };
    defer latest.deinit(alloc);

    const previous_successful = app_route_responses.loadPreviousSuccessfulDeployment(
        node.stateMachineDb(),
        alloc,
        app_name,
        latest.id,
    ) catch return common.internalError();
    defer if (previous_successful) |dep| dep.deinit(alloc);

    const body = app_route_responses.formatStatusFromDeployments(alloc, node.stateMachineDb(), latest, previous_successful) catch return common.internalError();
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

pub fn handleRolloutControl(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    control_state: []const u8,
    ctx: RouteContext,
) Response {
    return app_rollout_control.handleRolloutControl(alloc, app_name, control_state, ctx);
}

pub fn recoverActiveClusterRolloutsOnce(alloc: std.mem.Allocator, ctx: RouteContext) !usize {
    return app_rollout_control.recoverActiveClusterRolloutsOnce(alloc, ctx);
}
