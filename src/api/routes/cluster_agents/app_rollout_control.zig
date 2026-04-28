const std = @import("std");

const http = @import("../../http.zig");
const apply_release = @import("../../../manifest/apply_release.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const deploy_routes = @import("deploy_routes.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

pub fn handleRolloutControl(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    control_state: []const u8,
    ctx: RouteContext,
) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const active = store.getActiveDeploymentByAppInDb(node.stateMachineDb(), alloc, app_name) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        else => common.internalError(),
    };
    defer active.deinit(alloc);

    if (shouldResumeStoredRollout(active, control_state)) {
        return resumeStoredClusterRollout(alloc, active, ctx);
    }

    store.updateDeploymentRolloutControlStateInDb(node.stateMachineDb(), active.id, control_state) catch return common.internalError();
    return rolloutControlResponse(alloc, app_name, active.id, control_state);
}

pub fn recoverActiveClusterRolloutsOnce(alloc: std.mem.Allocator, ctx: RouteContext) !usize {
    const node = ctx.cluster orelse return 0;
    var deployments = try store.listRecoverableActiveDeploymentsByAppInDb(node.stateMachineDb(), alloc);
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    var recovered: usize = 0;
    for (deployments.items) |dep| {
        if (deploy_routes.isClusterRolloutActive(dep.id)) continue;

        const response = resumeStoredClusterRollout(alloc, dep, ctx);
        defer if (response.allocated) alloc.free(response.body);

        if (response.status == .ok) {
            recovered += 1;
        }
    }
    return recovered;
}

fn rolloutContextFromDeployment(dep: store.DeploymentRecord) apply_release.ApplyContext {
    return .{
        .trigger = if (dep.trigger != null and std.mem.eql(u8, dep.trigger.?, "rollback")) .rollback else .apply,
        .source_release_id = dep.source_release_id,
        .resumed_from_release_id = dep.resumed_from_release_id,
    };
}

fn resumeStoredClusterRollout(
    alloc: std.mem.Allocator,
    active: store.DeploymentRecord,
    ctx: RouteContext,
) Response {
    const request = http.Request{
        .method = .POST,
        .path = "/apps/apply",
        .path_only = "/apps/apply",
        .query = "",
        .headers_raw = "",
        .body = active.config_snapshot,
        .content_length = active.config_snapshot.len,
    };

    var context = rolloutContextFromDeployment(active);
    context.continue_release_id = active.id;
    return switch (context.trigger) {
        .apply => deploy_routes.handleAppApplyWithContext(alloc, request, ctx, context),
        .rollback => blk: {
            context.source_release_id = active.source_release_id orelse active.id;
            break :blk deploy_routes.handleAppRollbackApplyWithContext(alloc, request, ctx, context);
        },
    };
}

fn shouldResumeStoredRollout(active: store.DeploymentRecord, control_state: []const u8) bool {
    return std.mem.eql(u8, control_state, "active") and
        std.mem.eql(u8, active.rollout_control_state orelse "active", "paused") and
        active.rollout_checkpoint_json != null;
}

fn rolloutControlResponse(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    release_id: []const u8,
    control_state: []const u8,
) Response {
    const body = std.fmt.allocPrint(
        alloc,
        "{{\"app_name\":\"{s}\",\"release_id\":\"{s}\",\"rollout_control_state\":\"{s}\"}}",
        .{ app_name, release_id, control_state },
    ) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}
