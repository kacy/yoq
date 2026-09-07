const std = @import("std");

const http = @import("../../http.zig");
const apply_release = @import("../../../manifest/apply_release.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const mutations = @import("../../../cluster/deployment_mutations.zig");
const mutation_session = @import("../../../cluster/mutation_session.zig");
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
    const session = mutation_session.Session.begin(node) catch return common.notLeader(alloc, node);
    session.synchronize() catch |err| return deploy_routes.mutationFailure(alloc, node, err);
    const active = store.getActiveDeploymentByAppInDb(node.stateMachineDb(), alloc, app_name) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        else => common.internalError(),
    };
    defer active.deinit(alloc);

    const command = mutations.control(alloc, active.id, control_state) catch return common.internalError();
    defer alloc.free(command);
    session.commit(command) catch |err| return deploy_routes.mutationFailure(alloc, node, err);
    // The rollout may finish while this command waits for its quorum. Report
    // the applied state instead of acknowledging a control that did not apply.
    node.mu.lockUncancelable(std.Options.debug_io);
    const applied = store.getDeploymentInDb(node.stateMachineDb(), alloc, active.id) catch {
        node.mu.unlock(std.Options.debug_io);
        return common.internalError();
    };
    node.mu.unlock(std.Options.debug_io);
    defer applied.deinit(alloc);
    if (!std.mem.eql(u8, applied.status, "pending") and !std.mem.eql(u8, applied.status, "in_progress"))
        return common.conflict("rollout already finished");
    if (!std.mem.eql(u8, applied.rollout_control_state orelse "active", control_state))
        return common.conflict("rollout control changed concurrently");
    if (shouldResumeStoredRollout(active, control_state) and !deploy_routes.isClusterRolloutActive(active.id)) {
        return resumeStoredClusterRollout(alloc, active, ctx);
    }

    return rolloutControlResponse(alloc, app_name, active.id, control_state);
}

pub fn recoverActiveClusterRolloutsOnce(alloc: std.mem.Allocator, ctx: RouteContext) !usize {
    const node = ctx.cluster orelse return 0;
    if (!node.isLeader()) return 0;
    const session = try mutation_session.Session.begin(node);
    try session.synchronize();
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
