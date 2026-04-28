const std = @import("std");

const scheduler = @import("../../../cluster/scheduler.zig");
const cluster_node = @import("../../../cluster/node.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const apply_release = @import("../../../manifest/apply_release.zig");
const apply_request = @import("apply_request.zig");
const deploy_routes = @import("deploy_routes.zig");

pub fn run(
    alloc: std.mem.Allocator,
    node: *cluster_node.Node,
    requests: []const scheduler.PlacementRequest,
) deploy_routes.ClusterApplyError!apply_release.ApplyOutcome {
    const owned_requests = alloc.alloc(apply_request.ServiceRequest, requests.len) catch return deploy_routes.ClusterApplyError.InternalError;
    defer alloc.free(owned_requests);
    for (requests, 0..) |req, i| {
        owned_requests[i] = .{
            .request = req,
            .rollout = .{},
        };
    }
    const agents = agent_registry.listAgents(alloc, node.stateMachineDb()) catch return deploy_routes.ClusterApplyError.InternalError;
    defer {
        for (agents) |a| a.deinit(alloc);
        alloc.free(agents);
    }
    if (agents.len == 0) return error.InternalError;

    var backend = deploy_routes.ClusterApplyBackend{
        .alloc = alloc,
        .node = node,
        .requests = owned_requests,
        .agents = agents,
    };
    return backend.apply();
}

pub fn freeOutcomePayloads(alloc: std.mem.Allocator, outcome: apply_release.ApplyOutcome) void {
    if (outcome.failure_details_json) |json| alloc.free(json);
    if (outcome.rollout_targets_json) |json| alloc.free(json);
    if (outcome.rollout_checkpoint_json) |json| alloc.free(json);
}
