const std = @import("std");

const mutation_session = @import("../../../cluster/mutation_session.zig");
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
    return runWithSession(alloc, try mutation_session.Session.begin(node), requests);
}

pub fn runWithSession(alloc: std.mem.Allocator, session: mutation_session.Session, requests: []const scheduler.PlacementRequest) deploy_routes.ClusterApplyError!apply_release.ApplyOutcome {
    const node = session.node;
    const owned_requests = alloc.alloc(apply_request.ServiceRequest, requests.len) catch return deploy_routes.ClusterApplyError.InternalError;
    defer alloc.free(owned_requests);
    for (requests, 0..) |req, i| {
        owned_requests[i] = .{
            .request = req,
            .rollout = .{},
        };
    }
    if (!(agent_registry.hasAgents(node.stateMachineDb()) catch return error.InternalError)) return error.InternalError;

    var backend = deploy_routes.ClusterApplyBackend{
        .alloc = alloc,
        .session = session,
        .requests = owned_requests,
    };
    return backend.apply();
}

pub fn freeOutcomePayloads(alloc: std.mem.Allocator, outcome: apply_release.ApplyOutcome) void {
    outcome.deinit(alloc);
}
