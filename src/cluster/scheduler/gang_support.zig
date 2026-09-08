const std = @import("std");
const agent_types = @import("../agent_types.zig");
const gpu_scheduler = @import("../../gpu/scheduler.zig");
const placement = @import("placement.zig");
const constraints = @import("constraints.zig");
const common = @import("common.zig");

const Allocator = std.mem.Allocator;
pub const AgentRecord = agent_types.AgentRecord;
pub const PlacementRequest = common.PlacementRequest;

pub fn scheduleGang(
    alloc: Allocator,
    request: PlacementRequest,
    agents: []const AgentRecord,
) !?[]gpu_scheduler.GangPlacement {
    if (request.gang_world_size == 0 or request.gpus_per_rank == 0 or request.cpu_limit < 0 or request.memory_limit_mb < 0) return null;
    const eligible = try alloc.dupe(AgentRecord, agents);
    defer alloc.free(eligible);
    var total_ranks: u64 = 0;
    for (eligible) |*agent| {
        if (!placement.validCapacity(agent.*) or agent.cpu_used < 0 or agent.memory_used_mb < 0 or agent.gpu_used < 0 or
            !std.mem.eql(u8, agent.status, "active") or std.mem.eql(u8, agent.role orelse "", "server") or
            !constraints.matchesLabels(agent.labels orelse "", request.required_labels) or
            !constraints.matchesVolumeConstraints(agent.*, request.volume_constraints) or
            !gpu_scheduler.matchesGpuRequirements(agent.*, request.gpu_model, request.gpu_vram_min_mb))
        {
            agent.status = "unavailable";
            continue;
        }
        const free_cpu: i64 = @max(0, agent.cpu_cores * 1000 -| agent.cpu_used);
        const free_memory: i64 = @max(0, agent.memory_mb -| agent.memory_used_mb);
        const free_gpu: i64 = @max(0, agent.gpu_count -| agent.gpu_used);
        var ranks: i64 = @divTrunc(free_gpu, request.gpus_per_rank);
        if (request.cpu_limit > 0) ranks = @min(ranks, @divTrunc(free_cpu, request.cpu_limit));
        if (request.memory_limit_mb > 0) ranks = @min(ranks, @divTrunc(free_memory, request.memory_limit_mb));
        agent.gpu_count = agent.gpu_used +| ranks * request.gpus_per_rank;
        total_ranks +|= @intCast(ranks);
    }
    if (total_ranks < request.gang_world_size) return null;
    const gang = gpu_scheduler.GangSpec{
        .world_size = request.gang_world_size,
        .gpus_per_rank = request.gpus_per_rank,
        .master_port = request.gang_master_port,
    };
    return gpu_scheduler.scheduleGang(alloc, gang, eligible);
}
