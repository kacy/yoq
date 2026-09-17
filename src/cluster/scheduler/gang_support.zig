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
    if (request.gang_world_size == 0 or request.gpus_per_rank == 0) return null;
    if (request.cpu_limit < 0 or request.memory_limit_mb < 0) return null;

    // adjust a copy so the caller's resource records stay unchanged.
    const eligible = try alloc.dupe(AgentRecord, agents);
    defer alloc.free(eligible);
    var total_ranks: u64 = 0;
    for (eligible) |*agent| {
        if (!eligibleForGang(agent.*, request)) {
            agent.status = "unavailable";
            continue;
        }

        const ranks = rankCapacity(agent.*, request);
        // the gpu scheduler only accounts for gpus. cap the copy's gpu count
        // so it cannot place more ranks than the cpu and memory limits allow.
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

fn eligibleForGang(agent: AgentRecord, request: PlacementRequest) bool {
    if (!placement.validCapacity(agent)) return false;
    if (agent.cpu_used < 0 or agent.memory_used_mb < 0 or agent.gpu_used < 0) return false;
    if (!std.mem.eql(u8, agent.status, "active")) return false;
    if (std.mem.eql(u8, agent.role orelse "", "server")) return false;
    if (!constraints.matchesLabels(agent.labels orelse "", request.required_labels)) return false;
    if (!constraints.matchesVolumeConstraints(agent, request.volume_constraints)) return false;
    return gpu_scheduler.matchesGpuRequirements(agent, request.gpu_model, request.gpu_vram_min_mb);
}

// each rank needs its own cpu, memory, and gpus. a zero cpu or memory limit
// leaves that resource out of the capacity calculation.
fn rankCapacity(agent: AgentRecord, request: PlacementRequest) i64 {
    const free_cpu = @max(0, agent.cpu_cores * 1000 -| agent.cpu_used);
    const free_memory = @max(0, agent.memory_mb -| agent.memory_used_mb);
    const free_gpu = @max(0, agent.gpu_count -| agent.gpu_used);

    var ranks = @divTrunc(free_gpu, request.gpus_per_rank);
    if (request.cpu_limit > 0) ranks = @min(ranks, @divTrunc(free_cpu, request.cpu_limit));
    if (request.memory_limit_mb > 0) ranks = @min(ranks, @divTrunc(free_memory, request.memory_limit_mb));
    return ranks;
}
