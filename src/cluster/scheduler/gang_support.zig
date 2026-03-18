const std = @import("std");
const agent_types = @import("../agent_types.zig");
const gpu_scheduler = @import("../../gpu/scheduler.zig");
const common = @import("common.zig");

const Allocator = std.mem.Allocator;
pub const AgentRecord = agent_types.AgentRecord;
pub const PlacementRequest = common.PlacementRequest;

pub fn scheduleGang(
    alloc: Allocator,
    request: PlacementRequest,
    agents: []const AgentRecord,
) !?[]gpu_scheduler.GangPlacement {
    const gang = gpu_scheduler.GangSpec{
        .world_size = request.gang_world_size,
        .gpus_per_rank = request.gpus_per_rank,
        .master_port = request.gang_master_port,
    };
    return gpu_scheduler.scheduleGang(alloc, gang, agents);
}
