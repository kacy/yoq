const std = @import("std");
const agent_types = @import("../agent_types.zig");
const gpu_scheduler = @import("../../gpu/scheduler.zig");
const common = @import("common.zig");
const constraints = @import("constraints.zig");

const Allocator = std.mem.Allocator;
pub const AgentRecord = agent_types.AgentRecord;
pub const PlacementRequest = common.PlacementRequest;
pub const PlacementResult = common.PlacementResult;

const ResourceUsage = struct {
    cpu: i64,
    memory_mb: i64,
    gpu: i64,

    fn reserve(self: *ResourceUsage, request: PlacementRequest) void {
        self.cpu += request.cpu_limit;
        self.memory_mb += request.memory_limit_mb;
        self.gpu += request.gpu_limit;
    }
};

pub fn schedule(
    alloc: Allocator,
    requests: []const PlacementRequest,
    agents: []const AgentRecord,
) ![]?PlacementResult {
    var results = try alloc.alloc(?PlacementResult, requests.len);
    @memset(results, null);
    errdefer alloc.free(results);

    const usage = try alloc.alloc(ResourceUsage, agents.len);
    defer alloc.free(usage);
    for (agents, usage) |agent, *used| {
        used.* = .{
            .cpu = agent.cpu_used,
            .memory_mb = agent.memory_used_mb,
            .gpu = agent.gpu_used,
        };
    }

    for (requests, 0..) |request, request_idx| {
        if (request.cpu_limit < 0 or request.memory_limit_mb < 0 or request.gpu_limit < 0) continue;
        var best_idx: ?usize = null;
        var best_score: i64 = -1;

        for (agents, usage, 0..) |agent, used, agent_idx| {
            const score = placementScore(agent, used, request) orelse continue;
            // keep the first agent when scores tie, so input order stays significant.
            if (score > best_score) {
                best_score = score;
                best_idx = agent_idx;
            }
        }

        if (best_idx) |agent_idx| {
            results[request_idx] = .{
                .agent_id = agents[agent_idx].id,
                .request_idx = request_idx,
            };
            // later requests must account for placements made in this call.
            usage[agent_idx].reserve(request);
        }
    }

    return results;
}

// null means the agent cannot run this request. higher scores favor agents
// with more free capacity before placement.
fn placementScore(agent: AgentRecord, used: ResourceUsage, request: PlacementRequest) ?i64 {
    if (!std.mem.eql(u8, agent.status, "active")) return null;
    if (std.mem.eql(u8, agent.role orelse "", "server")) return null;
    if (!validCapacity(agent)) return null;
    if (used.cpu < 0 or used.memory_mb < 0 or used.gpu < 0) return null;

    const free_cpu = agent.cpu_cores * 1000 -| used.cpu;
    const free_memory = agent.memory_mb -| used.memory_mb;
    if (free_cpu < request.cpu_limit or free_memory < request.memory_limit_mb) return null;

    var gpu_score: i64 = 0;
    if (request.gpu_limit > 0) {
        const free_gpu = agent.gpu_count -| used.gpu;
        if (free_gpu < request.gpu_limit) return null;
        if (request.gpu_model != null or request.gpu_vram_min_mb != null) {
            if (!gpu_scheduler.matchesGpuRequirements(agent, request.gpu_model, request.gpu_vram_min_mb)) return null;
        }
        // gpu capacity only affects the score when the request needs a gpu.
        gpu_score = free_gpu *| 1000;
    }

    if (!constraints.matchesLabels(agent.labels orelse "", request.required_labels)) return null;
    if (!constraints.matchesVolumeConstraints(agent, request.volume_constraints)) return null;

    return free_cpu +| free_memory +| gpu_score;
}

pub fn validCapacity(agent: AgentRecord) bool {
    return agent.cpu_cores >= 0 and agent.cpu_cores <= @divTrunc(std.math.maxInt(i64), 1000) and
        agent.memory_mb >= 0 and agent.gpu_count >= 0 and agent.gpu_count <= std.math.maxInt(u32);
}
