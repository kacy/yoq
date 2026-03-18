const std = @import("std");
const agent_types = @import("../agent_types.zig");
const gpu_scheduler = @import("../../gpu/scheduler.zig");
const common = @import("common.zig");
const constraints = @import("constraints.zig");

const Allocator = std.mem.Allocator;
pub const AgentRecord = agent_types.AgentRecord;
pub const PlacementRequest = common.PlacementRequest;
pub const PlacementResult = common.PlacementResult;

pub fn schedule(
    alloc: Allocator,
    requests: []const PlacementRequest,
    agents: []const AgentRecord,
) ![]?PlacementResult {
    var results = try alloc.alloc(?PlacementResult, requests.len);
    @memset(results, null);

    var used_cpu = try alloc.alloc(i64, agents.len);
    defer alloc.free(used_cpu);
    var used_mem = try alloc.alloc(i64, agents.len);
    defer alloc.free(used_mem);
    var used_gpu = try alloc.alloc(i64, agents.len);
    defer alloc.free(used_gpu);

    for (agents, 0..) |agent, i| {
        used_cpu[i] = agent.cpu_used;
        used_mem[i] = agent.memory_used_mb;
        used_gpu[i] = agent.gpu_used;
    }

    for (requests, 0..) |req, req_idx| {
        var best_idx: ?usize = null;
        var best_score: i64 = -1;

        for (agents, 0..) |agent, agent_idx| {
            if (!std.mem.eql(u8, agent.status, "active")) continue;
            if (agent.role) |role| {
                if (std.mem.eql(u8, role, "server")) continue;
            }

            const free_cpu = agent.cpu_cores * 1000 - used_cpu[agent_idx];
            const free_mem = agent.memory_mb - used_mem[agent_idx];
            if (free_cpu < req.cpu_limit) continue;
            if (free_mem < req.memory_limit_mb) continue;

            if (req.gpu_limit > 0) {
                const free_gpu = agent.gpu_count - used_gpu[agent_idx];
                if (free_gpu < req.gpu_limit) continue;
                if (req.gpu_model != null or req.gpu_vram_min_mb != null) {
                    if (!gpu_scheduler.matchesGpuRequirements(agent, req.gpu_model, req.gpu_vram_min_mb)) continue;
                }
            }

            if (req.required_labels.len > 0) {
                if (!constraints.matchesLabels(agent.labels orelse "", req.required_labels)) continue;
            }
            if (req.volume_constraints.len > 0) {
                if (!constraints.matchesVolumeConstraints(agent, req.volume_constraints)) continue;
            }

            const gpu_score: i64 = if (req.gpu_limit > 0) (agent.gpu_count - used_gpu[agent_idx]) * 1000 else 0;
            const score = free_cpu + free_mem + gpu_score;
            if (score > best_score) {
                best_score = score;
                best_idx = agent_idx;
            }
        }

        if (best_idx) |idx| {
            results[req_idx] = .{
                .agent_id = agents[idx].id,
                .request_idx = req_idx,
            };
            used_cpu[idx] += req.cpu_limit;
            used_mem[idx] += req.memory_limit_mb;
            used_gpu[idx] += req.gpu_limit;
        }
    }

    return results;
}
