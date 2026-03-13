// scheduler — GPU-aware scheduling and gang placement
//
// extends cluster scheduling with GPU-specific logic:
//   - model/VRAM filtering: only place on agents with matching GPU hardware
//   - gang scheduling: place all ranks atomically or reject the entire group
//   - per-rank env injection: MASTER_ADDR, WORLD_SIZE, RANK, LOCAL_RANK
//
// pure functions — no I/O, no state. the caller provides agent records
// and this module returns placements.

const std = @import("std");
const agent_types = @import("../cluster/agent_types.zig");
const log = @import("../lib/log.zig");

const Allocator = std.mem.Allocator;
const AgentRecord = agent_types.AgentRecord;

pub const GpuRequest = struct {
    count: u32,
    model: ?[]const u8 = null,
    vram_min_mb: ?u64 = null,
    gang: ?GangSpec = null,
};

pub const GangSpec = struct {
    world_size: u32,
    gpus_per_rank: u32 = 1,
    master_port: u16 = 29500,
};

pub const GangPlacement = struct {
    agent_id: []const u8,
    rank: u32,
    gpu_start: u32, // first GPU index assigned to this rank
    gpu_count: u32,
    world_size: u32,
    master_addr: []const u8, // address of rank 0 agent
    master_port: u16,

    /// write per-rank environment variables to a buffer.
    pub fn writeEnv(self: GangPlacement, buf: *[512]u8) ![]const u8 {
        return std.fmt.bufPrint(buf,
            \\MASTER_ADDR={s}
            \\MASTER_PORT={d}
            \\WORLD_SIZE={d}
            \\RANK={d}
            \\LOCAL_RANK={d}
        , .{
            self.master_addr,
            self.master_port,
            self.world_size,
            self.rank,
            self.gpu_start,
        });
    }
};

/// schedule a gang of ranks across agents.
/// returns placements for all ranks, or null if the gang can't be fully placed.
/// gang scheduling is all-or-nothing: either every rank gets placed, or none do.
pub fn scheduleGang(
    alloc: Allocator,
    gang: GangSpec,
    agents: []const AgentRecord,
) !?[]GangPlacement {
    if (gang.world_size == 0) return null;

    var placements = try alloc.alloc(GangPlacement, gang.world_size);
    errdefer alloc.free(placements);

    // track GPU allocation per agent during placement
    var gpu_alloc = try alloc.alloc(i64, agents.len);
    defer alloc.free(gpu_alloc);
    for (agents, 0..) |a, i| {
        gpu_alloc[i] = a.gpu_used;
    }

    var rank: u32 = 0;
    var master_addr: []const u8 = "";

    // greedily assign ranks to agents with the most free GPUs
    while (rank < gang.world_size) {
        var best_idx: ?usize = null;
        var best_free: i64 = -1;

        for (agents, 0..) |a, agent_idx| {
            if (!std.mem.eql(u8, a.status, "active")) continue;

            // skip server-only agents
            if (a.role) |role| {
                if (std.mem.eql(u8, role, "server")) continue;
            }

            const free_gpu = a.gpu_count - gpu_alloc[agent_idx];
            if (free_gpu < gang.gpus_per_rank) continue;

            if (free_gpu > best_free) {
                best_free = free_gpu;
                best_idx = agent_idx;
            }
        }

        const idx = best_idx orelse {
            // can't place this rank — fail atomically
            alloc.free(placements);
            return null;
        };

        if (rank == 0) {
            master_addr = agents[idx].address;
        }

        const gpu_start: u32 = @intCast(gpu_alloc[idx]);
        placements[rank] = .{
            .agent_id = agents[idx].id,
            .rank = rank,
            .gpu_start = gpu_start,
            .gpu_count = gang.gpus_per_rank,
            .world_size = gang.world_size,
            .master_addr = master_addr,
            .master_port = gang.master_port,
        };

        gpu_alloc[idx] += gang.gpus_per_rank;
        rank += 1;
    }

    return placements;
}

/// check if an agent's GPU matches model and VRAM requirements.
pub fn matchesGpuRequirements(
    agent: AgentRecord,
    model: ?[]const u8,
    vram_min_mb: ?u64,
) bool {
    if (model) |required_model| {
        const agent_model = agent.gpu_model orelse return false;
        // case-insensitive substring match (e.g., "A100" matches "NVIDIA A100-SXM4-40GB")
        if (!containsIgnoreCase(agent_model, required_model)) return false;
    }
    if (vram_min_mb) |min_vram| {
        const agent_vram = agent.gpu_vram_mb orelse return false;
        if (agent_vram < @as(i64, @intCast(min_vram))) return false;
    }
    return true;
}

/// case-insensitive substring search.
fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    if (needle.len == 0) return true;

    const limit = haystack.len - needle.len + 1;
    for (0..limit) |i| {
        var match = true;
        for (0..needle.len) |j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

// -- tests --

fn makeGpuAgent(id: []const u8, addr: []const u8, gpu_count: i64, gpu_used: i64) AgentRecord {
    return .{
        .id = id,
        .address = addr,
        .status = "active",
        .cpu_cores = 32,
        .memory_mb = 131072,
        .cpu_used = 0,
        .memory_used_mb = 0,
        .containers = 0,
        .last_heartbeat = 0,
        .registered_at = 0,
        .gpu_count = gpu_count,
        .gpu_used = gpu_used,
    };
}

test "scheduleGang places all ranks" {
    const alloc = std.testing.allocator;

    const agents = &[_]AgentRecord{
        makeGpuAgent("node1", "10.0.0.1:9090", 4, 0),
        makeGpuAgent("node2", "10.0.0.2:9090", 4, 0),
    };

    const gang = GangSpec{ .world_size = 8, .gpus_per_rank = 1 };
    const placements = (try scheduleGang(alloc, gang, agents)) orelse return error.TestUnexpectedResult;
    defer alloc.free(placements);

    try std.testing.expectEqual(@as(usize, 8), placements.len);

    // verify all ranks are assigned
    for (placements, 0..) |p, i| {
        try std.testing.expectEqual(@as(u32, @intCast(i)), p.rank);
    }

    // rank 0 should define the master_addr
    try std.testing.expect(placements[0].master_addr.len > 0);
}

test "scheduleGang fails atomically when insufficient" {
    const alloc = std.testing.allocator;

    const agents = &[_]AgentRecord{
        makeGpuAgent("node1", "10.0.0.1:9090", 2, 0),
    };

    // need 4 GPUs but only 2 available
    const gang = GangSpec{ .world_size = 4, .gpus_per_rank = 1 };
    const result = try scheduleGang(alloc, gang, agents);
    try std.testing.expect(result == null);
}

test "scheduleGang with gpus_per_rank" {
    const alloc = std.testing.allocator;

    const agents = &[_]AgentRecord{
        makeGpuAgent("node1", "10.0.0.1:9090", 4, 0),
        makeGpuAgent("node2", "10.0.0.2:9090", 4, 0),
    };

    // 2 ranks, each needing 4 GPUs
    const gang = GangSpec{ .world_size = 2, .gpus_per_rank = 4 };
    const placements = (try scheduleGang(alloc, gang, agents)) orelse return error.TestUnexpectedResult;
    defer alloc.free(placements);

    try std.testing.expectEqual(@as(usize, 2), placements.len);
    try std.testing.expectEqual(@as(u32, 4), placements[0].gpu_count);
    try std.testing.expectEqual(@as(u32, 4), placements[1].gpu_count);
}

test "scheduleGang zero world_size returns null" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeGpuAgent("node1", "10.0.0.1:9090", 4, 0),
    };
    const result = try scheduleGang(alloc, .{ .world_size = 0 }, agents);
    try std.testing.expect(result == null);
}

test "scheduleGang skips non-active agents" {
    const alloc = std.testing.allocator;
    var agents_arr = [_]AgentRecord{
        makeGpuAgent("node1", "10.0.0.1:9090", 4, 0),
        makeGpuAgent("node2", "10.0.0.2:9090", 4, 0),
    };
    // make node1 draining
    agents_arr[0].status = "draining";

    const gang = GangSpec{ .world_size = 4, .gpus_per_rank = 1 };
    const placements = (try scheduleGang(alloc, gang, &agents_arr)) orelse return error.TestUnexpectedResult;
    defer alloc.free(placements);

    // all should be on node2
    for (placements) |p| {
        try std.testing.expectEqualStrings("node2", p.agent_id);
    }
}

test "matchesGpuRequirements no filter" {
    var agent = makeGpuAgent("n", "addr", 4, 0);
    agent.gpu_model = "NVIDIA A100";
    agent.gpu_vram_mb = 40960;
    try std.testing.expect(matchesGpuRequirements(agent, null, null));
}

test "matchesGpuRequirements model match" {
    var agent = makeGpuAgent("n", "addr", 4, 0);
    agent.gpu_model = "NVIDIA A100-SXM4-40GB";
    agent.gpu_vram_mb = 40960;
    try std.testing.expect(matchesGpuRequirements(agent, "A100", null));
    try std.testing.expect(matchesGpuRequirements(agent, "a100", null)); // case insensitive
}

test "matchesGpuRequirements model mismatch" {
    var agent = makeGpuAgent("n", "addr", 4, 0);
    agent.gpu_model = "NVIDIA V100";
    agent.gpu_vram_mb = 16384;
    try std.testing.expect(!matchesGpuRequirements(agent, "A100", null));
}

test "matchesGpuRequirements vram check" {
    var agent = makeGpuAgent("n", "addr", 4, 0);
    agent.gpu_model = "NVIDIA A100";
    agent.gpu_vram_mb = 40960;
    try std.testing.expect(matchesGpuRequirements(agent, null, 40960));
    try std.testing.expect(!matchesGpuRequirements(agent, null, 81920));
}

test "matchesGpuRequirements missing model on agent" {
    const agent = makeGpuAgent("n", "addr", 4, 0);
    // agent has no gpu_model set
    try std.testing.expect(!matchesGpuRequirements(agent, "A100", null));
}

test "containsIgnoreCase" {
    try std.testing.expect(containsIgnoreCase("NVIDIA A100-SXM4", "a100"));
    try std.testing.expect(containsIgnoreCase("NVIDIA A100-SXM4", "A100"));
    try std.testing.expect(containsIgnoreCase("hello world", "WORLD"));
    try std.testing.expect(!containsIgnoreCase("NVIDIA V100", "A100"));
    try std.testing.expect(containsIgnoreCase("any", ""));
    try std.testing.expect(!containsIgnoreCase("", "abc"));
}
