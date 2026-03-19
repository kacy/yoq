const agent_types = @import("../agent_types.zig");

pub const AgentRecord = agent_types.AgentRecord;

pub fn makeAgent(id: []const u8, status: []const u8, cores: i64, mem: i64, cpu_used: i64, mem_used: i64) AgentRecord {
    return makeAgentWithRole(id, status, cores, mem, cpu_used, mem_used, null);
}

pub fn makeAgentFull(id: []const u8, status: []const u8, cores: i64, mem: i64, cpu_used: i64, mem_used: i64, role: ?[]const u8, labels: ?[]const u8, gpu_count: i64, gpu_used: i64) AgentRecord {
    return .{
        .id = id,
        .address = "localhost",
        .status = status,
        .cpu_cores = cores,
        .memory_mb = mem,
        .cpu_used = cpu_used,
        .memory_used_mb = mem_used,
        .containers = 0,
        .last_heartbeat = 0,
        .registered_at = 0,
        .role = role,
        .labels = labels,
        .gpu_count = gpu_count,
        .gpu_used = gpu_used,
    };
}

pub fn makeAgentWithRole(id: []const u8, status: []const u8, cores: i64, mem: i64, cpu_used: i64, mem_used: i64, role: ?[]const u8) AgentRecord {
    return makeAgentFull(id, status, cores, mem, cpu_used, mem_used, role, null, 0, 0);
}
