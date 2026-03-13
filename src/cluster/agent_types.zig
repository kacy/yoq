// agent_types — shared types for agent/server communication
//
// defines the data structures used between cluster agents (worker nodes)
// and the server (control plane). agents register with the server,
// report their capacity via heartbeats, and receive container assignments.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const AgentStatus = enum {
    active,
    draining,
    offline,

    pub fn toString(self: AgentStatus) []const u8 {
        return switch (self) {
            .active => "active",
            .draining => "draining",
            .offline => "offline",
        };
    }

    pub fn fromString(s: []const u8) ?AgentStatus {
        if (std.mem.eql(u8, s, "active")) return .active;
        if (std.mem.eql(u8, s, "draining")) return .draining;
        if (std.mem.eql(u8, s, "offline")) return .offline;
        return null;
    }
};

/// resource snapshot reported by an agent during registration and heartbeats.
pub const AgentResources = struct {
    cpu_cores: u32,
    memory_mb: u64,
    cpu_used: u32 = 0,
    memory_used_mb: u64 = 0,
    containers: u32 = 0,
    gpu_count: u32 = 0,
    gpu_used: u32 = 0,
    gpu_model: ?[]const u8 = null,
    gpu_vram_mb: u64 = 0,
    gpu_health: GpuHealthBuf = .{},

    /// fixed-size buffer for gpu_health so it can be copied by value in the heartbeat batcher.
    pub const GpuHealthBuf = struct {
        data: [16]u8 = .{0} ** 16,
        len: u8 = 0,

        pub fn fromSlice(s: []const u8) GpuHealthBuf {
            var buf = GpuHealthBuf{};
            const n: u8 = @intCast(@min(s.len, 16));
            @memcpy(buf.data[0..n], s[0..n]);
            buf.len = n;
            return buf;
        }

        pub fn slice(self: *const GpuHealthBuf) []const u8 {
            return self.data[0..self.len];
        }
    };
};

/// an agent record as stored in the replicated state database.
/// all slices are allocated — caller must call deinit.
pub const AgentRecord = struct {
    id: []const u8,
    address: []const u8,
    status: []const u8,
    cpu_cores: i64,
    memory_mb: i64,
    cpu_used: i64,
    memory_used_mb: i64,
    containers: i64,
    last_heartbeat: i64,
    registered_at: i64,

    // wireguard / cluster networking fields (null for agents registered
    // before WireGuard support, or agents that didn't provide WG info)
    node_id: ?i64 = null,
    wg_public_key: ?[]const u8 = null,
    overlay_ip: ?[]const u8 = null,

    // role separation fields (null for agents registered before role support)
    role: ?[]const u8 = null,
    region: ?[]const u8 = null,
    labels: ?[]const u8 = null,
    gpu_count: i64 = 0,
    gpu_used: i64 = 0,
    gpu_model: ?[]const u8 = null,
    gpu_vram_mb: ?i64 = null,
    rdma_capable: bool = false,

    pub fn deinit(self: AgentRecord, alloc: Allocator) void {
        alloc.free(self.id);
        alloc.free(self.address);
        alloc.free(self.status);
        if (self.wg_public_key) |k| alloc.free(k);
        if (self.overlay_ip) |o| alloc.free(o);
        if (self.role) |r| alloc.free(r);
        if (self.region) |reg| alloc.free(reg);
        if (self.labels) |l| alloc.free(l);
        if (self.gpu_model) |m| alloc.free(m);
    }
};

/// a container assignment from the server to an agent.
/// all slices are allocated — caller must call deinit.
pub const Assignment = struct {
    id: []const u8,
    agent_id: []const u8,
    image: []const u8,
    command: []const u8,
    status: []const u8,
    cpu_limit: i64,
    memory_limit_mb: i64,

    pub fn deinit(self: Assignment, alloc: Allocator) void {
        alloc.free(self.id);
        alloc.free(self.agent_id);
        alloc.free(self.image);
        alloc.free(self.command);
        alloc.free(self.status);
    }
};

// -- tests --

test "agent status round-trip" {
    const statuses = [_]AgentStatus{ .active, .draining, .offline };
    for (statuses) |s| {
        const str = s.toString();
        const parsed = AgentStatus.fromString(str).?;
        try std.testing.expectEqual(s, parsed);
    }
}

test "agent status unknown returns null" {
    try std.testing.expect(AgentStatus.fromString("unknown") == null);
}

test "agent resources defaults" {
    const res = AgentResources{ .cpu_cores = 4, .memory_mb = 8192 };
    try std.testing.expectEqual(@as(u32, 0), res.cpu_used);
    try std.testing.expectEqual(@as(u64, 0), res.memory_used_mb);
    try std.testing.expectEqual(@as(u32, 0), res.containers);
}

test "agent record wireguard fields default to null" {
    const alloc = std.testing.allocator;
    const id = try alloc.dupe(u8, "test12345678");
    const addr = try alloc.dupe(u8, "10.0.0.1:7701");
    const status = try alloc.dupe(u8, "active");

    const record = AgentRecord{
        .id = id,
        .address = addr,
        .status = status,
        .cpu_cores = 4,
        .memory_mb = 8192,
        .cpu_used = 0,
        .memory_used_mb = 0,
        .containers = 0,
        .last_heartbeat = 1000,
        .registered_at = 1000,
    };
    defer record.deinit(alloc);

    try std.testing.expect(record.node_id == null);
    try std.testing.expect(record.wg_public_key == null);
    try std.testing.expect(record.overlay_ip == null);
}

test "agent record deinit frees wireguard fields" {
    const alloc = std.testing.allocator;
    const id = try alloc.dupe(u8, "test12345678");
    const addr = try alloc.dupe(u8, "10.0.0.1:7701");
    const status = try alloc.dupe(u8, "active");
    const wg_key = try alloc.dupe(u8, "base64pubkey==");
    const overlay = try alloc.dupe(u8, "10.40.0.3");

    const record = AgentRecord{
        .id = id,
        .address = addr,
        .status = status,
        .cpu_cores = 4,
        .memory_mb = 8192,
        .cpu_used = 0,
        .memory_used_mb = 0,
        .containers = 0,
        .last_heartbeat = 1000,
        .registered_at = 1000,
        .node_id = 3,
        .wg_public_key = wg_key,
        .overlay_ip = overlay,
    };
    // deinit should free all 5 slices (id, address, status, wg_public_key, overlay_ip)
    // testing allocator will detect leaks if any aren't freed
    record.deinit(alloc);
}
