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

    pub fn deinit(self: AgentRecord, alloc: Allocator) void {
        alloc.free(self.id);
        alloc.free(self.address);
        alloc.free(self.status);
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
