//! resource accounting for placement snapshots and rollback reservations.
const std = @import("std");
const sqlite = @import("sqlite");
const AgentRecord = @import("agent_types.zig").AgentRecord;
const scheduler = @import("scheduler/placement.zig");

pub const Resources = struct {
    cpu: i64 = 0,
    memory: i64 = 0,
    gpu: i64 = 0,

    fn add(self: *Resources, other: Resources) void {
        self.cpu = addUsage(self.cpu, other.cpu);
        self.memory = addUsage(self.memory, other.memory);
        self.gpu = addUsage(self.gpu, other.gpu);
    }

    fn nonnegative(self: Resources) bool {
        return self.cpu >= 0 and self.memory >= 0 and self.gpu >= 0;
    }
};

fn addUsage(left: i64, right: i64) i64 {
    return if (right < 0) std.math.maxInt(i64) else left +| right;
}

fn effectiveUsage(reported: i64, pending: i64, running: i64) i64 {
    if (reported < 0) return std.math.maxInt(i64);
    return pending +| @max(reported, running);
}

/// the caller holds the state database lock while reading all agent claims.
pub fn includeClaims(alloc: std.mem.Allocator, db: *sqlite.Db, agent: *AgentRecord, excluded_ids: []const []const u8) !void {
    var pending: Resources = .{};
    var running: Resources = .{};
    const Row = struct { id: sqlite.Text, status: sqlite.Text, cpu: i64, memory: i64, gpu: ?i64 };
    var stmt = try db.prepare(
        \\SELECT a.id, a.status, a.cpu_limit AS cpu, a.memory_limit_mb AS memory, c.gpu_count AS gpu
        \\FROM assignments a LEFT JOIN assignment_claims c ON c.assignment_id = a.id
        \\WHERE a.agent_id = ?;
    );
    defer stmt.deinit();
    var rows = try stmt.iterator(Row, .{agent.id});
    while (try rows.nextAlloc(alloc, .{})) |row| {
        defer alloc.free(row.id.data);
        defer alloc.free(row.status.data);
        if (containsId(excluded_ids, row.id.data) or isTerminal(row.status.data)) continue;
        // legacy assignments lack gpu claims, so reserve the worker's full gpu count.
        const used: Resources = .{ .cpu = row.cpu, .memory = row.memory, .gpu = row.gpu orelse agent.gpu_count };
        if (std.mem.eql(u8, row.status.data, "pending")) pending.add(used) else running.add(used);
    }

    // running claims form a floor under heartbeat usage; pending claims add to it.
    agent.cpu_used = effectiveUsage(agent.cpu_used, pending.cpu, running.cpu);
    agent.memory_used_mb = effectiveUsage(agent.memory_used_mb, pending.memory, running.memory);
    agent.gpu_used = effectiveUsage(agent.gpu_used, pending.gpu, running.gpu);
}

pub fn isTerminal(status: []const u8) bool {
    for ([_][]const u8{ "failed", "stopped", "exited", "completed", "canceled" }) |terminal| {
        if (std.mem.eql(u8, status, terminal)) return true;
    }
    return false;
}

fn containsId(ids: []const []const u8, id: []const u8) bool {
    for (ids) |candidate| if (std.mem.eql(u8, candidate, id)) return true;
    return false;
}

fn canConsume(agent: AgentRecord, resources: Resources) bool {
    if (!scheduler.validCapacity(agent) or !std.mem.eql(u8, agent.status, "active")) return false;
    const used: Resources = .{ .cpu = agent.cpu_used, .memory = agent.memory_used_mb, .gpu = agent.gpu_used };
    if (!resources.nonnegative() or !used.nonnegative()) return false;
    return resources.cpu <= agent.cpu_cores * 1000 -| used.cpu and
        resources.memory <= agent.memory_mb -| used.memory and
        resources.gpu <= agent.gpu_count -| used.gpu;
}

/// validate every resource before changing the snapshot's reservation counters.
pub fn consume(agents: []AgentRecord, agent_id: []const u8, resources: Resources) error{Conflict}!void {
    for (agents) |*agent| {
        if (!std.mem.eql(u8, agent.id, agent_id)) continue;
        if (!canConsume(agent.*, resources)) return error.Conflict;
        agent.cpu_used += resources.cpu;
        agent.memory_used_mb += resources.memory;
        agent.gpu_used += resources.gpu;
        return;
    }
    return error.Conflict;
}

const test_agent: AgentRecord = .{
    .id = "worker",
    .address = "127.0.0.1",
    .status = "active",
    .cpu_cores = 4,
    .memory_mb = 8192,
    .gpu_count = 4,
    .cpu_used = 0,
    .memory_used_mb = 0,
    .containers = 0,
    .last_heartbeat = 0,
    .registered_at = 0,
};

fn testDb() !sqlite.Db {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    errdefer db.deinit();
    try db.exec("CREATE TABLE assignments (id TEXT, agent_id TEXT, status TEXT, cpu_limit INTEGER, memory_limit_mb INTEGER);", .{}, .{});
    try db.exec("CREATE TABLE assignment_claims (assignment_id TEXT, gpu_count INTEGER);", .{}, .{});
    return db;
}

test "placement capacity combines pending claims with the larger running or heartbeat usage" {
    var db = try testDb();
    defer db.deinit();
    try db.exec("INSERT INTO assignments VALUES ('queued', 'worker', 'pending', 500, 500), ('running', 'worker', 'running', 800, 1000), ('starting', 'worker', 'starting', 200, 100), ('replaced', 'worker', 'pending', 9000, 9000), ('elsewhere', 'other', 'pending', 9000, 9000);", .{}, .{});
    try db.exec("INSERT INTO assignment_claims VALUES ('queued', 1), ('running', 2), ('starting', 1);", .{}, .{});
    for ([_][]const u8{ "failed", "stopped", "exited", "completed", "canceled" }) |status| {
        try db.exec("INSERT INTO assignments VALUES (?, 'worker', ?, 9000, 9000);", .{}, .{ status, status });
    }
    var agent = test_agent;
    agent.cpu_used = 600;
    agent.memory_used_mb = 1500;
    agent.gpu_used = 1;
    try includeClaims(std.testing.allocator, &db, &agent, &.{"replaced"});
    try std.testing.expectEqual(@as(i64, 1500), agent.cpu_used);
    try std.testing.expectEqual(@as(i64, 2000), agent.memory_used_mb);
    try std.testing.expectEqual(@as(i64, 4), agent.gpu_used);
}

test "placement capacity reserves all gpus for legacy assignments without claims" {
    var db = try testDb();
    defer db.deinit();
    try db.exec("INSERT INTO assignments VALUES ('legacy', 'worker', 'running', 500, 1000);", .{}, .{});
    var agent = test_agent;
    try includeClaims(std.testing.allocator, &db, &agent, &.{});
    try std.testing.expectEqual(test_agent.gpu_count, agent.gpu_used);
    var agents = [_]AgentRecord{agent};
    try std.testing.expectError(error.Conflict, consume(&agents, "worker", .{ .gpu = 1 }));
    try std.testing.expectEqualDeep(agent, agents[0]);
}

test "placement capacity treats negative and overflowing usage as exhausted" {
    var db = try testDb();
    defer db.deinit();
    try db.exec("INSERT INTO assignments VALUES ('large', 'worker', 'pending', 9223372036854775807, -1), ('extra', 'worker', 'pending', 1, 1);", .{}, .{});
    try db.exec("INSERT INTO assignment_claims VALUES ('large', 9223372036854775807), ('extra', 1);", .{}, .{});
    var agent = test_agent;
    agent.cpu_used = 1;
    agent.memory_used_mb = 1;
    agent.gpu_used = 1;
    try includeClaims(std.testing.allocator, &db, &agent, &.{});
    try std.testing.expectEqual(std.math.maxInt(i64), agent.cpu_used);
    try std.testing.expectEqual(std.math.maxInt(i64), agent.memory_used_mb);
    try std.testing.expectEqual(std.math.maxInt(i64), agent.gpu_used);

    try db.exec("DELETE FROM assignments;", .{}, .{});
    agent = test_agent;
    agent.cpu_used = -1;
    agent.memory_used_mb = -1;
    agent.gpu_used = -1;
    try includeClaims(std.testing.allocator, &db, &agent, &.{});
    try std.testing.expectEqual(std.math.maxInt(i64), agent.cpu_used);
    try std.testing.expectEqual(std.math.maxInt(i64), agent.memory_used_mb);
    try std.testing.expectEqual(std.math.maxInt(i64), agent.gpu_used);
}

test "placement capacity reservations consume each resource without partial updates" {
    var agents = [_]AgentRecord{test_agent};
    try consume(&agents, "worker", .{ .cpu = 3000, .memory = 7000, .gpu = 3 });
    const reserved = agents[0];
    for ([_]Resources{
        .{ .cpu = 1001, .memory = 1, .gpu = 1 },
        .{ .cpu = 1, .memory = 1193, .gpu = 1 },
        .{ .cpu = 1, .memory = 1, .gpu = 2 },
        .{ .cpu = -1 },
        .{ .memory = -1 },
        .{ .gpu = -1 },
    }) |request| {
        try std.testing.expectError(error.Conflict, consume(&agents, "worker", request));
        try std.testing.expectEqualDeep(reserved, agents[0]);
    }
    try std.testing.expectError(error.Conflict, consume(&agents, "missing", .{}));
    try std.testing.expectEqualDeep(reserved, agents[0]);
    try consume(&agents, "worker", .{ .cpu = 1000, .memory = 1192, .gpu = 1 });
    try std.testing.expectEqual(@as(i64, 4000), agents[0].cpu_used);
    try std.testing.expectEqual(@as(i64, 8192), agents[0].memory_used_mb);
    try std.testing.expectEqual(@as(i64, 4), agents[0].gpu_used);
}

test "placement capacity refuses inactive invalid or already overcommitted agents" {
    var offline = test_agent;
    offline.status = "offline";
    var invalid = test_agent;
    invalid.cpu_cores = std.math.maxInt(i64);
    var negative = test_agent;
    negative.gpu_used = -1;
    var overcommitted = test_agent;
    overcommitted.memory_used_mb = test_agent.memory_mb + 1;
    for ([_]AgentRecord{ offline, invalid, negative, overcommitted }) |agent| {
        var agents = [_]AgentRecord{agent};
        try std.testing.expectError(error.Conflict, consume(&agents, "worker", .{}));
        try std.testing.expectEqualDeep(agent, agents[0]);
    }
}
