// scheduler entry points
//
// regular placement favors agents with more free capacity. gang placement
// requires room for every rank. the implementations live in cluster/scheduler/.

const std = @import("std");
const agent_types = @import("agent_types.zig");
const common = @import("scheduler/common.zig");
const constraint_support = @import("scheduler/constraints.zig");
const gang_support = @import("scheduler/gang_support.zig");
const placement = @import("scheduler/placement.zig");
const sql_support = @import("scheduler/sql_support.zig");
const test_support = @import("scheduler/test_support.zig");

const AgentRecord = agent_types.AgentRecord;
pub const VolumeConstraint = common.VolumeConstraint;
pub const PlacementRequest = common.PlacementRequest;
pub const PlacementResult = common.PlacementResult;
pub const GangPlacementResult = common.GangPlacementResult;

pub const scheduleGang = gang_support.scheduleGang;
pub const schedule = placement.schedule;
pub const assignmentSql = sql_support.assignmentSql;
pub const assignmentSqlGang = sql_support.assignmentSqlGang;
pub const generateAssignmentId = sql_support.generateAssignmentId;

fn matchesLabels(agent_labels: []const u8, required: []const u8) bool {
    return constraint_support.matchesLabels(agent_labels, required);
}

fn matchesVolumeConstraints(agent: AgentRecord, volume_constraints: []const VolumeConstraint) bool {
    return constraint_support.matchesVolumeConstraints(agent, volume_constraints);
}

// -- tests --

const makeAgent = test_support.makeAgent;
const makeAgentFull = test_support.makeAgentFull;
const makeAgentWithRole = test_support.makeAgentWithRole;

test "schedule single container on single agent" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgent("agent1", "active", 4, 8192, 0, 0),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "nginx", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    try std.testing.expect(results[0] != null);
    try std.testing.expectEqualStrings("agent1", results[0].?.agent_id);
}

test "schedule spreads across agents" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgent("agent1", "active", 2, 4096, 1000, 2048),
        makeAgent("agent2", "active", 4, 8192, 0, 0),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "nginx", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    // agent2 has more free capacity, so it receives the placement.
    try std.testing.expect(results[0] != null);
    try std.testing.expectEqualStrings("agent2", results[0].?.agent_id);
}

test "schedule preserves agent order when tracked capacity ties" {
    const alloc = std.testing.allocator;
    const agents = [_]AgentRecord{
        makeAgent("agent1", "active", 4, 8192, 0, 0),
        makeAgent("agent2", "active", 4, 8192, 0, 0),
    };
    const request = PlacementRequest{
        .image = "nginx",
        .command = "",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
    };
    const requests = [_]PlacementRequest{request} ** 3;

    const results = try schedule(alloc, &requests, &agents);
    defer alloc.free(results);

    // the second placement restores a tie, so the third returns to agent1.
    const expected_agents = [_][]const u8{ "agent1", "agent2", "agent1" };
    for (results, expected_agents, 0..) |result, expected_agent, request_idx| {
        try std.testing.expect(result != null);
        try std.testing.expectEqualStrings(expected_agent, result.?.agent_id);
        try std.testing.expectEqual(request_idx, result.?.request_idx);
    }
}

test "schedule capacity exceeded returns null" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgent("agent1", "active", 1, 512, 0, 0),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "big-app", .command = "", .cpu_limit = 2000, .memory_limit_mb = 1024 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    try std.testing.expect(results[0] == null);
}

test "schedule skips draining agent" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgent("agent1", "draining", 4, 8192, 0, 0),
        makeAgent("agent2", "active", 2, 4096, 0, 0),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "nginx", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    try std.testing.expect(results[0] != null);
    try std.testing.expectEqualStrings("agent2", results[0].?.agent_id);
}

test "schedule skips offline agent" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgent("agent1", "offline", 4, 8192, 0, 0),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "nginx", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    try std.testing.expect(results[0] == null);
}

test "schedule no agents returns all nulls" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{};
    const requests = &[_]PlacementRequest{
        .{ .image = "nginx", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    try std.testing.expect(results[0] == null);
}

test "schedule multiple containers tracks usage" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgent("agent1", "active", 2, 1024, 0, 0),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "a", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
        .{ .image = "b", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    try std.testing.expect(results[0] != null);
    try std.testing.expect(results[1] != null);
}

test "schedule third container exceeds tracked capacity" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgent("agent1", "active", 2, 1024, 0, 0),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "a", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
        .{ .image = "b", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
        .{ .image = "c", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    try std.testing.expect(results[0] != null);
    try std.testing.expect(results[1] != null);
    // the first two requests use both cores.
    try std.testing.expect(results[2] == null);
}

test "schedule with zero requests returns empty" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgent("agent1", "active", 4, 8192, 0, 0),
    };
    const requests = &[_]PlacementRequest{};

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    try std.testing.expectEqual(@as(usize, 0), results.len);
}

test "generateAssignmentId produces 12 hex chars" {
    var buf: [12]u8 = undefined;
    generateAssignmentId(&buf);

    for (buf) |c| {
        const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        try std.testing.expect(is_hex);
    }
}

test "schedule skips server-role agent" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgentWithRole("server1", "active", 8, 16384, 0, 0, "server"),
        makeAgentWithRole("worker1", "active", 2, 4096, 0, 0, "agent"),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "nginx", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    try std.testing.expect(results[0] != null);
    try std.testing.expectEqualStrings("worker1", results[0].?.agent_id);
}

test "schedule allows both-role agent" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgentWithRole("node1", "active", 4, 8192, 0, 0, "both"),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "nginx", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    try std.testing.expect(results[0] != null);
    try std.testing.expectEqualStrings("node1", results[0].?.agent_id);
}

test "schedule allows null-role agent (backwards compat)" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgentWithRole("legacy1", "active", 4, 8192, 0, 0, null),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "nginx", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    try std.testing.expect(results[0] != null);
    try std.testing.expectEqualStrings("legacy1", results[0].?.agent_id);
}

test "schedule all server-role returns null" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgentWithRole("server1", "active", 8, 16384, 0, 0, "server"),
        makeAgentWithRole("server2", "active", 8, 16384, 0, 0, "server"),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "nginx", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    try std.testing.expect(results[0] == null);
}

test "schedule GPU capacity" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgentFull("gpu1", "active", 4, 8192, 0, 0, null, null, 2, 0),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "ml-model", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256, .gpu_limit = 1 },
    };
    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);
    try std.testing.expect(results[0] != null);
}

test "schedule GPU exceeded" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgentFull("gpu1", "active", 4, 8192, 0, 0, null, null, 1, 1),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "ml-model", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256, .gpu_limit = 1 },
    };
    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);
    try std.testing.expect(results[0] == null);
}

test "schedule label match" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgentFull("agent1", "active", 4, 8192, 0, 0, null, "zone=us-east,tier=gpu", 0, 0),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "nginx", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256, .required_labels = "zone=us-east" },
    };
    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);
    try std.testing.expect(results[0] != null);
}

test "schedule label mismatch" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgentFull("agent1", "active", 4, 8192, 0, 0, null, "zone=us-west", 0, 0),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "nginx", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256, .required_labels = "zone=us-east" },
    };
    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);
    try std.testing.expect(results[0] == null);
}

test "schedule empty labels matches all" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgentFull("agent1", "active", 4, 8192, 0, 0, null, "zone=us-east", 0, 0),
    };
    const requests = &[_]PlacementRequest{
        .{ .image = "nginx", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
    };
    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);
    try std.testing.expect(results[0] != null);
}

test "matchesLabels" {
    try std.testing.expect(matchesLabels("zone=us-east,tier=gpu", "zone=us-east"));
    try std.testing.expect(matchesLabels("zone=us-east,tier=gpu", "zone=us-east,tier=gpu"));
    try std.testing.expect(!matchesLabels("zone=us-west", "zone=us-east"));
    try std.testing.expect(matchesLabels("zone=us-east", ""));
    try std.testing.expect(!matchesLabels("", "zone=us-east"));
    try std.testing.expect(matchesLabels(" zone=us-east , tier=gpu ", " , zone=us-east, , tier=gpu, "));
    try std.testing.expect(matchesLabels("", " , , "));
    try std.testing.expect(!matchesLabels("zone=us-east-1", "zone=us-east"));
    try std.testing.expect(!matchesLabels("\tzone=us-east", "zone=us-east"));
    try std.testing.expect(!matchesLabels("zone=us-east", "\tzone=us-east"));
}

test "assignmentSql generates valid SQL" {
    var buf: [1024]u8 = undefined;
    const sql = try assignmentSql(&buf, "assign123456", "agent1", .{
        .image = "nginx:latest",
        .command = "/bin/sh",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
    }, 1000);

    try std.testing.expect(std.mem.indexOf(u8, sql, "INSERT INTO assignments") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "assign123456") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "agent1") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "nginx:latest") != null);
}

test "scheduler with registry data: server-only skipped, capacity-based placement" {
    const alloc = std.testing.allocator;
    const StateMachine = @import("state_machine.zig").StateMachine;
    const registry = @import("registry.zig");

    // use registry records to exercise the stored role and capacity fields.
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    // the server has the same capacity as the large worker but cannot accept workloads.
    sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role) VALUES ('server-1', '10.0.0.1:9090', 'active', 8, 16384, 0, 0, 0, 1000, 1000, 'server');",
    });
    sm.apply(.{
        .index = 2,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role) VALUES ('worker-large', '10.0.0.2:9090', 'active', 8, 16384, 0, 0, 0, 1000, 1000, 'agent');",
    });
    sm.apply(.{
        .index = 3,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role) VALUES ('worker-small', '10.0.0.3:9090', 'active', 2, 2048, 0, 0, 0, 1000, 1000, 'agent');",
    });

    const agents = try registry.listAgents(alloc, &sm.db);
    defer {
        for (agents) |*a| {
            var agent = a.*;
            agent.deinit(alloc);
        }
        alloc.free(agents);
    }

    try std.testing.expectEqual(@as(usize, 3), agents.len);

    const requests = &[_]PlacementRequest{
        .{ .image = "nginx:latest", .command = "", .cpu_limit = 1000, .memory_limit_mb = 512 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    // both workers fit, but worker-large has the higher capacity score.
    try std.testing.expect(results[0] != null);
    try std.testing.expectEqualStrings("worker-large", results[0].?.agent_id);
}

test "schedule exact capacity boundary" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgent("agent1", "active", 2, 4096, 0, 0), // 2000 millicores free
    };

    const requests = &[_]PlacementRequest{
        .{ .image = "app", .command = "", .cpu_limit = 2000, .memory_limit_mb = 256 },
        .{ .image = "app2", .command = "", .cpu_limit = 1, .memory_limit_mb = 1 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    // the first request uses all available cpu capacity.
    try std.testing.expect(results[0] != null);
    try std.testing.expectEqualStrings("agent1", results[0].?.agent_id);

    // one additional millicore exceeds capacity.
    try std.testing.expect(results[1] == null);
}

test "assignmentSql escapes single quotes in image name" {
    var buf: [1024]u8 = undefined;
    const sql = try assignmentSql(&buf, "id123", "agent1", .{
        .image = "nginx'latest",
        .command = "echo 'hello'",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
    }, 1000);

    // escape quotes in both values so they remain inside the sql string literals.
    try std.testing.expect(std.mem.indexOf(u8, sql, "nginx''latest") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "echo ''hello''") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "INSERT INTO assignments") != null);
}

test "schedule more requests than capacity" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgent("agent1", "active", 1, 2048, 0, 0), // 1000 millicores
    };

    // only two 500-millicore requests fit on one core.
    var requests: [10]PlacementRequest = undefined;
    for (&requests) |*r| {
        r.* = .{ .image = "app", .command = "", .cpu_limit = 500, .memory_limit_mb = 128 };
    }

    const results = try schedule(alloc, &requests, agents);
    defer alloc.free(results);

    var placed: usize = 0;
    var unplaced: usize = 0;
    for (results) |r| {
        if (r != null) placed += 1 else unplaced += 1;
    }

    try std.testing.expectEqual(@as(usize, 2), placed);
    try std.testing.expectEqual(@as(usize, 8), unplaced);
}

test "schedule volume constraint pins to correct node" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgentFull("node1", "active", 4, 8192, 0, 0, null, null, 0, 0),
        makeAgentFull("node2", "active", 4, 8192, 0, 0, null, null, 0, 0),
        makeAgentFull("node3", "active", 4, 8192, 0, 0, null, null, 0, 0),
    };
    var agents_mut: [3]AgentRecord = undefined;
    for (agents, 0..) |a, i| {
        agents_mut[i] = a;
    }
    agents_mut[0].node_id = 1;
    agents_mut[1].node_id = 2;
    agents_mut[2].node_id = 3;

    const constraints = [_]VolumeConstraint{
        .{ .driver = "local", .node_id = "2" },
    };

    const requests = &[_]PlacementRequest{
        .{ .image = "app", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256, .volume_constraints = &constraints },
    };

    const results = try schedule(alloc, requests, &agents_mut);
    defer alloc.free(results);

    try std.testing.expect(results[0] != null);
    try std.testing.expectEqualStrings("node2", results[0].?.agent_id);
}

test "schedule volume constraint with no matching node returns null" {
    const alloc = std.testing.allocator;
    var agents_mut = [_]AgentRecord{
        makeAgentFull("node1", "active", 4, 8192, 0, 0, null, null, 0, 0),
    };
    agents_mut[0].node_id = 1;

    const constraints = [_]VolumeConstraint{
        .{ .driver = "local", .node_id = "99" },
    };

    const requests = &[_]PlacementRequest{
        .{ .image = "app", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256, .volume_constraints = &constraints },
    };

    const results = try schedule(alloc, requests, &agents_mut);
    defer alloc.free(results);

    try std.testing.expect(results[0] == null);
}

test "schedule unconstrained volume (nfs/host) allows any node" {
    const alloc = std.testing.allocator;
    var agents_mut = [_]AgentRecord{
        makeAgentFull("node1", "active", 4, 8192, 0, 0, null, null, 0, 0),
    };
    agents_mut[0].node_id = 1;

    const constraints = [_]VolumeConstraint{
        .{ .driver = "nfs", .node_id = null }, // unconstrained
    };

    const requests = &[_]PlacementRequest{
        .{ .image = "app", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256, .volume_constraints = &constraints },
    };

    const results = try schedule(alloc, requests, &agents_mut);
    defer alloc.free(results);

    try std.testing.expect(results[0] != null);
}

test "matchesVolumeConstraints — no constraints" {
    const agent = makeAgent("a", "active", 4, 8192, 0, 0);
    try std.testing.expect(matchesVolumeConstraints(agent, &.{}));
}

test "matchesVolumeConstraints — agent without node_id fails constrained" {
    const agent = makeAgent("a", "active", 4, 8192, 0, 0);
    const constraints = [_]VolumeConstraint{
        .{ .driver = "local", .node_id = "1" },
    };
    try std.testing.expect(!matchesVolumeConstraints(agent, &constraints));
}

test "volume constraints require the decimal node id without extra characters" {
    var agent = makeAgent("a", "active", 4, 8192, 0, 0);
    agent.node_id = 1;

    try std.testing.expect(matchesVolumeConstraints(agent, &.{.{ .driver = "local", .node_id = "1" }}));
    for ([_][]const u8{ "01", "+1", " 1", "1 " }) |node_id| {
        try std.testing.expect(!matchesVolumeConstraints(agent, &.{.{ .driver = "local", .node_id = node_id }}));
    }
}

test "schedule gang respects memory per rank without changing agent capacity" {
    const alloc = std.testing.allocator;
    const agents = [_]AgentRecord{
        makeAgentFull("agent1", "active", 4, 1024, 0, 256, "agent", null, 4, 1),
    };
    var request = PlacementRequest{
        .image = "training",
        .command = "",
        .cpu_limit = 0,
        .memory_limit_mb = 512,
        .gang_world_size = 2,
    };

    // three free gpus fit two ranks, but the remaining memory fits only one.
    try std.testing.expect((try scheduleGang(alloc, request, &agents)) == null);

    request.memory_limit_mb = 384;
    const placements = (try scheduleGang(alloc, request, &agents)).?;
    defer alloc.free(placements);
    try std.testing.expectEqual(@as(usize, 2), placements.len);
    for (placements) |rank| {
        try std.testing.expectEqualStrings("agent1", rank.agent_id);
    }
    try std.testing.expectEqual(@as(i64, 4), agents[0].gpu_count);
    try std.testing.expectEqual(@as(i64, 1), agents[0].gpu_used);
}

test "schedule gang with zero cpu and memory limits uses available gpus" {
    const alloc = std.testing.allocator;
    const agents = [_]AgentRecord{
        makeAgentFull("agent1", "active", 0, 0, 0, 0, "agent", null, 5, 1),
    };
    const request = PlacementRequest{
        .image = "training",
        .command = "",
        .cpu_limit = 0,
        .memory_limit_mb = 0,
        .gang_world_size = 2,
        .gpus_per_rank = 2,
    };

    const placements = (try scheduleGang(alloc, request, &agents)).?;
    defer alloc.free(placements);
    try std.testing.expectEqual(@as(usize, 2), placements.len);
    for (placements, 0..) |rank, index| {
        try std.testing.expectEqualStrings("agent1", rank.agent_id);
        try std.testing.expectEqual(@as(u32, 2), rank.gpu_count);
        try std.testing.expectEqual(@as(u32, @intCast(1 + index * 2)), rank.gpu_start);
    }
}
