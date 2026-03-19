// scheduler — placement facade
//
// keep the public scheduler API stable while the bin-packing, constraint,
// gang, and SQL helpers live in cluster/scheduler/.

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

    // agent2 has more free resources, should be picked
    try std.testing.expect(results[0] != null);
    try std.testing.expectEqualStrings("agent2", results[0].?.agent_id);
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
    // two containers that each need 1 core and 256MB
    const requests = &[_]PlacementRequest{
        .{ .image = "a", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
        .{ .image = "b", .command = "", .cpu_limit = 1000, .memory_limit_mb = 256 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    // both should fit on agent1 (2 cores, 1024MB)
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
    // third doesn't fit — only 2 cores
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

    // should skip server1 and place on worker1
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

    // create state machine and register 3 agents via SQL
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    // agent 1: server-only (should be skipped for scheduling)
    sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role) VALUES ('server-1', '10.0.0.1:9090', 'active', 8, 16384, 0, 0, 0, 1000, 1000, 'server');",
    });
    // agent 2: large worker
    sm.apply(.{
        .index = 2,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role) VALUES ('worker-large', '10.0.0.2:9090', 'active', 8, 16384, 0, 0, 0, 1000, 1000, 'agent');",
    });
    // agent 3: small worker
    sm.apply(.{
        .index = 3,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role) VALUES ('worker-small', '10.0.0.3:9090', 'active', 2, 2048, 0, 0, 0, 1000, 1000, 'agent');",
    });

    // read agents from the DB via registry
    const agents = try registry.listAgents(alloc, &sm.db);
    defer {
        for (agents) |*a| {
            var agent = a.*;
            agent.deinit(alloc);
        }
        alloc.free(agents);
    }

    try std.testing.expectEqual(@as(usize, 3), agents.len);

    // schedule a container that fits on either worker
    const requests = &[_]PlacementRequest{
        .{ .image = "nginx:latest", .command = "", .cpu_limit = 1000, .memory_limit_mb = 512 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    // server-only agent should be skipped, placed on the large worker (most resources)
    try std.testing.expect(results[0] != null);
    try std.testing.expectEqualStrings("worker-large", results[0].?.agent_id);
}

test "schedule exact capacity boundary" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgent("agent1", "active", 2, 4096, 0, 0), // 2000 millicores free
    };

    // request exactly 2000 millicores — should succeed
    const requests = &[_]PlacementRequest{
        .{ .image = "app", .command = "", .cpu_limit = 2000, .memory_limit_mb = 256 },
        .{ .image = "app2", .command = "", .cpu_limit = 1, .memory_limit_mb = 1 },
    };

    const results = try schedule(alloc, requests, agents);
    defer alloc.free(results);

    // first container takes all CPU
    try std.testing.expect(results[0] != null);
    try std.testing.expectEqualStrings("agent1", results[0].?.agent_id);

    // second container has no room — even 1 millicore exceeds capacity
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

    // single quotes in image should be doubled for SQL safety
    try std.testing.expect(std.mem.indexOf(u8, sql, "nginx''latest") != null);
    // single quotes in command should also be doubled
    try std.testing.expect(std.mem.indexOf(u8, sql, "echo ''hello''") != null);
    // verify it's still valid-looking SQL
    try std.testing.expect(std.mem.indexOf(u8, sql, "INSERT INTO assignments") != null);
}

test "schedule more requests than capacity" {
    const alloc = std.testing.allocator;
    const agents = &[_]AgentRecord{
        makeAgent("agent1", "active", 1, 2048, 0, 0), // 1000 millicores
    };

    // 10 requests each needing 500 millicores — only 2 fit
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
    // set node_ids
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

    // should land on node2 (node_id=2)
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
