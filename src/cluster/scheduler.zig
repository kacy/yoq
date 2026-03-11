// scheduler — container placement via bin-packing
//
// pure function: takes placement requests + agent list, returns
// assignments. no I/O, no state — the caller (API handler) is
// responsible for proposing assignments through raft.
//
// scoring: agents with the most free resources win. draining and
// offline agents are skipped. during a batch, resource usage is
// tracked locally to avoid over-scheduling multiple containers
// to the same agent.

const std = @import("std");
const agent_types = @import("agent_types.zig");
const sql_escape = @import("../lib/sql.zig");

const Allocator = std.mem.Allocator;
const AgentRecord = agent_types.AgentRecord;

pub const PlacementRequest = struct {
    image: []const u8,
    command: []const u8,
    cpu_limit: i64, // millicores (1000 = 1 core)
    memory_limit_mb: i64,
    gpu_limit: i64 = 0,
    required_labels: []const u8 = "",
};

pub const PlacementResult = struct {
    agent_id: []const u8,
    request_idx: usize,
};

/// schedule containers onto agents using best-fit bin-packing.
///
/// returns a list of placements. entries are null if the request
/// couldn't fit on any agent. the caller should check for nulls
/// and handle partial placement.
pub fn schedule(
    alloc: Allocator,
    requests: []const PlacementRequest,
    agents: []const AgentRecord,
) ![]?PlacementResult {
    var results = try alloc.alloc(?PlacementResult, requests.len);
    @memset(results, null);

    // track resource usage during this batch to avoid over-scheduling.
    // keyed by index into agents slice.
    var used_cpu = try alloc.alloc(i64, agents.len);
    defer alloc.free(used_cpu);
    var used_mem = try alloc.alloc(i64, agents.len);
    defer alloc.free(used_mem);
    var used_gpu = try alloc.alloc(i64, agents.len);
    defer alloc.free(used_gpu);

    for (agents, 0..) |a, i| {
        used_cpu[i] = a.cpu_used;
        used_mem[i] = a.memory_used_mb;
        used_gpu[i] = a.gpu_used;
    }

    for (requests, 0..) |req, req_idx| {
        var best_idx: ?usize = null;
        var best_score: i64 = -1;

        for (agents, 0..) |a, agent_idx| {
            // skip non-active agents
            if (!std.mem.eql(u8, a.status, "active")) continue;

            // skip server-only agents — they run raft consensus, not workloads
            if (a.role) |role| {
                if (std.mem.eql(u8, role, "server")) continue;
            }

            // check capacity (cpu in millicores: cores * 1000)
            const free_cpu = a.cpu_cores * 1000 - used_cpu[agent_idx];
            const free_mem = a.memory_mb - used_mem[agent_idx];

            if (free_cpu < req.cpu_limit) continue;
            if (free_mem < req.memory_limit_mb) continue;

            // check GPU capacity
            if (req.gpu_limit > 0) {
                const free_gpu = a.gpu_count - used_gpu[agent_idx];
                if (free_gpu < req.gpu_limit) continue;
            }

            // check label constraints
            if (req.required_labels.len > 0) {
                if (!matchesLabels(if (a.labels) |l| l else "", req.required_labels)) continue;
            }

            // score: total free resources (higher = more room)
            const gpu_score: i64 = if (req.gpu_limit > 0) (a.gpu_count - used_gpu[agent_idx]) * 1000 else 0;
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
            // update tracked usage
            used_cpu[idx] += req.cpu_limit;
            used_mem[idx] += req.memory_limit_mb;
            used_gpu[idx] += req.gpu_limit;
        }
    }

    return results;
}

/// generate SQL INSERT for a container assignment.
pub fn assignmentSql(
    buf: []u8,
    id: []const u8,
    agent_id: []const u8,
    request: PlacementRequest,
    now: i64,
) ![]const u8 {
    // escape user-controlled values (image and command come from API requests)
    var img_esc_buf: [512]u8 = undefined;
    const img_esc = try sql_escape.escapeSqlString(&img_esc_buf, request.image);
    var cmd_esc_buf: [512]u8 = undefined;
    const cmd_esc = try sql_escape.escapeSqlString(&cmd_esc_buf, request.command);

    return std.fmt.bufPrint(buf,
        \\INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, created_at)
        \\ VALUES ('{s}', '{s}', '{s}', '{s}', 'pending', {d}, {d}, {d});
    , .{ id, agent_id, img_esc, cmd_esc, request.cpu_limit, request.memory_limit_mb, now });
}

/// generate a random hex assignment ID.
pub fn generateAssignmentId(buf: *[12]u8) void {
    var random_bytes: [6]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    const hex = "0123456789abcdef";
    for (random_bytes, 0..) |b, i| {
        buf[i * 2] = hex[b >> 4];
        buf[i * 2 + 1] = hex[b & 0x0f];
    }
}

/// check that every required label exists in the agent's label set.
/// labels are comma-separated key=value pairs (e.g., "zone=us-east,tier=gpu").
/// empty required_labels matches any agent.
fn matchesLabels(agent_labels: []const u8, required: []const u8) bool {
    if (required.len == 0) return true;

    // iterate over required labels
    var req_iter = std.mem.splitScalar(u8, required, ',');
    while (req_iter.next()) |req_label| {
        const trimmed = std.mem.trim(u8, req_label, " ");
        if (trimmed.len == 0) continue;

        // check if this required label exists in agent_labels
        var found = false;
        var agent_iter = std.mem.splitScalar(u8, agent_labels, ',');
        while (agent_iter.next()) |agent_label| {
            const agent_trimmed = std.mem.trim(u8, agent_label, " ");
            if (std.mem.eql(u8, agent_trimmed, trimmed)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

// -- tests --

fn makeAgent(id: []const u8, status: []const u8, cores: i64, mem: i64, cpu_used: i64, mem_used: i64) AgentRecord {
    return makeAgentWithRole(id, status, cores, mem, cpu_used, mem_used, null);
}

fn makeAgentFull(id: []const u8, status: []const u8, cores: i64, mem: i64, cpu_used: i64, mem_used: i64, role: ?[]const u8, labels: ?[]const u8, gpu_count: i64, gpu_used: i64) AgentRecord {
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

fn makeAgentWithRole(id: []const u8, status: []const u8, cores: i64, mem: i64, cpu_used: i64, mem_used: i64, role: ?[]const u8) AgentRecord {
    return makeAgentFull(id, status, cores, mem, cpu_used, mem_used, role, null, 0, 0);
}

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
