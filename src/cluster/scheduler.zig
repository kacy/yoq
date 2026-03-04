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

    for (agents, 0..) |a, i| {
        used_cpu[i] = a.cpu_used;
        used_mem[i] = a.memory_used_mb;
    }

    for (requests, 0..) |req, req_idx| {
        var best_idx: ?usize = null;
        var best_score: i64 = -1;

        for (agents, 0..) |a, agent_idx| {
            // skip non-active agents
            if (!std.mem.eql(u8, a.status, "active")) continue;

            // check capacity (cpu in millicores: cores * 1000)
            const free_cpu = a.cpu_cores * 1000 - used_cpu[agent_idx];
            const free_mem = a.memory_mb - used_mem[agent_idx];

            if (free_cpu < req.cpu_limit) continue;
            if (free_mem < req.memory_limit_mb) continue;

            // score: total free resources (higher = more room)
            const score = free_cpu + free_mem;
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

// -- tests --

fn makeAgent(id: []const u8, status: []const u8, cores: i64, mem: i64, cpu_used: i64, mem_used: i64) AgentRecord {
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
    };
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
