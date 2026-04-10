// registry — server-side agent registry facade
//
// keep the public registry API stable while the implementation lives in
// cluster/registry/ by concern: SQL mutations, DB queries, and identity.

const std = @import("std");
const sqlite = @import("sqlite");
const agent_types = @import("agent_types.zig");
const sql_mutations = @import("registry/sql_mutations.zig");
const identity = @import("registry/identity.zig");
const queries = @import("registry/queries.zig");
const test_support = @import("registry/test_support.zig");

pub const AgentRecord = agent_types.AgentRecord;
pub const AgentResources = agent_types.AgentResources;
pub const Assignment = agent_types.Assignment;
pub const RegisterOpts = sql_mutations.RegisterOpts;
pub const NodeIdError = identity.NodeIdError;
pub const WireguardPeer = queries.WireguardPeer;

pub const registerSql = sql_mutations.registerSql;
pub const registerSqlFull = sql_mutations.registerSqlFull;
pub const heartbeatSql = sql_mutations.heartbeatSql;
pub const drainSql = sql_mutations.drainSql;
pub const updateAssignmentStatusSql = sql_mutations.updateAssignmentStatusSql;
pub const markOfflineSql = sql_mutations.markOfflineSql;
pub const markActiveSql = sql_mutations.markActiveSql;
pub const updateLabelsSql = sql_mutations.updateLabelsSql;
pub const removeSql = sql_mutations.removeSql;
pub const orphanAssignmentsSql = sql_mutations.orphanAssignmentsSql;
pub const reassignSql = sql_mutations.reassignSql;
pub const deleteAgentAssignmentsSql = sql_mutations.deleteAgentAssignmentsSql;
pub const deleteAssignmentsForWorkloadSql = sql_mutations.deleteAssignmentsForWorkloadSql;
pub const wireguardPeerSql = sql_mutations.wireguardPeerSql;
pub const removeWireguardPeerSql = sql_mutations.removeWireguardPeerSql;

pub const findAgentIdByNodeId = identity.findAgentIdByNodeId;
pub const assignNodeId = identity.assignNodeId;
pub const getGossipSeeds = identity.getGossipSeeds;
pub const freeGossipSeeds = identity.freeGossipSeeds;
pub const validateToken = identity.validateToken;
pub const generateAgentId = identity.generateAgentId;

pub const listWireguardPeers = queries.listWireguardPeers;
pub const listWireguardServerPeers = queries.listWireguardServerPeers;
pub const listAgents = queries.listAgents;
pub const getAgent = queries.getAgent;
pub const getAssignments = queries.getAssignments;
pub const getOrphanedAssignments = queries.getOrphanedAssignments;
pub const countAssignmentsForWorkload = queries.countAssignmentsForWorkload;

// -- tests --

test "registerSql generates valid SQL" {
    var buf: [1024]u8 = undefined;
    const sql = try registerSql(&buf, "abc123def456", "10.0.0.5:7701", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
    }, 1000);

    try std.testing.expect(std.mem.indexOf(u8, sql, "INSERT INTO agents") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "abc123def456") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "10.0.0.5:7701") != null);
}

test "registerSqlFull includes wireguard columns" {
    var buf: [2048]u8 = undefined;
    const sql = try registerSqlFull(&buf, "abc123def456", "10.0.0.5:7701", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
    }, 1000, .{ .node_id = 3, .wg_public_key = "base64pubkey==", .overlay_ip = "10.40.0.3" });

    try std.testing.expect(std.mem.indexOf(u8, sql, "node_id") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "wg_public_key") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "overlay_ip") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "base64pubkey==") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "10.40.0.3") != null);
}

test "registerSqlFull without wireguard falls back to base columns" {
    var buf: [2048]u8 = undefined;
    const sql = try registerSqlFull(&buf, "abc123def456", "10.0.0.5:7701", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
    }, 1000, .{});

    // should NOT have wireguard columns
    try std.testing.expect(std.mem.indexOf(u8, sql, "node_id") == null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "wg_public_key") == null);
    // but should still have the base columns
    try std.testing.expect(std.mem.indexOf(u8, sql, "INSERT INTO agents") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "abc123def456") != null);
}

test "registerSql escapes single quotes in address" {
    var buf: [1024]u8 = undefined;
    const sql = try registerSql(&buf, "abc123def456", "10.0.0.5'; DROP TABLE agents; --", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
    }, 1000);

    // the single quote should be doubled, not passed through raw
    try std.testing.expect(std.mem.indexOf(u8, sql, "DROP TABLE") == null or
        std.mem.indexOf(u8, sql, "''") != null);
    // verify the escaped value is in the SQL
    try std.testing.expect(std.mem.indexOf(u8, sql, "10.0.0.5''; DROP TABLE agents; --") != null);
}

test "heartbeatSql generates valid SQL with status recovery" {
    var buf: [512]u8 = undefined;
    const sql = try heartbeatSql(&buf, "abc123def456", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
        .cpu_used = 2,
        .memory_used_mb = 4096,
        .containers = 3,
    }, 2000);

    try std.testing.expect(std.mem.indexOf(u8, sql, "UPDATE agents SET") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "abc123def456") != null);
    // should include CASE expression for status recovery
    try std.testing.expect(std.mem.indexOf(u8, sql, "CASE WHEN status = 'offline' THEN 'active' ELSE status END") != null);
}

test "heartbeatSql restores offline agent to active" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(test_support.agents_schema, .{}, .{}) catch return;

    // insert an offline agent
    db.exec(
        \\INSERT INTO agents (id, address, status, cpu_cores, memory_mb, last_heartbeat, registered_at)
        \\ VALUES ('test12345678', '10.0.0.1:7701', 'offline', 4, 8192, 1000, 1000);
    , .{}, .{}) catch return;

    // apply heartbeat — should restore to active
    var sql_buf: [512]u8 = undefined;
    const sql = heartbeatSql(&sql_buf, "test12345678", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
        .cpu_used = 1,
        .memory_used_mb = 2048,
        .containers = 2,
    }, 2000) catch return;
    db.execDynamic(sql, .{}, .{}) catch return;

    const alloc = std.testing.allocator;
    const agent = (try getAgent(alloc, &db, "test12345678")).?;
    defer agent.deinit(alloc);

    try std.testing.expectEqualStrings("active", agent.status);
    try std.testing.expectEqual(@as(i64, 2000), agent.last_heartbeat);
}

test "heartbeatSql preserves draining status" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(test_support.agents_schema, .{}, .{}) catch return;

    // insert a draining agent
    db.exec(
        \\INSERT INTO agents (id, address, status, cpu_cores, memory_mb, last_heartbeat, registered_at)
        \\ VALUES ('test12345678', '10.0.0.1:7701', 'draining', 4, 8192, 1000, 1000);
    , .{}, .{}) catch return;

    // apply heartbeat — should NOT override draining
    var sql_buf: [512]u8 = undefined;
    const sql = heartbeatSql(&sql_buf, "test12345678", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
        .cpu_used = 1,
        .memory_used_mb = 2048,
        .containers = 2,
    }, 2000) catch return;
    db.execDynamic(sql, .{}, .{}) catch return;

    const alloc = std.testing.allocator;
    const agent = (try getAgent(alloc, &db, "test12345678")).?;
    defer agent.deinit(alloc);

    try std.testing.expectEqualStrings("draining", agent.status);
}

test "drainSql generates valid SQL" {
    var buf: [256]u8 = undefined;
    const sql = try drainSql(&buf, "abc123def456");

    try std.testing.expect(std.mem.indexOf(u8, sql, "draining") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "abc123def456") != null);
}

test "updateAssignmentStatusSql generates valid SQL" {
    var buf: [256]u8 = undefined;
    const sql = try updateAssignmentStatusSql(&buf, "assign123456", "running");

    try std.testing.expect(std.mem.indexOf(u8, sql, "UPDATE assignments SET status") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "running") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "assign123456") != null);
}

test "updateAssignmentStatusSql escapes values" {
    var buf: [512]u8 = undefined;
    const sql = try updateAssignmentStatusSql(&buf, "id'; DROP TABLE assignments; --", "running");

    // single quote should be doubled
    try std.testing.expect(std.mem.indexOf(u8, sql, "id''; DROP TABLE assignments; --") != null);
}

test "validateToken correct" {
    try std.testing.expect(validateToken("my-secret", "my-secret"));
}

test "validateToken wrong" {
    try std.testing.expect(!validateToken("wrong", "my-secret"));
}

test "validateToken empty" {
    try std.testing.expect(!validateToken("", "my-secret"));
}

test "generateAgentId produces 12 hex chars" {
    var buf: [12]u8 = undefined;
    generateAgentId(&buf);

    for (buf) |c| {
        const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        try std.testing.expect(is_hex);
    }
}

test "generateAgentId produces different values" {
    var buf1: [12]u8 = undefined;
    var buf2: [12]u8 = undefined;
    generateAgentId(&buf1);
    generateAgentId(&buf2);

    // extremely unlikely to be equal
    try std.testing.expect(!std.mem.eql(u8, &buf1, &buf2));
}

test "listAgents with empty table" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    // create the agents table
    db.exec(test_support.agents_schema, .{}, .{}) catch return;

    const alloc = std.testing.allocator;
    const agents = try listAgents(alloc, &db);
    defer alloc.free(agents);

    try std.testing.expectEqual(@as(usize, 0), agents.len);
}

test "listAgents returns inserted agent" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(test_support.agents_schema, .{}, .{}) catch return;

    // insert via the generated SQL
    var sql_buf: [1024]u8 = undefined;
    const sql = registerSql(&sql_buf, "test12345678", "10.0.0.1:7701", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
    }, 1000) catch return;
    db.execDynamic(sql, .{}, .{}) catch return;

    const alloc = std.testing.allocator;
    const agents = try listAgents(alloc, &db);
    defer {
        for (agents) |a| a.deinit(alloc);
        alloc.free(agents);
    }

    try std.testing.expectEqual(@as(usize, 1), agents.len);
    try std.testing.expectEqualStrings("test12345678", agents[0].id);
    try std.testing.expectEqualStrings("active", agents[0].status);
    try std.testing.expectEqual(@as(i64, 4), agents[0].cpu_cores);
}

test "getAgent returns null for missing" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(test_support.agents_schema, .{}, .{}) catch return;

    const alloc = std.testing.allocator;
    const agent = try getAgent(alloc, &db, "nonexistent");
    try std.testing.expect(agent == null);
}

test "orphanAssignmentsSql generates valid SQL" {
    var buf: [256]u8 = undefined;
    const sql = try orphanAssignmentsSql(&buf, "agent1234567");

    try std.testing.expect(std.mem.indexOf(u8, sql, "UPDATE assignments SET") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "agent_id = ''") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "status = 'pending'") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "agent1234567") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "IN ('pending', 'running')") != null);
}

test "orphanAssignmentsSql only affects non-terminal assignments" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(
        \\CREATE TABLE assignments (
        \\    id TEXT PRIMARY KEY,
        \\    agent_id TEXT NOT NULL,
        \\    image TEXT NOT NULL,
        \\    command TEXT NOT NULL DEFAULT '',
        \\    status TEXT NOT NULL DEFAULT 'pending',
        \\    cpu_limit INTEGER NOT NULL DEFAULT 0,
        \\    memory_limit_mb INTEGER NOT NULL DEFAULT 0,
        \\    gang_rank INTEGER,
        \\    gang_world_size INTEGER,
        \\    gang_master_addr TEXT,
        \\    gang_master_port INTEGER,
        \\    created_at INTEGER NOT NULL DEFAULT 0
        \\);
    , .{}, .{}) catch return;

    // insert assignments in different statuses
    db.exec("INSERT INTO assignments (id, agent_id, image, status) VALUES ('a1', 'agent1', 'nginx', 'pending');", .{}, .{}) catch return;
    db.exec("INSERT INTO assignments (id, agent_id, image, status) VALUES ('a2', 'agent1', 'redis', 'running');", .{}, .{}) catch return;
    db.exec("INSERT INTO assignments (id, agent_id, image, status) VALUES ('a3', 'agent1', 'postgres', 'stopped');", .{}, .{}) catch return;
    db.exec("INSERT INTO assignments (id, agent_id, image, status) VALUES ('a4', 'agent1', 'mysql', 'failed');", .{}, .{}) catch return;

    // orphan agent1's assignments
    var sql_buf: [256]u8 = undefined;
    const sql = orphanAssignmentsSql(&sql_buf, "agent1") catch return;
    db.execDynamic(sql, .{}, .{}) catch return;

    // pending and running should be orphaned (agent_id = '', status = pending)
    const alloc = std.testing.allocator;

    const orphans = try getOrphanedAssignments(alloc, &db);
    defer {
        for (orphans) |a| a.deinit(alloc);
        alloc.free(orphans);
    }
    try std.testing.expectEqual(@as(usize, 2), orphans.len);

    // stopped and failed should remain on agent1
    const remaining = try getAssignments(alloc, &db, "agent1");
    defer {
        for (remaining) |a| a.deinit(alloc);
        alloc.free(remaining);
    }
    try std.testing.expectEqual(@as(usize, 2), remaining.len);
}

test "reassignSql generates valid SQL" {
    var buf: [256]u8 = undefined;
    const sql = try reassignSql(&buf, "assign123456", "newagent1234");

    try std.testing.expect(std.mem.indexOf(u8, sql, "UPDATE assignments SET") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "newagent1234") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "assign123456") != null);
    // guard against double-assignment
    try std.testing.expect(std.mem.indexOf(u8, sql, "agent_id = ''") != null);
}

test "getOrphanedAssignments returns only orphaned pending" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(
        \\CREATE TABLE assignments (
        \\    id TEXT PRIMARY KEY,
        \\    agent_id TEXT NOT NULL,
        \\    image TEXT NOT NULL,
        \\    command TEXT NOT NULL DEFAULT '',
        \\    status TEXT NOT NULL DEFAULT 'pending',
        \\    cpu_limit INTEGER NOT NULL DEFAULT 0,
        \\    memory_limit_mb INTEGER NOT NULL DEFAULT 0,
        \\    gang_rank INTEGER,
        \\    gang_world_size INTEGER,
        \\    gang_master_addr TEXT,
        \\    gang_master_port INTEGER,
        \\    created_at INTEGER NOT NULL DEFAULT 0
        \\);
    , .{}, .{}) catch return;

    // orphaned pending — should be returned
    db.exec("INSERT INTO assignments (id, agent_id, image, status) VALUES ('a1', '', 'nginx', 'pending');", .{}, .{}) catch return;
    // normal assignment — should NOT be returned
    db.exec("INSERT INTO assignments (id, agent_id, image, status) VALUES ('a2', 'agent1', 'redis', 'pending');", .{}, .{}) catch return;
    // orphaned but running status was reset to pending during orphan, so this tests
    // a weird edge case if someone manually set it — should NOT be returned since
    // status is running not pending
    db.exec("INSERT INTO assignments (id, agent_id, image, status) VALUES ('a3', '', 'pg', 'running');", .{}, .{}) catch return;

    const alloc = std.testing.allocator;
    const orphans = try getOrphanedAssignments(alloc, &db);
    defer {
        for (orphans) |a| a.deinit(alloc);
        alloc.free(orphans);
    }

    try std.testing.expectEqual(@as(usize, 1), orphans.len);
    try std.testing.expectEqualStrings("a1", orphans[0].id);
}

test "deleteAgentAssignmentsSql generates valid SQL" {
    var buf: [256]u8 = undefined;
    const sql = try deleteAgentAssignmentsSql(&buf, "agent1234567");

    try std.testing.expect(std.mem.indexOf(u8, sql, "DELETE FROM assignments") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "agent1234567") != null);
}

test "deleteAssignmentsForWorkloadSql generates valid SQL" {
    var buf: [512]u8 = undefined;
    const sql = try deleteAssignmentsForWorkloadSql(&buf, "demo-app", "training", "finetune");

    try std.testing.expect(std.mem.indexOf(u8, sql, "DELETE FROM assignments") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "demo-app") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "training") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "finetune") != null);
}

test "assignNodeId returns 1 for empty table" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(test_support.agents_schema, .{}, .{}) catch return;

    const nid = try assignNodeId(&db);
    try std.testing.expectEqual(@as(u8, 1), nid);
}

test "assignNodeId fills gaps" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(test_support.agents_schema, .{}, .{}) catch return;

    // insert agents with node_id 1 and 3 (gap at 2)
    db.exec("INSERT INTO agents (id, address, node_id, last_heartbeat, registered_at) VALUES ('a1', '10.0.0.1:7701', 1, 1000, 1000);", .{}, .{}) catch return;
    db.exec("INSERT INTO agents (id, address, node_id, last_heartbeat, registered_at) VALUES ('a3', '10.0.0.3:7701', 3, 1000, 1000);", .{}, .{}) catch return;

    const nid = try assignNodeId(&db);
    try std.testing.expectEqual(@as(u8, 2), nid);
}

test "assignNodeId skips agents without node_id" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(test_support.agents_schema, .{}, .{}) catch return;

    // agent without node_id (legacy)
    db.exec("INSERT INTO agents (id, address, last_heartbeat, registered_at) VALUES ('a0', '10.0.0.1:7701', 1000, 1000);", .{}, .{}) catch return;

    const nid = try assignNodeId(&db);
    try std.testing.expectEqual(@as(u8, 1), nid);
}

test "getGossipSeeds respects requested count" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(test_support.agents_schema, .{}, .{}) catch return;
    db.exec("INSERT INTO agents (id, address, status, node_id, role, last_heartbeat, registered_at) VALUES ('a1', '10.0.0.1', 'active', 1, 'agent', 1000, 1000);", .{}, .{}) catch return;
    db.exec("INSERT INTO agents (id, address, status, node_id, role, last_heartbeat, registered_at) VALUES ('a2', '10.0.0.2', 'active', 2, 'agent', 1000, 1000);", .{}, .{}) catch return;
    db.exec("INSERT INTO agents (id, address, status, node_id, role, last_heartbeat, registered_at) VALUES ('a3', '10.0.0.3', 'active', 3, 'agent', 1000, 1000);", .{}, .{}) catch return;

    const alloc = std.testing.allocator;
    const seeds = try getGossipSeeds(alloc, &db, 2);
    defer freeGossipSeeds(alloc, seeds);

    try std.testing.expectEqual(@as(usize, 2), seeds.len);
}

test "wireguardPeerSql generates valid SQL" {
    var buf: [1024]u8 = undefined;
    const sql = try wireguardPeerSql(&buf, 3, "abc123def456", "base64key==", "10.0.0.5:51820", "10.40.0.3", "10.42.3.0/24");

    try std.testing.expect(std.mem.indexOf(u8, sql, "INSERT INTO wireguard_peers") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "abc123def456") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "base64key==") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "10.0.0.5:51820") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "10.40.0.3") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "10.42.3.0/24") != null);
}

test "removeWireguardPeerSql generates valid SQL" {
    var buf: [256]u8 = undefined;
    const sql = try removeWireguardPeerSql(&buf, 5);

    try std.testing.expect(std.mem.indexOf(u8, sql, "DELETE FROM wireguard_peers") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "5") != null);
}

test "listAgents returns wireguard fields" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(test_support.agents_schema, .{}, .{}) catch return;

    // insert via registerSqlFull with wireguard fields
    var sql_buf: [2048]u8 = undefined;
    const sql = registerSqlFull(&sql_buf, "wgtest123456", "10.0.0.5:7701", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
    }, 1000, .{ .node_id = 3, .wg_public_key = "base64pubkey==", .overlay_ip = "10.40.0.3" }) catch return;
    db.execDynamic(sql, .{}, .{}) catch return;

    const alloc = std.testing.allocator;
    const agents = try listAgents(alloc, &db);
    defer {
        for (agents) |a| a.deinit(alloc);
        alloc.free(agents);
    }

    try std.testing.expectEqual(@as(usize, 1), agents.len);
    try std.testing.expectEqual(@as(?i64, 3), agents[0].node_id);
    try std.testing.expectEqualStrings("base64pubkey==", agents[0].wg_public_key.?);
    try std.testing.expectEqualStrings("10.40.0.3", agents[0].overlay_ip.?);
}

test "getAgent returns wireguard fields" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(test_support.agents_schema, .{}, .{}) catch return;

    var sql_buf: [2048]u8 = undefined;
    const sql = registerSqlFull(&sql_buf, "wgtest123456", "10.0.0.5:7701", .{
        .cpu_cores = 4,
        .memory_mb = 8192,
    }, 1000, .{ .node_id = 7, .wg_public_key = "mypubkey==", .overlay_ip = "10.40.0.7" }) catch return;
    db.execDynamic(sql, .{}, .{}) catch return;

    const alloc = std.testing.allocator;
    const agent = (try getAgent(alloc, &db, "wgtest123456")).?;
    defer agent.deinit(alloc);

    try std.testing.expectEqual(@as(?i64, 7), agent.node_id);
    try std.testing.expectEqualStrings("mypubkey==", agent.wg_public_key.?);
    try std.testing.expectEqualStrings("10.40.0.7", agent.overlay_ip.?);
}

test "getAgent returns null wireguard fields for legacy agent" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(test_support.agents_schema, .{}, .{}) catch return;

    // legacy registration without WG fields
    var sql_buf: [1024]u8 = undefined;
    const sql = registerSql(&sql_buf, "legacy123456", "10.0.0.1:7701", .{
        .cpu_cores = 2,
        .memory_mb = 4096,
    }, 1000) catch return;
    db.execDynamic(sql, .{}, .{}) catch return;

    const alloc = std.testing.allocator;
    const agent = (try getAgent(alloc, &db, "legacy123456")).?;
    defer agent.deinit(alloc);

    try std.testing.expect(agent.node_id == null);
    try std.testing.expect(agent.wg_public_key == null);
    try std.testing.expect(agent.overlay_ip == null);
}
