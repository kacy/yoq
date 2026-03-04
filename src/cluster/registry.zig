// registry — server-side agent registry
//
// manages agent lifecycle on the server. generates SQL statements that
// get proposed through raft for state mutations (register, heartbeat,
// drain). reads from the state machine DB directly for queries.
//
// the split between SQL generation and DB queries is intentional:
// writes go through raft consensus (all nodes agree), reads are
// local to the leader (good enough for management operations).

const std = @import("std");
const sqlite = @import("sqlite");
const agent_types = @import("agent_types.zig");
const sql_escape = @import("../lib/sql.zig");

const Allocator = std.mem.Allocator;
pub const AgentRecord = agent_types.AgentRecord;
pub const AgentResources = agent_types.AgentResources;
pub const Assignment = agent_types.Assignment;

// -- SQL generation --
// these produce SQL strings that the caller proposes through raft.
// using fixed-size buffers avoids allocation in the hot path.

/// generate SQL to register a new agent.
pub fn registerSql(
    buf: []u8,
    id: []const u8,
    address: []const u8,
    resources: AgentResources,
    now: i64,
) ![]const u8 {
    // escape user-controlled values to prevent SQL injection.
    // committed SQL is replicated via raft to ALL nodes, so a single
    // injection would corrupt the entire cluster.
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);
    var addr_esc_buf: [512]u8 = undefined;
    const addr_esc = try sql_escape.escapeSqlString(&addr_esc_buf, address);

    return std.fmt.bufPrint(buf,
        \\INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at)
        \\ VALUES ('{s}', '{s}', 'active', {d}, {d}, 0, 0, 0, {d}, {d});
    , .{ id_esc, addr_esc, resources.cpu_cores, resources.memory_mb, now, now });
}

/// generate SQL to update an agent's heartbeat and resource usage.
pub fn heartbeatSql(
    buf: []u8,
    id: []const u8,
    resources: AgentResources,
    now: i64,
) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);

    return std.fmt.bufPrint(buf,
        \\UPDATE agents SET cpu_used = {d}, memory_used_mb = {d}, containers = {d}, last_heartbeat = {d},
        \\ status = CASE WHEN status = 'offline' THEN 'active' ELSE status END
        \\ WHERE id = '{s}';
    , .{ resources.cpu_used, resources.memory_used_mb, resources.containers, now, id_esc });
}

/// generate SQL to mark an agent as draining.
pub fn drainSql(buf: []u8, id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);

    return std.fmt.bufPrint(buf,
        "UPDATE agents SET status = 'draining' WHERE id = '{s}';",
        .{id_esc},
    );
}

/// generate SQL to update an assignment's status.
pub fn updateAssignmentStatusSql(buf: []u8, assignment_id: []const u8, new_status: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, assignment_id);
    var status_esc_buf: [64]u8 = undefined;
    const status_esc = try sql_escape.escapeSqlString(&status_esc_buf, new_status);

    return std.fmt.bufPrint(buf,
        "UPDATE assignments SET status = '{s}' WHERE id = '{s}';",
        .{ status_esc, id_esc },
    );
}

/// generate SQL to mark an agent as offline.
pub fn markOfflineSql(buf: []u8, id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);

    return std.fmt.bufPrint(buf,
        "UPDATE agents SET status = 'offline' WHERE id = '{s}';",
        .{id_esc},
    );
}

/// generate SQL to remove an agent.
pub fn removeSql(buf: []u8, id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);

    return std.fmt.bufPrint(buf,
        "DELETE FROM agents WHERE id = '{s}';",
        .{id_esc},
    );
}

/// generate SQL to orphan an agent's active assignments.
/// resets pending/running assignments so they can be rescheduled.
/// terminal statuses (stopped/failed) are left untouched.
pub fn orphanAssignmentsSql(buf: []u8, agent_id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, agent_id);

    return std.fmt.bufPrint(buf,
        "UPDATE assignments SET agent_id = '', status = 'pending' WHERE agent_id = '{s}' AND status IN ('pending', 'running');",
        .{id_esc},
    );
}

/// generate SQL to reassign an orphaned assignment to a new agent.
/// the agent_id = '' guard prevents double-assignment races.
pub fn reassignSql(buf: []u8, assignment_id: []const u8, new_agent_id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, assignment_id);
    var agent_esc_buf: [64]u8 = undefined;
    const agent_esc = try sql_escape.escapeSqlString(&agent_esc_buf, new_agent_id);

    return std.fmt.bufPrint(buf,
        "UPDATE assignments SET agent_id = '{s}' WHERE id = '{s}' AND agent_id = '';",
        .{ agent_esc, id_esc },
    );
}

/// generate SQL to delete all assignments for an agent.
/// used during dead agent cleanup to remove terminal assignments.
pub fn deleteAgentAssignmentsSql(buf: []u8, agent_id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, agent_id);

    return std.fmt.bufPrint(buf,
        "DELETE FROM assignments WHERE agent_id = '{s}';",
        .{id_esc},
    );
}

// -- DB queries --
// read directly from the state machine database (leader only).

/// list all registered agents.
pub fn listAgents(alloc: Allocator, db: *sqlite.Db) ![]AgentRecord {
    const Row = struct {
        id: sqlite.Text,
        address: sqlite.Text,
        status: sqlite.Text,
        cpu_cores: i64,
        memory_mb: i64,
        cpu_used: i64,
        memory_used_mb: i64,
        containers: i64,
        last_heartbeat: i64,
        registered_at: i64,
    };

    var stmt = db.prepare(
        "SELECT id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at FROM agents ORDER BY registered_at;",
    ) catch return error.QueryFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(Row, .{}) catch return error.QueryFailed;

    var results: std.ArrayListUnmanaged(AgentRecord) = .empty;
    errdefer {
        for (results.items) |r| r.deinit(alloc);
        results.deinit(alloc);
    }

    while (iter.nextAlloc(alloc, .{}) catch null) |row| {
        try results.append(alloc, .{
            .id = row.id.data,
            .address = row.address.data,
            .status = row.status.data,
            .cpu_cores = row.cpu_cores,
            .memory_mb = row.memory_mb,
            .cpu_used = row.cpu_used,
            .memory_used_mb = row.memory_used_mb,
            .containers = row.containers,
            .last_heartbeat = row.last_heartbeat,
            .registered_at = row.registered_at,
        });
    }

    return results.toOwnedSlice(alloc);
}

/// get a single agent by ID.
pub fn getAgent(alloc: Allocator, db: *sqlite.Db, id: []const u8) !?AgentRecord {
    const Row = struct {
        id: sqlite.Text,
        address: sqlite.Text,
        status: sqlite.Text,
        cpu_cores: i64,
        memory_mb: i64,
        cpu_used: i64,
        memory_used_mb: i64,
        containers: i64,
        last_heartbeat: i64,
        registered_at: i64,
    };

    const row = (db.oneAlloc(Row, alloc,
        "SELECT id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at FROM agents WHERE id = ?;",
        .{},
        .{id},
    ) catch return error.QueryFailed) orelse return null;

    return .{
        .id = row.id.data,
        .address = row.address.data,
        .status = row.status.data,
        .cpu_cores = row.cpu_cores,
        .memory_mb = row.memory_mb,
        .cpu_used = row.cpu_used,
        .memory_used_mb = row.memory_used_mb,
        .containers = row.containers,
        .last_heartbeat = row.last_heartbeat,
        .registered_at = row.registered_at,
    };
}

/// get all assignments for a specific agent.
pub fn getAssignments(alloc: Allocator, db: *sqlite.Db, agent_id: []const u8) ![]Assignment {
    const Row = struct {
        id: sqlite.Text,
        agent_id: sqlite.Text,
        image: sqlite.Text,
        command: sqlite.Text,
        status: sqlite.Text,
        cpu_limit: i64,
        memory_limit_mb: i64,
    };

    var stmt = db.prepare(
        "SELECT id, agent_id, image, command, status, cpu_limit, memory_limit_mb FROM assignments WHERE agent_id = ?;",
    ) catch return error.QueryFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(Row, .{agent_id}) catch return error.QueryFailed;

    var results: std.ArrayListUnmanaged(Assignment) = .empty;
    errdefer {
        for (results.items) |a| a.deinit(alloc);
        results.deinit(alloc);
    }

    while (iter.nextAlloc(alloc, .{}) catch null) |row| {
        try results.append(alloc, .{
            .id = row.id.data,
            .agent_id = row.agent_id.data,
            .image = row.image.data,
            .command = row.command.data,
            .status = row.status.data,
            .cpu_limit = row.cpu_limit,
            .memory_limit_mb = row.memory_limit_mb,
        });
    }

    return results.toOwnedSlice(alloc);
}

/// get orphaned assignments (agent_id = '', status = 'pending').
/// these are assignments that were detached from an offline agent
/// and are waiting to be rescheduled.
pub fn getOrphanedAssignments(alloc: Allocator, db: *sqlite.Db) ![]Assignment {
    const Row = struct {
        id: sqlite.Text,
        agent_id: sqlite.Text,
        image: sqlite.Text,
        command: sqlite.Text,
        status: sqlite.Text,
        cpu_limit: i64,
        memory_limit_mb: i64,
    };

    var stmt = db.prepare(
        "SELECT id, agent_id, image, command, status, cpu_limit, memory_limit_mb FROM assignments WHERE agent_id = '' AND status = 'pending';",
    ) catch return error.QueryFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(Row, .{}) catch return error.QueryFailed;

    var results: std.ArrayListUnmanaged(Assignment) = .empty;
    errdefer {
        for (results.items) |a| a.deinit(alloc);
        results.deinit(alloc);
    }

    while (iter.nextAlloc(alloc, .{}) catch null) |row| {
        try results.append(alloc, .{
            .id = row.id.data,
            .agent_id = row.agent_id.data,
            .image = row.image.data,
            .command = row.command.data,
            .status = row.status.data,
            .cpu_limit = row.cpu_limit,
            .memory_limit_mb = row.memory_limit_mb,
        });
    }

    return results.toOwnedSlice(alloc);
}

// -- token validation --

/// compare a provided token against the expected join token.
/// uses constant-time comparison to avoid timing attacks.
pub fn validateToken(token: []const u8, expected: []const u8) bool {
    if (token.len != expected.len) return false;
    var diff: u8 = 0;
    for (token, expected) |a, b| {
        diff |= a ^ b;
    }
    return diff == 0;
}

/// generate a random hex agent ID.
pub fn generateAgentId(buf: *[12]u8) void {
    var random_bytes: [6]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    const hex = "0123456789abcdef";
    for (random_bytes, 0..) |b, i| {
        buf[i * 2] = hex[b >> 4];
        buf[i * 2 + 1] = hex[b & 0x0f];
    }
}

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

    db.exec(
        \\CREATE TABLE agents (
        \\    id TEXT PRIMARY KEY,
        \\    address TEXT NOT NULL,
        \\    status TEXT NOT NULL DEFAULT 'active',
        \\    cpu_cores INTEGER NOT NULL DEFAULT 0,
        \\    memory_mb INTEGER NOT NULL DEFAULT 0,
        \\    cpu_used INTEGER NOT NULL DEFAULT 0,
        \\    memory_used_mb INTEGER NOT NULL DEFAULT 0,
        \\    containers INTEGER NOT NULL DEFAULT 0,
        \\    last_heartbeat INTEGER NOT NULL,
        \\    registered_at INTEGER NOT NULL
        \\);
    , .{}, .{}) catch return;

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

    db.exec(
        \\CREATE TABLE agents (
        \\    id TEXT PRIMARY KEY,
        \\    address TEXT NOT NULL,
        \\    status TEXT NOT NULL DEFAULT 'active',
        \\    cpu_cores INTEGER NOT NULL DEFAULT 0,
        \\    memory_mb INTEGER NOT NULL DEFAULT 0,
        \\    cpu_used INTEGER NOT NULL DEFAULT 0,
        \\    memory_used_mb INTEGER NOT NULL DEFAULT 0,
        \\    containers INTEGER NOT NULL DEFAULT 0,
        \\    last_heartbeat INTEGER NOT NULL,
        \\    registered_at INTEGER NOT NULL
        \\);
    , .{}, .{}) catch return;

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
    db.exec(
        \\CREATE TABLE agents (
        \\    id TEXT PRIMARY KEY,
        \\    address TEXT NOT NULL,
        \\    status TEXT NOT NULL DEFAULT 'active',
        \\    cpu_cores INTEGER NOT NULL DEFAULT 0,
        \\    memory_mb INTEGER NOT NULL DEFAULT 0,
        \\    cpu_used INTEGER NOT NULL DEFAULT 0,
        \\    memory_used_mb INTEGER NOT NULL DEFAULT 0,
        \\    containers INTEGER NOT NULL DEFAULT 0,
        \\    last_heartbeat INTEGER NOT NULL,
        \\    registered_at INTEGER NOT NULL
        \\);
    , .{}, .{}) catch return;

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

    db.exec(
        \\CREATE TABLE agents (
        \\    id TEXT PRIMARY KEY,
        \\    address TEXT NOT NULL,
        \\    status TEXT NOT NULL DEFAULT 'active',
        \\    cpu_cores INTEGER NOT NULL DEFAULT 0,
        \\    memory_mb INTEGER NOT NULL DEFAULT 0,
        \\    cpu_used INTEGER NOT NULL DEFAULT 0,
        \\    memory_used_mb INTEGER NOT NULL DEFAULT 0,
        \\    containers INTEGER NOT NULL DEFAULT 0,
        \\    last_heartbeat INTEGER NOT NULL,
        \\    registered_at INTEGER NOT NULL
        \\);
    , .{}, .{}) catch return;

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

    db.exec(
        \\CREATE TABLE agents (
        \\    id TEXT PRIMARY KEY,
        \\    address TEXT NOT NULL,
        \\    status TEXT NOT NULL DEFAULT 'active',
        \\    cpu_cores INTEGER NOT NULL DEFAULT 0,
        \\    memory_mb INTEGER NOT NULL DEFAULT 0,
        \\    cpu_used INTEGER NOT NULL DEFAULT 0,
        \\    memory_used_mb INTEGER NOT NULL DEFAULT 0,
        \\    containers INTEGER NOT NULL DEFAULT 0,
        \\    last_heartbeat INTEGER NOT NULL,
        \\    registered_at INTEGER NOT NULL
        \\);
    , .{}, .{}) catch return;

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
