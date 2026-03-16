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

pub const RegisterOpts = struct {
    node_id: ?u16 = null,
    wg_public_key: ?[]const u8 = null,
    overlay_ip: ?[]const u8 = null,
    role: ?[]const u8 = null,
    region: ?[]const u8 = null,
    labels: ?[]const u8 = null,
};

/// generate SQL to register a new agent.
/// when opts.node_id/wg_public_key/overlay_ip are provided, the agent is
/// registered with wireguard networking support. otherwise falls back to base columns.
pub fn registerSql(
    buf: []u8,
    id: []const u8,
    address: []const u8,
    resources: AgentResources,
    now: i64,
) ![]const u8 {
    return registerSqlFull(buf, id, address, resources, now, .{});
}

/// generate SQL to register a new agent with optional wireguard and role fields.
pub fn registerSqlFull(
    buf: []u8,
    id: []const u8,
    address: []const u8,
    resources: AgentResources,
    now: i64,
    opts: RegisterOpts,
) ![]const u8 {
    const node_id = opts.node_id;
    const wg_public_key = opts.wg_public_key;
    const overlay_ip = opts.overlay_ip;
    const role = opts.role;
    const region = opts.region;
    const labels = opts.labels;
    // escape user-controlled values to prevent SQL injection.
    // committed SQL is replicated via raft to ALL nodes, so a single
    // injection would corrupt the entire cluster.
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);
    var addr_esc_buf: [512]u8 = undefined;
    const addr_esc = try sql_escape.escapeSqlString(&addr_esc_buf, address);

    var role_esc_buf: [32]u8 = undefined;
    const role_esc = try sql_escape.escapeSqlString(&role_esc_buf, role orelse "both");
    var region_esc_buf: [128]u8 = undefined;
    const region_val = region orelse "";
    var labels_esc_buf: [512]u8 = undefined;
    const labels_esc = try sql_escape.escapeSqlString(&labels_esc_buf, labels orelse "");

    // escape GPU model (user-controlled via agent registration)
    var model_esc_buf: [128]u8 = undefined;
    const model_esc = if (resources.gpu_model) |m|
        try sql_escape.escapeSqlString(&model_esc_buf, m)
    else
        "";
    const vram_mb: u64 = resources.gpu_vram_mb;

    // build the GPU suffix that's appended to all INSERT variants
    var gpu_cols_buf: [128]u8 = undefined;
    var gpu_vals_buf: [256]u8 = undefined;
    const gpu_cols = if (resources.gpu_model != null)
        try std.fmt.bufPrint(&gpu_cols_buf, ", gpu_count, gpu_used, gpu_model, gpu_vram_mb", .{})
    else
        try std.fmt.bufPrint(&gpu_cols_buf, ", gpu_count, gpu_used", .{});
    const gpu_vals = if (resources.gpu_model != null)
        try std.fmt.bufPrint(&gpu_vals_buf, ", {d}, {d}, '{s}', {d}", .{ resources.gpu_count, resources.gpu_used, model_esc, vram_mb })
    else
        try std.fmt.bufPrint(&gpu_vals_buf, ", {d}, {d}", .{ resources.gpu_count, resources.gpu_used });

    if (node_id) |nid| {
        var key_esc_buf: [128]u8 = undefined;
        const key_esc = try sql_escape.escapeSqlString(&key_esc_buf, wg_public_key orelse "");
        var ip_esc_buf: [64]u8 = undefined;
        const ip_esc = try sql_escape.escapeSqlString(&ip_esc_buf, overlay_ip orelse "");

        if (region_val.len > 0) {
            const reg_esc = try sql_escape.escapeSqlString(&region_esc_buf, region_val);
            return std.fmt.bufPrint(
                buf,
                "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, node_id, wg_public_key, overlay_ip, role, region, labels{s})" ++
                    " VALUES ('{s}', '{s}', 'active', {d}, {d}, 0, 0, 0, {d}, {d}, {d}, '{s}', '{s}', '{s}', '{s}', '{s}'{s});",
                .{ gpu_cols, id_esc, addr_esc, resources.cpu_cores, resources.memory_mb, now, now, nid, key_esc, ip_esc, role_esc, reg_esc, labels_esc, gpu_vals },
            );
        }
        return std.fmt.bufPrint(
            buf,
            "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, node_id, wg_public_key, overlay_ip, role, labels{s})" ++
                " VALUES ('{s}', '{s}', 'active', {d}, {d}, 0, 0, 0, {d}, {d}, {d}, '{s}', '{s}', '{s}', '{s}'{s});",
            .{ gpu_cols, id_esc, addr_esc, resources.cpu_cores, resources.memory_mb, now, now, nid, key_esc, ip_esc, role_esc, labels_esc, gpu_vals },
        );
    }

    if (region_val.len > 0) {
        const reg_esc = try sql_escape.escapeSqlString(&region_esc_buf, region_val);
        return std.fmt.bufPrint(
            buf,
            "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role, region, labels{s})" ++
                " VALUES ('{s}', '{s}', 'active', {d}, {d}, 0, 0, 0, {d}, {d}, '{s}', '{s}', '{s}'{s});",
            .{ gpu_cols, id_esc, addr_esc, resources.cpu_cores, resources.memory_mb, now, now, role_esc, reg_esc, labels_esc, gpu_vals },
        );
    }

    return std.fmt.bufPrint(
        buf,
        "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role, labels{s})" ++
            " VALUES ('{s}', '{s}', 'active', {d}, {d}, 0, 0, 0, {d}, {d}, '{s}', '{s}'{s});",
        .{ gpu_cols, id_esc, addr_esc, resources.cpu_cores, resources.memory_mb, now, now, role_esc, labels_esc, gpu_vals },
    );
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

    const health_raw = resources.gpu_health.slice();
    var health_esc_buf: [64]u8 = undefined;
    const health_esc = if (health_raw.len > 0)
        try sql_escape.escapeSqlString(&health_esc_buf, health_raw)
    else
        "healthy";

    return std.fmt.bufPrint(buf,
        \\UPDATE agents SET cpu_used = {d}, memory_used_mb = {d}, containers = {d}, gpu_used = {d}, gpu_health = '{s}', last_heartbeat = {d},
        \\ status = CASE WHEN status = 'offline' THEN 'active' ELSE status END
        \\ WHERE id = '{s}';
    , .{ resources.cpu_used, resources.memory_used_mb, resources.containers, resources.gpu_used, health_esc, now, id_esc });
}

/// generate SQL to mark an agent as draining.
pub fn drainSql(buf: []u8, id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);

    return std.fmt.bufPrint(
        buf,
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

    return std.fmt.bufPrint(
        buf,
        "UPDATE assignments SET status = '{s}' WHERE id = '{s}';",
        .{ status_esc, id_esc },
    );
}

/// generate SQL to mark an agent as offline.
pub fn markOfflineSql(buf: []u8, id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);

    return std.fmt.bufPrint(
        buf,
        "UPDATE agents SET status = 'offline' WHERE id = '{s}';",
        .{id_esc},
    );
}

/// generate SQL to mark an offline agent as active (used by gossip member_alive).
pub fn markActiveSql(buf: []u8, id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);

    return std.fmt.bufPrint(
        buf,
        "UPDATE agents SET status = 'active' WHERE id = '{s}' AND status = 'offline';",
        .{id_esc},
    );
}

/// generate SQL to update an agent's labels.
pub fn updateLabelsSql(buf: []u8, id: []const u8, labels: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);
    var labels_esc_buf: [512]u8 = undefined;
    const labels_esc = try sql_escape.escapeSqlString(&labels_esc_buf, labels);
    return std.fmt.bufPrint(buf, "UPDATE agents SET labels = '{s}' WHERE id = '{s}';", .{ labels_esc, id_esc });
}

/// find an agent's string ID by its numeric node_id.
/// returns null if no agent has that node_id.
pub fn findAgentIdByNodeId(alloc: Allocator, db: *sqlite.Db, node_id: u64) ?[]const u8 {
    const Row = struct { id: sqlite.Text };

    var stmt = db.prepare(
        "SELECT id FROM agents WHERE node_id = ? LIMIT 1;",
    ) catch return null;
    defer stmt.deinit();

    var iter = stmt.iterator(Row, .{@as(i64, @intCast(node_id))}) catch return null;

    if (iter.nextAlloc(alloc, .{}) catch null) |row| {
        return row.id.data;
    }
    return null;
}

/// generate SQL to remove an agent.
pub fn removeSql(buf: []u8, id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);

    return std.fmt.bufPrint(
        buf,
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

    return std.fmt.bufPrint(
        buf,
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

    return std.fmt.bufPrint(
        buf,
        "UPDATE assignments SET agent_id = '{s}' WHERE id = '{s}' AND agent_id = '';",
        .{ agent_esc, id_esc },
    );
}

/// generate SQL to delete all assignments for an agent.
/// used during dead agent cleanup to remove terminal assignments.
pub fn deleteAgentAssignmentsSql(buf: []u8, agent_id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, agent_id);

    return std.fmt.bufPrint(
        buf,
        "DELETE FROM assignments WHERE agent_id = '{s}';",
        .{id_esc},
    );
}

// -- node_id assignment --

pub const NodeIdError = error{
    /// all 254 node IDs (1-254) are already assigned to existing agents
    NoAvailableNodeId,
    /// failed to query the agents table for existing node_id values
    QueryFailed,
};

/// find the lowest available node_id (1-254) by checking which IDs
/// are already in use. gaps left by removed agents are reused.
pub fn assignNodeId(db: *sqlite.Db) NodeIdError!u16 {
    const Row = struct { node_id: i64 };

    var stmt = db.prepare(
        "SELECT node_id FROM agents WHERE node_id IS NOT NULL ORDER BY node_id;",
    ) catch return NodeIdError.QueryFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(Row, .{}) catch return NodeIdError.QueryFailed;

    // walk through assigned IDs looking for a gap
    var next_id: u16 = 1;
    while (iter.next(.{}) catch null) |row| {
        const used: u16 = if (row.node_id >= 1 and row.node_id <= 65534)
            @intCast(row.node_id)
        else
            continue;

        if (next_id < used) {
            // found a gap — use it
            return next_id;
        }
        next_id = used +| 1; // saturating add to avoid overflow at 65535
    }

    if (next_id <= 65534) return next_id;
    return NodeIdError.NoAvailableNodeId;
}

// -- gossip seeds --

/// return up to `count` active agent seeds as "node_id@address" strings.
/// seeds are agents with role 'agent' or 'both' that are currently active
/// and have a node_id assigned. the caller should include these in
/// registration responses so new agents can bootstrap gossip membership.
pub fn getGossipSeeds(
    alloc: Allocator,
    db: *sqlite.Db,
    count: u32,
) ![][]const u8 {
    const Row = struct { node_id: i64, address: sqlite.Text };

    var stmt = db.prepare(
        "SELECT node_id, address FROM agents WHERE status = 'active' AND node_id IS NOT NULL AND (role = 'agent' OR role = 'both' OR role IS NULL) LIMIT ?;",
    ) catch return &[_][]const u8{};
    defer stmt.deinit();

    var results: std.ArrayListUnmanaged([]const u8) = .{};
    errdefer {
        for (results.items) |s| alloc.free(s);
        results.deinit(alloc);
    }

    const limit: i64 = @max(@as(i64, 0), @as(i64, @intCast(count)));
    var iter = stmt.iterator(Row, .{limit}) catch return &[_][]const u8{};

    while (iter.nextAlloc(alloc, .{}) catch null) |row| {
        defer alloc.free(row.address.data);
        // format as "node_id@address" so agents know the gossip member ID
        var buf: [256]u8 = undefined;
        const seed_str = std.fmt.bufPrint(&buf, "{d}@{s}", .{ row.node_id, row.address.data }) catch continue;
        const dupe = alloc.dupe(u8, seed_str) catch continue;
        results.append(alloc, dupe) catch {
            alloc.free(dupe);
            continue;
        };
    }

    return results.toOwnedSlice(alloc) catch return &[_][]const u8{};
}

/// free gossip seeds returned by getGossipSeeds.
pub fn freeGossipSeeds(alloc: Allocator, seeds: [][]const u8) void {
    for (seeds) |s| alloc.free(s);
    alloc.free(seeds);
}

// -- wireguard peer SQL --

/// generate SQL to insert a wireguard peer record.
pub fn wireguardPeerSql(
    buf: []u8,
    node_id: u16,
    agent_id: []const u8,
    public_key: []const u8,
    endpoint: []const u8,
    overlay_ip: []const u8,
    container_subnet: []const u8,
) ![]const u8 {
    var agent_esc_buf: [64]u8 = undefined;
    const agent_esc = try sql_escape.escapeSqlString(&agent_esc_buf, agent_id);
    var key_esc_buf: [128]u8 = undefined;
    const key_esc = try sql_escape.escapeSqlString(&key_esc_buf, public_key);
    var ep_esc_buf: [128]u8 = undefined;
    const ep_esc = try sql_escape.escapeSqlString(&ep_esc_buf, endpoint);
    var ip_esc_buf: [64]u8 = undefined;
    const ip_esc = try sql_escape.escapeSqlString(&ip_esc_buf, overlay_ip);
    var subnet_esc_buf: [64]u8 = undefined;
    const subnet_esc = try sql_escape.escapeSqlString(&subnet_esc_buf, container_subnet);

    return std.fmt.bufPrint(buf,
        \\INSERT INTO wireguard_peers (node_id, agent_id, public_key, endpoint, overlay_ip, container_subnet)
        \\ VALUES ({d}, '{s}', '{s}', '{s}', '{s}', '{s}');
    , .{ node_id, agent_esc, key_esc, ep_esc, ip_esc, subnet_esc });
}

/// generate SQL to remove a wireguard peer by node_id.
pub fn removeWireguardPeerSql(buf: []u8, node_id: u16) ![]const u8 {
    return std.fmt.bufPrint(
        buf,
        "DELETE FROM wireguard_peers WHERE node_id = {d};",
        .{node_id},
    );
}

/// a wireguard peer record as stored in the database.
pub const WireguardPeer = struct {
    node_id: i64,
    agent_id: []const u8,
    public_key: []const u8,
    endpoint: []const u8,
    overlay_ip: []const u8,
    container_subnet: []const u8,

    pub fn deinit(self: WireguardPeer, alloc: Allocator) void {
        alloc.free(self.agent_id);
        alloc.free(self.public_key);
        alloc.free(self.endpoint);
        alloc.free(self.overlay_ip);
        alloc.free(self.container_subnet);
    }
};

/// list all wireguard peers from the database.
pub fn listWireguardPeers(alloc: Allocator, db: *sqlite.Db) ![]WireguardPeer {
    return queryWireguardPeers(
        alloc,
        db,
        "SELECT node_id, agent_id, public_key, endpoint, overlay_ip, container_subnet FROM wireguard_peers ORDER BY node_id;",
    );
}

/// list wireguard peers that are servers (role=server or role=both).
/// agents with role=agent use this to connect only to hub nodes,
/// enabling hub-and-spoke topology for large clusters.
pub fn listWireguardServerPeers(alloc: Allocator, db: *sqlite.Db) ![]WireguardPeer {
    return queryWireguardPeers(alloc, db,
        \\SELECT wp.node_id, wp.agent_id, wp.public_key, wp.endpoint, wp.overlay_ip, wp.container_subnet
        \\FROM wireguard_peers wp
        \\JOIN agents a ON wp.agent_id = a.id
        \\WHERE a.role IN ('server', 'both') OR a.role IS NULL
        \\ORDER BY wp.node_id;
    );
}

fn queryWireguardPeers(alloc: Allocator, db: *sqlite.Db, sql: []const u8) ![]WireguardPeer {
    const Row = struct {
        node_id: i64,
        agent_id: sqlite.Text,
        public_key: sqlite.Text,
        endpoint: sqlite.Text,
        overlay_ip: sqlite.Text,
        container_subnet: sqlite.Text,
    };

    var stmt = db.prepareDynamic(sql) catch return error.QueryFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(Row, .{}) catch return error.QueryFailed;

    var results: std.ArrayListUnmanaged(WireguardPeer) = .empty;
    errdefer {
        for (results.items) |p| p.deinit(alloc);
        results.deinit(alloc);
    }

    while (iter.nextAlloc(alloc, .{}) catch null) |row| {
        try results.append(alloc, .{
            .node_id = row.node_id,
            .agent_id = row.agent_id.data,
            .public_key = row.public_key.data,
            .endpoint = row.endpoint.data,
            .overlay_ip = row.overlay_ip.data,
            .container_subnet = row.container_subnet.data,
        });
    }

    return results.toOwnedSlice(alloc);
}

// -- DB queries --
// read directly from the state machine database (leader only).

const AgentRow = struct {
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
    node_id: ?i64,
    wg_public_key: ?sqlite.Text,
    overlay_ip: ?sqlite.Text,
    role: ?sqlite.Text,
    region: ?sqlite.Text,
    labels: ?sqlite.Text,
    gpu_count: i64,
    gpu_used: i64,
    gpu_model: ?sqlite.Text,
    gpu_vram_mb: ?i64,
    rdma_capable: ?i64,
};

const agent_select_cols = "id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, node_id, wg_public_key, overlay_ip, role, region, labels, gpu_count, gpu_used, gpu_model, gpu_vram_mb, rdma_capable";

fn agentRowToRecord(row: AgentRow) AgentRecord {
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
        .node_id = row.node_id,
        .wg_public_key = if (row.wg_public_key) |k| k.data else null,
        .overlay_ip = if (row.overlay_ip) |o| o.data else null,
        .role = if (row.role) |r| r.data else null,
        .region = if (row.region) |r| r.data else null,
        .labels = if (row.labels) |l| l.data else null,
        .gpu_count = row.gpu_count,
        .gpu_used = row.gpu_used,
        .gpu_model = if (row.gpu_model) |m| m.data else null,
        .gpu_vram_mb = row.gpu_vram_mb,
        .rdma_capable = if (row.rdma_capable) |r| r != 0 else false,
    };
}

/// list all registered agents.
pub fn listAgents(alloc: Allocator, db: *sqlite.Db) ![]AgentRecord {
    var stmt = db.prepare(
        "SELECT " ++ agent_select_cols ++ " FROM agents ORDER BY registered_at;",
    ) catch return error.QueryFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(AgentRow, .{}) catch return error.QueryFailed;

    var results: std.ArrayListUnmanaged(AgentRecord) = .empty;
    errdefer {
        for (results.items) |r| r.deinit(alloc);
        results.deinit(alloc);
    }

    while (iter.nextAlloc(alloc, .{}) catch null) |row| {
        try results.append(alloc, agentRowToRecord(row));
    }

    return results.toOwnedSlice(alloc);
}

/// get a single agent by ID.
pub fn getAgent(alloc: Allocator, db: *sqlite.Db, id: []const u8) !?AgentRecord {
    const row = (db.oneAlloc(
        AgentRow,
        alloc,
        "SELECT " ++ agent_select_cols ++ " FROM agents WHERE id = ?;",
        .{},
        .{id},
    ) catch return error.QueryFailed) orelse return null;

    return agentRowToRecord(row);
}

/// get all assignments for a specific agent.
pub fn getAssignments(alloc: Allocator, db: *sqlite.Db, agent_id: []const u8) ![]Assignment {
    return queryAssignmentRows(
        alloc,
        db,
        "SELECT id, agent_id, image, command, status, cpu_limit, memory_limit_mb, gang_rank, gang_world_size, gang_master_addr, gang_master_port FROM assignments WHERE agent_id = ?;",
        .{agent_id},
    );
}

/// get orphaned assignments (agent_id = '', status = 'pending').
/// these are assignments that were detached from an offline agent
/// and are waiting to be rescheduled.
pub fn getOrphanedAssignments(alloc: Allocator, db: *sqlite.Db) ![]Assignment {
    return queryAssignmentRows(
        alloc,
        db,
        "SELECT id, agent_id, image, command, status, cpu_limit, memory_limit_mb, gang_rank, gang_world_size, gang_master_addr, gang_master_port FROM assignments WHERE agent_id = '' AND status = 'pending';",
        .{},
    );
}

const AssignmentRow = struct {
    id: sqlite.Text,
    agent_id: sqlite.Text,
    image: sqlite.Text,
    command: sqlite.Text,
    status: sqlite.Text,
    cpu_limit: i64,
    memory_limit_mb: i64,
    gang_rank: ?i64,
    gang_world_size: ?i64,
    gang_master_addr: ?sqlite.Text,
    gang_master_port: ?i64,
};

fn queryAssignmentRows(alloc: Allocator, db: *sqlite.Db, comptime query: []const u8, args: anytype) ![]Assignment {
    var stmt = db.prepare(query) catch return error.QueryFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(AssignmentRow, args) catch return error.QueryFailed;

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
            .gang_rank = row.gang_rank,
            .gang_world_size = row.gang_world_size,
            .gang_master_addr = if (row.gang_master_addr) |a| a.data else null,
            .gang_master_port = row.gang_master_port,
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

const test_agents_schema =
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
    \\    registered_at INTEGER NOT NULL,
    \\    node_id INTEGER,
    \\    wg_public_key TEXT,
    \\    overlay_ip TEXT,
    \\    role TEXT DEFAULT 'both',
    \\    region TEXT,
    \\    labels TEXT DEFAULT '',
    \\    gpu_count INTEGER DEFAULT 0,
    \\    gpu_used INTEGER DEFAULT 0,
    \\    gpu_model TEXT,
    \\    gpu_vram_mb INTEGER,
    \\    rdma_capable INTEGER DEFAULT 0
    \\);
;

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

    db.exec(test_agents_schema, .{}, .{}) catch return;

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

    db.exec(test_agents_schema, .{}, .{}) catch return;

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
    db.exec(test_agents_schema, .{}, .{}) catch return;

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

    db.exec(test_agents_schema, .{}, .{}) catch return;

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

    db.exec(test_agents_schema, .{}, .{}) catch return;

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

test "assignNodeId returns 1 for empty table" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(test_agents_schema, .{}, .{}) catch return;

    const nid = try assignNodeId(&db);
    try std.testing.expectEqual(@as(u8, 1), nid);
}

test "assignNodeId fills gaps" {
    var db = sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{ .write = true },
    }) catch return;
    defer db.deinit();

    db.exec(test_agents_schema, .{}, .{}) catch return;

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

    db.exec(test_agents_schema, .{}, .{}) catch return;

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

    db.exec(test_agents_schema, .{}, .{}) catch return;
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

    db.exec(test_agents_schema, .{}, .{}) catch return;

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

    db.exec(test_agents_schema, .{}, .{}) catch return;

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

    db.exec(test_agents_schema, .{}, .{}) catch return;

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
