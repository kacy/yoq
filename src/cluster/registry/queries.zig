const std = @import("std");
const sqlite = @import("sqlite");
const agent_types = @import("../agent_types.zig");

const Allocator = std.mem.Allocator;
pub const AgentRecord = agent_types.AgentRecord;
pub const Assignment = agent_types.Assignment;

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

pub fn listWireguardPeers(alloc: Allocator, db: *sqlite.Db) ![]WireguardPeer {
    return queryWireguardPeers(
        alloc,
        db,
        "SELECT node_id, agent_id, public_key, endpoint, overlay_ip, container_subnet FROM wireguard_peers ORDER BY node_id;",
    );
}

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
        for (results.items) |peer| peer.deinit(alloc);
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

const AgentRow = struct {
    id: sqlite.Text,
    address: sqlite.Text,
    agent_api_port: ?i64,
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

const agent_select_cols = "id, address, agent_api_port, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, node_id, wg_public_key, overlay_ip, role, region, labels, gpu_count, gpu_used, gpu_model, gpu_vram_mb, rdma_capable";

fn agentRowToRecord(row: AgentRow) AgentRecord {
    return .{
        .id = row.id.data,
        .address = row.address.data,
        .agent_api_port = row.agent_api_port,
        .status = row.status.data,
        .cpu_cores = row.cpu_cores,
        .memory_mb = row.memory_mb,
        .cpu_used = row.cpu_used,
        .memory_used_mb = row.memory_used_mb,
        .containers = row.containers,
        .last_heartbeat = row.last_heartbeat,
        .registered_at = row.registered_at,
        .node_id = row.node_id,
        .wg_public_key = if (row.wg_public_key) |key| key.data else null,
        .overlay_ip = if (row.overlay_ip) |overlay| overlay.data else null,
        .role = if (row.role) |role| role.data else null,
        .region = if (row.region) |region| region.data else null,
        .labels = if (row.labels) |labels| labels.data else null,
        .gpu_count = row.gpu_count,
        .gpu_used = row.gpu_used,
        .gpu_model = if (row.gpu_model) |model| model.data else null,
        .gpu_vram_mb = row.gpu_vram_mb,
        .rdma_capable = if (row.rdma_capable) |rdma| rdma != 0 else false,
    };
}

pub fn listAgents(alloc: Allocator, db: *sqlite.Db) ![]AgentRecord {
    var stmt = db.prepare("SELECT " ++ agent_select_cols ++ " FROM agents ORDER BY registered_at;") catch return error.QueryFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(AgentRow, .{}) catch return error.QueryFailed;
    var results: std.ArrayListUnmanaged(AgentRecord) = .empty;
    errdefer {
        for (results.items) |record| record.deinit(alloc);
        results.deinit(alloc);
    }

    while (iter.nextAlloc(alloc, .{}) catch null) |row| {
        try results.append(alloc, agentRowToRecord(row));
    }

    return results.toOwnedSlice(alloc);
}

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

pub fn getAssignments(alloc: Allocator, db: *sqlite.Db, agent_id: []const u8) ![]Assignment {
    return queryAssignmentRows(
        alloc,
        db,
        "SELECT id, agent_id, image, command, status, cpu_limit, memory_limit_mb, app_name, workload_kind, workload_name, health_check_json, gang_rank, gang_world_size, gang_master_addr, gang_master_port FROM assignments WHERE agent_id = ?;",
        .{agent_id},
    );
}

pub fn getOrphanedAssignments(alloc: Allocator, db: *sqlite.Db) ![]Assignment {
    return queryAssignmentRows(
        alloc,
        db,
        "SELECT id, agent_id, image, command, status, cpu_limit, memory_limit_mb, app_name, workload_kind, workload_name, health_check_json, gang_rank, gang_world_size, gang_master_addr, gang_master_port FROM assignments WHERE agent_id = '' AND status = 'pending';",
        .{},
    );
}

pub fn listAssignmentsForWorkload(
    alloc: Allocator,
    db: *sqlite.Db,
    app_name: []const u8,
    workload_kind: []const u8,
    workload_name: []const u8,
) ![]Assignment {
    return queryAssignmentRows(
        alloc,
        db,
        "SELECT id, agent_id, image, command, status, cpu_limit, memory_limit_mb, app_name, workload_kind, workload_name, health_check_json, gang_rank, gang_world_size, gang_master_addr, gang_master_port FROM assignments WHERE app_name = ? AND workload_kind = ? AND workload_name = ? ORDER BY created_at, id;",
        .{ app_name, workload_kind, workload_name },
    );
}

pub fn countAssignmentsForWorkload(db: *sqlite.Db, app_name: []const u8, workload_kind: []const u8, workload_name: []const u8) !usize {
    const Row = struct { count: i64 };
    const row = (db.one(
        Row,
        "SELECT COUNT(*) AS count FROM assignments WHERE app_name = ? AND workload_kind = ? AND workload_name = ?;",
        .{},
        .{ app_name, workload_kind, workload_name },
    ) catch return error.QueryFailed) orelse return 0;
    return @intCast(row.count);
}

pub const WorkloadHost = struct {
    agent_id: []const u8,
    address: []const u8,
    agent_api_port: ?i64,

    pub fn deinit(self: WorkloadHost, alloc: Allocator) void {
        alloc.free(self.agent_id);
        alloc.free(self.address);
    }
};

pub fn findWorkloadHostByRank(
    alloc: Allocator,
    db: *sqlite.Db,
    app_name: []const u8,
    workload_kind: []const u8,
    workload_name: []const u8,
    rank: u32,
) !?WorkloadHost {
    const Row = struct {
        agent_id: sqlite.Text,
        address: sqlite.Text,
        agent_api_port: ?i64,
    };
    const row = (db.oneAlloc(
        Row,
        alloc,
        \\SELECT agents.id AS agent_id, agents.address, agents.agent_api_port
        \\FROM assignments
        \\JOIN agents ON assignments.agent_id = agents.id
        \\WHERE assignments.app_name = ?
        \\  AND assignments.workload_kind = ?
        \\  AND assignments.workload_name = ?
        \\  AND COALESCE(assignments.gang_rank, 0) = ?
        \\ORDER BY assignments.created_at DESC, assignments.id DESC
        \\LIMIT 1;
        ,
        .{},
        .{ app_name, workload_kind, workload_name, @as(i64, rank) },
    ) catch return error.QueryFailed) orelse return null;
    return .{
        .agent_id = row.agent_id.data,
        .address = row.address.data,
        .agent_api_port = row.agent_api_port,
    };
}

const AssignmentRow = struct {
    id: sqlite.Text,
    agent_id: sqlite.Text,
    image: sqlite.Text,
    command: sqlite.Text,
    status: sqlite.Text,
    cpu_limit: i64,
    memory_limit_mb: i64,
    app_name: ?sqlite.Text,
    workload_kind: ?sqlite.Text,
    workload_name: ?sqlite.Text,
    health_check_json: ?sqlite.Text,
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
        for (results.items) |assignment| assignment.deinit(alloc);
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
            .app_name = if (row.app_name) |app_name| app_name.data else null,
            .workload_kind = if (row.workload_kind) |workload_kind| workload_kind.data else null,
            .workload_name = if (row.workload_name) |workload_name| workload_name.data else null,
            .health_check_json = if (row.health_check_json) |health_check_json| health_check_json.data else null,
            .gang_rank = row.gang_rank,
            .gang_world_size = row.gang_world_size,
            .gang_master_addr = if (row.gang_master_addr) |addr| addr.data else null,
            .gang_master_port = row.gang_master_port,
        });
    }

    return results.toOwnedSlice(alloc);
}
