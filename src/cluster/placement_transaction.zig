// placement holds a lease until its assignment batch commits.
// a new leader commits a barrier before reading capacity, so inherited
// assignments count toward the next placement decision.
const std = @import("std");
const sqlite = @import("sqlite");
const registry = @import("registry.zig");
const scheduler = @import("scheduler.zig");
const mutation = @import("mutation_session.zig");
const sql = @import("sql_command.zig");
const capacity = @import("placement_capacity.zig");

pub const Resources = capacity.Resources;
pub const isTerminal = capacity.isTerminal;

pub const max_gang_ranks = 4096;
const max_batch_bytes = 1024 * 1024;

var placement_mu: std.Io.Mutex = .init;

pub const schema_sql = @import("../state/schema.zig").assignment_claims_create_table_sql;
pub const cleanup_sql = "DELETE FROM assignment_claims WHERE assignment_id NOT IN (SELECT id FROM assignments);";

pub const Lease = struct {
    session: mutation.Session,

    pub fn begin(session: mutation.Session) mutation.Error!Lease {
        placement_mu.lockUncancelable(std.Options.debug_io);
        errdefer placement_mu.unlock(std.Options.debug_io);
        // committing the schema also establishes the current-term read barrier
        // and upgrades snapshots that predate durable gpu claims.
        try session.commit(schema_sql);
        return .{ .session = session };
    }

    pub fn deinit(_: Lease) void {
        placement_mu.unlock(std.Options.debug_io);
    }

    pub fn agents(self: Lease, alloc: std.mem.Allocator, excluded_ids: []const []const u8) !AgentSnapshot {
        const node = self.session.node;
        node.mu.lockUncancelable(std.Options.debug_io);
        defer node.mu.unlock(std.Options.debug_io);
        try self.session.checkLocked();
        const records = try registry.listAgents(alloc, node.stateMachineDb());
        errdefer freeAgents(alloc, records);
        for (records) |*agent| {
            try capacity.includeClaims(alloc, node.stateMachineDb(), agent, excluded_ids);
        }
        return .{ .records = records, .index = node.state_machine.last_applied };
    }

    pub fn commit(self: Lease, command: []const u8) mutation.Error!void {
        if (command.len > max_batch_bytes) return error.Conflict;
        try self.session.commit(command);
    }
};

pub fn freeAgents(alloc: std.mem.Allocator, agents: []registry.AgentRecord) void {
    for (agents) |agent| agent.deinit(alloc);
    alloc.free(agents);
}

pub const AgentSnapshot = struct {
    records: []registry.AgentRecord,
    index: u64,

    pub fn deinit(self: AgentSnapshot, alloc: std.mem.Allocator) void {
        freeAgents(alloc, self.records);
    }
};

pub fn appendClaim(writer: *std.Io.Writer, assignment_id: []const u8, claim: Claim) !void {
    if (claim.gpu_count < 0) return error.InvalidClaim;
    try sql.write(writer, "INSERT OR REPLACE INTO assignment_claims (assignment_id, gpu_count, release_id, group_id, request_json) VALUES (?, ?, ?, ?, ?);", .{ assignment_id, claim.gpu_count, claim.release_id, claim.group_id, claim.request_json });
}

/// reject stale capacity decisions through the agent_id not-null constraint.
/// the state index is checked when the assignment batch is applied.
pub fn appendAssignment(writer: *std.Io.Writer, id: []const u8, agent_id: []const u8, request: scheduler.PlacementRequest, gang: ?@import("../gpu/scheduler.zig").GangPlacement, index: u64, now: i64) !void {
    try sql.write(writer, "INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, " ++
        "app_name, workload_kind, workload_name, health_check_json, " ++
        "gang_rank, gang_world_size, gang_master_addr, gang_master_port, created_at) " ++
        "VALUES (?, CASE WHEN (SELECT last_applied FROM state_machine_meta WHERE id = 1) = ? " ++
        "THEN ? ELSE NULL END, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", .{
        id,
        index,
        agent_id,
        request.image,
        request.command,
        request.cpu_limit,
        request.memory_limit_mb,
        request.app_name,
        request.workload_kind,
        request.workload_name,
        request.health_check_json,
        @as(?u32, if (gang) |g| g.rank else null),
        @as(?u32, if (gang) |g| g.world_size else null),
        @as(?[]const u8, if (gang) |g| g.master_addr else null),
        @as(?u16, if (gang) |g| g.master_port else null),
        now,
    });
}

pub const Placement = struct {
    assignment_ids: [][]const u8,

    pub fn deinit(self: Placement, alloc: std.mem.Allocator) void {
        for (self.assignment_ids) |id| alloc.free(id);
        alloc.free(self.assignment_ids);
    }
};

pub fn place(alloc: std.mem.Allocator, session: mutation.Session, request: scheduler.PlacementRequest, release_id: ?[]const u8) mutation.Error!?Placement {
    return placeReplicas(alloc, session, request, release_id, 1);
}

/// reserve every replica together; a failed placement leaves the prior release intact.
pub fn placeReplicas(alloc: std.mem.Allocator, session: mutation.Session, request: scheduler.PlacementRequest, release_id: ?[]const u8, replicas: u32) mutation.Error!?Placement {
    return placeWithMetadata(alloc, session, request, release_id, null, replicas);
}

/// Replace one workload only when its complete new placement fits. Assignment
/// deletion, new claims and caller metadata are applied or rejected together.
pub fn replaceWorkload(alloc: std.mem.Allocator, session: mutation.Session, request: scheduler.PlacementRequest, metadata_sql: []const u8) mutation.Error!?Placement {
    const app_name = request.app_name orelse return error.Conflict;
    const workload_kind = request.workload_kind orelse return error.Conflict;
    const workload_name = request.workload_name orelse return error.Conflict;
    if (app_name.len == 0 or workload_kind.len == 0 or workload_name.len == 0) return error.Conflict;
    return placeWithMetadata(alloc, session, request, null, metadata_sql, 1);
}

fn placeWithMetadata(alloc: std.mem.Allocator, session: mutation.Session, request: scheduler.PlacementRequest, release_id: ?[]const u8, metadata_sql: ?[]const u8, replicas: u32) mutation.Error!?Placement {
    // bound the full replica group before allocating or building sql.
    if (replicas == 0 or replicas > @import("../manifest/spec.zig").max_service_replicas or @as(u64, replicas) * @max(@as(u64, 1), request.gang_world_size) > max_gang_ranks) return error.Conflict;
    if (request.cpu_limit <= 0 or request.memory_limit_mb <= 0 or request.gpu_limit < 0 or request.gang_world_size > max_gang_ranks) return error.Conflict;
    if (std.mem.eql(u8, request.workload_kind orelse "", "service") and @as(u64, replicas) * @max(@as(u64, 1), request.gang_world_size) > @import("../manifest/spec.zig").max_service_replicas) return error.Conflict;
    for (0..3) |_| {
        return placeOnce(alloc, session, request, release_id, metadata_sql, replicas) catch |err| {
            if (err == error.Conflict) continue;
            return err;
        };
    }
    return error.Conflict;
}

fn placeOnce(alloc: std.mem.Allocator, session: mutation.Session, request: scheduler.PlacementRequest, release_id: ?[]const u8, metadata_sql: ?[]const u8, replicas: u32) mutation.Error!?Placement {
    const lease = try Lease.begin(session);
    defer lease.deinit();
    if (!try serviceNameAvailableInLease(lease, request)) return null;
    if (release_id) |id| {
        if (try resumePlacement(alloc, lease, request, id, replicas)) |existing| return existing;
    }
    if (metadata_sql == null and !try serviceSurgeFits(lease, request, replicas)) return null;
    const prior = if (metadata_sql != null) try workloadIds(alloc, session, request) else Placement{ .assignment_ids = &.{} };
    defer prior.deinit(alloc);
    const agents = lease.agents(alloc, prior.assignment_ids) catch return error.InternalError;
    defer agents.deinit(alloc);
    var batch = std.Io.Writer.Allocating.init(alloc);
    defer batch.deinit();
    if (metadata_sql) |metadata| {
        sql.write(&batch.writer, "DELETE FROM assignments WHERE app_name = ? AND workload_kind = ? AND workload_name = ?;", .{ request.app_name, request.workload_kind, request.workload_name }) catch return error.InternalError;
        batch.writer.writeAll(cleanup_sql) catch return error.InternalError;
        batch.writer.writeAll(metadata) catch return error.InternalError;
    }
    var ids: std.ArrayList([]const u8) = .empty;
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }
    const request_json = std.json.Stringify.valueAlloc(alloc, request, .{}) catch return error.InternalError;
    defer alloc.free(request_json);
    const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
    var gang_ports: std.ArrayList(u16) = .empty;
    defer gang_ports.deinit(alloc);
    for (0..replicas) |_| {
        const first_rank = ids.items.len;
        if (request.gang_world_size > 0) {
            const placements = (scheduler.scheduleGang(alloc, request, agents.records) catch return error.InternalError) orelse return null;
            defer alloc.free(placements);
            const port = try reserveGangPort(session, request.gang_master_port, gang_ports.items);
            gang_ports.append(alloc, port) catch return error.InternalError;
            for (placements) |*rank| rank.master_port = port;
            for (placements) |placement| {
                const id = try newId(alloc);
                ids.append(alloc, id) catch {
                    alloc.free(id);
                    return error.InternalError;
                };
                appendAssignment(&batch.writer, id, placement.agent_id, request, placement, agents.index, now) catch return error.InternalError;
                appendClaim(&batch.writer, id, .{ .gpu_count = placement.gpu_count, .release_id = release_id, .group_id = ids.items[first_rank], .request_json = request_json }) catch return error.InternalError;
                try consume(agents.records, placement.agent_id, .{ .cpu = request.cpu_limit, .memory = request.memory_limit_mb, .gpu = placement.gpu_count });
                if (batch.written().len > max_batch_bytes) return error.Conflict;
            }
        } else {
            const choices = scheduler.schedule(alloc, &.{request}, agents.records) catch return error.InternalError;
            defer alloc.free(choices);
            const choice = choices[0] orelse return null;
            const id = try newId(alloc);
            ids.append(alloc, id) catch {
                alloc.free(id);
                return error.InternalError;
            };
            appendAssignment(&batch.writer, id, choice.agent_id, request, null, agents.index, now) catch return error.InternalError;
            appendClaim(&batch.writer, id, .{ .gpu_count = request.gpu_limit, .release_id = release_id, .group_id = id, .request_json = request_json }) catch return error.InternalError;
            try consume(agents.records, choice.agent_id, .{ .cpu = request.cpu_limit, .memory = request.memory_limit_mb, .gpu = request.gpu_limit });
            if (batch.written().len > max_batch_bytes) return error.Conflict;
        }
    }
    // Reserve memory for the returned IDs before committing. An allocation
    // failure must not strand a successful placement without its owner.
    const owned = ids.toOwnedSlice(alloc) catch return error.InternalError;
    errdefer {
        for (owned) |id| alloc.free(id);
        alloc.free(owned);
    }
    try lease.commit(batch.written());
    return .{ .assignment_ids = owned };
}

pub fn serviceNameAvailable(session: mutation.Session, request: scheduler.PlacementRequest) mutation.Error!bool {
    const lease = try Lease.begin(session);
    defer lease.deinit();
    return serviceNameAvailableInLease(lease, request);
}

fn serviceNameAvailableInLease(lease: Lease, request: scheduler.PlacementRequest) mutation.Error!bool {
    if (!std.mem.eql(u8, request.workload_kind orelse "", "service")) return true;
    const name = request.workload_name orelse return true;
    const node = lease.session.node;
    node.mu.lockUncancelable(std.Options.debug_io);
    defer node.mu.unlock(std.Options.debug_io);
    try lease.session.checkLocked();
    const row = node.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignments WHERE workload_kind = 'service' AND workload_name = ? AND coalesce(app_name, '') != ? AND status IN ('pending', 'running');", .{}, .{ name, request.app_name orelse "" }) catch return error.InternalError;
    return row.?.count == 0;
}

pub fn replicaSurgeFits(session: mutation.Session, request: scheduler.PlacementRequest, replicas: u32) mutation.Error!bool {
    const lease = try Lease.begin(session);
    defer lease.deinit();
    return serviceSurgeFits(lease, request, replicas);
}

fn serviceSurgeFits(lease: Lease, request: scheduler.PlacementRequest, replicas: u32) mutation.Error!bool {
    if (!std.mem.eql(u8, request.workload_kind orelse "", "service")) return true;
    const app_name = request.app_name orelse return true;
    const workload_name = request.workload_name orelse return true;
    const node = lease.session.node;
    node.mu.lockUncancelable(std.Options.debug_io);
    defer node.mu.unlock(std.Options.debug_io);
    try lease.session.checkLocked();
    const row = node.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignments WHERE app_name = ? AND workload_kind = 'service' AND workload_name = ?;", .{}, .{ app_name, workload_name }) catch return error.InternalError;
    const prior: u64 = @intCast(@max(0, row.?.count));
    const desired = @as(u64, replicas) * @max(@as(u64, 1), request.gang_world_size);
    return prior +| desired <= @import("../manifest/spec.zig").max_service_replicas;
}

// reserve from applied assignments and groups staged in this lease. old
// assignments keep their port until their replacement commits, so cleanup of
// an old rank cannot remove its replacement's rendezvous mapping.
fn reserveGangPort(session: mutation.Session, preferred: u16, pending: []const u16) mutation.Error!u16 {
    session.node.mu.lockUncancelable(std.Options.debug_io);
    defer session.node.mu.unlock(std.Options.debug_io);
    try session.checkLocked();
    var used = [_]bool{false} ** 65536;
    for (pending) |port| used[port] = true;
    const Row = struct { port: i64 };
    var statement = session.node.stateMachineDb().prepare("SELECT DISTINCT gang_master_port AS port FROM assignments WHERE gang_rank = 0 AND gang_master_port IS NOT NULL AND status IN ('pending', 'running');") catch return error.InternalError;
    defer statement.deinit();
    var rows = statement.iterator(Row, .{}) catch return error.InternalError;
    while (rows.next(.{}) catch return error.InternalError) |row| {
        const port = std.math.cast(u16, row.port) orelse return error.InternalError;
        used[port] = true;
    }
    const first: u32 = @max(@as(u32, preferred), 1024);
    for (0..64512) |offset| {
        const port: u16 = @intCast(1024 + (first - 1024 + offset) % 64512);
        if (!used[port]) return port;
    }
    return error.Conflict;
}

fn workloadIds(alloc: std.mem.Allocator, session: mutation.Session, request: scheduler.PlacementRequest) mutation.Error!Placement {
    session.node.mu.lockUncancelable(std.Options.debug_io);
    defer session.node.mu.unlock(std.Options.debug_io);
    try session.checkLocked();
    const records = registry.listAssignmentsForWorkload(alloc, session.node.stateMachineDb(), request.app_name.?, request.workload_kind.?, request.workload_name.?) catch return error.InternalError;
    defer {
        for (records) |record| record.deinit(alloc);
        alloc.free(records);
    }
    const ids = alloc.alloc([]const u8, records.len) catch return error.InternalError;
    var initialized: usize = 0;
    errdefer {
        for (ids[0..initialized]) |id| alloc.free(id);
        alloc.free(ids);
    }
    for (records, ids) |record, *id| {
        id.* = alloc.dupe(u8, record.id) catch return error.InternalError;
        initialized += 1;
    }
    return .{ .assignment_ids = ids };
}

fn newId(alloc: std.mem.Allocator) mutation.Error![]const u8 {
    var buffer: [12]u8 = undefined;
    scheduler.generateAssignmentId(&buffer);
    return alloc.dupe(u8, &buffer) catch return error.InternalError;
}

fn resumePlacement(alloc: std.mem.Allocator, lease: Lease, request: scheduler.PlacementRequest, release_id: []const u8, replicas: u32) mutation.Error!?Placement {
    const node = lease.session.node;
    node.mu.lockUncancelable(std.Options.debug_io);
    defer node.mu.unlock(std.Options.debug_io);
    try lease.session.checkLocked();
    const Row = struct { id: sqlite.Text };
    var stmt = node.stateMachineDb().prepare("SELECT a.id FROM assignments a JOIN assignment_claims c ON c.assignment_id = a.id WHERE c.release_id = ? AND a.app_name = ? AND a.workload_kind = ? AND a.workload_name = ? ORDER BY a.gang_rank, a.id;") catch return error.InternalError;
    defer stmt.deinit();
    var rows = stmt.iterator(Row, .{ release_id, request.app_name, request.workload_kind, request.workload_name }) catch return error.InternalError;
    var ids: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }
    while (rows.nextAlloc(alloc, .{}) catch return error.InternalError) |row| {
        ids.append(alloc, row.id.data) catch {
            alloc.free(row.id.data);
            return error.InternalError;
        };
    }
    if (ids.items.len == 0) return null;
    const expected = @as(usize, replicas) * @max(@as(usize, 1), request.gang_world_size);
    if (ids.items.len != expected) return error.Conflict;
    return .{ .assignment_ids = ids.toOwnedSlice(alloc) catch return error.InternalError };
}

pub const Claim = struct {
    gpu_count: i64,
    release_id: ?[]const u8,
    group_id: ?[]const u8 = null,
    request_json: ?[]const u8 = null,

    pub fn deinit(self: Claim, alloc: std.mem.Allocator) void {
        if (self.release_id) |id| alloc.free(id);
        if (self.group_id) |id| alloc.free(id);
        if (self.request_json) |json| alloc.free(json);
    }
};

pub fn readClaim(alloc: std.mem.Allocator, db: *sqlite.Db, assignment: registry.Assignment) !Claim {
    const Row = struct { gpu_count: i64, release_id: ?sqlite.Text, group_id: ?sqlite.Text, request_json: ?sqlite.Text };
    if (try db.oneAlloc(Row, alloc, "SELECT gpu_count, release_id, group_id, request_json FROM assignment_claims WHERE assignment_id = ?;", .{}, .{assignment.id})) |row| {
        return .{ .gpu_count = row.gpu_count, .release_id = if (row.release_id) |id| id.data else null, .group_id = if (row.group_id) |id| id.data else null, .request_json = if (row.request_json) |json| json.data else null };
    }
    const Agent = struct { gpu_count: i64 };
    const agent = (try db.one(Agent, "SELECT gpu_count FROM agents WHERE id = ?;", .{}, .{assignment.agent_id})) orelse return error.InvalidClaim;
    return .{ .gpu_count = agent.gpu_count, .release_id = null };
}

/// reserve a rollback's original worker capacity before committing its batch.
pub fn consume(agents: []registry.AgentRecord, agent_id: []const u8, resources: Resources) mutation.Error!void {
    try capacity.consume(agents, agent_id, resources);
}

pub fn reconcileOrphans(alloc: std.mem.Allocator, session: mutation.Session) !void {
    const orphans = blk: {
        const lease = try Lease.begin(session);
        defer lease.deinit();
        session.node.mu.lockUncancelable(std.Options.debug_io);
        defer session.node.mu.unlock(std.Options.debug_io);
        try session.checkLocked();
        break :blk try registry.getOrphanedAssignments(alloc, session.node.stateMachineDb());
    };
    defer {
        for (orphans) |orphan| orphan.deinit(alloc);
        alloc.free(orphans);
    }
    for (orphans) |orphan| {
        reassignGroup(alloc, session, orphan.id) catch |err| switch (err) {
            error.Conflict => continue, // a later reconciliation takes a fresh view
            else => return err,
        };
    }
}

fn reassignGroup(alloc: std.mem.Allocator, session: mutation.Session, orphan_id: []const u8) !void {
    const lease = try Lease.begin(session);
    defer lease.deinit();
    const ClaimRow = struct { group_id: ?sqlite.Text, request_json: ?sqlite.Text };
    const claim = blk: {
        session.node.mu.lockUncancelable(std.Options.debug_io);
        defer session.node.mu.unlock(std.Options.debug_io);
        try session.checkLocked();
        break :blk (try session.node.stateMachineDb().oneAlloc(ClaimRow, alloc, "SELECT c.group_id, c.request_json FROM assignment_claims c JOIN assignments a ON a.id = c.assignment_id WHERE a.id = ? AND a.agent_id = '';", .{}, .{orphan_id})) orelse return;
    };
    defer if (claim.group_id) |id| alloc.free(id.data);
    defer if (claim.request_json) |json| alloc.free(json.data);
    // An old assignment without recorded constraints requires an explicit
    // redeploy; guessing its GPU or volume requirements could move it unsafely.
    const group_id = (claim.group_id orelse return).data;
    const encoded = (claim.request_json orelse return).data;
    const parsed = try std.json.parseFromSlice(scheduler.PlacementRequest, alloc, encoded, .{});
    defer parsed.deinit();
    const request = parsed.value;
    if (request.gang_world_size > max_gang_ranks) return error.Conflict;
    var ids: std.ArrayList([]const u8) = .empty;
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }
    {
        session.node.mu.lockUncancelable(std.Options.debug_io);
        defer session.node.mu.unlock(std.Options.debug_io);
        try session.checkLocked();
        const Row = struct { id: sqlite.Text };
        var stmt = try session.node.stateMachineDb().prepare("SELECT a.id FROM assignments a JOIN assignment_claims c ON c.assignment_id = a.id WHERE c.group_id = ? ORDER BY a.gang_rank, a.id;");
        defer stmt.deinit();
        var rows = try stmt.iterator(Row, .{group_id});
        while (try rows.nextAlloc(alloc, .{})) |row| {
            ids.append(alloc, row.id.data) catch |err| {
                alloc.free(row.id.data);
                return err;
            };
        }
    }
    if (ids.items.len != @max(@as(usize, 1), request.gang_world_size)) return error.Conflict;
    const snapshot = try lease.agents(alloc, ids.items);
    defer snapshot.deinit(alloc);
    var batch = std.Io.Writer.Allocating.init(alloc);
    defer batch.deinit();
    if (request.gang_world_size > 0) {
        const ranks = (try scheduler.scheduleGang(alloc, request, snapshot.records)) orelse return;
        defer alloc.free(ranks);
        const port = try reserveGangPort(session, request.gang_master_port, &.{});
        for (ranks) |*rank| rank.master_port = port;
        for (ranks, ids.items) |rank, id| {
            try sql.write(&batch.writer, "UPDATE assignments SET agent_id = CASE WHEN (SELECT last_applied FROM state_machine_meta WHERE id = 1) = ? THEN ? ELSE NULL END, status = 'pending', status_reason = NULL, gang_master_addr = ?, gang_master_port = ? WHERE id = ?;", .{ snapshot.index, rank.agent_id, rank.master_addr, rank.master_port, id });
        }
    } else {
        const choices = try scheduler.schedule(alloc, &.{request}, snapshot.records);
        defer alloc.free(choices);
        const choice = choices[0] orelse return;
        try sql.write(&batch.writer, "UPDATE assignments SET agent_id = CASE WHEN (SELECT last_applied FROM state_machine_meta WHERE id = 1) = ? THEN ? ELSE NULL END, status = 'pending', status_reason = NULL WHERE id = ?;", .{ snapshot.index, choice.agent_id, orphan_id });
    }
    try lease.commit(batch.written());
}

fn testNode() !@import("node.zig").Node {
    var node = try @import("node.zig").Node.initForTests(std.testing.allocator, .{ .id = 1, .port = 0, .peers = &.{}, .data_dir = "/tmp" });
    errdefer node.deinit();
    node.raft.role = .leader;
    _ = try node.proposeCommitted("INSERT INTO agents (id, address, status, cpu_cores, memory_mb, gpu_count, last_heartbeat, registered_at) VALUES ('worker', '127.0.0.1', 'active', 1, 1024, 2, 0, 0);", 0);
    return node;
}

fn countRows(db: *sqlite.Db, comptime table: []const u8) !i64 {
    return (try db.one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM " ++ table ++ ";", .{}, .{})).?.count;
}

const test_request: scheduler.PlacementRequest = .{ .image = "example", .command = "", .cpu_limit = 600, .memory_limit_mb = 128, .app_name = "demo", .workload_kind = "service", .workload_name = "web" };

test "durable placement claims span separate applies and concurrent requests" {
    const alloc = std.testing.allocator;
    var node = try testNode();
    defer node.deinit();
    const session = try mutation.Session.begin(&node);
    const Worker = struct {
        session: mutation.Session,
        release: []const u8,
        placed: bool = false,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            const result = place(std.testing.allocator, self.session, test_request, self.release) catch |err| {
                self.failure = err;
                return;
            };
            if (result) |reserved| {
                self.placed = true;
                reserved.deinit(std.testing.allocator);
            }
        }
    };
    var first = Worker{ .session = session, .release = "first" };
    var second = Worker{ .session = session, .release = "second" };
    const thread1 = try std.Thread.spawn(.{}, Worker.run, .{&first});
    const thread2 = try std.Thread.spawn(.{}, Worker.run, .{&second});
    thread1.join();
    thread2.join();
    try std.testing.expect(first.failure == null and second.failure == null);
    try std.testing.expect(first.placed != second.placed);
    try std.testing.expectEqual(@as(i64, 1), try countRows(node.stateMachineDb(), "assignments"));
    try std.testing.expect((try place(alloc, session, test_request, "third")) == null);
    const lease = try Lease.begin(session);
    defer lease.deinit();
    const snapshot = try lease.agents(alloc, &.{});
    defer snapshot.deinit(alloc);
    try std.testing.expectEqual(@as(i64, 600), snapshot.records[0].cpu_used);
}

test "placement revision rejects a heartbeat race without partial assignments" {
    const alloc = std.testing.allocator;
    var node = try testNode();
    defer node.deinit();
    const session = try mutation.Session.begin(&node);
    const lease = try Lease.begin(session);
    defer lease.deinit();
    const snapshot = try lease.agents(alloc, &.{});
    defer snapshot.deinit(alloc);
    var batch = std.Io.Writer.Allocating.init(alloc);
    defer batch.deinit();
    try appendAssignment(&batch.writer, "stale", "worker", test_request, null, snapshot.index, 1);
    try appendClaim(&batch.writer, "stale", .{ .gpu_count = 0, .release_id = null });
    try session.commit("UPDATE agents SET cpu_used = 700 WHERE id = 'worker';");
    try std.testing.expectError(error.Conflict, lease.commit(batch.written()));
    try std.testing.expectEqual(@as(i64, 0), try countRows(node.stateMachineDb(), "assignments"));
    try std.testing.expectEqual(@as(i64, 0), try countRows(node.stateMachineDb(), "assignment_claims"));
}

test "gang reservation includes cpu and rolls back every rank on rejection" {
    const alloc = std.testing.allocator;
    var node = try testNode();
    defer node.deinit();
    const session = try mutation.Session.begin(&node);
    var request = test_request;
    request.gang_world_size = 2;
    request.gpus_per_rank = 1;
    // Two GPUs alone are insufficient for two 600-millicpu ranks.
    try std.testing.expect((try place(alloc, session, request, "gang")) == null);
    request.cpu_limit = 400;
    try node.stateMachineDb().exec("CREATE TRIGGER reject_second_rank BEFORE INSERT ON assignments WHEN NEW.gang_rank = 1 BEGIN SELECT RAISE(ABORT, 'rank rejected'); END;", .{}, .{});
    try std.testing.expectError(error.Conflict, place(alloc, session, request, "gang"));
    try std.testing.expectEqual(@as(i64, 0), try countRows(node.stateMachineDb(), "assignments"));
    try std.testing.expectEqual(@as(i64, 0), try countRows(node.stateMachineDb(), "assignment_claims"));
    try node.stateMachineDb().exec("DROP TRIGGER reject_second_rank;", .{}, .{});
    const placed = (try place(alloc, session, request, "gang")).?;
    defer placed.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 2), placed.assignment_ids.len);
    var third = test_request;
    third.cpu_limit = 100;
    third.gpu_limit = 1;
    try std.testing.expect((try place(alloc, session, third, "gpu-third")) == null);
}

test "promoted replica resumes the committed placement without reserving twice" {
    const alloc = std.testing.allocator;
    var leader = try testNode();
    defer leader.deinit();
    const old_session = try mutation.Session.begin(&leader);
    const original = (try place(alloc, old_session, test_request, "resume")).?;
    defer original.deinit(alloc);
    var replica = try @import("node.zig").Node.initForTests(alloc, .{ .id = 2, .port = 0, .peers = &.{}, .data_dir = "/tmp" });
    defer replica.deinit();
    const entries = try leader.log.getEntries(alloc, 1, leader.log.lastIndex());
    defer {
        for (entries) |entry| alloc.free(entry.data);
        alloc.free(entries);
    }
    for (entries) |entry| try replica.log.append(entry);
    replica.state_machine.applyUpTo(&replica.log, alloc, leader.raft.commit_index);
    replica.raft.commit_index = leader.raft.commit_index;
    replica.raft.role = .leader;
    replica.raft.persistent_state.current_term = 1;
    try std.testing.expect(replica.log.setCurrentTerm(1));
    const resumed = (try place(alloc, try mutation.Session.begin(&replica), test_request, "resume")).?;
    defer resumed.deinit(alloc);
    try std.testing.expectEqualStrings(original.assignment_ids[0], resumed.assignment_ids[0]);
    try std.testing.expectEqual(@as(i64, 1), try countRows(replica.stateMachineDb(), "assignments"));
    leader.raft.role = .follower;
    leader.raft.persistent_state.current_term = 1;
    try std.testing.expect(leader.log.setCurrentTerm(1));
    try std.testing.expectError(error.NotLeader, place(alloc, old_session, test_request, "stale"));
}

test "rollback capacity conflict preserves current assignments and later restores claims" {
    const alloc = std.testing.allocator;
    const rollback = @import("../api/routes/cluster_agents/cluster_rollback.zig");
    const Target = @import("../api/routes/cluster_agents/rollout_targets.zig").ScheduledTarget;
    var node = try testNode();
    defer node.deinit();
    const session = try mutation.Session.begin(&node);
    var old_request = test_request;
    old_request.cpu_limit = 400;
    old_request.gpu_limit = 1;
    const original = (try place(alloc, session, old_request, "old-release")).?;
    defer original.deinit(alloc);
    var state = try rollback.RollbackState.capture(alloc, session, &.{.{ .request = old_request, .rollout = .{} }});
    defer state.deinit();
    var new_request = old_request;
    new_request.cpu_limit = 200;
    new_request.gpu_limit = 0;
    const current = (try place(alloc, session, new_request, "new-release")).?;
    defer current.deinit(alloc);
    const current_target = Target{ .request = new_request, .assignment_ids = current.assignment_ids, .placement_count = 1 };
    try state.recordActivatedTarget(current_target);
    try rollback.activateTarget(session, current_target);
    var other_request = new_request;
    other_request.app_name = "other";
    other_request.cpu_limit = 700;
    const other = (try place(alloc, session, other_request, "other-release")).?;
    defer other.deinit(alloc);
    try std.testing.expectError(error.Conflict, state.rollbackActivatedTargets(session));
    const current_count = (try node.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignments WHERE id = ?;", .{}, .{current.assignment_ids[0]})).?.count;
    try std.testing.expectEqual(@as(i64, 1), current_count);
    try rollback.discardTarget(session, .{ .request = other_request, .assignment_ids = other.assignment_ids, .placement_count = 1 });
    try state.rollbackActivatedTargets(session);
    try std.testing.expectEqual(@as(i64, 1), try countRows(node.stateMachineDb(), "assignments"));
    const restored = (try node.stateMachineDb().one(struct { gpu_count: i64 }, "SELECT gpu_count FROM assignment_claims WHERE assignment_id = ?;", .{}, .{original.assignment_ids[0]})).?;
    try std.testing.expectEqual(@as(i64, 1), restored.gpu_count);
}

test "orphan reconciliation preserves constraints and reserves replacement capacity" {
    const alloc = std.testing.allocator;
    var node = try testNode();
    defer node.deinit();
    const session = try mutation.Session.begin(&node);
    try session.commit("UPDATE agents SET labels = 'zone=blue' WHERE id = 'worker';");
    var request = test_request;
    request.required_labels = "zone=blue";
    const original = (try place(alloc, session, request, "orphan-release")).?;
    defer original.deinit(alloc);
    try session.commit("INSERT INTO agents (id, address, status, cpu_cores, memory_mb, gpu_count, labels, last_heartbeat, registered_at) VALUES ('replacement', '127.0.0.2', 'active', 1, 1024, 2, 'zone=red', 0, 0); UPDATE agents SET status = 'offline' WHERE id = 'worker'; UPDATE assignments SET agent_id = '' WHERE agent_id = 'worker';");
    try reconcileOrphans(alloc, session);
    const orphan_count = (try node.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignments WHERE agent_id = '';", .{}, .{})).?.count;
    try std.testing.expectEqual(@as(i64, 1), orphan_count);
    try session.commit("UPDATE agents SET labels = 'zone=blue' WHERE id = 'replacement';");
    try reconcileOrphans(alloc, session);
    const assigned_count = (try node.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignments WHERE agent_id = 'replacement';", .{}, .{})).?.count;
    try std.testing.expectEqual(@as(i64, 1), assigned_count);
    try std.testing.expect((try place(alloc, session, request, "competing-release")) == null);
}

test "partial gang loss rehomes all ranks and their master endpoint atomically" {
    const alloc = std.testing.allocator;
    var node = try testNode();
    defer node.deinit();
    const session = try mutation.Session.begin(&node);
    var request = test_request;
    request.cpu_limit = 400;
    request.gang_world_size = 2;
    const original = (try place(alloc, session, request, "gang-release")).?;
    defer original.deinit(alloc);
    try session.commit("INSERT INTO agents (id, address, status, cpu_cores, memory_mb, gpu_count, last_heartbeat, registered_at) VALUES ('replacement', '127.0.0.2', 'active', 1, 1024, 2, 0, 0); UPDATE agents SET status = 'offline' WHERE id = 'worker'; UPDATE assignments SET agent_id = '' WHERE gang_rank = 0;");
    try reconcileOrphans(alloc, session);
    const moved = (try node.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignments WHERE agent_id = 'replacement' AND gang_master_addr = '127.0.0.2';", .{}, .{})).?.count;
    try std.testing.expectEqual(@as(i64, 2), moved);
    try std.testing.expectEqual(@as(i64, 2), try countRows(node.stateMachineDb(), "assignment_claims"));
}

test "three service replicas reserve together resume and roll back as one target" {
    const alloc = std.testing.allocator;
    const rollback = @import("../api/routes/cluster_agents/cluster_rollback.zig");
    const Target = @import("../api/routes/cluster_agents/rollout_targets.zig").ScheduledTarget;
    var node = try testNode();
    defer node.deinit();
    const session = try mutation.Session.begin(&node);
    var request = test_request;
    request.cpu_limit = 100;
    const original = (try placeReplicas(alloc, session, request, "original", 3)).?;
    defer original.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 3), original.assignment_ids.len);
    const resumed = (try placeReplicas(alloc, session, request, "original", 3)).?;
    defer resumed.deinit(alloc);
    try std.testing.expectEqual(@as(i64, 3), try countRows(node.stateMachineDb(), "assignments"));
    var state = try rollback.RollbackState.capture(alloc, session, &.{.{ .request = request, .replicas = 3 }});
    defer state.deinit();
    const replacement = (try placeReplicas(alloc, session, request, "replacement", 3)).?;
    defer replacement.deinit(alloc);
    const target: Target = .{ .request = request, .assignment_ids = replacement.assignment_ids, .placement_count = 3 };
    try state.recordActivatedTarget(target);
    try rollback.activateTarget(session, target);
    try std.testing.expectEqual(@as(i64, 3), try countRows(node.stateMachineDb(), "assignments"));
    for (replacement.assignment_ids) |id| {
        const row = try node.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignments WHERE id = ? AND workload_name = 'web';", .{}, .{id});
        try std.testing.expectEqual(@as(i64, 1), row.?.count);
    }
    try state.rollbackActivatedTargets(session);
    try std.testing.expectEqual(@as(i64, 3), try countRows(node.stateMachineDb(), "assignments"));
    for (original.assignment_ids) |id| {
        try std.testing.expect((try node.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignments WHERE id = ?;", .{}, .{id})).?.count == 1);
    }
}

test "replica capacity rejection commits no partial group" {
    const alloc = std.testing.allocator;
    var node = try testNode();
    defer node.deinit();
    const session = try mutation.Session.begin(&node);
    var request = test_request;
    request.cpu_limit = 400;
    try std.testing.expect((try placeReplicas(alloc, session, request, "too-large", 3)) == null);
    try std.testing.expectEqual(@as(i64, 0), try countRows(node.stateMachineDb(), "assignments"));
    try std.testing.expectEqual(@as(i64, 0), try countRows(node.stateMachineDb(), "assignment_claims"));
}

test "replica surge limit preserves the prior group and permits resume" {
    const alloc = std.testing.allocator;
    var node = try testNode();
    defer node.deinit();
    const session = try mutation.Session.begin(&node);
    var request = test_request;
    request.cpu_limit = 10;
    request.memory_limit_mb = 1;
    const prior = (try placeReplicas(alloc, session, request, "prior", 33)).?;
    defer prior.deinit(alloc);
    try std.testing.expect(!try replicaSurgeFits(session, request, 32));
    try std.testing.expect((try placeReplicas(alloc, session, request, "replacement", 32)) == null);
    try std.testing.expectEqual(@as(i64, 33), try countRows(node.stateMachineDb(), "assignments"));
    try std.testing.expectEqual(@as(i64, 33), try countRows(node.stateMachineDb(), "assignment_claims"));
    const resumed = (try placeReplicas(alloc, session, request, "prior", 33)).?;
    defer resumed.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 33), resumed.assignment_ids.len);
}

test "cluster placement reserves service names across apps" {
    const alloc = std.testing.allocator;
    var node = try testNode();
    defer node.deinit();
    const session = try mutation.Session.begin(&node);
    const first = (try place(alloc, session, test_request, "first")).?;
    defer first.deinit(alloc);
    var other = test_request;
    other.app_name = "another-app";
    other.cpu_limit = 100;
    try std.testing.expect(!try serviceNameAvailable(session, other));
    try std.testing.expect((try place(alloc, session, other, "second")) == null);
    try std.testing.expectEqual(@as(i64, 1), try countRows(node.stateMachineDb(), "assignments"));
    _ = try node.proposeCommitted("UPDATE assignments SET status = 'stopped';", 0);
    try std.testing.expect(try serviceNameAvailable(session, other));
    const reused = (try place(alloc, session, other, "second")).?;
    defer reused.deinit(alloc);
}

test "replicated gang groups reserve distinct rendezvous ports" {
    const alloc = std.testing.allocator;
    var node = try testNode();
    defer node.deinit();
    _ = try node.proposeCommitted("UPDATE agents SET cpu_cores = 8, gpu_count = 8;", 0);
    const session = try mutation.Session.begin(&node);
    var request = test_request;
    request.gang_world_size = 2;
    request.gpus_per_rank = 1;
    const groups = (try placeReplicas(alloc, session, request, "mesh", 2)).?;
    defer groups.deinit(alloc);
    const counts = (try node.stateMachineDb().one(struct { ports: i64, ranks: i64 }, "SELECT COUNT(DISTINCT gang_master_port) AS ports, COUNT(*) AS ranks FROM assignments;", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 2), counts.ports);
    try std.testing.expectEqual(@as(i64, 4), counts.ranks);
}
