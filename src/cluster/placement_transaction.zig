// Placement decisions are serialized through their committed assignment batch.
// A new leader first commits a barrier, so inherited proposals participate in
// the next capacity calculation. The assignments themselves reserve capacity.
const std = @import("std");
const sqlite = @import("sqlite");
const registry = @import("registry.zig");
const scheduler = @import("scheduler.zig");
const mutation = @import("mutation_session.zig");
const sql = @import("sql_command.zig");

const max_gang_ranks = 4096;
const max_batch_bytes = 1024 * 1024;

var placement_mu: std.Io.Mutex = .init;

pub const schema_sql = "CREATE TABLE IF NOT EXISTS assignment_claims (assignment_id TEXT PRIMARY KEY, gpu_count INTEGER NOT NULL CHECK (gpu_count >= 0), release_id TEXT, group_id TEXT, request_json TEXT);";
pub const cleanup_sql = "DELETE FROM assignment_claims WHERE assignment_id NOT IN (SELECT id FROM assignments);";

pub const Lease = struct {
    session: mutation.Session,

    pub fn begin(session: mutation.Session) mutation.Error!Lease {
        placement_mu.lockUncancelable(std.Options.debug_io);
        errdefer placement_mu.unlock(std.Options.debug_io);
        // The schema command also supplies the current-term read barrier and
        // upgrades snapshots created before durable GPU claims existed.
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
            var pending: Resources = .{};
            var running: Resources = .{};
            const Row = struct { id: sqlite.Text, status: sqlite.Text, cpu: i64, memory: i64, gpu: ?i64 };
            var stmt = try node.stateMachineDb().prepare("SELECT a.id, a.status, a.cpu_limit AS cpu, a.memory_limit_mb AS memory, c.gpu_count AS gpu FROM assignments a LEFT JOIN assignment_claims c ON c.assignment_id = a.id WHERE a.agent_id = ?;");
            defer stmt.deinit();
            var rows = try stmt.iterator(Row, .{agent.id});
            while (try rows.nextAlloc(alloc, .{})) |row| {
                defer alloc.free(row.id.data);
                defer alloc.free(row.status.data);
                if (containsId(excluded_ids, row.id.data) or isTerminal(row.status.data)) continue;
                // Old assignments did not record GPU requests. Preserve their
                // worker's GPU capacity conservatively until they are replaced.
                const used: Resources = .{ .cpu = row.cpu, .memory = row.memory, .gpu = row.gpu orelse agent.gpu_count };
                if (std.mem.eql(u8, row.status.data, "pending")) pending.add(used) else running.add(used);
            }
            // Heartbeats can lag starts and omit pending assignments. Running
            // claims form a floor; pending claims reserve additional capacity.
            agent.cpu_used = if (agent.cpu_used < 0) std.math.maxInt(i64) else pending.cpu +| @max(agent.cpu_used, running.cpu);
            agent.memory_used_mb = if (agent.memory_used_mb < 0) std.math.maxInt(i64) else pending.memory +| @max(agent.memory_used_mb, running.memory);
            agent.gpu_used = if (agent.gpu_used < 0) std.math.maxInt(i64) else pending.gpu +| @max(agent.gpu_used, running.gpu);
        }
        return .{ .records = records, .index = node.state_machine.last_applied };
    }

    pub fn commit(self: Lease, command: []const u8) mutation.Error!void {
        if (command.len > max_batch_bytes) return error.Conflict;
        try self.session.commit(command);
    }
};

pub const Resources = struct {
    cpu: i64 = 0,
    memory: i64 = 0,
    gpu: i64 = 0,

    fn add(self: *Resources, other: Resources) void {
        self.cpu = addUsage(self.cpu, other.cpu);
        self.memory = addUsage(self.memory, other.memory);
        self.gpu = addUsage(self.gpu, other.gpu);
    }

    fn addUsage(left: i64, right: i64) i64 {
        return if (right < 0) std.math.maxInt(i64) else left +| right;
    }
};

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

/// The NOT NULL agent_id constraint turns a stale read into an atomic command
/// rejection. A heartbeat or membership change between selection and apply
/// cannot silently invalidate the capacity decision.
pub fn appendAssignment(writer: *std.Io.Writer, id: []const u8, agent_id: []const u8, request: scheduler.PlacementRequest, gang: ?@import("../gpu/scheduler.zig").GangPlacement, index: u64, now: i64) !void {
    try sql.write(writer, "INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, app_name, workload_kind, workload_name, health_check_json, gang_rank, gang_world_size, gang_master_addr, gang_master_port, created_at) VALUES (?, CASE WHEN (SELECT last_applied FROM state_machine_meta WHERE id = 1) = ? THEN ? ELSE NULL END, ?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", .{
        id,                                        index,                                           agent_id,                                                request.image,                                    request.command, request.cpu_limit, request.memory_limit_mb, request.app_name, request.workload_kind, request.workload_name, request.health_check_json,
        @as(?u32, if (gang) |g| g.rank else null), @as(?u32, if (gang) |g| g.world_size else null), @as(?[]const u8, if (gang) |g| g.master_addr else null), @as(?u16, if (gang) |g| g.master_port else null), now,
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
    // Bound gang work before allocating a ranks array or building SQL.
    if (request.cpu_limit <= 0 or request.memory_limit_mb <= 0 or request.gpu_limit < 0 or request.gang_world_size > max_gang_ranks) return error.Conflict;
    for (0..3) |_| {
        return placeOnce(alloc, session, request, release_id) catch |err| {
            if (err == error.Conflict) continue;
            return err;
        };
    }
    return error.Conflict;
}

fn placeOnce(alloc: std.mem.Allocator, session: mutation.Session, request: scheduler.PlacementRequest, release_id: ?[]const u8) mutation.Error!?Placement {
    const lease = try Lease.begin(session);
    defer lease.deinit();
    if (release_id) |id| {
        if (try resumePlacement(alloc, lease, request, id)) |existing| return existing;
    }
    const agents = lease.agents(alloc, &.{}) catch return error.InternalError;
    defer agents.deinit(alloc);
    var batch = std.Io.Writer.Allocating.init(alloc);
    defer batch.deinit();
    var ids: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }
    const request_json = std.json.Stringify.valueAlloc(alloc, request, .{}) catch return error.InternalError;
    defer alloc.free(request_json);
    const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
    if (request.gang_world_size > 0) {
        const placements = (scheduler.scheduleGang(alloc, request, agents.records) catch return error.InternalError) orelse return null;
        defer alloc.free(placements);
        for (placements) |placement| {
            const id = try newId(alloc);
            ids.append(alloc, id) catch {
                alloc.free(id);
                return error.InternalError;
            };
            appendAssignment(&batch.writer, id, placement.agent_id, request, placement, agents.index, now) catch return error.InternalError;
            appendClaim(&batch.writer, id, .{ .gpu_count = placement.gpu_count, .release_id = release_id, .group_id = ids.items[0], .request_json = request_json }) catch return error.InternalError;
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

fn newId(alloc: std.mem.Allocator) mutation.Error![]const u8 {
    var buffer: [12]u8 = undefined;
    scheduler.generateAssignmentId(&buffer);
    return alloc.dupe(u8, &buffer) catch return error.InternalError;
}

fn resumePlacement(alloc: std.mem.Allocator, lease: Lease, request: scheduler.PlacementRequest, release_id: []const u8) mutation.Error!?Placement {
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
    const expected = @max(@as(usize, 1), request.gang_world_size);
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

/// Reserve a rollback's original placement on its original worker. A failed
/// check leaves all current assignments intact, rather than partially restoring.
pub fn consume(agents: []registry.AgentRecord, agent_id: []const u8, resources: Resources) mutation.Error!void {
    for (agents) |*agent| {
        if (!std.mem.eql(u8, agent.id, agent_id)) continue;
        if (!@import("scheduler/placement.zig").validCapacity(agent.*) or !std.mem.eql(u8, agent.status, "active") or
            resources.cpu < 0 or resources.memory < 0 or resources.gpu < 0 or
            agent.cpu_used < 0 or agent.memory_used_mb < 0 or agent.gpu_used < 0 or
            resources.cpu > agent.cpu_cores * 1000 -| agent.cpu_used or
            resources.memory > agent.memory_mb -| agent.memory_used_mb or
            resources.gpu > agent.gpu_count -| agent.gpu_used) return error.Conflict;
        agent.cpu_used += resources.cpu;
        agent.memory_used_mb += resources.memory;
        agent.gpu_used += resources.gpu;
        return;
    }
    return error.Conflict;
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
