// track each service replica through its handoff. the original assignment
// remains live until its durable replacement passes the agent's readiness check.
const std = @import("std");
const sqlite = @import("sqlite");
const registry = @import("registry.zig");
const placement = @import("placement_transaction.zig");
const scheduler = @import("scheduler.zig");
const mutation = @import("mutation_session.zig");
const sql = @import("sql_command.zig");

pub const schema_sql = @import("../state/schema.zig").assignment_handoffs_create_table_sql;

pub fn isDraining(status: []const u8) bool {
    return std.mem.eql(u8, status, "draining") or std.mem.eql(u8, status, "drain_pending") or std.mem.eql(u8, status, "drain_blocked");
}

pub fn reconcile(alloc: std.mem.Allocator, session: mutation.Session, agent_id: []const u8) !void {
    const lease = try placement.Lease.begin(session);
    defer lease.deinit();
    try session.commit(schema_sql);
    const node = session.node;
    const assignments = blk: {
        node.mu.lockUncancelable(std.Options.debug_io);
        defer node.mu.unlock(std.Options.debug_io);
        try session.checkLocked();
        const agent = (try registry.getAgent(alloc, node.stateMachineDb(), agent_id)) orelse return;
        defer agent.deinit(alloc);
        if (!isDraining(agent.status)) return;
        break :blk try registry.getAssignments(alloc, node.stateMachineDb(), agent_id);
    };
    defer {
        for (assignments) |assignment| assignment.deinit(alloc);
        alloc.free(assignments);
    }
    var active = false;
    var blocked = false;
    for (assignments) |assignment| {
        if (placement.isTerminal(assignment.status)) continue;
        active = true;
        if (!std.mem.eql(u8, assignment.workload_kind orelse "", "service")) {
            // jobs and training ranks must finish or be stopped explicitly.
            blocked = true;
            continue;
        }
        if (try advance(alloc, lease, assignment) == .blocked) blocked = true;
    }
    const status = if (!active) "drained" else if (blocked) "drain_blocked" else "drain_pending";
    const command = try sql.render(alloc, "UPDATE agents SET status = ? WHERE id = ? AND status IN ('draining', 'drain_pending', 'drain_blocked');", .{ status, agent_id });
    defer alloc.free(command);
    try session.commit(command);
}

const Progress = enum { waiting, blocked };

fn advance(alloc: std.mem.Allocator, lease: placement.Lease, original: registry.Assignment) !Progress {
    const session = lease.session;
    const node = session.node;
    const Handoff = struct { replacement_id: sqlite.Text, generation: i64, status: ?sqlite.Text };
    const handoff, const claim, const index = blk: {
        node.mu.lockUncancelable(std.Options.debug_io);
        defer node.mu.unlock(std.Options.debug_io);
        try session.checkLocked();
        const present = (try node.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignments WHERE id = ? AND agent_id = ? AND generation = ? AND status IN ('pending', 'running');", .{}, .{ original.id, original.agent_id, original.generation })).?;
        if (present.count == 0) return .waiting;
        const handoff = try node.stateMachineDb().oneAlloc(Handoff, alloc, "SELECT h.replacement_id, h.generation, a.status FROM assignment_handoffs h LEFT JOIN assignments a ON a.id = h.replacement_id WHERE h.assignment_id = ?;", .{}, .{original.id});
        errdefer if (handoff) |record| {
            alloc.free(record.replacement_id.data);
            if (record.status) |status| alloc.free(status.data);
        };
        break :blk .{ handoff, try placement.readClaim(alloc, node.stateMachineDb(), original), node.state_machine.last_applied };
    };
    defer claim.deinit(alloc);
    if (handoff) |record| {
        defer alloc.free(record.replacement_id.data);
        defer if (record.status) |status| alloc.free(status.data);
        // a replaced original or a failed replacement needs an explicit redeploy.
        if (record.generation != original.generation) return .blocked;
        const status = (record.status orelse return .blocked).data;
        if (placement.isTerminal(status)) return .blocked;
        if (!std.mem.eql(u8, status, "running")) return .waiting;
        const command = try sql.render(alloc, "UPDATE assignments SET agent_id = CASE WHEN (SELECT last_applied FROM state_machine_meta WHERE id = 1) = ? THEN agent_id ELSE NULL END, status = 'stopped', status_reason = 'drained' WHERE id = ? AND generation = ? AND status IN ('pending', 'running');", .{ index, original.id, original.generation });
        defer alloc.free(command);
        try lease.commit(command);
        return .waiting;
    }

    if (claim.release_id) |release_id| {
        node.mu.lockUncancelable(std.Options.debug_io);
        defer node.mu.unlock(std.Options.debug_io);
        try session.checkLocked();
        const rollout = try node.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM deployments WHERE id = ? AND status IN ('pending', 'in_progress');", .{}, .{release_id});
        if (rollout.?.count > 0) return .blocked;
    }
    const encoded = claim.request_json orelse return .blocked;
    const parsed = try std.json.parseFromSlice(scheduler.PlacementRequest, alloc, encoded, .{});
    defer parsed.deinit();
    const request = parsed.value;
    if (request.gang_world_size != 0) return .blocked;
    const execution = try @import("assignment_spec.zig").decode(alloc, request.command);
    defer execution.deinit();
    for (execution.value.volumes) |mount| {
        if (mount.kind == .bind) return .blocked;
        var found = false;
        for (execution.value.volume_definitions) |volume| {
            if (!std.mem.eql(u8, volume.name, mount.source)) continue;
            found = true;
            switch (volume.driver) {
                .local, .host => return .blocked,
                else => {},
            }
        }
        if (!found) return .blocked;
    }
    for (request.volume_constraints) |volume| {
        // these paths belong to their current host. a second empty directory
        // is not a replacement for the original workload's data.
        if (std.mem.eql(u8, volume.driver, "local") or std.mem.eql(u8, volume.driver, "host")) return .blocked;
    }
    const snapshot = try lease.agents(alloc, &.{});
    defer snapshot.deinit(alloc);
    if (snapshot.index != index) return error.Conflict;
    const choices = try scheduler.schedule(alloc, &.{request}, snapshot.records);
    defer alloc.free(choices);
    const choice = choices[0] orelse return .blocked;
    var replacement_id: [12]u8 = undefined;
    scheduler.generateAssignmentId(&replacement_id);
    var batch = std.Io.Writer.Allocating.init(alloc);
    defer batch.deinit();
    try placement.appendAssignment(&batch.writer, &replacement_id, choice.agent_id, request, null, snapshot.index, std.Io.Clock.real.now(std.Options.debug_io).toSeconds());
    try placement.appendClaim(&batch.writer, &replacement_id, .{ .gpu_count = claim.gpu_count, .release_id = claim.release_id, .group_id = &replacement_id, .request_json = encoded });
    try sql.write(&batch.writer, "INSERT INTO assignment_handoffs (assignment_id, replacement_id, generation) VALUES (?, ?, ?);", .{ original.id, &replacement_id, original.generation });
    try lease.commit(batch.written());
    return .waiting;
}
