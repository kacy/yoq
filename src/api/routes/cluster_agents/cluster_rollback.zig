const std = @import("std");

const sql_command = @import("../../../cluster/sql_command.zig");
const placement = @import("../../../cluster/placement_transaction.zig");
const scheduler = @import("../../../cluster/scheduler.zig");
const mutation_session = @import("../../../cluster/mutation_session.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const apply_request = @import("apply_request.zig");
const rollout_targets_mod = @import("rollout_targets.zig");

const ActivatedTarget = rollout_targets_mod.ActivatedTarget;
const RolloutTargets = @import("../../../manifest/rollout_progress.zig").Targets;
const ScheduledTarget = rollout_targets_mod.ScheduledTarget;

pub const ApplyError = mutation_session.Error;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

const PriorAssignmentSnapshot = struct {
    request: scheduler.PlacementRequest,
    assignments: []agent_registry.Assignment,
    claims: []placement.Claim,

    fn deinit(self: *const PriorAssignmentSnapshot, alloc: std.mem.Allocator) void {
        for (self.assignments) |assignment| assignment.deinit(alloc);
        alloc.free(self.assignments);
        for (self.claims) |claim| claim.deinit(alloc);
        alloc.free(self.claims);
    }
};

pub const RollbackState = struct {
    alloc: std.mem.Allocator,
    snapshots: []PriorAssignmentSnapshot,
    activated_targets: std.ArrayListUnmanaged(ActivatedTarget) = .empty,

    pub fn capture(
        alloc: std.mem.Allocator,
        session: mutation_session.Session,
        requests: []const apply_request.ServiceRequest,
    ) ApplyError!RollbackState {
        const lease = try placement.Lease.begin(session);
        defer lease.deinit();
        session.node.mu.lockUncancelable(std.Options.debug_io);
        defer session.node.mu.unlock(std.Options.debug_io);
        try session.checkLocked();
        const db = session.node.stateMachineDb();
        var snapshots = std.ArrayListUnmanaged(PriorAssignmentSnapshot).empty;
        errdefer {
            for (snapshots.items) |*snapshot| snapshot.deinit(alloc);
            snapshots.deinit(alloc);
        }

        for (requests) |req| {
            const app_name = req.request.app_name orelse continue;
            const workload_kind = req.request.workload_kind orelse continue;
            const workload_name = req.request.workload_name orelse continue;
            const assignments = agent_registry.listAssignmentsForWorkload(
                alloc,
                db,
                app_name,
                workload_kind,
                workload_name,
            ) catch return ApplyError.InternalError;
            errdefer {
                for (assignments) |assignment| assignment.deinit(alloc);
                alloc.free(assignments);
            }
            const claims = alloc.alloc(placement.Claim, assignments.len) catch return error.InternalError;
            var initialized: usize = 0;
            errdefer {
                for (claims[0..initialized]) |claim| claim.deinit(alloc);
                alloc.free(claims);
            }
            for (assignments, 0..) |assignment, index| {
                claims[index] = placement.readClaim(alloc, db, assignment) catch return error.InternalError;
                initialized += 1;
            }
            snapshots.append(alloc, .{
                .request = req.request,
                .assignments = assignments,
                .claims = claims,
            }) catch return ApplyError.InternalError;
        }

        return .{
            .alloc = alloc,
            .snapshots = snapshots.toOwnedSlice(alloc) catch return ApplyError.InternalError,
        };
    }

    pub fn deinit(self: *RollbackState) void {
        for (self.snapshots) |*snapshot| snapshot.deinit(self.alloc);
        self.alloc.free(self.snapshots);
        for (self.activated_targets.items) |*target| target.deinit(self.alloc);
        self.activated_targets.deinit(self.alloc);
    }

    pub fn recordActivatedTarget(self: *RollbackState, target: ScheduledTarget) ApplyError!void {
        const assignment_ids = copyAssignmentIds(self.alloc, target.assignment_ids) catch return ApplyError.InternalError;
        self.activated_targets.append(self.alloc, .{
            .request = target.request,
            .assignment_ids = assignment_ids,
        }) catch return ApplyError.InternalError;
    }

    pub fn rollbackActivatedTargets(self: *RollbackState, session: mutation_session.Session) ApplyError!void {
        if (self.activated_targets.items.len == 0) return;
        const lease = try placement.Lease.begin(session);
        defer lease.deinit();
        var removed_ids: std.ArrayList([]const u8) = .empty;
        defer {
            for (removed_ids.items) |id| self.alloc.free(id);
            removed_ids.deinit(self.alloc);
        }
        // Read the assignments being replaced under the same placement lease
        // that will validate and commit every restored assignment.
        {
            session.node.mu.lockUncancelable(std.Options.debug_io);
            defer session.node.mu.unlock(std.Options.debug_io);
            try session.checkLocked();
            for (self.activated_targets.items) |target| {
                const current = agent_registry.listAssignmentsForWorkload(self.alloc, session.node.stateMachineDb(), target.request.app_name.?, target.request.workload_kind.?, target.request.workload_name.?) catch return error.InternalError;
                defer {
                    for (current) |assignment| assignment.deinit(self.alloc);
                    self.alloc.free(current);
                }
                for (current) |assignment| {
                    const id = self.alloc.dupe(u8, assignment.id) catch return error.InternalError;
                    removed_ids.append(self.alloc, id) catch {
                        self.alloc.free(id);
                        return error.InternalError;
                    };
                }
            }
        }
        const agents = lease.agents(self.alloc, removed_ids.items) catch return error.InternalError;
        defer agents.deinit(self.alloc);
        var batch = std.Io.Writer.Allocating.init(self.alloc);
        defer batch.deinit();
        for (self.activated_targets.items) |target| {
            var delete_buffer: [2048]u8 = undefined;
            const deletion = agent_registry.deleteAssignmentsForWorkloadSql(&delete_buffer, target.request.app_name.?, target.request.workload_kind.?, target.request.workload_name.?) catch return error.InternalError;
            batch.writer.writeAll(deletion) catch return error.InternalError;
            if (self.findSnapshot(target.request)) |snapshot| {
                for (snapshot.assignments, snapshot.claims) |assignment, claim| {
                    try placement.consume(agents.records, assignment.agent_id, .{ .cpu = assignment.cpu_limit, .memory = assignment.memory_limit_mb, .gpu = claim.gpu_count });
                    appendRestoredAssignment(&batch.writer, assignment, agents.index) catch return error.InternalError;
                    placement.appendClaim(&batch.writer, assignment.id, claim) catch return error.InternalError;
                }
            }
        }
        batch.writer.writeAll(placement.cleanup_sql) catch return error.InternalError;
        try lease.commit(batch.written());
    }

    pub fn markActivatedTargets(
        self: *const RollbackState,
        rollout_targets: *RolloutTargets,
        state: []const u8,
        reason: ?[]const u8,
    ) void {
        for (self.activated_targets.items) |target| {
            rollout_targets.set(rollout_targets_mod.workloadForRequest(target.request), state, reason);
        }
    }

    fn findSnapshot(self: *const RollbackState, request: scheduler.PlacementRequest) ?*const PriorAssignmentSnapshot {
        const app_name = request.app_name orelse return null;
        const workload_kind = request.workload_kind orelse return null;
        const workload_name = request.workload_name orelse return null;
        for (self.snapshots) |*snapshot| {
            if (std.mem.eql(u8, snapshot.request.app_name orelse return null, app_name) and
                std.mem.eql(u8, snapshot.request.workload_kind orelse return null, workload_kind) and
                std.mem.eql(u8, snapshot.request.workload_name orelse return null, workload_name))
            {
                return snapshot;
            }
        }
        return null;
    }
};

pub fn activateTarget(session: mutation_session.Session, target: ScheduledTarget) ApplyError!void {
    try reconcilePriorAssignments(session, target.request, target.assignment_ids);
}

fn reconcilePriorAssignments(
    session: mutation_session.Session,
    request: scheduler.PlacementRequest,
    keep_ids: []const []const u8,
) ApplyError!void {
    const app_name = request.app_name orelse return;
    const workload_kind = request.workload_kind orelse return;
    const workload_name = request.workload_name orelse return;

    const lease = try placement.Lease.begin(session);
    defer lease.deinit();
    var batch = std.Io.Writer.Allocating.init(session.node.alloc);
    defer batch.deinit();
    sql_command.write(&batch.writer, "DELETE FROM assignments WHERE app_name = ? AND workload_kind = ? AND workload_name = ?", .{ app_name, workload_kind, workload_name }) catch return error.InternalError;
    if (keep_ids.len > 0) {
        batch.writer.writeAll(" AND id NOT IN (") catch return error.InternalError;
        for (keep_ids, 0..) |id, index| {
            if (index > 0) batch.writer.writeByte(',') catch return error.InternalError;
            sql_command.write(&batch.writer, "?", .{id}) catch return error.InternalError;
        }
        batch.writer.writeByte(')') catch return error.InternalError;
    }
    batch.writer.writeByte(';') catch return error.InternalError;
    batch.writer.writeAll(placement.cleanup_sql) catch return error.InternalError;
    try lease.commit(batch.written());
}

pub fn discardTarget(session: mutation_session.Session, target: ScheduledTarget) ApplyError!void {
    const lease = try placement.Lease.begin(session);
    defer lease.deinit();
    var batch = std.Io.Writer.Allocating.init(session.node.alloc);
    defer batch.deinit();
    for (target.assignment_ids) |id| sql_command.write(&batch.writer, "DELETE FROM assignments WHERE id = ?;", .{id}) catch return error.InternalError;
    batch.writer.writeAll(placement.cleanup_sql) catch return error.InternalError;
    try lease.commit(batch.written());
}

fn appendRestoredAssignment(writer: *std.Io.Writer, assignment: agent_registry.Assignment, index: u64) !void {
    const request: scheduler.PlacementRequest = .{
        .image = assignment.image,
        .command = assignment.command,
        .health_check_json = assignment.health_check_json,
        .cpu_limit = assignment.cpu_limit,
        .memory_limit_mb = assignment.memory_limit_mb,
        .app_name = assignment.app_name,
        .workload_kind = assignment.workload_kind,
        .workload_name = assignment.workload_name,
    };
    const gang: ?@import("../../../gpu/scheduler.zig").GangPlacement = if (assignment.gang_rank != null and assignment.gang_world_size != null and assignment.gang_master_addr != null and assignment.gang_master_port != null) .{
        .agent_id = assignment.agent_id,
        .rank = std.math.cast(u32, assignment.gang_rank.?) orelse return error.InternalError,
        .gpu_start = 0,
        .gpu_count = 0,
        .world_size = std.math.cast(u32, assignment.gang_world_size.?) orelse return error.InternalError,
        .master_addr = assignment.gang_master_addr.?,
        .master_port = std.math.cast(u16, assignment.gang_master_port.?) orelse return error.InternalError,
    } else null;
    try placement.appendAssignment(writer, assignment.id, assignment.agent_id, request, gang, index, nowRealSeconds());
}

fn copyAssignmentIds(alloc: std.mem.Allocator, ids: []const []const u8) ![]const []const u8 {
    const owned = try alloc.alloc([]const u8, ids.len);
    errdefer alloc.free(owned);
    for (ids, 0..) |id, i| {
        owned[i] = try alloc.dupe(u8, id);
        errdefer {
            for (owned[0..i]) |prior| alloc.free(prior);
        }
    }
    return owned;
}
