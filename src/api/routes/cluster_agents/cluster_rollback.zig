const std = @import("std");
const sqlite = @import("sqlite");

const scheduler = @import("../../../cluster/scheduler.zig");
const cluster_node = @import("../../../cluster/node.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const apply_request = @import("apply_request.zig");
const rollout_targets_mod = @import("rollout_targets.zig");

const ActivatedTarget = rollout_targets_mod.ActivatedTarget;
const RolloutTargetBuilder = rollout_targets_mod.RolloutTargetBuilder;
const ScheduledTarget = rollout_targets_mod.ScheduledTarget;

pub const ApplyError = error{
    NotLeader,
    InternalError,
};

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

const PriorAssignmentSnapshot = struct {
    request: scheduler.PlacementRequest,
    assignments: []agent_registry.Assignment,

    fn deinit(self: *const PriorAssignmentSnapshot, alloc: std.mem.Allocator) void {
        for (self.assignments) |assignment| assignment.deinit(alloc);
        alloc.free(self.assignments);
    }
};

pub const RollbackState = struct {
    alloc: std.mem.Allocator,
    snapshots: []PriorAssignmentSnapshot,
    activated_targets: std.ArrayListUnmanaged(ActivatedTarget) = .empty,

    pub fn capture(
        alloc: std.mem.Allocator,
        db: *sqlite.Db,
        requests: []const apply_request.ServiceRequest,
    ) ApplyError!RollbackState {
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
            snapshots.append(alloc, .{
                .request = req.request,
                .assignments = assignments,
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

    pub fn rollbackActivatedTargets(self: *RollbackState, node: *cluster_node.Node) ApplyError!void {
        for (self.activated_targets.items) |target| {
            try deleteAssignmentsForRequest(node, target.request);
            if (self.findSnapshot(target.request)) |snapshot| {
                for (snapshot.assignments) |assignment| {
                    try restoreAssignment(node, assignment);
                }
            }
        }
    }

    pub fn markActivatedTargets(
        self: *const RollbackState,
        rollout_targets: *RolloutTargetBuilder,
        state: []const u8,
        reason: ?[]const u8,
    ) void {
        for (self.activated_targets.items) |target| {
            rollout_targets.setActivatedState(target, state, reason);
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

pub fn activateTarget(node: *cluster_node.Node, target: ScheduledTarget) ApplyError!void {
    try reconcilePriorAssignments(node, target.request, target.assignment_ids);
}

fn reconcilePriorAssignments(
    node: *cluster_node.Node,
    request: scheduler.PlacementRequest,
    keep_ids: []const []const u8,
) ApplyError!void {
    const app_name = request.app_name orelse return;
    const workload_kind = request.workload_kind orelse return;
    const workload_name = request.workload_name orelse return;

    var sql_buf: [2048]u8 = undefined;
    const sql = agent_registry.deleteOtherAssignmentsForWorkloadSql(
        &sql_buf,
        app_name,
        workload_kind,
        workload_name,
        keep_ids,
    ) catch return ApplyError.InternalError;
    _ = node.propose(sql) catch return ApplyError.NotLeader;
}

pub fn discardTarget(node: *cluster_node.Node, target: ScheduledTarget) ApplyError!void {
    var sql_buf: [2048]u8 = undefined;
    const sql = agent_registry.deleteAssignmentsByIdsSql(&sql_buf, target.assignment_ids) catch return ApplyError.InternalError;
    _ = node.propose(sql) catch return ApplyError.NotLeader;
}

fn deleteAssignmentsForRequest(node: *cluster_node.Node, request: scheduler.PlacementRequest) ApplyError!void {
    const app_name = request.app_name orelse return;
    const workload_kind = request.workload_kind orelse return;
    const workload_name = request.workload_name orelse return;

    var sql_buf: [2048]u8 = undefined;
    const sql = agent_registry.deleteAssignmentsForWorkloadSql(
        &sql_buf,
        app_name,
        workload_kind,
        workload_name,
    ) catch return ApplyError.InternalError;
    _ = node.propose(sql) catch return ApplyError.NotLeader;
}

fn restoreAssignment(node: *cluster_node.Node, assignment: agent_registry.Assignment) ApplyError!void {
    var sql_buf: [2048]u8 = undefined;
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

    const sql = if (assignment.gang_rank != null and assignment.gang_world_size != null and assignment.gang_master_addr != null and assignment.gang_master_port != null)
        scheduler.assignmentSqlGang(
            &sql_buf,
            assignment.id,
            assignment.agent_id,
            request,
            nowRealSeconds(),
            .{
                .agent_id = assignment.agent_id,
                .rank = @intCast(assignment.gang_rank.?),
                .gpu_start = 0,
                .gpu_count = 0,
                .world_size = @intCast(assignment.gang_world_size.?),
                .master_addr = assignment.gang_master_addr.?,
                .master_port = @intCast(assignment.gang_master_port.?),
            },
        ) catch return ApplyError.InternalError
    else
        scheduler.assignmentSql(
            &sql_buf,
            assignment.id,
            assignment.agent_id,
            request,
            nowRealSeconds(),
        ) catch return ApplyError.InternalError;

    _ = node.propose(sql) catch return ApplyError.NotLeader;
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
