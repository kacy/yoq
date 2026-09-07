const std = @import("std");

const mutation = @import("../../../cluster/mutation_session.zig");
const sql = @import("../../../cluster/sql_command.zig");
const placement = @import("../../../cluster/placement_transaction.zig");
const apply_lock = @import("../../../manifest/apply_lock.zig");
const deploy_routes = @import("deploy_routes.zig");
const scheduler = @import("../../../cluster/scheduler.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const http = @import("../../http.zig");
const workload_placements = @import("workload_placements.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

const Action = enum { start, resume_job, scale, pause, stop };

pub fn handleStart(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8, ctx: RouteContext) Response {
    return mutate(alloc, app_name, job_name, .start, null, ctx);
}

pub fn handleResume(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8, ctx: RouteContext) Response {
    return mutate(alloc, app_name, job_name, .resume_job, null, ctx);
}

pub fn handleScale(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8, request: http.Request, ctx: RouteContext) Response {
    const numbers = @import("../../../lib/json_numbers.zig");
    const parsed = numbers.parse(alloc, request.body) catch return common.badRequest("invalid gpus");
    defer parsed.deinit();
    const gpus = (numbers.optional(u32, parsed.value, "gpus", 1, std.math.maxInt(u32)) catch return common.badRequest("invalid gpus")) orelse return common.badRequest("missing gpus");
    return mutate(alloc, app_name, job_name, .scale, gpus, ctx);
}

pub fn handleStateChange(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8, state: []const u8, ctx: RouteContext) Response {
    const action: Action = if (std.mem.eql(u8, state, "paused")) .pause else if (std.mem.eql(u8, state, "stopped")) .stop else return common.badRequest("invalid training state");
    return mutate(alloc, app_name, job_name, action, null, ctx);
}

fn mutate(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8, action: Action, gpus_override: ?u32, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    var lock = apply_lock.acquire(alloc, app_name) catch |err| return switch (err) {
        error.AlreadyLocked => common.conflict("app mutation already in progress"),
        else => common.internalError(),
    };
    defer lock.release();
    const session = mutation.Session.begin(node) catch return common.notLeader(alloc, node);
    session.synchronize() catch |err| return deploy_routes.mutationFailure(alloc, node, err);
    const existing = findRecord(alloc, session, app_name, job_name) catch |err| return deploy_routes.mutationFailure(alloc, node, err);
    defer if (existing) |record| record.deinit(alloc);
    if (action != .start and existing == null) return common.notFound();

    if (action == .pause or action == .stop) {
        const state = if (action == .pause) "paused" else "stopped";
        var batch = std.Io.Writer.Allocating.init(alloc);
        defer batch.deinit();
        appendClearAssignments(&batch.writer, app_name, job_name) catch return common.internalError();
        appendState(&batch.writer, existing.?.id, state, nowRealSeconds()) catch return common.internalError();
        session.commit(batch.written()) catch |err| return deploy_routes.mutationFailure(alloc, node, err);
        const updated = readRecord(alloc, session, existing.?.id) catch |err| return deploy_routes.mutationFailure(alloc, node, err);
        defer updated.deinit(alloc);
        return formatRecordResponse(alloc, updated, updated.state, if (action == .pause) "training job paused" else "training job stopped");
    }
    return schedule(alloc, session, app_name, job_name, if (action == .start) null else existing.?.id, gpus_override, existing);
}

pub fn handleStatus(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const rec = store.findTrainingJobInDb(node.stateMachineDb(), alloc, app_name, job_name) catch return common.internalError();
    if (rec == null) return common.notFound();
    defer rec.?.deinit(alloc);

    const body = formatRecordJson(alloc, rec.?, null, null) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn schedule(
    alloc: std.mem.Allocator,
    session: mutation.Session,
    app_name: []const u8,
    job_name: []const u8,
    existing_job_id: ?[]const u8,
    gpus_override: ?u32,
    existing: ?store.TrainingJobRecord,
) Response {
    const node = session.node;
    const latest = readLatestRelease(alloc, session, app_name) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        else => deploy_routes.mutationFailure(alloc, node, err),
    };
    defer latest.deinit(alloc);

    const job = app_snapshot.findTrainingJobSpec(alloc, latest.config_snapshot, job_name) catch return common.internalError();
    if (job == null) return common.notFound();
    defer job.?.deinit(alloc);

    const job_id = if (existing_job_id) |id|
        alloc.dupe(u8, id) catch return common.internalError()
    else
        generateJobId(alloc, app_name, job_name) catch return common.internalError();
    defer alloc.free(job_id);

    const desired_gpus = gpus_override orelse if (existing_job_id != null)
        std.math.cast(u32, existing.?.gpus) orelse return common.internalError()
    else
        job.?.gpus;
    if (desired_gpus == 0) return common.badRequest("invalid gpus");
    const now = nowRealSeconds();
    var batch = std.Io.Writer.Allocating.init(alloc);
    defer batch.deinit();
    appendClearAssignments(&batch.writer, app_name, job_name) catch return common.internalError();
    appendRecord(&batch.writer, .{
        .id = job_id,
        .name = job_name,
        .app_name = app_name,
        .state = "scheduling",
        .image = job.?.image,
        .gpus = desired_gpus,
        .checkpoint_path = job.?.checkpoint_path,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = if (existing) |record| record.restart_count else 0,
        .created_at = if (existing_job_id != null and existing != null) existing.?.created_at else now,
        .updated_at = now,
    }) catch return common.internalError();
    session.commit(batch.written()) catch |err| return deploy_routes.mutationFailure(alloc, node, err);

    const outcome = workload_placements.runWithSession(alloc, session, &[_]scheduler.PlacementRequest{.{
        .image = job.?.image,
        .command = job.?.command,
        .cpu_limit = job.?.cpu_limit,
        .memory_limit_mb = job.?.memory_limit_mb,
        .app_name = app_name,
        .workload_kind = "training",
        .workload_name = job_name,
        .gpu_limit = desired_gpus,
        .gpu_model = job.?.gpu_type,
        .gang_world_size = desired_gpus,
        .gpus_per_rank = 1,
    }}) catch |err| return deploy_routes.mutationFailure(alloc, node, err);
    defer workload_placements.freeOutcomePayloads(alloc, outcome);

    const final_state = if (outcome.failed == 0 and outcome.placed > 0) "running" else "failed";
    batch.clearRetainingCapacity();
    appendState(&batch.writer, job_id, final_state, nowRealSeconds()) catch return common.internalError();
    session.commit(batch.written()) catch |err| return deploy_routes.mutationFailure(alloc, node, err);

    const rec = readRecord(alloc, session, job_id) catch |err| return deploy_routes.mutationFailure(alloc, node, err);
    defer rec.deinit(alloc);

    return formatRecordResponse(
        alloc,
        rec,
        final_state,
        if (std.mem.eql(u8, final_state, "running")) "training job scheduled" else "training job scheduling failed",
    );
}

fn findRecord(alloc: std.mem.Allocator, session: mutation.Session, app_name: []const u8, job_name: []const u8) mutation.Error!?store.TrainingJobRecord {
    session.node.mu.lockUncancelable(std.Options.debug_io);
    defer session.node.mu.unlock(std.Options.debug_io);
    try session.checkLocked();
    return store.findTrainingJobInDb(session.node.stateMachineDb(), alloc, app_name, job_name) catch error.InternalError;
}

fn readLatestRelease(alloc: std.mem.Allocator, session: mutation.Session, app_name: []const u8) (mutation.Error || error{NotFound})!store.DeploymentRecord {
    session.node.mu.lockUncancelable(std.Options.debug_io);
    defer session.node.mu.unlock(std.Options.debug_io);
    try session.checkLocked();
    return store.getLatestDeploymentByAppInDb(session.node.stateMachineDb(), alloc, app_name) catch |err| switch (err) {
        error.NotFound => error.NotFound,
        else => error.InternalError,
    };
}

fn readRecord(alloc: std.mem.Allocator, session: mutation.Session, id: []const u8) mutation.Error!store.TrainingJobRecord {
    session.node.mu.lockUncancelable(std.Options.debug_io);
    defer session.node.mu.unlock(std.Options.debug_io);
    try session.checkLocked();
    return store.getTrainingJobInDb(session.node.stateMachineDb(), alloc, id) catch error.InternalError;
}

fn appendClearAssignments(writer: *std.Io.Writer, app_name: []const u8, job_name: []const u8) !void {
    try writer.writeAll(placement.schema_sql);
    try sql.write(writer, "DELETE FROM assignments WHERE app_name = ? AND workload_kind = 'training' AND workload_name = ?;", .{ app_name, job_name });
    try writer.writeAll(placement.cleanup_sql);
}

fn appendRecord(writer: *std.Io.Writer, record: store.TrainingJobRecord) !void {
    try sql.write(writer, "INSERT OR REPLACE INTO training_jobs (id, name, app_name, state, image, gpus, checkpoint_path, checkpoint_interval, checkpoint_keep, restart_count, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", .{ record.id, record.name, record.app_name, record.state, record.image, record.gpus, record.checkpoint_path, record.checkpoint_interval, record.checkpoint_keep, record.restart_count, record.created_at, record.updated_at });
}

fn appendState(writer: *std.Io.Writer, id: []const u8, state: []const u8, now: i64) !void {
    try sql.write(writer, "UPDATE training_jobs SET state = ?, updated_at = ? WHERE id = ?;", .{ state, now, id });
}

fn generateJobId(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8) ![]u8 {
    var suffix: [12]u8 = undefined;
    scheduler.generateAssignmentId(&suffix);
    return std.fmt.allocPrint(alloc, "cluster-{s}-{s}-{s}", .{ app_name, job_name, suffix });
}

fn formatRecordResponse(
    alloc: std.mem.Allocator,
    record: store.TrainingJobRecord,
    state: []const u8,
    message: []const u8,
) Response {
    const body = formatRecordJson(alloc, record, state, message) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn formatRecordJson(
    alloc: std.mem.Allocator,
    record: store.TrainingJobRecord,
    state_override: ?[]const u8,
    message: ?[]const u8,
) ![]u8 {
    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();

    const writer = &json_buf_writer.writer;

    try writer.writeByte('{');
    try json_helpers.writeJsonStringField(writer, "app_name", record.app_name);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "training_job", record.name);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "job_id", record.id);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "state", state_override orelse record.state);
    try writer.print(",\"gpus\":{d},\"restart_count\":{d}", .{ record.gpus, record.restart_count });
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "checkpoint_path", record.checkpoint_path);
    try writer.print(",\"updated_at\":{d}", .{record.updated_at});
    if (message) |msg| {
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "message", msg);
    }
    try writer.writeByte('}');
    return json_buf_writer.toOwnedSlice();
}

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}
