const std = @import("std");

const scheduler = @import("../../../cluster/scheduler.zig");
const cluster_node = @import("../../../cluster/node.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const http = @import("../../http.zig");
const workload_placements = @import("workload_placements.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

pub fn handleStart(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8, ctx: RouteContext) Response {
    return schedule(alloc, app_name, job_name, null, null, ctx);
}

pub fn handleResume(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const rec = store.findTrainingJobInDb(node.stateMachineDb(), alloc, app_name, job_name) catch return common.internalError();
    if (rec == null) return common.notFound();
    defer rec.?.deinit(alloc);
    return schedule(alloc, app_name, job_name, rec.?.id, null, ctx);
}

pub fn handleScale(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    job_name: []const u8,
    request: http.Request,
    ctx: RouteContext,
) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const gpus = json_helpers.extractJsonInt(request.body, "gpus") orelse return common.badRequest("missing gpus");
    if (gpus <= 0) return common.badRequest("invalid gpus");

    const rec = store.findTrainingJobInDb(node.stateMachineDb(), alloc, app_name, job_name) catch return common.internalError();
    if (rec == null) return common.notFound();
    defer rec.?.deinit(alloc);

    store.updateTrainingJobGpusInDb(node.stateMachineDb(), rec.?.id, @intCast(gpus), nowRealSeconds()) catch return common.internalError();
    return schedule(alloc, app_name, job_name, rec.?.id, @intCast(gpus), ctx);
}

pub fn handleStateChange(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    job_name: []const u8,
    new_state: []const u8,
    ctx: RouteContext,
) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const rec = store.findTrainingJobInDb(node.stateMachineDb(), alloc, app_name, job_name) catch return common.internalError();
    if (rec == null) return common.notFound();
    defer rec.?.deinit(alloc);

    clearAssignments(node, app_name, job_name) catch |err| return switch (err) {
        error.NotLeader => common.notLeader(alloc, node),
        else => common.internalError(),
    };
    store.updateTrainingJobStateInDb(node.stateMachineDb(), rec.?.id, new_state, nowRealSeconds()) catch return common.internalError();
    const updated = store.getTrainingJobInDb(node.stateMachineDb(), alloc, rec.?.id) catch return common.internalError();
    defer updated.deinit(alloc);
    return formatRecordResponse(
        alloc,
        updated,
        new_state,
        if (std.mem.eql(u8, new_state, "paused")) "training job paused" else "training job stopped",
    );
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
    app_name: []const u8,
    job_name: []const u8,
    existing_job_id: ?[]const u8,
    gpus_override: ?u32,
    ctx: RouteContext,
) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const latest = store.getLatestDeploymentByAppInDb(node.stateMachineDb(), alloc, app_name) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        else => common.internalError(),
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

    const now = nowRealSeconds();
    const existing = store.findTrainingJobInDb(node.stateMachineDb(), alloc, app_name, job_name) catch return common.internalError();
    defer if (existing) |rec| rec.deinit(alloc);
    const restarts = if (existing) |rec| rec.restart_count else 0;

    clearAssignments(node, app_name, job_name) catch |err| return switch (err) {
        error.NotLeader => common.notLeader(alloc, node),
        else => common.internalError(),
    };

    store.saveTrainingJobInDb(node.stateMachineDb(), .{
        .id = job_id,
        .name = job_name,
        .app_name = app_name,
        .state = "scheduling",
        .image = job.?.image,
        .gpus = if (gpus_override) |gpus| @intCast(gpus) else @intCast(job.?.gpus),
        .checkpoint_path = job.?.checkpoint_path,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = restarts,
        .created_at = if (existing_job_id == null) now else if (existing) |rec| rec.created_at else now,
        .updated_at = now,
    }) catch return common.internalError();

    const outcome = workload_placements.run(alloc, node, &[_]scheduler.PlacementRequest{.{
        .image = job.?.image,
        .command = job.?.command,
        .cpu_limit = job.?.cpu_limit,
        .memory_limit_mb = job.?.memory_limit_mb,
        .app_name = app_name,
        .workload_kind = "training",
        .workload_name = job_name,
        .gpu_limit = if (gpus_override) |gpus| gpus else job.?.gpus,
        .gpu_model = job.?.gpu_type,
        .gang_world_size = if (gpus_override) |gpus| gpus else job.?.gpus,
        .gpus_per_rank = 1,
    }}) catch |err| return switch (err) {
        error.NotLeader => common.notLeader(alloc, node),
        else => common.internalError(),
    };
    defer workload_placements.freeOutcomePayloads(alloc, outcome);

    const final_state = if (outcome.failed == 0 and outcome.placed > 0) "running" else "failed";
    store.updateTrainingJobStateInDb(node.stateMachineDb(), job_id, final_state, nowRealSeconds()) catch return common.internalError();

    const rec = store.getTrainingJobInDb(node.stateMachineDb(), alloc, job_id) catch return common.internalError();
    defer rec.deinit(alloc);

    return formatRecordResponse(
        alloc,
        rec,
        final_state,
        if (std.mem.eql(u8, final_state, "running")) "training job scheduled" else "training job scheduling failed",
    );
}

fn clearAssignments(node: *cluster_node.Node, app_name: []const u8, job_name: []const u8) !void {
    var sql_buf: [512]u8 = undefined;
    const sql = try agent_registry.deleteAssignmentsForWorkloadSql(&sql_buf, app_name, "training", job_name);
    _ = try node.propose(sql);
}

fn generateJobId(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "cluster-{s}-{s}-{d}", .{ app_name, job_name, nowRealSeconds() });
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
