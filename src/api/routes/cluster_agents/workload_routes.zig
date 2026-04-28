const std = @import("std");
const scheduler = @import("../../../cluster/scheduler.zig");
const cluster_node = @import("../../../cluster/node.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const apply_release = @import("../../../manifest/apply_release.zig");
const apply_request = @import("apply_request.zig");
const deploy_routes = @import("deploy_routes.zig");
const workload_training_logs = @import("workload_training_logs.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const http = @import("../../http.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

pub fn setTestProxyTrainingLogsResponse(path: []const u8, body: []const u8) void {
    workload_training_logs.setTestProxyResponse(path, body);
}

pub fn clearTestProxyTrainingLogsResponse() void {
    workload_training_logs.clearTestProxyResponse();
}

pub fn route(request: http.Request, alloc: std.mem.Allocator, ctx: RouteContext) ?Response {
    if (!std.mem.startsWith(u8, request.path_only, "/apps/")) return null;

    const rest = request.path_only["/apps/".len..];
    if (matchWorkerRun(rest)) |parsed| {
        if (!common.validateClusterInput(parsed.app_name) or !common.validateClusterInput(parsed.worker_name)) {
            return common.badRequest("invalid app or worker name");
        }
        if (request.method != .POST) return common.methodNotAllowed();
        return handleWorkerRun(alloc, parsed.app_name, parsed.worker_name, ctx);
    }

    if (matchTrainingAction(rest)) |parsed| {
        if (!common.validateClusterInput(parsed.app_name) or !common.validateClusterInput(parsed.job_name)) {
            return common.badRequest("invalid app or training job name");
        }
        if (parsed.action == TrainingAction.start) {
            if (request.method != .POST) return common.methodNotAllowed();
            return handleTrainingStart(alloc, parsed.app_name, parsed.job_name, ctx);
        }
        if (parsed.action == TrainingAction.status) {
            if (request.method != .GET) return common.methodNotAllowed();
            return handleTrainingStatus(alloc, parsed.app_name, parsed.job_name, ctx);
        }
        if (parsed.action == TrainingAction.stop) {
            if (request.method != .POST) return common.methodNotAllowed();
            return handleTrainingStateChange(alloc, parsed.app_name, parsed.job_name, "stopped", ctx);
        }
        if (parsed.action == TrainingAction.pause) {
            if (request.method != .POST) return common.methodNotAllowed();
            return handleTrainingStateChange(alloc, parsed.app_name, parsed.job_name, "paused", ctx);
        }
        if (parsed.action == TrainingAction.resume_) {
            if (request.method != .POST) return common.methodNotAllowed();
            return handleTrainingResume(alloc, parsed.app_name, parsed.job_name, ctx);
        }
        if (parsed.action == TrainingAction.scale) {
            if (request.method != .POST) return common.methodNotAllowed();
            return handleTrainingScale(alloc, parsed.app_name, parsed.job_name, request, ctx);
        }
        if (request.method != .GET) return common.methodNotAllowed();
        return handleTrainingLogs(alloc, parsed.app_name, parsed.job_name, request, ctx);
    }

    return null;
}

const WorkerRunPath = struct {
    app_name: []const u8,
    worker_name: []const u8,
};

fn matchWorkerRun(rest: []const u8) ?WorkerRunPath {
    const workers_idx = std.mem.indexOf(u8, rest, "/workers/") orelse return null;
    const app_name = rest[0..workers_idx];
    const tail = rest[workers_idx + "/workers/".len ..];
    const slash = std.mem.indexOfScalar(u8, tail, '/') orelse return null;
    const worker_name = tail[0..slash];
    if (!std.mem.eql(u8, tail[slash..], "/run")) return null;
    if (app_name.len == 0 or worker_name.len == 0) return null;
    return .{ .app_name = app_name, .worker_name = worker_name };
}

const TrainingAction = enum { start, status, stop, pause, resume_, scale, logs };

const TrainingPath = struct {
    app_name: []const u8,
    job_name: []const u8,
    action: TrainingAction,
};

fn matchTrainingAction(rest: []const u8) ?TrainingPath {
    const idx = std.mem.indexOf(u8, rest, "/training/") orelse return null;
    const app_name = rest[0..idx];
    const tail = rest[idx + "/training/".len ..];
    const slash = std.mem.indexOfScalar(u8, tail, '/') orelse return null;
    const job_name = tail[0..slash];
    const action_str = tail[slash + 1 ..];
    if (app_name.len == 0 or job_name.len == 0) return null;

    const action = if (std.mem.eql(u8, action_str, "start"))
        TrainingAction.start
    else if (std.mem.eql(u8, action_str, "status"))
        TrainingAction.status
    else if (std.mem.eql(u8, action_str, "stop"))
        TrainingAction.stop
    else if (std.mem.eql(u8, action_str, "pause"))
        TrainingAction.pause
    else if (std.mem.eql(u8, action_str, "resume"))
        TrainingAction.resume_
    else if (std.mem.eql(u8, action_str, "scale"))
        TrainingAction.scale
    else if (std.mem.eql(u8, action_str, "logs"))
        TrainingAction.logs
    else
        return null;

    return .{ .app_name = app_name, .job_name = job_name, .action = action };
}

fn handleWorkerRun(alloc: std.mem.Allocator, app_name: []const u8, worker_name: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const latest = store.getLatestDeploymentByAppInDb(node.stateMachineDb(), alloc, app_name) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        else => common.internalError(),
    };
    defer latest.deinit(alloc);

    const worker = app_snapshot.findWorkerRunSpec(alloc, latest.config_snapshot, worker_name) catch return common.internalError();
    if (worker == null) return common.notFound();
    defer worker.?.deinit(alloc);

    const outcome = runPlacementRequests(alloc, node, &[_]scheduler.PlacementRequest{.{
        .image = worker.?.image,
        .command = worker.?.command,
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
        .app_name = app_name,
        .workload_kind = "worker",
        .workload_name = worker_name,
        .gpu_limit = worker.?.gpu_limit,
        .gpu_model = worker.?.gpu_model,
        .gpu_vram_min_mb = worker.?.gpu_vram_min_mb,
        .required_labels = worker.?.required_labels,
    }}) catch |err| return switch (err) {
        error.NotLeader => common.notLeader(alloc, node),
        else => common.internalError(),
    };
    defer freeApplyOutcomePayloads(alloc, outcome);

    const body = std.fmt.allocPrint(
        alloc,
        "{{\"app_name\":\"{s}\",\"worker\":\"{s}\",\"placed\":{d},\"failed\":{d},\"message\":\"{s}\"}}",
        .{ app_name, worker_name, outcome.placed, outcome.failed, if (outcome.failed == 0) "worker scheduled" else "worker scheduling failed" },
    ) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleTrainingStart(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8, ctx: RouteContext) Response {
    return scheduleTrainingJob(alloc, app_name, job_name, null, null, ctx);
}

fn handleTrainingResume(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const rec = store.findTrainingJobInDb(node.stateMachineDb(), alloc, app_name, job_name) catch return common.internalError();
    if (rec == null) return common.notFound();
    defer rec.?.deinit(alloc);
    return scheduleTrainingJob(alloc, app_name, job_name, rec.?.id, null, ctx);
}

fn handleTrainingScale(
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
    return scheduleTrainingJob(alloc, app_name, job_name, rec.?.id, @intCast(gpus), ctx);
}

fn handleTrainingStateChange(
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

    clearTrainingAssignments(node, app_name, job_name) catch |err| return switch (err) {
        error.NotLeader => common.notLeader(alloc, node),
        else => common.internalError(),
    };
    store.updateTrainingJobStateInDb(node.stateMachineDb(), rec.?.id, new_state, nowRealSeconds()) catch return common.internalError();
    const updated = store.getTrainingJobInDb(node.stateMachineDb(), alloc, rec.?.id) catch return common.internalError();
    defer updated.deinit(alloc);
    return formatTrainingRecordResponse(
        alloc,
        updated,
        new_state,
        if (std.mem.eql(u8, new_state, "paused")) "training job paused" else "training job stopped",
    );
}

fn handleTrainingStatus(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const rec = store.findTrainingJobInDb(node.stateMachineDb(), alloc, app_name, job_name) catch return common.internalError();
    if (rec == null) return common.notFound();
    defer rec.?.deinit(alloc);

    const body = formatTrainingRecordJson(alloc, rec.?, null, null) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleTrainingLogs(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    job_name: []const u8,
    request: http.Request,
    ctx: RouteContext,
) Response {
    return workload_training_logs.handle(alloc, app_name, job_name, request, ctx);
}

fn scheduleTrainingJob(
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
        generateClusterTrainingJobId(alloc, app_name, job_name) catch return common.internalError();
    defer alloc.free(job_id);

    const now = nowRealSeconds();
    const existing = store.findTrainingJobInDb(node.stateMachineDb(), alloc, app_name, job_name) catch return common.internalError();
    defer if (existing) |rec| rec.deinit(alloc);
    const restarts = if (existing) |rec| rec.restart_count else 0;

    clearTrainingAssignments(node, app_name, job_name) catch |err| return switch (err) {
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

    const outcome = runPlacementRequests(alloc, node, &[_]scheduler.PlacementRequest{.{
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
    defer freeApplyOutcomePayloads(alloc, outcome);

    const final_state = if (outcome.failed == 0 and outcome.placed > 0) "running" else "failed";
    store.updateTrainingJobStateInDb(node.stateMachineDb(), job_id, final_state, nowRealSeconds()) catch return common.internalError();

    const rec = store.getTrainingJobInDb(node.stateMachineDb(), alloc, job_id) catch return common.internalError();
    defer rec.deinit(alloc);

    return formatTrainingRecordResponse(
        alloc,
        rec,
        final_state,
        if (std.mem.eql(u8, final_state, "running")) "training job scheduled" else "training job scheduling failed",
    );
}

fn clearTrainingAssignments(node: *cluster_node.Node, app_name: []const u8, job_name: []const u8) !void {
    var sql_buf: [512]u8 = undefined;
    const sql = try agent_registry.deleteAssignmentsForWorkloadSql(&sql_buf, app_name, "training", job_name);
    _ = try node.propose(sql);
}

fn runPlacementRequests(
    alloc: std.mem.Allocator,
    node: *cluster_node.Node,
    requests: []const scheduler.PlacementRequest,
) deploy_routes.ClusterApplyError!apply_release.ApplyOutcome {
    const owned_requests = alloc.alloc(apply_request.ServiceRequest, requests.len) catch return deploy_routes.ClusterApplyError.InternalError;
    defer alloc.free(owned_requests);
    for (requests, 0..) |req, i| {
        owned_requests[i] = .{
            .request = req,
            .rollout = .{},
        };
    }
    const agents = agent_registry.listAgents(alloc, node.stateMachineDb()) catch return deploy_routes.ClusterApplyError.InternalError;
    defer {
        for (agents) |a| a.deinit(alloc);
        alloc.free(agents);
    }
    if (agents.len == 0) return error.InternalError;

    var backend = deploy_routes.ClusterApplyBackend{
        .alloc = alloc,
        .node = node,
        .requests = owned_requests,
        .agents = agents,
    };
    return backend.apply();
}

fn freeApplyOutcomePayloads(alloc: std.mem.Allocator, outcome: apply_release.ApplyOutcome) void {
    if (outcome.failure_details_json) |json| alloc.free(json);
    if (outcome.rollout_targets_json) |json| alloc.free(json);
    if (outcome.rollout_checkpoint_json) |json| alloc.free(json);
}

fn generateClusterTrainingJobId(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "cluster-{s}-{s}-{d}", .{ app_name, job_name, nowRealSeconds() });
}

fn formatTrainingRecordResponse(
    alloc: std.mem.Allocator,
    record: store.TrainingJobRecord,
    state: []const u8,
    message: []const u8,
) Response {
    const body = formatTrainingRecordJson(alloc, record, state, message) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn formatTrainingRecordJson(
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
