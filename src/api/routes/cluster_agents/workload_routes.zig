const std = @import("std");
const sqlite = @import("sqlite");
const scheduler = @import("../../../cluster/scheduler.zig");
const cluster_node = @import("../../../cluster/node.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const apply_release = @import("../../../manifest/apply_release.zig");
const deploy_routes = @import("deploy_routes.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const http = @import("../../http.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

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
        .gpu_limit = worker.?.gpu_limit,
        .gpu_model = worker.?.gpu_model,
        .gpu_vram_min_mb = worker.?.gpu_vram_min_mb,
        .required_labels = worker.?.required_labels,
    }}) catch |err| return switch (err) {
        error.NotLeader => common.notLeader(alloc, node),
        else => common.internalError(),
    };

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

    store.updateTrainingJobGpusInDb(node.stateMachineDb(), rec.?.id, @intCast(gpus), std.time.timestamp()) catch return common.internalError();
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
    store.updateTrainingJobStateInDb(node.stateMachineDb(), rec.?.id, new_state, std.time.timestamp()) catch return common.internalError();
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
    _ = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const rank = if (common.extractQueryValue(request.query, "rank")) |rank_str|
        std.fmt.parseInt(u32, rank_str, 10) catch 0
    else
        0;

    var hostname_buf: [128]u8 = undefined;
    const hostname = std.fmt.bufPrint(&hostname_buf, "{s}-rank-{d}", .{ job_name, rank }) catch return common.internalError();
    const record = store.findAppContainer(alloc, app_name, hostname) catch return common.internalError();
    if (record == null) return common.notFound();
    defer record.?.deinit(alloc);

    const logs = @import("../../../runtime/logs.zig");
    const data = logs.readLogs(alloc, record.?.id) catch return common.notFound();
    return .{ .status = .ok, .body = data, .allocated = true, .content_type = "text/plain" };
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

    const now = std.time.timestamp();
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

    const final_state = if (outcome.failed == 0 and outcome.placed > 0) "running" else "failed";
    store.updateTrainingJobStateInDb(node.stateMachineDb(), job_id, final_state, std.time.timestamp()) catch return common.internalError();

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
    const owned_requests = alloc.dupe(scheduler.PlacementRequest, requests) catch return deploy_routes.ClusterApplyError.InternalError;
    defer alloc.free(owned_requests);
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

fn generateClusterTrainingJobId(alloc: std.mem.Allocator, app_name: []const u8, job_name: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "cluster-{s}-{s}-{d}", .{ app_name, job_name, std.time.timestamp() });
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
    var json_buf: std.ArrayList(u8) = .empty;
    errdefer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

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
    return json_buf.toOwnedSlice(alloc);
}

const RouteFlowHarness = struct {
    alloc: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    node: cluster_node.Node,

    fn init(alloc: std.mem.Allocator) !RouteFlowHarness {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();

        var path_buf: [512]u8 = undefined;
        const tmp_path = tmp.dir.realpath(".", &path_buf) catch return error.SkipZigTest;

        var node = cluster_node.Node.init(alloc, .{
            .id = 1,
            .port = 0,
            .peers = &.{},
            .data_dir = tmp_path,
        }) catch return error.SkipZigTest;
        errdefer node.deinit();

        node.raft.role = .leader;
        node.leader_id = node.config.id;

        var harness = RouteFlowHarness{
            .alloc = alloc,
            .tmp = tmp,
            .node = node,
        };
        try harness.seedActiveAgent();
        return harness;
    }

    fn deinit(self: *RouteFlowHarness) void {
        self.node.deinit();
        self.tmp.cleanup();
    }

    fn ctx(self: *RouteFlowHarness) RouteContext {
        return .{ .cluster = &self.node, .join_token = null };
    }

    fn applyCommitted(self: *RouteFlowHarness) void {
        self.node.state_machine.applyUpTo(&self.node.log, self.alloc, self.node.log.lastIndex());
    }

    fn seedActiveAgent(self: *RouteFlowHarness) !void {
        self.node.stateMachineDb().exec(
            "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role, labels, gpu_count, gpu_used, gpu_model, gpu_vram_mb) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            .{},
            .{ "abc123def456", "10.0.0.2:7701", "active", @as(i64, 8), @as(i64, 16384), @as(i64, 0), @as(i64, 0), @as(i64, 0), @as(i64, 100), @as(i64, 100), "agent", "", @as(i64, 4), @as(i64, 0), "L4", @as(i64, 24576) },
        ) catch return error.SkipZigTest;
    }

    fn seedLatestRelease(self: *RouteFlowHarness, app_name: []const u8, snapshot: []const u8) !void {
        try store.saveDeploymentInDb(self.node.stateMachineDb(), .{
            .id = "dep-seed",
            .app_name = app_name,
            .service_name = app_name,
            .trigger = "apply",
            .manifest_hash = "sha256:seed",
            .config_snapshot = snapshot,
            .status = "completed",
            .message = "apply completed",
            .created_at = 100,
        });
    }
};

fn makeRequest(method: http.Method, path: []const u8, body: []const u8, query: []const u8) http.Request {
    return .{
        .method = method,
        .path = path,
        .path_only = path,
        .query = query,
        .headers_raw = "",
        .body = body,
        .content_length = body.len,
    };
}

fn freeResponse(alloc: std.mem.Allocator, response: Response) void {
    if (response.allocated) alloc.free(response.body);
}

fn countTrainingAssignments(db: *sqlite.Db, app_name: []const u8, job_name: []const u8) usize {
    const Row = struct { count: i64 };
    const row = (db.one(
        Row,
        "SELECT COUNT(*) AS count FROM assignments WHERE app_name = ? AND workload_kind = 'training' AND workload_name = ?;",
        .{},
        .{ app_name, job_name },
    ) catch unreachable) orelse unreachable;
    return @intCast(row.count);
}

test "route rejects worker run without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = makeRequest(.POST, "/apps/demo-app/workers/migrate/run", "", "");
    const resp = route(req, std.testing.allocator, ctx).?;
    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "route rejects training status without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = makeRequest(.GET, "/apps/demo-app/training/finetune/status", "", "");
    const resp = route(req, std.testing.allocator, ctx).?;
    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "worker run route schedules worker from latest app snapshot" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    try harness.seedLatestRelease(
        "demo-app",
        "{\"app_name\":\"demo-app\",\"services\":[],\"workers\":[{\"name\":\"migrate\",\"image\":\"alpine:latest\",\"command\":[\"/bin/sh\",\"-c\",\"echo ok\"],\"gpu_limit\":0,\"required_labels\":[]}],\"crons\":[],\"training_jobs\":[]}",
    );

    const resp = route(
        makeRequest(.POST, "/apps/demo-app/workers/migrate/run", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, resp);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"worker\":\"migrate\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"placed\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"failed\":0") != null);
}

test "training start and status routes persist job state from app snapshot" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    try harness.seedLatestRelease(
        "demo-app",
        "{\"app_name\":\"demo-app\",\"services\":[],\"workers\":[],\"crons\":[],\"training_jobs\":[{\"name\":\"finetune\",\"image\":\"pytorch:latest\",\"command\":[\"python\",\"train.py\"],\"gpus\":1,\"cpu_limit\":2000,\"memory_limit_mb\":4096}]}",
    );

    const start_resp = route(
        makeRequest(.POST, "/apps/demo-app/training/finetune/start", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, start_resp);

    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);
    try std.testing.expect(std.mem.indexOf(u8, start_resp.body, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, start_resp.body, "\"training_job\":\"finetune\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, start_resp.body, "\"state\":\"running\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, start_resp.body, "\"gpus\":1") != null);

    const status_resp = route(
        makeRequest(.GET, "/apps/demo-app/training/finetune/status", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, status_resp);

    try std.testing.expectEqual(http.StatusCode.ok, status_resp.status);
    try std.testing.expect(std.mem.indexOf(u8, status_resp.body, "\"state\":\"running\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_resp.body, "\"training_job\":\"finetune\"") != null);
}

test "training start tags assignments with workload metadata" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    try harness.seedLatestRelease(
        "demo-app",
        "{\"app_name\":\"demo-app\",\"services\":[],\"workers\":[],\"crons\":[],\"training_jobs\":[{\"name\":\"finetune\",\"image\":\"pytorch:latest\",\"command\":[\"python\",\"train.py\"],\"gpus\":2,\"cpu_limit\":2000,\"memory_limit_mb\":4096}]}",
    );

    const start_resp = route(
        makeRequest(.POST, "/apps/demo-app/training/finetune/start", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, start_resp);
    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);
    harness.applyCommitted();
    try std.testing.expectEqual(@as(usize, 2), countTrainingAssignments(harness.node.stateMachineDb(), "demo-app", "finetune"));
}

test "training pause route clears scheduled assignments" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    try harness.seedLatestRelease(
        "demo-app",
        "{\"app_name\":\"demo-app\",\"services\":[],\"workers\":[],\"crons\":[],\"training_jobs\":[{\"name\":\"finetune\",\"image\":\"pytorch:latest\",\"command\":[\"python\",\"train.py\"],\"gpus\":2,\"cpu_limit\":2000,\"memory_limit_mb\":4096}]}",
    );

    const start_resp = route(
        makeRequest(.POST, "/apps/demo-app/training/finetune/start", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, start_resp);
    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);

    const pause_resp = route(
        makeRequest(.POST, "/apps/demo-app/training/finetune/pause", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, pause_resp);
    harness.applyCommitted();

    try std.testing.expectEqual(http.StatusCode.ok, pause_resp.status);
    try std.testing.expect(std.mem.indexOf(u8, pause_resp.body, "\"state\":\"paused\"") != null);
    try std.testing.expectEqual(@as(usize, 0), countTrainingAssignments(harness.node.stateMachineDb(), "demo-app", "finetune"));
}

test "training scale route replaces prior scheduled assignments" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    try harness.seedLatestRelease(
        "demo-app",
        "{\"app_name\":\"demo-app\",\"services\":[],\"workers\":[],\"crons\":[],\"training_jobs\":[{\"name\":\"finetune\",\"image\":\"pytorch:latest\",\"command\":[\"python\",\"train.py\"],\"gpus\":1,\"cpu_limit\":2000,\"memory_limit_mb\":4096}]}",
    );

    const start_resp = route(
        makeRequest(.POST, "/apps/demo-app/training/finetune/start", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, start_resp);
    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);

    const scale_resp = route(
        makeRequest(.POST, "/apps/demo-app/training/finetune/scale", "{\"gpus\":2}", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, scale_resp);
    harness.applyCommitted();

    try std.testing.expectEqual(http.StatusCode.ok, scale_resp.status);
    try std.testing.expect(std.mem.indexOf(u8, scale_resp.body, "\"state\":\"running\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, scale_resp.body, "\"gpus\":2") != null);
    try std.testing.expectEqual(@as(usize, 2), countTrainingAssignments(harness.node.stateMachineDb(), "demo-app", "finetune"));
}
