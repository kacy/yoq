const std = @import("std");
const workload_training_jobs = @import("workload_training_jobs.zig");
const workload_training_logs = @import("workload_training_logs.zig");
const workload_workers = @import("workload_workers.zig");
const common = @import("../common.zig");
const http = @import("../../http.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

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
        return workload_workers.handleRun(alloc, parsed.app_name, parsed.worker_name, ctx);
    }

    if (matchTrainingAction(rest)) |parsed| {
        if (!common.validateClusterInput(parsed.app_name) or !common.validateClusterInput(parsed.job_name)) {
            return common.badRequest("invalid app or training job name");
        }
        if (parsed.action == TrainingAction.start) {
            if (request.method != .POST) return common.methodNotAllowed();
            return workload_training_jobs.handleStart(alloc, parsed.app_name, parsed.job_name, ctx);
        }
        if (parsed.action == TrainingAction.status) {
            if (request.method != .GET) return common.methodNotAllowed();
            return workload_training_jobs.handleStatus(alloc, parsed.app_name, parsed.job_name, ctx);
        }
        if (parsed.action == TrainingAction.stop) {
            if (request.method != .POST) return common.methodNotAllowed();
            return workload_training_jobs.handleStateChange(alloc, parsed.app_name, parsed.job_name, "stopped", ctx);
        }
        if (parsed.action == TrainingAction.pause) {
            if (request.method != .POST) return common.methodNotAllowed();
            return workload_training_jobs.handleStateChange(alloc, parsed.app_name, parsed.job_name, "paused", ctx);
        }
        if (parsed.action == TrainingAction.resume_) {
            if (request.method != .POST) return common.methodNotAllowed();
            return workload_training_jobs.handleResume(alloc, parsed.app_name, parsed.job_name, ctx);
        }
        if (parsed.action == TrainingAction.scale) {
            if (request.method != .POST) return common.methodNotAllowed();
            return workload_training_jobs.handleScale(alloc, parsed.app_name, parsed.job_name, request, ctx);
        }
        if (request.method != .GET) return common.methodNotAllowed();
        return workload_training_logs.handle(alloc, parsed.app_name, parsed.job_name, request, ctx);
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
