const std = @import("std");

const scheduler = @import("../../../cluster/scheduler.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const workload_placements = @import("workload_placements.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

pub fn handleRun(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    worker_name: []const u8,
    ctx: RouteContext,
) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const latest = store.getLatestDeploymentByAppInDb(node.stateMachineDb(), alloc, app_name) catch |err| return switch (err) {
        error.NotFound => common.notFound(),
        else => common.internalError(),
    };
    defer latest.deinit(alloc);

    const worker = app_snapshot.findWorkerRunSpec(alloc, latest.config_snapshot, worker_name) catch return common.internalError();
    if (worker == null) return common.notFound();
    defer worker.?.deinit(alloc);

    const outcome = workload_placements.run(alloc, node, &[_]scheduler.PlacementRequest{.{
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
    defer workload_placements.freeOutcomePayloads(alloc, outcome);

    const body = std.fmt.allocPrint(
        alloc,
        "{{\"app_name\":\"{s}\",\"worker\":\"{s}\",\"placed\":{d},\"failed\":{d},\"message\":\"{s}\"}}",
        .{ app_name, worker_name, outcome.placed, outcome.failed, if (outcome.failed == 0) "worker scheduled" else "worker scheduling failed" },
    ) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}
