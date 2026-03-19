const std = @import("std");
const scheduler = @import("../../../cluster/scheduler.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const volumes_mod = @import("../../../state/volumes.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const common = @import("../common.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;

pub fn handleDeploy(alloc: std.mem.Allocator, request: @import("../../http.zig").Request, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (request.body.len == 0) return common.badRequest("missing request body");

    var requests: std.ArrayListUnmanaged(scheduler.PlacementRequest) = .empty;
    defer requests.deinit(alloc);

    const volume_app = extractJsonString(request.body, "volume_app");

    var pos: usize = 0;
    while (pos < request.body.len) {
        const block_start = std.mem.indexOfPos(u8, request.body, pos, "{\"image\":\"") orelse break;
        const block_end = std.mem.indexOfPos(u8, request.body, block_start + 1, "}") orelse break;
        const block = request.body[block_start .. block_end + 1];

        const image = extractJsonString(block, "image") orelse {
            pos = block_end + 1;
            continue;
        };
        const command = extractJsonString(block, "command") orelse "";
        const cpu_limit = extractJsonInt(block, "cpu_limit") orelse 1000;
        const memory_limit_mb = extractJsonInt(block, "memory_limit_mb") orelse 256;
        const gpu_limit = extractJsonInt(block, "gpu_limit") orelse 0;
        const gpu_model = json_helpers.extractJsonString(block, "gpu_model");
        const gpu_vram_min = extractJsonInt(block, "gpu_vram_min_mb");
        const required_labels = extractJsonString(block, "required_labels") orelse "";
        const gang_world_size_val = extractJsonInt(block, "gang_world_size");
        const gpus_per_rank_val = extractJsonInt(block, "gpus_per_rank");

        if (!common.validateClusterInput(image)) {
            pos = block_end + 1;
            continue;
        }
        if (command.len > 0 and !common.validateClusterInput(command)) {
            pos = block_end + 1;
            continue;
        }

        requests.append(alloc, .{
            .image = image,
            .command = command,
            .cpu_limit = cpu_limit,
            .memory_limit_mb = memory_limit_mb,
            .gpu_limit = gpu_limit,
            .gpu_model = gpu_model,
            .gpu_vram_min_mb = if (gpu_vram_min) |v| @as(u64, @intCast(@max(0, v))) else null,
            .required_labels = required_labels,
            .gang_world_size = if (gang_world_size_val) |v| @intCast(@max(0, v)) else 0,
            .gpus_per_rank = if (gpus_per_rank_val) |v| @intCast(@max(1, v)) else 1,
        }) catch return common.internalError();

        pos = block_end + 1;
    }

    if (requests.items.len == 0) return common.badRequest("no services to deploy");

    const db = node.stateMachineDb();

    const vol_constraints = if (volume_app) |app_name|
        volumes_mod.getVolumesByApp(alloc, db, app_name) catch &[_]volumes_mod.VolumeConstraint{}
    else
        &[_]volumes_mod.VolumeConstraint{};
    defer if (volume_app != null) alloc.free(vol_constraints);

    if (vol_constraints.len > 0) {
        for (requests.items) |*req| {
            req.volume_constraints = vol_constraints;
        }
    }

    const agents = agent_registry.listAgents(alloc, db) catch return common.internalError();
    defer {
        for (agents) |a| a.deinit(alloc);
        alloc.free(agents);
    }

    if (agents.len == 0) {
        return .{ .status = .bad_request, .body = "{\"error\":\"no agents available\"}", .allocated = false };
    }

    var placed: usize = 0;
    var failed: usize = 0;

    for (requests.items) |req| {
        if (req.gang_world_size > 0) {
            const gang_placements = scheduler.scheduleGang(alloc, req, agents) catch {
                failed += 1;
                continue;
            };

            if (gang_placements) |gps| {
                defer alloc.free(gps);

                var gang_ok = true;
                for (gps) |gp| {
                    var id_buf: [12]u8 = undefined;
                    scheduler.generateAssignmentId(&id_buf);

                    var sql_buf: [2048]u8 = undefined;
                    const sql = scheduler.assignmentSqlGang(
                        &sql_buf,
                        &id_buf,
                        gp.agent_id,
                        req,
                        std.time.timestamp(),
                        gp,
                    ) catch {
                        gang_ok = false;
                        break;
                    };

                    _ = node.propose(sql) catch {
                        return common.notLeader(alloc, node);
                    };
                }

                if (gang_ok) {
                    placed += gps.len;
                } else {
                    failed += req.gang_world_size;
                }
            } else {
                failed += req.gang_world_size;
            }
        }
    }

    var normal_requests: std.ArrayListUnmanaged(scheduler.PlacementRequest) = .empty;
    defer normal_requests.deinit(alloc);
    for (requests.items) |req| {
        if (req.gang_world_size == 0) {
            normal_requests.append(alloc, req) catch {
                failed += 1;
                continue;
            };
        }
    }

    if (normal_requests.items.len > 0) {
        const placements = scheduler.schedule(alloc, normal_requests.items, agents) catch return common.internalError();
        defer alloc.free(placements);

        for (placements) |maybe_placement| {
            if (maybe_placement) |placement| {
                var id_buf: [12]u8 = undefined;
                scheduler.generateAssignmentId(&id_buf);

                var sql_buf: [1024]u8 = undefined;
                const sql = scheduler.assignmentSql(
                    &sql_buf,
                    &id_buf,
                    placement.agent_id,
                    normal_requests.items[placement.request_idx],
                    std.time.timestamp(),
                ) catch {
                    failed += 1;
                    continue;
                };

                _ = node.propose(sql) catch {
                    return common.notLeader(alloc, node);
                };
                placed += 1;
            } else {
                failed += 1;
            }
        }
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);
    std.fmt.format(writer, "{{\"placed\":{d},\"failed\":{d}}}", .{ placed, failed }) catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}
