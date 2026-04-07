const std = @import("std");
const scheduler = @import("../../../cluster/scheduler.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const volumes_mod = @import("../../../state/volumes.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const deployment_store = @import("../../../manifest/update/deployment_store.zig");
const common = @import("../common.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;
const extractJsonArray = json_helpers.extractJsonArray;

const ResponseMode = enum {
    legacy,
    app,
};

fn extractJsonStringArray(alloc: std.mem.Allocator, json: []const u8, key: []const u8) !?[]u8 {
    const array_json = extractJsonArray(json, key) orelse return null;
    if (array_json.len < 2) return null;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    var pos: usize = 1;
    var first = true;
    while (pos < array_json.len - 1) {
        while (pos < array_json.len - 1 and (array_json[pos] == ' ' or array_json[pos] == '\n' or array_json[pos] == '\r' or array_json[pos] == '\t' or array_json[pos] == ',')) : (pos += 1) {}
        if (pos >= array_json.len - 1) break;
        if (array_json[pos] != '"') return null;
        pos += 1;
        const start = pos;

        while (pos < array_json.len - 1) : (pos += 1) {
            if (array_json[pos] == '\\') {
                pos += 1;
                if (pos >= array_json.len - 1) return null;
                continue;
            }
            if (array_json[pos] == '"') break;
        }
        if (pos >= array_json.len - 1) return null;

        if (!first) try out.append(alloc, ' ');
        first = false;
        try out.appendSlice(alloc, array_json[start..pos]);
        pos += 1;
    }

    return try out.toOwnedSlice(alloc);
}

fn extractCommandString(alloc: std.mem.Allocator, block: []const u8) ![]const u8 {
    if (extractJsonString(block, "command")) |command| {
        return alloc.dupe(u8, command);
    }
    if (try extractJsonStringArray(alloc, block, "command")) |joined| {
        defer alloc.free(joined);
        return alloc.dupe(u8, joined);
    }
    return alloc.dupe(u8, "");
}

fn handleApply(
    alloc: std.mem.Allocator,
    request: @import("../../http.zig").Request,
    ctx: RouteContext,
    response_mode: ResponseMode,
) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (request.body.len == 0) return common.badRequest("missing request body");

    var requests: std.ArrayListUnmanaged(scheduler.PlacementRequest) = .empty;
    defer {
        for (requests.items) |req| alloc.free(req.command);
        requests.deinit(alloc);
    }

    const app_name = extractJsonString(request.body, "app_name") orelse extractJsonString(request.body, "volume_app");
    if (response_mode == .app and app_name == null) {
        return common.badRequest("missing app_name");
    }
    const services_json = extractJsonArray(request.body, "services") orelse
        return common.badRequest("missing services array");

    var iter = json_helpers.extractJsonObjects(services_json);
    while (iter.next()) |block| {
        const image = extractJsonString(block, "image") orelse {
            continue;
        };
        const command = extractCommandString(alloc, block) catch return common.internalError();
        errdefer alloc.free(command);
        const cpu_limit = extractJsonInt(block, "cpu_limit") orelse 1000;
        const memory_limit_mb = extractJsonInt(block, "memory_limit_mb") orelse 256;
        const gpu_limit = extractJsonInt(block, "gpu_limit") orelse 0;
        const gpu_model = json_helpers.extractJsonString(block, "gpu_model");
        const gpu_vram_min = extractJsonInt(block, "gpu_vram_min_mb");
        const required_labels = extractJsonString(block, "required_labels") orelse "";
        const gang_world_size_val = extractJsonInt(block, "gang_world_size");
        const gpus_per_rank_val = extractJsonInt(block, "gpus_per_rank");

        if (!common.validateClusterInput(image)) {
            alloc.free(command);
            continue;
        }
        if (command.len > 0 and !common.validateClusterInput(command)) {
            alloc.free(command);
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
        }) catch {
            alloc.free(command);
            return common.internalError();
        };
    }

    if (requests.items.len == 0) return common.badRequest("no services to deploy");

    const db = node.stateMachineDb();

    const vol_constraints = if (app_name) |name|
        volumes_mod.getVolumesByApp(alloc, db, name) catch &[_]volumes_mod.VolumeConstraint{}
    else
        &[_]volumes_mod.VolumeConstraint{};
    defer if (app_name != null) alloc.free(vol_constraints);

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

    var release_id: ?[]const u8 = null;
    defer if (release_id) |id| alloc.free(id);
    if (app_name) |name| {
        const manifest_hash = deployment_store.computeManifestHash(alloc, request.body) catch return common.internalError();
        defer alloc.free(manifest_hash);

        release_id = recordClusterReleaseStart(alloc, db, name, manifest_hash, request.body) catch return common.internalError();
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
                        if (release_id) |id| {
                            deployment_store.updateDeploymentStatusInDb(db, id, .failed, "leadership changed during apply") catch {};
                        }
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
        const placements = scheduler.schedule(alloc, normal_requests.items, agents) catch {
            if (release_id) |id| {
                deployment_store.updateDeploymentStatusInDb(db, id, .failed, "scheduler error during apply") catch {};
            }
            return common.internalError();
        };
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
                    if (release_id) |id| {
                        deployment_store.updateDeploymentStatusInDb(db, id, .failed, "leadership changed during apply") catch {};
                    }
                    return common.notLeader(alloc, node);
                };
                placed += 1;
            } else {
                failed += 1;
            }
        }
    }

    const status = if (failed == 0) "completed" else "failed";
    if (release_id) |id| {
        const message: ?[]const u8 = if (failed == 0) null else "one or more placements failed";
        deployment_store.updateDeploymentStatusInDb(
            db,
            id,
            if (failed == 0) .completed else .failed,
            message,
        ) catch return common.internalError();
    }

    const body = switch (response_mode) {
        .legacy => formatLegacyApplyResponse(alloc, placed, failed) catch return common.internalError(),
        .app => formatAppApplyResponse(
            alloc,
            app_name.?,
            release_id orelse "",
            status,
            requests.items.len,
            placed,
            failed,
        ) catch return common.internalError(),
    };
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleAppApply(alloc: std.mem.Allocator, request: @import("../../http.zig").Request, ctx: RouteContext) Response {
    return handleApply(alloc, request, ctx, .app);
}

pub fn handleDeploy(alloc: std.mem.Allocator, request: @import("../../http.zig").Request, ctx: RouteContext) Response {
    return handleApply(alloc, request, ctx, .legacy);
}

fn recordClusterReleaseStart(
    alloc: std.mem.Allocator,
    db: anytype,
    app_name: []const u8,
    manifest_hash: []const u8,
    config_snapshot: []const u8,
) ![]const u8 {
    const id = try deployment_store.generateDeploymentId(alloc);
    errdefer alloc.free(id);

    try deployment_store.recordDeploymentInDb(
        db,
        id,
        app_name,
        app_name,
        manifest_hash,
        config_snapshot,
        .in_progress,
        null,
    );

    return id;
}

fn formatLegacyApplyResponse(alloc: std.mem.Allocator, placed: usize, failed: usize) ![]u8 {
    return std.fmt.allocPrint(alloc, "{{\"placed\":{d},\"failed\":{d}}}", .{ placed, failed });
}

fn formatAppApplyResponse(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    release_id: []const u8,
    status: []const u8,
    service_count: usize,
    placed: usize,
    failed: usize,
) ![]u8 {
    var json_buf: std.ArrayList(u8) = .empty;
    errdefer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    try writer.writeAll("{\"app_name\":\"");
    try json_helpers.writeJsonEscaped(writer, app_name);
    try writer.writeAll("\",\"release_id\":\"");
    try json_helpers.writeJsonEscaped(writer, release_id);
    try writer.writeAll("\",\"status\":\"");
    try json_helpers.writeJsonEscaped(writer, status);
    try writer.print("\",\"service_count\":{d},\"placed\":{d},\"failed\":{d}", .{
        service_count,
        placed,
        failed,
    });
    try writer.writeByte('}');

    return json_buf.toOwnedSlice(alloc);
}

test "extractJsonArray finds services array regardless of field order" {
    const json =
        \\{"services":[{"name":"svc-a","image":"alpine","gpu":{"devices":["../../dev/sda"]}},{"image":"busybox","name":"svc-b"}]}
    ;

    const services = extractJsonArray(json, "services").?;
    var iter = json_helpers.extractJsonObjects(services);

    const first = iter.next().?;
    try std.testing.expectEqualStrings("svc-a", extractJsonString(first, "name").?);
    try std.testing.expectEqualStrings("alpine", extractJsonString(first, "image").?);

    const second = iter.next().?;
    try std.testing.expectEqualStrings("svc-b", extractJsonString(second, "name").?);
    try std.testing.expectEqualStrings("busybox", extractJsonString(second, "image").?);

    try std.testing.expect(iter.next() == null);
}

test "extractCommandString joins structured command arrays" {
    const alloc = std.testing.allocator;
    const block =
        \\{"name":"web","image":"nginx","command":["nginx","-g","daemon off;"]}
    ;

    const command = try extractCommandString(alloc, block);
    defer alloc.free(command);

    try std.testing.expectEqualStrings("nginx -g daemon off;", command);
}

test "formatAppApplyResponse includes app release metadata" {
    const alloc = std.testing.allocator;
    const json = try formatAppApplyResponse(alloc, "demo-app", "abc123def456", "completed", 2, 2, 0);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"abc123def456\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":\"completed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"service_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"placed\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed\":0") != null);
}

test "formatLegacyApplyResponse preserves compact deploy shape" {
    const alloc = std.testing.allocator;
    const json = try formatLegacyApplyResponse(alloc, 1, 1);
    defer alloc.free(json);

    try std.testing.expectEqualStrings("{\"placed\":1,\"failed\":1}", json);
}
