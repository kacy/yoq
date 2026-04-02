const std = @import("std");
const http = @import("../../http.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const cluster_config = @import("../../../cluster/config.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const common = @import("../common.zig");
const writers = @import("writers.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;

pub fn handleAgentRegister(alloc: std.mem.Allocator, request: http.Request, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const expected_token = ctx.join_token orelse return common.badRequest("no join token configured");
    if (request.body.len == 0) return common.badRequest("missing request body");

    const token = extractJsonString(request.body, "token") orelse return common.badRequest("missing token field");
    const address = extractJsonString(request.body, "address") orelse return common.badRequest("missing address field");
    const cpu_cores = extractJsonInt(request.body, "cpu_cores") orelse return common.badRequest("missing cpu_cores field");
    const memory_mb = extractJsonInt(request.body, "memory_mb") orelse return common.badRequest("missing memory_mb field");
    if (cpu_cores <= 0 or cpu_cores > 10000) return common.badRequest("invalid cpu_cores");
    if (memory_mb <= 0 or memory_mb > 10_000_000) return common.badRequest("invalid memory_mb");
    if (cpu_cores > std.math.maxInt(u32)) return common.badRequest("cpu_cores too large");
    if (memory_mb > std.math.maxInt(u64)) return common.badRequest("memory_mb too large");

    const wg_public_key = extractJsonString(request.body, "wg_public_key");
    const wg_listen_port = extractJsonInt(request.body, "wg_listen_port");

    if (!common.validateClusterInput(address)) return common.badRequest("invalid address");
    if (!agent_registry.validateToken(token, expected_token)) {
        return .{ .status = .bad_request, .body = "{\"error\":\"invalid token\"}", .allocated = false };
    }

    var id_buf: [12]u8 = undefined;
    agent_registry.generateAgentId(&id_buf);

    var assigned_node_id: ?u16 = null;
    var overlay_ip_str: ?[]const u8 = null;
    var overlay_ip_buf: [16]u8 = undefined;
    var container_subnet_buf: [20]u8 = undefined;
    var container_subnet: ?[]const u8 = null;
    var endpoint_buf: [64]u8 = undefined;
    var endpoint: ?[]const u8 = null;
    var peer_sql: ?[]const u8 = null;
    var peer_sql_buf: [1024]u8 = undefined;

    const role_str = json_helpers.extractJsonString(request.body, "role");
    const region_str = json_helpers.extractJsonString(request.body, "region");
    const labels_str = json_helpers.extractJsonString(request.body, "labels");

    if (wg_public_key) |pub_key| {
        if (!common.validateClusterInput(pub_key)) return common.badRequest("invalid wg_public_key");

        const db = node.stateMachineDb();
        const nid = agent_registry.assignNodeId(db) catch {
            return .{ .status = .internal_server_error, .body = "{\"error\":\"no available node_id\"}", .allocated = false };
        };
        assigned_node_id = nid;

        if (nid <= 254) {
            overlay_ip_str = std.fmt.bufPrint(&overlay_ip_buf, "10.40.0.{d}", .{nid}) catch null;
        } else {
            overlay_ip_str = std.fmt.bufPrint(&overlay_ip_buf, "10.40.{d}.{d}", .{ nid >> 8, nid & 0xFF }) catch null;
        }

        const subnet_cfg = @import("../../../network/ip.zig").subnetForNode(nid) catch {
            return common.badRequest("node_id too large for subnet allocation");
        };
        container_subnet = std.fmt.bufPrint(&container_subnet_buf, "{d}.{d}.{d}.0/24", .{
            subnet_cfg.base[0], subnet_cfg.base[1], subnet_cfg.base[2],
        }) catch null;

        const port: u16 = if (wg_listen_port) |p| blk: {
            if (p <= 0 or p > 65535) return common.badRequest("invalid wg_listen_port");
            break :blk @intCast(p);
        } else 51820;
        endpoint = std.fmt.bufPrint(&endpoint_buf, "{s}:{d}", .{ address, port }) catch null;

        if (endpoint != null and overlay_ip_str != null and container_subnet != null) {
            peer_sql = agent_registry.wireguardPeerSql(
                &peer_sql_buf,
                nid,
                &id_buf,
                pub_key,
                endpoint.?,
                overlay_ip_str.?,
                container_subnet.?,
            ) catch return common.internalError();
        }
    }

    var sql_buf: [2048]u8 = undefined;
    const gpu_count_val = extractJsonInt(request.body, "gpu_count");
    const gpu_model_str = json_helpers.extractJsonString(request.body, "gpu_model");
    const gpu_vram_val = extractJsonInt(request.body, "gpu_vram_mb");

    if (gpu_count_val) |g| {
        if (g > std.math.maxInt(u32)) return common.badRequest("gpu_count too large");
    }
    if (gpu_vram_val) |v| {
        if (v > std.math.maxInt(u64)) return common.badRequest("gpu_vram_mb too large");
    }

    const sql = agent_registry.registerSqlFull(
        &sql_buf,
        &id_buf,
        address,
        .{
            .cpu_cores = @intCast(cpu_cores),
            .memory_mb = @intCast(memory_mb),
            .gpu_count = if (gpu_count_val) |g| @intCast(@max(0, g)) else 0,
            .gpu_model = gpu_model_str,
            .gpu_vram_mb = if (gpu_vram_val) |v| @intCast(@max(0, v)) else 0,
        },
        std.time.timestamp(),
        .{
            .node_id = assigned_node_id,
            .wg_public_key = wg_public_key,
            .overlay_ip = overlay_ip_str,
            .role = role_str,
            .region = region_str,
            .labels = labels_str,
        },
    ) catch return common.internalError();

    if (peer_sql) |wg_sql| {
        var combined_buf: [4096]u8 = undefined;
        const combined = std.fmt.bufPrint(&combined_buf, "{s} {s}", .{ wg_sql, sql }) catch
            return common.internalError();
        _ = node.propose(combined) catch {
            return common.notLeader(alloc, node);
        };
    } else {
        _ = node.propose(sql) catch {
            return common.notLeader(alloc, node);
        };
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeAll("{\"id\":\"") catch return common.internalError();
    writer.writeAll(&id_buf) catch return common.internalError();
    writer.writeByte('"') catch return common.internalError();

    if (assigned_node_id) |nid| {
        std.fmt.format(writer, ",\"node_id\":{d}", .{nid}) catch return common.internalError();
    }
    if (overlay_ip_str) |oip| {
        writer.writeAll(",\"overlay_ip\":\"") catch return common.internalError();
        writer.writeAll(oip) catch return common.internalError();
        writer.writeByte('"') catch return common.internalError();
    }

    if (assigned_node_id != null) {
        const db = node.stateMachineDb();
        const parsed_role = if (role_str) |rs| cluster_config.NodeRole.fromString(rs) else null;
        const is_agent_role = if (parsed_role) |r| r == .agent else false;
        const peers = (if (is_agent_role)
            agent_registry.listWireguardServerPeers(alloc, db)
        else
            agent_registry.listWireguardPeers(alloc, db)) catch {
            writer.writeByte('}') catch return common.internalError();
            const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
            return .{ .status = .ok, .body = body, .allocated = true };
        };
        defer {
            for (peers) |p| p.deinit(alloc);
            alloc.free(peers);
        }

        writer.writeAll(",\"peers\":[") catch return common.internalError();
        var first = true;
        for (peers) |peer| {
            if (peer.node_id == @as(i64, assigned_node_id.?)) continue;
            if (!first) writer.writeByte(',') catch return common.internalError();
            first = false;
            writers.writeWireguardPeerJson(writer, peer) catch return common.internalError();
        }
        writer.writeByte(']') catch return common.internalError();
    }

    blk: {
        const db = node.stateMachineDb();
        const seeds = agent_registry.getGossipSeeds(alloc, db, 5) catch break :blk;
        defer agent_registry.freeGossipSeeds(alloc, seeds);

        if (seeds.len > 0) {
            writer.writeAll(",\"gossip_seeds\":[") catch return common.internalError();
            for (seeds, 0..) |seed, i| {
                if (i > 0) writer.writeByte(',') catch return common.internalError();
                writer.writeByte('"') catch return common.internalError();
                json_helpers.writeJsonEscaped(writer, seed) catch return common.internalError();
                writer.writeByte('"') catch return common.internalError();
            }
            writer.writeByte(']') catch return common.internalError();
        }
    }

    writer.writeByte('}') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleAgentHeartbeat(alloc: std.mem.Allocator, request: http.Request, id: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (request.body.len == 0) return common.badRequest("missing request body");

    const cpu_used = extractJsonInt(request.body, "cpu_used") orelse 0;
    const memory_used_mb = extractJsonInt(request.body, "memory_used_mb") orelse 0;
    const containers = extractJsonInt(request.body, "containers") orelse 0;
    const cpu_cores = extractJsonInt(request.body, "cpu_cores") orelse 0;
    const memory_mb = extractJsonInt(request.body, "memory_mb") orelse 0;
    const gpu_count = extractJsonInt(request.body, "gpu_count") orelse 0;
    const gpu_used = extractJsonInt(request.body, "gpu_used") orelse 0;
    const gpu_health_str = extractJsonString(request.body, "gpu_health");

    const agent_types = @import("../../../cluster/agent_types.zig");

    node.recordHeartbeat(
        id,
        .{
            .cpu_cores = @intCast(@max(0, cpu_cores)),
            .memory_mb = @intCast(@max(0, memory_mb)),
            .cpu_used = @intCast(@max(0, cpu_used)),
            .memory_used_mb = @intCast(@max(0, memory_used_mb)),
            .containers = @intCast(@max(0, containers)),
            .gpu_count = @intCast(@max(0, gpu_count)),
            .gpu_used = @intCast(@max(0, gpu_used)),
            .gpu_health = if (gpu_health_str) |s| agent_types.AgentResources.GpuHealthBuf.fromSlice(s) else .{},
        },
        std.time.timestamp(),
    );

    const db = node.stateMachineDb();
    const peers_count: i64 = blk: {
        const CountRow = struct { count: i64 };
        const count_result = (db.one(CountRow, "SELECT COUNT(*) AS count FROM wireguard_peers;", .{}, .{}) catch break :blk 0) orelse break :blk 0;
        break :blk count_result.count;
    };

    const agent = agent_registry.getAgent(alloc, db, id) catch {
        return .{ .status = .ok, .body = "{\"status\":\"ok\"}", .allocated = false };
    };

    if (agent) |a| {
        defer a.deinit(alloc);
        var json_buf: std.ArrayList(u8) = .empty;
        defer json_buf.deinit(alloc);
        const writer = json_buf.writer(alloc);
        writer.writeAll("{\"status\":\"") catch return common.internalError();
        writer.writeAll(a.status) catch return common.internalError();
        writer.print("\",\"peers_count\":{d}", .{peers_count}) catch return common.internalError();
        var addr_buf: [64]u8 = undefined;
        if (node.leaderAddrBuf(&addr_buf)) |addr| {
            writer.writeAll(",\"leader\":\"") catch return common.internalError();
            writer.writeAll(addr) catch return common.internalError();
            writer.writeByte('"') catch return common.internalError();
        }
        writer.writeByte('}') catch return common.internalError();
        const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
        return .{ .status = .ok, .body = body, .allocated = true };
    }

    return .{ .status = .ok, .body = "{\"status\":\"ok\"}", .allocated = false };
}

pub fn handleListAgents(alloc: std.mem.Allocator, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return .{ .status = .ok, .body = "[]", .allocated = false };

    const db = node.stateMachineDb();
    const agents = agent_registry.listAgents(alloc, db) catch return common.internalError();
    defer {
        for (agents) |a| a.deinit(alloc);
        alloc.free(agents);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return common.internalError();
    for (agents, 0..) |a, i| {
        if (i > 0) writer.writeByte(',') catch return common.internalError();
        writers.writeAgentJson(writer, a) catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleWireguardPeers(alloc: std.mem.Allocator, request: http.Request, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return .{ .status = .ok, .body = "[]", .allocated = false };

    const db = node.stateMachineDb();
    const servers_only = std.mem.eql(u8, request.query, "servers_only=1") or
        std.mem.startsWith(u8, request.query, "servers_only=1&") or
        std.mem.indexOf(u8, request.query, "&servers_only=1") != null;
    const peers = (if (servers_only)
        agent_registry.listWireguardServerPeers(alloc, db)
    else
        agent_registry.listWireguardPeers(alloc, db)) catch return common.internalError();
    defer {
        for (peers) |p| p.deinit(alloc);
        alloc.free(peers);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return common.internalError();
    for (peers, 0..) |peer, i| {
        if (i > 0) writer.writeByte(',') catch return common.internalError();
        writers.writeWireguardPeerJson(writer, peer) catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleAgentAssignments(alloc: std.mem.Allocator, agent_id: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");

    const db = node.stateMachineDb();
    const assignments = agent_registry.getAssignments(alloc, db, agent_id) catch return common.internalError();
    defer {
        for (assignments) |a| a.deinit(alloc);
        alloc.free(assignments);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return common.internalError();
    for (assignments, 0..) |a, i| {
        if (i > 0) writer.writeByte(',') catch return common.internalError();
        writers.writeAssignmentJson(writer, a) catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleAssignmentStatusUpdate(alloc: std.mem.Allocator, request: http.Request, assignment_id: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (request.body.len == 0) return common.badRequest("missing request body");

    const status = extractJsonString(request.body, "status") orelse return common.badRequest("missing status field");

    const valid_statuses = [_][]const u8{ "running", "stopped", "failed" };
    var valid = false;
    for (valid_statuses) |s| {
        if (std.mem.eql(u8, status, s)) {
            valid = true;
            break;
        }
    }
    if (!valid) return common.badRequest("invalid status value");

    var sql_buf: [256]u8 = undefined;
    const sql = agent_registry.updateAssignmentStatusSql(&sql_buf, assignment_id, status) catch return common.internalError();

    _ = node.propose(sql) catch {
        return common.notLeader(alloc, node);
    };

    const body = std.fmt.allocPrint(alloc, "{{\"ok\":true,\"status\":\"{s}\"}}", .{status}) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleAgentDrain(alloc: std.mem.Allocator, id: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");

    var sql_buf: [256]u8 = undefined;
    const sql = agent_registry.drainSql(&sql_buf, id) catch return common.internalError();

    _ = node.propose(sql) catch {
        return common.notLeader(alloc, node);
    };

    return .{ .status = .ok, .body = "{\"status\":\"draining\"}", .allocated = false };
}

pub fn handleUpdateLabels(alloc: std.mem.Allocator, request: http.Request, id: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (request.body.len == 0) return common.badRequest("missing request body");

    const labels = extractJsonString(request.body, "labels") orelse return common.badRequest("missing labels field");

    var sql_buf: [1024]u8 = undefined;
    const sql = agent_registry.updateLabelsSql(&sql_buf, id, labels) catch return common.internalError();

    _ = node.propose(sql) catch {
        return common.notLeader(alloc, node);
    };

    return .{ .status = .ok, .body = "{\"ok\":true}", .allocated = false };
}
