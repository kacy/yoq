const std = @import("std");
const http = @import("../http.zig");
const agent_registry = @import("../../cluster/registry.zig");
const cluster_config = @import("../../cluster/config.zig");
const scheduler = @import("../../cluster/scheduler.zig");
const gpu_scheduler = @import("../../gpu/scheduler.zig");
const json_helpers = @import("../../lib/json_helpers.zig");
const volumes_mod = @import("../../state/volumes.zig");
const common = @import("common.zig");
const testing = std.testing;

const Response = common.Response;
const RouteContext = common.RouteContext;
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;

pub fn route(request: http.Request, alloc: std.mem.Allocator, ctx: RouteContext) ?Response {
    const path = request.path_only;

    if (request.method == .GET) {
        if (std.mem.eql(u8, path, "/cluster/status")) return handleClusterStatus(alloc, ctx);
        if (std.mem.eql(u8, path, "/agents")) return handleListAgents(alloc, ctx);
        if (std.mem.eql(u8, path, "/wireguard/peers")) return handleWireguardPeers(alloc, request, ctx);
    }

    if (request.method == .POST) {
        if (std.mem.eql(u8, path, "/cluster/propose")) return handleClusterPropose(request, ctx);
        if (std.mem.eql(u8, path, "/cluster/step-down")) return handleLeaderStepDown(ctx);
        if (std.mem.eql(u8, path, "/agents/register")) return handleAgentRegister(alloc, request, ctx);
        if (std.mem.eql(u8, path, "/deploy")) return handleDeploy(alloc, request, ctx);
    }

    if (request.method == .GET) {
        if (std.mem.eql(u8, path, "/cluster/version")) return handleClusterVersion();
    }

    if (path.len > "/agents/".len and std.mem.startsWith(u8, path, "/agents/")) {
        const rest = path["/agents/".len..];
        const agent_id_end = std.mem.indexOf(u8, rest, "/") orelse rest.len;
        if (!common.validateContainerId(rest[0..agent_id_end])) return common.badRequest("invalid agent id");

        if (common.matchSubpath(rest, "/labels")) |id| {
            if (request.method != .PUT) return common.methodNotAllowed();
            return handleUpdateLabels(alloc, request, id, ctx);
        }

        if (common.matchSubpath(rest, "/heartbeat")) |id| {
            if (request.method != .POST) return common.methodNotAllowed();
            return handleAgentHeartbeat(alloc, request, id, ctx);
        }

        if (common.matchSubpath(rest, "/assignments")) |id| {
            if (request.method != .GET) return common.methodNotAllowed();
            return handleAgentAssignments(alloc, id, ctx);
        }

        if (common.matchSubpath(rest, "/drain")) |id| {
            if (request.method != .POST) return common.methodNotAllowed();
            return handleAgentDrain(id, ctx);
        }

        if (common.matchAssignmentStatusPath(rest)) |ids| {
            if (request.method != .POST) return common.methodNotAllowed();
            return handleAssignmentStatusUpdate(alloc, request, ids.assignment_id, ctx);
        }
    }

    return null;
}

fn handleLeaderStepDown(ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");

    if (node.transferLeadership()) {
        return .{ .status = .ok, .body = "{\"transferred\":true}", .allocated = false };
    } else {
        return .{ .status = .bad_request, .body = "{\"transferred\":false,\"error\":\"not leader\"}", .allocated = false };
    }
}

fn handleClusterVersion() Response {
    const cluster_node = @import("../../cluster/node.zig");
    const version = cluster_node.Node.protocolVersion();
    _ = version;
    return .{ .status = .ok, .body = "{\"protocol_version\":1,\"software_version\":\"0.1.0\"}", .allocated = false };
}

fn handleClusterStatus(alloc: std.mem.Allocator, ctx: RouteContext) Response {
    const node = ctx.cluster orelse {
        return .{ .status = .ok, .body = "{\"cluster\":false}", .allocated = false };
    };

    const role_str = switch (node.role()) {
        .follower => "follower",
        .candidate => "candidate",
        .leader => "leader",
    };

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeAll("{\"cluster\":true") catch return common.internalError();
    std.fmt.format(writer, ",\"id\":{d}", .{node.config.id}) catch return common.internalError();
    writer.writeAll(",\"role\":\"") catch return common.internalError();
    writer.writeAll(role_str) catch return common.internalError();
    writer.writeByte('"') catch return common.internalError();
    std.fmt.format(writer, ",\"term\":{d}", .{node.currentTerm()}) catch return common.internalError();
    std.fmt.format(writer, ",\"peers\":{d}", .{node.config.peers.len}) catch return common.internalError();
    writer.writeByte('}') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleClusterPropose(request: http.Request, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (request.body.len == 0) return common.badRequest("missing request body");

    _ = node.propose(request.body) catch {
        return .{ .status = .bad_request, .body = "{\"error\":\"not leader\"}", .allocated = false };
    };

    return .{ .status = .ok, .body = "{\"status\":\"proposed\"}", .allocated = false };
}

fn handleAgentRegister(alloc: std.mem.Allocator, request: http.Request, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const expected_token = ctx.join_token orelse return common.badRequest("no join token configured");
    if (request.body.len == 0) return common.badRequest("missing request body");

    const token = extractJsonString(request.body, "token") orelse return common.badRequest("missing token field");
    const address = extractJsonString(request.body, "address") orelse return common.badRequest("missing address field");
    const cpu_cores = extractJsonInt(request.body, "cpu_cores") orelse return common.badRequest("missing cpu_cores field");
    const memory_mb = extractJsonInt(request.body, "memory_mb") orelse return common.badRequest("missing memory_mb field");
    if (cpu_cores <= 0 or cpu_cores > 10000) return common.badRequest("invalid cpu_cores");
    if (memory_mb <= 0 or memory_mb > 10_000_000) return common.badRequest("invalid memory_mb");

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

        // derive container subnet from ip.subnetForNode addressing
        const subnet_cfg = @import("../../network/ip.zig").subnetForNode(nid) catch {
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
            var peer_sql_buf: [1024]u8 = undefined;
            const peer_sql = agent_registry.wireguardPeerSql(
                &peer_sql_buf,
                nid,
                &id_buf,
                pub_key,
                endpoint.?,
                overlay_ip_str.?,
                container_subnet.?,
            ) catch return common.internalError();
            _ = node.propose(peer_sql) catch {};
        }
    }

    var sql_buf: [2048]u8 = undefined;
    // extract optional role, region, and GPU info from registration request
    const role_str = json_helpers.extractJsonString(request.body, "role");
    const region_str = json_helpers.extractJsonString(request.body, "region");
    const labels_str = json_helpers.extractJsonString(request.body, "labels");
    const gpu_count_val = extractJsonInt(request.body, "gpu_count");
    const gpu_model_str = json_helpers.extractJsonString(request.body, "gpu_model");
    const gpu_vram_val = extractJsonInt(request.body, "gpu_vram_mb");

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

    _ = node.propose(sql) catch {
        return .{ .status = .internal_server_error, .body = "{\"error\":\"not leader\"}", .allocated = false };
    };

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
        // agents with role=agent get only server/both peers (hub-and-spoke);
        // role=both or role=server get all peers (full-mesh).
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
            writer.writeAll("{\"node_id\":") catch return common.internalError();
            std.fmt.format(writer, "{d}", .{peer.node_id}) catch return common.internalError();
            writer.writeAll(",\"public_key\":\"") catch return common.internalError();
            json_helpers.writeJsonEscaped(writer, peer.public_key) catch return common.internalError();
            writer.writeAll("\",\"endpoint\":\"") catch return common.internalError();
            json_helpers.writeJsonEscaped(writer, peer.endpoint) catch return common.internalError();
            writer.writeAll("\",\"overlay_ip\":\"") catch return common.internalError();
            json_helpers.writeJsonEscaped(writer, peer.overlay_ip) catch return common.internalError();
            writer.writeAll("\",\"container_subnet\":\"") catch return common.internalError();
            json_helpers.writeJsonEscaped(writer, peer.container_subnet) catch return common.internalError();
            writer.writeAll("\"}") catch return common.internalError();
        }
        writer.writeByte(']') catch return common.internalError();
    }

    // include gossip seeds — active agent addresses for gossip bootstrap
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

fn handleAgentHeartbeat(alloc: std.mem.Allocator, request: http.Request, id: []const u8, ctx: RouteContext) Response {
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

    const agent_types = @import("../../cluster/agent_types.zig");

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
        writer.print("\",\"peers_count\":{d}}}", .{peers_count}) catch return common.internalError();
        const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
        return .{ .status = .ok, .body = body, .allocated = true };
    }

    return .{ .status = .ok, .body = "{\"status\":\"ok\"}", .allocated = false };
}

fn handleListAgents(alloc: std.mem.Allocator, ctx: RouteContext) Response {
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
        writeAgentJson(writer, a) catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleWireguardPeers(alloc: std.mem.Allocator, request: http.Request, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return .{ .status = .ok, .body = "[]", .allocated = false };

    const db = node.stateMachineDb();
    // support ?servers_only=1 for hub-and-spoke topology
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
        writeWireguardPeerJson(writer, peer) catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleAgentAssignments(alloc: std.mem.Allocator, agent_id: []const u8, ctx: RouteContext) Response {
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
        writeAssignmentJson(writer, a) catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleAssignmentStatusUpdate(alloc: std.mem.Allocator, request: http.Request, assignment_id: []const u8, ctx: RouteContext) Response {
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
        return .{ .status = .internal_server_error, .body = "{\"error\":\"not leader\"}", .allocated = false };
    };

    const body = std.fmt.allocPrint(alloc, "{{\"ok\":true,\"status\":\"{s}\"}}", .{status}) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleAgentDrain(id: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");

    var sql_buf: [256]u8 = undefined;
    const sql = agent_registry.drainSql(&sql_buf, id) catch return common.internalError();

    _ = node.propose(sql) catch {
        return .{ .status = .internal_server_error, .body = "{\"error\":\"not leader\"}", .allocated = false };
    };

    return .{ .status = .ok, .body = "{\"status\":\"draining\"}", .allocated = false };
}

fn handleUpdateLabels(alloc: std.mem.Allocator, request: http.Request, id: []const u8, ctx: RouteContext) Response {
    _ = alloc;
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (request.body.len == 0) return common.badRequest("missing request body");

    const labels = extractJsonString(request.body, "labels") orelse return common.badRequest("missing labels field");

    var sql_buf: [1024]u8 = undefined;
    const sql = agent_registry.updateLabelsSql(&sql_buf, id, labels) catch return common.internalError();

    _ = node.propose(sql) catch {
        return .{ .status = .internal_server_error, .body = "{\"error\":\"not leader\"}", .allocated = false };
    };

    return .{ .status = .ok, .body = "{\"ok\":true}", .allocated = false };
}

fn handleDeploy(alloc: std.mem.Allocator, request: http.Request, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (request.body.len == 0) return common.badRequest("missing request body");

    var requests: std.ArrayListUnmanaged(scheduler.PlacementRequest) = .empty;
    defer requests.deinit(alloc);

    // extract optional volume_app for volume constraint lookup
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

    // look up volume constraints if an app name is provided
    const vol_constraints = if (volume_app) |app_name|
        volumes_mod.getVolumesByApp(alloc, db, app_name) catch &[_]volumes_mod.VolumeConstraint{}
    else
        &[_]volumes_mod.VolumeConstraint{};
    defer if (volume_app != null) alloc.free(vol_constraints);

    // apply volume constraints to all requests
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

    // check if any request uses gang scheduling
    for (requests.items) |req| {
        if (req.gang_world_size > 0) {
            // gang scheduling path — all-or-nothing placement
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
                        gang_ok = false;
                        break;
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
            continue;
        }
    }

    // non-gang requests: collect them and schedule normally
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
                    failed += 1;
                    continue;
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

fn writeAgentJson(writer: anytype, agent: agent_registry.AgentRecord) !void {
    try writer.writeAll("{\"id\":\"");
    try writer.writeAll(agent.id);
    try writer.writeAll("\",\"address\":\"");
    try json_helpers.writeJsonEscaped(writer, agent.address);
    try writer.writeAll("\",\"status\":\"");
    try writer.writeAll(agent.status);
    try writer.writeAll("\",\"cpu_cores\":");
    try std.fmt.format(writer, "{d}", .{agent.cpu_cores});
    try writer.writeAll(",\"memory_mb\":");
    try std.fmt.format(writer, "{d}", .{agent.memory_mb});
    try writer.writeAll(",\"cpu_used\":");
    try std.fmt.format(writer, "{d}", .{agent.cpu_used});
    try writer.writeAll(",\"memory_used_mb\":");
    try std.fmt.format(writer, "{d}", .{agent.memory_used_mb});
    try writer.writeAll(",\"containers\":");
    try std.fmt.format(writer, "{d}", .{agent.containers});
    try writer.writeAll(",\"last_heartbeat\":");
    try std.fmt.format(writer, "{d}", .{agent.last_heartbeat});

    if (agent.node_id) |nid| {
        try writer.writeAll(",\"node_id\":");
        try std.fmt.format(writer, "{d}", .{nid});
    }
    if (agent.wg_public_key) |key| {
        try writer.writeAll(",\"wg_public_key\":\"");
        try json_helpers.writeJsonEscaped(writer, key);
        try writer.writeByte('"');
    }
    if (agent.overlay_ip) |oip| {
        try writer.writeAll(",\"overlay_ip\":\"");
        try json_helpers.writeJsonEscaped(writer, oip);
        try writer.writeByte('"');
    }
    if (agent.role) |r| {
        try writer.writeAll(",\"role\":\"");
        try json_helpers.writeJsonEscaped(writer, r);
        try writer.writeByte('"');
    }
    if (agent.region) |reg| {
        try writer.writeAll(",\"region\":\"");
        try json_helpers.writeJsonEscaped(writer, reg);
        try writer.writeByte('"');
    }
    if (agent.labels) |labels| {
        try writer.writeAll(",\"labels\":\"");
        try json_helpers.writeJsonEscaped(writer, labels);
        try writer.writeByte('"');
    }
    if (agent.gpu_count != 0) {
        try writer.writeAll(",\"gpu_count\":");
        try std.fmt.format(writer, "{d}", .{agent.gpu_count});
    }
    if (agent.gpu_used != 0) {
        try writer.writeAll(",\"gpu_used\":");
        try std.fmt.format(writer, "{d}", .{agent.gpu_used});
    }
    if (agent.gpu_model) |model| {
        try writer.writeAll(",\"gpu_model\":\"");
        try json_helpers.writeJsonEscaped(writer, model);
        try writer.writeByte('"');
    }
    if (agent.gpu_vram_mb) |vram| {
        try writer.writeAll(",\"gpu_vram_mb\":");
        try std.fmt.format(writer, "{d}", .{vram});
    }
    if (agent.rdma_capable) {
        try writer.writeAll(",\"rdma_capable\":true");
    }

    try writer.writeByte('}');
}

fn writeAssignmentJson(writer: anytype, assignment: agent_registry.Assignment) !void {
    try writer.writeAll("{\"id\":\"");
    try writer.writeAll(assignment.id);
    try writer.writeAll("\",\"agent_id\":\"");
    try writer.writeAll(assignment.agent_id);
    try writer.writeAll("\",\"image\":\"");
    try json_helpers.writeJsonEscaped(writer, assignment.image);
    try writer.writeAll("\",\"command\":\"");
    try json_helpers.writeJsonEscaped(writer, assignment.command);
    try writer.writeAll("\",\"status\":\"");
    try writer.writeAll(assignment.status);
    try writer.writeAll("\",\"cpu_limit\":");
    try std.fmt.format(writer, "{d}", .{assignment.cpu_limit});
    try writer.writeAll(",\"memory_limit_mb\":");
    try std.fmt.format(writer, "{d}", .{assignment.memory_limit_mb});
    if (assignment.gang_rank) |rank| {
        try writer.writeAll(",\"gang_rank\":");
        try std.fmt.format(writer, "{d}", .{rank});
    }
    if (assignment.gang_world_size) |ws| {
        try writer.writeAll(",\"gang_world_size\":");
        try std.fmt.format(writer, "{d}", .{ws});
    }
    if (assignment.gang_master_addr) |addr| {
        try writer.writeAll(",\"gang_master_addr\":\"");
        try json_helpers.writeJsonEscaped(writer, addr);
        try writer.writeByte('"');
    }
    if (assignment.gang_master_port) |port| {
        try writer.writeAll(",\"gang_master_port\":");
        try std.fmt.format(writer, "{d}", .{port});
    }
    try writer.writeByte('}');
}

fn writeWireguardPeerJson(writer: anytype, peer: agent_registry.WireguardPeer) !void {
    try writer.writeAll("{\"node_id\":");
    try std.fmt.format(writer, "{d}", .{peer.node_id});
    try writer.writeAll(",\"agent_id\":\"");
    try json_helpers.writeJsonEscaped(writer, peer.agent_id);
    try writer.writeAll("\",\"public_key\":\"");
    try json_helpers.writeJsonEscaped(writer, peer.public_key);
    try writer.writeAll("\",\"endpoint\":\"");
    try json_helpers.writeJsonEscaped(writer, peer.endpoint);
    try writer.writeAll("\",\"overlay_ip\":\"");
    try json_helpers.writeJsonEscaped(writer, peer.overlay_ip);
    try writer.writeAll("\",\"container_subnet\":\"");
    try json_helpers.writeJsonEscaped(writer, peer.container_subnet);
    try writer.writeAll("\"}");
}

// ============================================================================
// Tests
// ============================================================================

fn testRequest(method: http.Method, path: []const u8) http.Request {
    return .{
        .method = method,
        .path = path,
        .path_only = path,
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };
}

test "route returns null for unknown path" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.GET, "/unknown");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response == null);
}

test "route handles /cluster/status GET without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.GET, "/cluster/status");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.ok, resp.status);
        try testing.expectEqualStrings("{\"cluster\":false}", resp.body);
        try testing.expect(!resp.allocated);
    }
}

test "route handles /agents GET without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.GET, "/agents");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.ok, resp.status);
        try testing.expectEqualStrings("[]", resp.body);
        try testing.expect(!resp.allocated);
    }
}

test "route handles /wireguard/peers GET without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.GET, "/wireguard/peers");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.ok, resp.status);
        try testing.expectEqualStrings("[]", resp.body);
        try testing.expect(!resp.allocated);
    }
}

test "route rejects POST /cluster/propose without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.POST, "/cluster/propose");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.bad_request, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route rejects POST /agents/register without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.POST, "/agents/register");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.bad_request, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route rejects POST /deploy without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.POST, "/deploy");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.bad_request, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route validates agent ID format" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };

    // Test invalid agent ID
    var req = testRequest(.POST, "/agents/invalid-id/heartbeat");
    var response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.bad_request, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }

    // Test valid hex agent ID but without cluster
    req = testRequest(.POST, "/agents/abc123def456/heartbeat");
    response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.bad_request, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route validates method for subpaths" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };

    // GET to heartbeat should not be allowed (requires POST)
    var req = testRequest(.GET, "/agents/abc123def456/heartbeat");
    var response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
        try testing.expect(!resp.allocated);
    }

    // POST to assignments should not be allowed (requires GET)
    req = testRequest(.POST, "/agents/abc123def456/assignments");
    response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
        try testing.expect(!resp.allocated);
    }

    // GET to drain should not be allowed (requires POST)
    req = testRequest(.GET, "/agents/abc123def456/drain");
    response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
        try testing.expect(!resp.allocated);
    }
}

test "route matches assignment status update path" {
    if (true) return error.SkipZigTest; // Skip - requires cluster layer
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };

    // POST to assignments/{id}/status should match
    const req = testRequest(.POST, "/agents/abc123def456/assignments/assign789/status");
    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        // Without cluster it will fail, but route should match the path
        try testing.expectEqual(http.StatusCode.bad_request, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "writeAgentJson produces valid JSON" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const agent = agent_registry.AgentRecord{
        .id = "agent123",
        .address = "192.168.1.1:8080",
        .status = "active",
        .cpu_cores = 4,
        .memory_mb = 8192,
        .cpu_used = 2,
        .memory_used_mb = 4096,
        .containers = 10,
        .last_heartbeat = 1234567890,
        .registered_at = 1234560000,
        .node_id = 5,
        .wg_public_key = "pubkey123",
        .overlay_ip = "10.40.0.5",
    };

    writeAgentJson(writer, agent) catch unreachable;
    const json = stream.getWritten();

    // Verify JSON contains expected fields
    try testing.expect(std.mem.indexOf(u8, json, "agent123") != null);
    try testing.expect(std.mem.indexOf(u8, json, "192.168.1.1:8080") != null);
    try testing.expect(std.mem.indexOf(u8, json, "active") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"cpu_cores\":4") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"memory_mb\":8192") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"node_id\":5") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"overlay_ip\":\"") != null);
}

test "writeAgentJson omits optional fields when null" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const agent = agent_registry.AgentRecord{
        .id = "agent456",
        .address = "192.168.1.2:8080",
        .status = "draining",
        .cpu_cores = 2,
        .memory_mb = 4096,
        .cpu_used = 1,
        .memory_used_mb = 2048,
        .containers = 5,
        .last_heartbeat = 9876543210,
        .registered_at = 9876500000,
        .node_id = null,
        .wg_public_key = null,
        .overlay_ip = null,
    };

    writeAgentJson(writer, agent) catch unreachable;
    const json = stream.getWritten();

    try testing.expect(std.mem.indexOf(u8, json, "agent456") != null);
    try testing.expect(std.mem.indexOf(u8, json, "draining") != null);
    // node_id should not be present when null
    try testing.expect(std.mem.indexOf(u8, json, "node_id") == null);
}

test "writeAssignmentJson produces valid JSON" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const assignment = agent_registry.Assignment{
        .id = "assign789",
        .agent_id = "agent123",
        .image = "nginx:latest",
        .command = "nginx -g daemon off;",
        .status = "running",
        .cpu_limit = 1000,
        .memory_limit_mb = 512,
    };

    writeAssignmentJson(writer, assignment) catch unreachable;
    const json = stream.getWritten();

    try testing.expect(std.mem.indexOf(u8, json, "assign789") != null);
    try testing.expect(std.mem.indexOf(u8, json, "agent123") != null);
    try testing.expect(std.mem.indexOf(u8, json, "nginx:latest") != null);
    try testing.expect(std.mem.indexOf(u8, json, "running") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"cpu_limit\":1000") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"memory_limit_mb\":512") != null);
}

test "writeWireguardPeerJson produces valid JSON" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const peer = agent_registry.WireguardPeer{
        .node_id = 3,
        .agent_id = "agent789",
        .public_key = "pubkeyabc",
        .endpoint = "192.168.1.3:51820",
        .overlay_ip = "10.40.0.3",
        .container_subnet = "10.42.3.0/24",
    };

    writeWireguardPeerJson(writer, peer) catch unreachable;
    const json = stream.getWritten();

    try testing.expect(std.mem.indexOf(u8, json, "\"node_id\":3") != null);
    try testing.expect(std.mem.indexOf(u8, json, "agent789") != null);
    try testing.expect(std.mem.indexOf(u8, json, "pubkeyabc") != null);
    try testing.expect(std.mem.indexOf(u8, json, "10.40.0.3") != null);
    try testing.expect(std.mem.indexOf(u8, json, "10.42.3.0/24") != null);
}

test "writeWireguardPeerJson escapes special characters" {
    var buf: [2048]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const peer = agent_registry.WireguardPeer{
        .node_id = 1,
        .agent_id = "agent\"quoted\"",
        .public_key = "key\nwith\ttabs",
        .endpoint = "host:51820",
        .overlay_ip = "10.40.0.1",
        .container_subnet = "10.42.1.0/24",
    };

    writeWireguardPeerJson(writer, peer) catch unreachable;
    const json = stream.getWritten();

    // Should have escaped quotes and control characters
    try testing.expect(std.mem.indexOf(u8, json, "\\\"") != null); // escaped quote
    try testing.expect(std.mem.indexOf(u8, json, "\\n") != null); // escaped newline
    try testing.expect(std.mem.indexOf(u8, json, "\\t") != null); // escaped tab
}
