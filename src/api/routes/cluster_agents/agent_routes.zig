const std = @import("std");
const http = @import("../../http.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const cluster_config = @import("../../../cluster/config.zig");
const request_support = @import("../../../cluster/agent/request_support.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const audit = @import("../../../state/audit.zig");
const common = @import("../common.zig");
const writers = @import("writers.zig");
const credentials = @import("../../../cluster/agent_credentials.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

pub fn handleAgentRegister(alloc: std.mem.Allocator, request: http.Request, ctx: RouteContext) Response {
    const resp = handleAgentRegisterImpl(alloc, request, ctx);
    if (!resp.status.isError()) {
        const address = extractJsonString(request.body, "address") orelse "";
        audit.record(.agent_register, address, .ok);
    }
    return resp;
}

fn handleAgentRegisterImpl(alloc: std.mem.Allocator, request: http.Request, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const expected_token = ctx.join_token orelse return common.badRequest("no join token configured");
    if (request.body.len == 0) return common.badRequest("missing request body");

    const token = extractJsonString(request.body, "token") orelse return common.badRequest("missing token field");
    const address = extractJsonString(request.body, "address") orelse return common.badRequest("missing address field");
    const agent_api_port = extractJsonInt(request.body, "agent_api_port");
    const cpu_cores = extractJsonInt(request.body, "cpu_cores") orelse return common.badRequest("missing cpu_cores field");
    const memory_mb = extractJsonInt(request.body, "memory_mb") orelse return common.badRequest("missing memory_mb field");
    if (cpu_cores <= 0 or cpu_cores > 10000) return common.badRequest("invalid cpu_cores");
    if (memory_mb <= 0 or memory_mb > 10_000_000) return common.badRequest("invalid memory_mb");
    if (agent_api_port) |port| {
        if (port <= 0 or port > 65535) return common.badRequest("invalid agent_api_port");
    }
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

    var endpoint_buf: [64]u8 = undefined;
    var peer_sql: ?[]const u8 = null;
    var peer_sql_buf: [6144]u8 = undefined;

    const role_str = json_helpers.extractJsonString(request.body, "role");
    const region_str = json_helpers.extractJsonString(request.body, "region");
    const labels_str = json_helpers.extractJsonString(request.body, "labels");

    if (wg_public_key) |pub_key| {
        if (!common.validateClusterInput(pub_key)) return common.badRequest("invalid wg_public_key");

        const port: u16 = if (wg_listen_port) |p| blk: {
            if (p <= 0 or p > 65535) return common.badRequest("invalid wg_listen_port");
            break :blk @intCast(p);
        } else 51820;
        const endpoint_host = if (request_support.parseHostPort(address)) |hp|
            std.fmt.bufPrint(&endpoint_buf, "{d}.{d}.{d}.{d}:{d}", .{ hp.addr[0], hp.addr[1], hp.addr[2], hp.addr[3], port }) catch null
        else
            std.fmt.bufPrint(&endpoint_buf, "{s}:{d}", .{ address, port }) catch null;

        const reserved_nodes = alloc.alloc(u64, node.config.peers.len + 1) catch return common.internalError();
        defer alloc.free(reserved_nodes);
        reserved_nodes[0] = node.config.id;
        for (node.config.peers, 1..) |peer, i| reserved_nodes[i] = peer.id;
        peer_sql = agent_registry.allocateWireguardPeerSql(
            &peer_sql_buf,
            &id_buf,
            pub_key,
            endpoint_host orelse return common.badRequest("invalid wireguard endpoint"),
            reserved_nodes,
        ) catch return common.internalError();
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
        nowRealSeconds(),
        .{
            .agent_api_port = if (agent_api_port) |port| @intCast(port) else null,
            .role = role_str,
            .region = region_str,
            .labels = labels_str,
        },
    ) catch return common.internalError();

    var credential = credentials.issue();
    defer std.crypto.secureZero(u8, &credential);
    const credential_hash = credentials.hash(&credential);
    var combined_buf: [9216]u8 = undefined;
    const combined = std.fmt.bufPrint(&combined_buf, "{s} {s} UPDATE agents SET credential_hash = '{s}' WHERE id = '{s}';", .{ sql, peer_sql orelse "", credential_hash, id_buf }) catch return common.internalError();
    _ = node.proposeCommitted(combined, 5000) catch |err| return switch (err) {
        error.NotLeader, error.LeadershipLost => common.notLeader(alloc, node),
        error.CommandRejected => common.conflict("registration conflicts with cluster state"),
        error.CommitTimeout => .{ .status = .service_unavailable, .body = "{\"error\":\"registration outcome unknown; retry after cluster recovers\"}", .allocated = false },
        else => common.internalError(),
    };
    const registered = (agent_registry.getAgent(alloc, node.stateMachineDb(), &id_buf) catch return common.internalError()) orelse
        return .{ .status = .service_unavailable, .body = "{\"error\":\"no available node_id\"}", .allocated = false };
    defer registered.deinit(alloc);
    const assigned_node_id: ?u16 = if (registered.node_id) |nid| std.math.cast(u16, nid) else null;
    const overlay_ip_str = registered.overlay_ip;

    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();

    const writer = &json_buf_writer.writer;

    writer.writeAll("{\"id\":\"") catch return common.internalError();
    writer.writeAll(&id_buf) catch return common.internalError();
    writer.print("\",\"credential\":\"{s}\"", .{credential}) catch return common.internalError();

    if (assigned_node_id) |nid| {
        writer.print(",\"node_id\":{d}", .{nid}) catch return common.internalError();
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
            const body = json_buf_writer.toOwnedSlice() catch return common.internalError();
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

    // The first worker has no other worker seed. Advertise this authenticated
    // server's identity and actual port; the agent pins its IP to the API peer.
    writer.print(",\"gossip_server\":{{\"id\":{d},\"port\":{d}}}", .{ node.config.id, node.gossip_port }) catch return common.internalError();

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

    const body = json_buf_writer.toOwnedSlice() catch return common.internalError();
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
        nowRealSeconds(),
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
        var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
        defer json_buf_writer.deinit();

        const writer = &json_buf_writer.writer;
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
        const body = json_buf_writer.toOwnedSlice() catch return common.internalError();
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

    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();

    const writer = &json_buf_writer.writer;

    writer.writeByte('[') catch return common.internalError();
    for (agents, 0..) |a, i| {
        if (i > 0) writer.writeByte(',') catch return common.internalError();
        writers.writeAgentJson(writer, a) catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf_writer.toOwnedSlice() catch return common.internalError();
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

    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();

    const writer = &json_buf_writer.writer;

    writer.writeByte('[') catch return common.internalError();
    for (peers, 0..) |peer, i| {
        if (i > 0) writer.writeByte(',') catch return common.internalError();
        writers.writeWireguardPeerJson(writer, peer) catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf_writer.toOwnedSlice() catch return common.internalError();
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

    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();

    const writer = &json_buf_writer.writer;

    writer.writeByte('[') catch return common.internalError();
    for (assignments, 0..) |a, i| {
        if (i > 0) writer.writeByte(',') catch return common.internalError();
        writers.writeAssignmentJson(writer, a) catch return common.internalError();
    }
    writer.writeByte(']') catch return common.internalError();

    const body = json_buf_writer.toOwnedSlice() catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleAssignmentStatusUpdate(alloc: std.mem.Allocator, request: http.Request, agent_id: []const u8, assignment_id: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (!(credentials.ownsAssignment(node.stateMachineDb(), agent_id, assignment_id) catch false)) return common.forbidden();
    if (request.body.len == 0) return common.badRequest("missing request body");

    const status = extractJsonString(request.body, "status") orelse return common.badRequest("missing status field");
    const reason = extractJsonString(request.body, "reason");

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
    const sql = agent_registry.updateAssignmentStatusSql(&sql_buf, assignment_id, status, reason) catch return common.internalError();
    // Retain ownership at apply time too: an assignment can move between
    // authorization and this replicated mutation being committed.
    var owner_buf: [64]u8 = undefined;
    const escaped = @import("../../../lib/sql.zig").escapeSqlString(&owner_buf, agent_id) catch return common.internalError();
    var bound_buf: [512]u8 = undefined;
    const bound = std.fmt.bufPrint(&bound_buf, "{s} AND agent_id = '{s}' AND status IN ('pending', 'running');", .{ sql[0 .. sql.len - 1], escaped }) catch return common.internalError();

    _ = node.propose(bound) catch {
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
        audit.record(.agent_drain, id, .failed);
        return common.notLeader(alloc, node);
    };

    audit.record(.agent_drain, id, .ok);
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

pub fn handleRevokeCredential(alloc: std.mem.Allocator, agent_id: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    var escaped_buf: [64]u8 = undefined;
    const id = @import("../../../lib/sql.zig").escapeSqlString(&escaped_buf, agent_id) catch return common.internalError();
    var sql_buf: [192]u8 = undefined;
    const sql = std.fmt.bufPrint(&sql_buf, "UPDATE agents SET credential_hash = NULL WHERE id = '{s}';", .{id}) catch return common.internalError();
    _ = node.propose(sql) catch return common.notLeader(alloc, node);
    return .{ .status = .ok, .body = "{\"revoked\":true}", .allocated = false };
}

test "registration returns credentials only after their row is applied" {
    const node_mod = @import("../../../cluster/node.zig");
    const alloc = std.testing.allocator;
    var node = try node_mod.Node.initForTests(alloc, .{
        .id = 1,
        .port = 0,
        .gossip_port = 19877,
        .peers = &.{},
        .data_dir = "/unused-in-memory-registration",
    });
    defer node.deinit();
    node.fixPointers();
    for (0..61) |_| node.raft.tick();
    const body = "{\"token\":\"join-secret\",\"address\":\"10.0.0.2\",\"cpu_cores\":2,\"memory_mb\":512,\"wg_public_key\":\"test-key\"}";
    const response = handleAgentRegisterImpl(alloc, .{
        .method = .POST,
        .path = "/agents/register",
        .path_only = "/agents/register",
        .query = "",
        .content_length = body.len,
        .body = body,
        .headers_raw = "",
    }, .{ .cluster = &node, .join_token = "join-secret" });
    defer if (response.allocated) alloc.free(response.body);
    try std.testing.expectEqual(http.StatusCode.ok, response.status);
    const id = extractJsonString(response.body, "id") orelse return error.MissingIdentity;
    const secret = extractJsonString(response.body, "credential") orelse return error.MissingCredential;
    try std.testing.expect(try credentials.authenticates(&node.state_machine.db, secret, id));
    try std.testing.expectEqual(@as(?i64, 2), extractJsonInt(response.body, "node_id"));
    const gossip = json_helpers.extractJsonObject(response.body, "gossip_server") orelse return error.MissingGossipServer;
    try std.testing.expectEqual(@as(?i64, 1), json_helpers.extractJsonInt(gossip, "id"));
    try std.testing.expectEqual(@as(?i64, 19877), json_helpers.extractJsonInt(gossip, "port"));
    try std.testing.expectEqual(node.raft.commit_index, node.state_machine.last_applied);
}
