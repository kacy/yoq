const std = @import("std");
const http = @import("../../http.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const cluster_config = @import("../../../cluster/config.zig");
const request_support = @import("../../../cluster/agent/request_support.zig");
const numbers = @import("../../../lib/json_numbers.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const audit = @import("../../../state/audit.zig");
const common = @import("../common.zig");
const writers = @import("writers.zig");
const enrollment = @import("../../../cluster/enrollment_identity.zig");
const mutation = @import("../../../cluster/mutation_session.zig");
const deploy_routes = @import("deploy_routes.zig");
const credentials = @import("../../../cluster/agent_credentials.zig");
const Node = @import("../../../cluster/node.zig").Node;

const Response = common.Response;
const RouteContext = common.RouteContext;
const extractJsonString = json_helpers.extractJsonString;

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
    const parsed = numbers.parse(alloc, request.body) catch return common.badRequest("invalid resource snapshot");
    defer parsed.deinit();
    const agent_api_port = numbers.optional(u16, parsed.value, "agent_api_port", 1, 65535) catch return common.badRequest("invalid agent_api_port");
    const cpu_cores = (numbers.optional(u32, parsed.value, "cpu_cores", 1, 10000) catch return common.badRequest("invalid cpu_cores")) orelse return common.badRequest("missing cpu_cores field");
    const memory_mb = (numbers.optional(u64, parsed.value, "memory_mb", 1, 10_000_000) catch return common.badRequest("invalid memory_mb")) orelse return common.badRequest("missing memory_mb field");
    const wg_public_key = extractJsonString(request.body, "wg_public_key");
    const wg_listen_port = numbers.optional(u16, parsed.value, "wg_listen_port", 1, 65535) catch return common.badRequest("invalid wg_listen_port");

    if (!common.validateClusterInput(address)) return common.badRequest("invalid address");
    if (!agent_registry.validateToken(token, expected_token)) {
        return .{ .status = .bad_request, .body = "{\"error\":\"invalid token\"}", .allocated = false };
    }

    var registration_key = enrollment.parseKey(alloc, request.body) catch return common.badRequest("invalid registration_key");
    defer if (registration_key) |*key| std.crypto.secureZero(u8, key);
    if (registration_key != null and wg_public_key == null) return common.badRequest("retryable registration requires wg_public_key");
    var credential = registration_key orelse credentials.issue();
    defer std.crypto.secureZero(u8, &credential);
    const credential_hash = credentials.hash(&credential);
    var id_buf: [12]u8 = undefined;
    if (registration_key != null) @memcpy(&id_buf, credential_hash[0..12]) else agent_registry.generateAgentId(&id_buf);

    var endpoint_buf: [64]u8 = undefined;
    var wireguard_endpoint: ?[]const u8 = null;
    var peer_sql: ?[]const u8 = null;
    var peer_sql_buf: [6144]u8 = undefined;

    const role_str = json_helpers.extractJsonString(request.body, "role");
    const region_str = json_helpers.extractJsonString(request.body, "region");
    const labels_str = json_helpers.extractJsonString(request.body, "labels");

    if (wg_public_key) |pub_key| {
        if (!common.validateClusterInput(pub_key)) return common.badRequest("invalid wg_public_key");

        const port = wg_listen_port orelse 51820;
        const endpoint_host = if (request_support.parseHostPort(address)) |hp|
            std.fmt.bufPrint(&endpoint_buf, "{d}.{d}.{d}.{d}:{d}", .{ hp.addr[0], hp.addr[1], hp.addr[2], hp.addr[3], port }) catch null
        else
            std.fmt.bufPrint(&endpoint_buf, "{s}:{d}", .{ address, port }) catch null;

        wireguard_endpoint = endpoint_host orelse return common.badRequest("invalid wireguard endpoint");
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
    const gpu_count_val = numbers.optional(u32, parsed.value, "gpu_count", 0, std.math.maxInt(u32)) catch return common.badRequest("invalid gpu_count");
    const gpu_model_str = json_helpers.extractJsonString(request.body, "gpu_model");
    const gpu_vram_val = numbers.optional(u64, parsed.value, "gpu_vram_mb", 0, std.math.maxInt(i64)) catch return common.badRequest("invalid gpu_vram_mb");

    const resources: agent_registry.AgentResources = .{
        .cpu_cores = cpu_cores,
        .memory_mb = memory_mb,
        .gpu_count = gpu_count_val orelse 0,
        .gpu_model = gpu_model_str,
        .gpu_vram_mb = gpu_vram_val orelse 0,
    };
    const options: agent_registry.RegisterOpts = .{
        .agent_api_port = agent_api_port,
        .role = role_str,
        .region = region_str,
        .labels = labels_str,
    };
    const now = nowRealSeconds();
    const sql = agent_registry.registerSqlFull(&sql_buf, &id_buf, address, resources, now, options) catch return common.internalError();
    var combined_buf: [9216]u8 = undefined;
    const combined = std.fmt.bufPrint(&combined_buf, "{s} {s} UPDATE agents SET credential_hash = '{s}' WHERE id = '{s}';", .{ sql, peer_sql orelse "", credential_hash, id_buf }) catch return common.internalError();
    const session = mutation.Session.begin(node) catch return common.notLeader(alloc, node);
    session.commit(combined) catch |err| {
        if (err == error.Conflict and registration_key != null) {
            enrollment.refresh(alloc, session, &id_buf, &credential, .{
                .address = address,
                .endpoint = wireguard_endpoint.?,
                .public_key = wg_public_key.?,
                .resources = resources,
                .options = options,
                .now = now,
            }) catch |refresh_error| return deploy_routes.mutationFailure(alloc, node, refresh_error);
        } else return deploy_routes.mutationFailure(alloc, node, err);
    };
    // validate the credential and read the assigned identity and bootstrap peers
    // from one applied-state snapshot.
    node.mu.lockUncancelable(std.Options.debug_io);
    defer node.mu.unlock(std.Options.debug_io);
    const registered = (enrollment.readRegisteredLocked(alloc, session, &id_buf, &credential, if (registration_key != null) wg_public_key else null) catch |err| return switch (err) {
        error.NotLeader => common.badRequest("not leader"),
        error.Conflict => common.conflict("registration credential does not own this identity"),
        else => common.internalError(),
    }) orelse return common.conflict("registration identity unavailable");
    defer registered.deinit(alloc);
    var json = std.Io.Writer.Allocating.init(alloc);
    defer json.deinit();
    writeRegistrationJson(alloc, &json.writer, node, .{
        .id = &id_buf,
        .credential = &credential,
        .registration_key_accepted = registration_key != null,
        .node_id = if (registered.node_id) |nid| std.math.cast(u16, nid) else null,
        .overlay_ip = registered.overlay_ip,
        .role = role_str,
    }) catch return common.internalError();
    const body = json.toOwnedSlice() catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

const RegistrationResponse = struct {
    id: []const u8,
    credential: []const u8,
    registration_key_accepted: bool,
    node_id: ?u16,
    overlay_ip: ?[]const u8,
    role: ?[]const u8,
};

// the caller holds the node lock through all bootstrap queries and serialization.
fn writeRegistrationJson(alloc: std.mem.Allocator, writer: *std.Io.Writer, node: *Node, response: RegistrationResponse) !void {
    try writer.writeAll("{\"id\":\"");
    try writer.writeAll(response.id);
    try writer.print("\",\"credential\":\"{s}\"", .{response.credential});
    if (response.registration_key_accepted) try writer.writeAll(",\"registration_key_accepted\":true");

    if (response.node_id) |nid| {
        try writer.print(",\"node_id\":{d}", .{nid});
    }
    if (response.overlay_ip) |oip| {
        try writer.writeAll(",\"overlay_ip\":\"");
        try writer.writeAll(oip);
        try writer.writeByte('"');
    }

    if (response.node_id) |node_id| {
        const db = node.stateMachineDb();
        const parsed_role = if (response.role) |role| cluster_config.NodeRole.fromString(role) else null;
        const is_agent_role = parsed_role == .agent;
        const peers = (if (is_agent_role)
            agent_registry.listWireguardServerPeers(alloc, db)
        else
            agent_registry.listWireguardPeers(alloc, db)) catch {
            // return the assigned identity if peer lookup fails.
            try writer.writeByte('}');
            return;
        };
        defer {
            for (peers) |p| p.deinit(alloc);
            alloc.free(peers);
        }

        try writer.writeAll(",\"peers\":[");
        var first = true;
        for (peers) |peer| {
            if (peer.node_id == @as(i64, node_id)) continue;
            if (!first) try writer.writeByte(',');
            first = false;
            try writers.writeWireguardPeerJson(writer, peer);
        }
        try writer.writeByte(']');
    }

    // the first worker needs a server to contact before other worker seeds exist.
    // the agent uses this port and pins the server IP to the authenticated API peer.
    try writer.print(",\"gossip_server\":{{\"id\":{d},\"port\":{d}}}", .{ node.config.id, node.gossip_port });

    blk: {
        const db = node.stateMachineDb();
        const seeds = agent_registry.getGossipSeeds(alloc, db, 5) catch break :blk;
        defer agent_registry.freeGossipSeeds(alloc, seeds);

        if (seeds.len > 0) {
            try writer.writeAll(",\"gossip_seeds\":[");
            for (seeds, 0..) |seed, i| {
                if (i > 0) try writer.writeByte(',');
                try writer.writeByte('"');
                try json_helpers.writeJsonEscaped(writer, seed);
                try writer.writeByte('"');
            }
            try writer.writeByte(']');
        }
    }

    try writer.writeByte('}');
}

pub fn handleAgentHeartbeat(alloc: std.mem.Allocator, request: http.Request, id: []const u8, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (request.body.len == 0) return common.badRequest("missing request body");

    const parsed = numbers.parse(alloc, request.body) catch return common.badRequest("invalid resource snapshot");
    defer parsed.deinit();
    const cpu_used = numbers.field(u32, parsed.value, "cpu_used", 0, std.math.maxInt(u32), 0) catch return common.badRequest("invalid cpu_used");
    const memory_used_mb = numbers.field(u64, parsed.value, "memory_used_mb", 0, std.math.maxInt(i64), 0) catch return common.badRequest("invalid memory_used_mb");
    const containers = numbers.field(u32, parsed.value, "containers", 0, std.math.maxInt(u32), 0) catch return common.badRequest("invalid containers");
    const cpu_cores = numbers.field(u32, parsed.value, "cpu_cores", 0, 10000, 0) catch return common.badRequest("invalid cpu_cores");
    const memory_mb = numbers.field(u64, parsed.value, "memory_mb", 0, 10_000_000, 0) catch return common.badRequest("invalid memory_mb");
    const gpu_count = numbers.field(u32, parsed.value, "gpu_count", 0, std.math.maxInt(u32), 0) catch return common.badRequest("invalid gpu_count");
    const gpu_used = numbers.field(u32, parsed.value, "gpu_used", 0, std.math.maxInt(u32), 0) catch return common.badRequest("invalid gpu_used");
    const gpu_health_str = extractJsonString(request.body, "gpu_health");

    const agent_types = @import("../../../cluster/agent_types.zig");

    node.recordHeartbeat(
        id,
        .{
            .cpu_cores = cpu_cores,
            .memory_mb = memory_mb,
            .cpu_used = cpu_used,
            .memory_used_mb = memory_used_mb,
            .containers = containers,
            .gpu_count = gpu_count,
            .gpu_used = gpu_used,
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
    try std.testing.expectEqual(@as(?i64, 2), json_helpers.extractJsonInt(response.body, "node_id"));
    const gossip = json_helpers.extractJsonObject(response.body, "gossip_server") orelse return error.MissingGossipServer;
    try std.testing.expectEqual(@as(?i64, 1), json_helpers.extractJsonInt(gossip, "id"));
    try std.testing.expectEqual(@as(?i64, 19877), json_helpers.extractJsonInt(gossip, "port"));
    try std.testing.expectEqual(node.raft.commit_index, node.state_machine.last_applied);
}

const retry_test_key = "0123456789abcdef" ** 4;

fn registerRetryForTest(node: *@import("../../../cluster/node.zig").Node, key: []const u8, public_key: []const u8, address: []const u8) !Response {
    const alloc = std.testing.allocator;
    const body = try std.fmt.allocPrint(alloc, "{{\"token\":\"join-secret\",\"address\":\"{s}\",\"cpu_cores\":2,\"memory_mb\":512,\"registration_key\":\"{s}\",\"wg_public_key\":\"{s}\"}}", .{ address, key, public_key });
    defer alloc.free(body);
    return handleAgentRegisterImpl(alloc, .{
        .method = .POST,
        .path = "/agents/register",
        .path_only = "/agents/register",
        .query = "",
        .content_length = body.len,
        .body = body,
        .headers_raw = "",
    }, .{ .cluster = node, .join_token = "join-secret" });
}

test "enrollment retry after lost response and replica promotion keeps one identity" {
    const node_mod = @import("../../../cluster/node.zig");
    const alloc = std.testing.allocator;
    var leader = try node_mod.Node.initForTests(alloc, .{ .id = 1, .port = 0, .peers = &.{}, .data_dir = "/unused" });
    defer leader.deinit();
    leader.fixPointers();
    leader.raft.role = .leader;
    const first = try registerRetryForTest(&leader, retry_test_key, "test-key", "10.0.0.2");
    defer if (first.allocated) alloc.free(first.body);
    try std.testing.expectEqual(http.StatusCode.ok, first.status);
    const first_id = extractJsonString(first.body, "id").?;
    try std.testing.expectEqualStrings(retry_test_key, extractJsonString(first.body, "credential").?);
    try std.testing.expect(std.mem.indexOf(u8, first.body, "\"registration_key_accepted\":true") != null);

    var replica = try node_mod.Node.initForTests(alloc, .{ .id = 1, .port = 0, .peers = &.{}, .data_dir = "/unused" });
    defer replica.deinit();
    replica.fixPointers();
    const entries = try leader.log.getEntries(alloc, 1, leader.raft.commit_index);
    defer {
        for (entries) |entry| alloc.free(entry.data);
        alloc.free(entries);
    }
    for (entries) |entry| try replica.log.append(entry);
    replica.state_machine.applyUpTo(&replica.log, alloc, leader.raft.commit_index);
    replica.raft.commit_index = leader.raft.commit_index;
    replica.raft.role = .leader;
    replica.raft.persistent_state.current_term = 1;
    try std.testing.expect(replica.log.setCurrentTerm(1));
    leader.raft.role = .follower;
    const retried = try registerRetryForTest(&replica, retry_test_key, "test-key", "10.0.0.3");
    defer if (retried.allocated) alloc.free(retried.body);
    try std.testing.expectEqual(http.StatusCode.ok, retried.status);
    try std.testing.expectEqualStrings(first_id, extractJsonString(retried.body, "id").?);
    try std.testing.expectEqual(@as(?i64, 2), json_helpers.extractJsonInt(retried.body, "node_id"));
    const row = (try replica.stateMachineDb().one(struct { agents: i64, peers: i64 }, "SELECT (SELECT COUNT(*) FROM agents) AS agents, (SELECT COUNT(*) FROM wireguard_peers) AS peers;", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 1), row.agents);
    try std.testing.expectEqual(@as(i64, 1), row.peers);
    const endpoint = (try replica.stateMachineDb().oneAlloc(struct { endpoint: []const u8 }, alloc, "SELECT endpoint FROM wireguard_peers;", .{}, .{})).?;
    defer alloc.free(endpoint.endpoint);
    try std.testing.expectEqualStrings("10.0.0.3:51820", endpoint.endpoint);
}

test "enrollment retries cannot replace wireguard identity or revive revoked credentials" {
    const alloc = std.testing.allocator;
    var node = try @import("../../../cluster/node.zig").Node.initForTests(alloc, .{ .id = 1, .port = 0, .peers = &.{}, .data_dir = "/unused" });
    defer node.deinit();
    node.fixPointers();
    node.raft.role = .leader;
    const first = try registerRetryForTest(&node, retry_test_key, "original-key", "10.0.0.2");
    defer if (first.allocated) alloc.free(first.body);
    try std.testing.expectEqual(http.StatusCode.ok, first.status);
    const id = extractJsonString(first.body, "id").?;
    const replacement = try registerRetryForTest(&node, retry_test_key, "different-key", "10.0.0.9");
    defer if (replacement.allocated) alloc.free(replacement.body);
    try std.testing.expectEqual(http.StatusCode.conflict, replacement.status);
    const session = try mutation.Session.begin(&node);
    try session.commit("UPDATE agents SET credential_hash = NULL;");
    const revoked = try registerRetryForTest(&node, retry_test_key, "original-key", "10.0.0.9");
    defer if (revoked.allocated) alloc.free(revoked.body);
    try std.testing.expectEqual(http.StatusCode.conflict, revoked.status);
    try std.testing.expect(!(try credentials.authenticates(node.stateMachineDb(), retry_test_key, id)));
    const unchanged = (try agent_registry.getAgent(alloc, node.stateMachineDb(), id)).?;
    defer unchanged.deinit(alloc);
    try std.testing.expectEqualStrings("10.0.0.2", unchanged.address);
    try std.testing.expectEqualStrings("original-key", unchanged.wg_public_key.?);
}

test "simultaneous enrollment retries converge on the same applied identity" {
    const alloc = std.testing.allocator;
    var node = try @import("../../../cluster/node.zig").Node.initForTests(alloc, .{ .id = 1, .port = 0, .peers = &.{}, .data_dir = "/unused" });
    defer node.deinit();
    node.fixPointers();
    node.raft.role = .leader;
    const Worker = struct {
        node: *@import("../../../cluster/node.zig").Node,
        response: ?Response = null,
        fn run(self: *@This()) void {
            self.response = registerRetryForTest(self.node, retry_test_key, "test-key", "10.0.0.2") catch null;
        }
    };
    var workers = [_]Worker{ .{ .node = &node }, .{ .node = &node } };
    var first_thread = try std.Thread.spawn(.{}, Worker.run, .{&workers[0]});
    var second_thread = std.Thread.spawn(.{}, Worker.run, .{&workers[1]}) catch |err| {
        first_thread.join();
        if (workers[0].response) |response| if (response.allocated) alloc.free(response.body);
        return err;
    };
    first_thread.join();
    second_thread.join();
    defer for (workers) |worker| if (worker.response) |response| {
        if (response.allocated) alloc.free(response.body);
    };
    for (workers) |worker| try std.testing.expectEqual(http.StatusCode.ok, (worker.response orelse return error.MissingResponse).status);
    try std.testing.expectEqualStrings(extractJsonString(workers[0].response.?.body, "id").?, extractJsonString(workers[1].response.?.body, "id").?);
    const count = (try node.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM agents;", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 1), count.count);
}

test "enrollment rejects malformed retry keys instead of creating a legacy identity" {
    const alloc = std.testing.allocator;
    for ([_][]const u8{ "{\"registration_key\":7}", "{\"registration_key\":\"short\"}", "{\"registration_key\":null}" }) |body|
        try std.testing.expectError(error.InvalidKey, enrollment.parseKey(alloc, body));
    try std.testing.expect((try enrollment.parseKey(alloc, "{}")) == null);
}

test "registration bootstrap filters worker peers and excludes the assigned identity" {
    const alloc = std.testing.allocator;
    var node = try Node.initForTests(alloc, .{ .id = 1, .port = 0, .gossip_port = 19877, .peers = &.{}, .data_dir = "/unused" });
    defer node.deinit();
    node.fixPointers();
    node.mu.lockUncancelable(std.Options.debug_io);
    defer node.mu.unlock(std.Options.debug_io);
    const db = node.stateMachineDb();
    for ([_][]const u8{ "server", "agent", "both" }, 2..) |role, id| {
        const node_id: u16 = @intCast(id);
        var sql_buf: [2048]u8 = undefined;
        const agent_sql = try agent_registry.registerSqlFull(&sql_buf, role, "10.0.0.2", .{ .cpu_cores = 2, .memory_mb = 512 }, 0, .{
            .role = role,
            .node_id = node_id,
            .wg_public_key = role,
            .overlay_ip = "10.42.0.2",
        });
        try db.execDynamic(agent_sql, .{}, .{});
        const peer_sql = try agent_registry.wireguardPeerSql(&sql_buf, node_id, role, role, "10.0.0.2:51820", "10.42.0.2", "10.42.2.0/24");
        try db.execDynamic(peer_sql, .{}, .{});
    }

    for ([_]?[]const u8{ "agent", "server", "both", null, "unknown" }) |role| {
        var json = std.Io.Writer.Allocating.init(alloc);
        defer json.deinit();
        try writeRegistrationJson(alloc, &json.writer, &node, .{
            .id = "both",
            .credential = retry_test_key,
            .registration_key_accepted = true,
            .node_id = 4,
            .overlay_ip = "10.42.0.2",
            .role = role,
        });
        const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json.written(), .{});
        defer parsed.deinit();
        const object = parsed.value.object;
        try std.testing.expect(object.get("registration_key_accepted").?.bool);
        try std.testing.expectEqualStrings(retry_test_key, object.get("credential").?.string);
        const peers = object.get("peers").?.array.items;
        const worker_only = if (role) |value| std.mem.eql(u8, value, "agent") else false;
        try std.testing.expectEqual(@as(usize, if (worker_only) 1 else 2), peers.len);
        try std.testing.expectEqual(@as(i64, 2), peers[0].object.get("node_id").?.integer);
        if (!worker_only) try std.testing.expectEqual(@as(i64, 3), peers[1].object.get("node_id").?.integer);
        const gossip = object.get("gossip_server").?.object;
        try std.testing.expectEqual(@as(i64, 1), gossip.get("id").?.integer);
        try std.testing.expectEqual(@as(i64, 19877), gossip.get("port").?.integer);
        try std.testing.expectEqual(@as(usize, 2), object.get("gossip_seeds").?.array.items.len);
    }
}

test "registration bootstrap preserves responses without peer data" {
    const alloc = std.testing.allocator;
    var node = try Node.initForTests(alloc, .{ .id = 1, .port = 0, .gossip_port = 19877, .peers = &.{}, .data_dir = "/unused" });
    defer node.deinit();
    node.fixPointers();
    node.mu.lockUncancelable(std.Options.debug_io);
    defer node.mu.unlock(std.Options.debug_io);
    try node.stateMachineDb().exec("DROP TABLE wireguard_peers;", .{}, .{});
    var response: RegistrationResponse = .{
        .id = "assigned-id",
        .credential = retry_test_key,
        .registration_key_accepted = false,
        .node_id = 2,
        .overlay_ip = "10.42.0.2",
        .role = null,
    };
    var json = std.Io.Writer.Allocating.init(alloc);
    defer json.deinit();
    try writeRegistrationJson(alloc, &json.writer, &node, response);
    try std.testing.expectEqualStrings(
        "{\"id\":\"assigned-id\",\"credential\":\"" ++ retry_test_key ++ "\",\"node_id\":2,\"overlay_ip\":\"10.42.0.2\"}",
        json.written(),
    );

    response.node_id = null;
    response.overlay_ip = null;
    var legacy_json = std.Io.Writer.Allocating.init(alloc);
    defer legacy_json.deinit();
    try writeRegistrationJson(alloc, &legacy_json.writer, &node, response);
    try std.testing.expectEqualStrings(
        "{\"id\":\"assigned-id\",\"credential\":\"" ++ retry_test_key ++ "\",\"gossip_server\":{\"id\":1,\"port\":19877}}",
        legacy_json.written(),
    );
    var short_buffer: [8]u8 = undefined;
    var short_writer = std.Io.Writer.fixed(&short_buffer);
    try std.testing.expectError(error.WriteFailed, writeRegistrationJson(alloc, &short_writer, &node, response));
}
