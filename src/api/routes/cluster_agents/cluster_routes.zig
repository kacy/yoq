const std = @import("std");
const http = @import("../../http.zig");
const common = @import("../common.zig");
const cluster_node = @import("../../../cluster/node.zig");
const version = @import("../../../lib/version.zig");
const http_client = @import("../../../cluster/http_client.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");

fn nowMilliseconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toMilliseconds();
}

const Response = common.Response;
const RouteContext = common.RouteContext;
const ClusterStatusContext = struct {
    node: *cluster_node.Node,
    role_str: []const u8,
};

pub fn handleLeaderStepDown(alloc: std.mem.Allocator, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");

    if (node.transferLeadership()) {
        return .{ .status = .ok, .body = "{\"transferred\":true}", .allocated = false };
    } else {
        var buf: [64]u8 = undefined;
        if (node.leaderAddrBuf(&buf)) |addr| {
            var json_buf: [128]u8 = undefined;
            const body = std.fmt.bufPrint(&json_buf, "{{\"transferred\":false,\"error\":\"not leader\",\"leader\":\"{s}\"}}", .{addr}) catch
                return .{ .status = .bad_request, .body = "{\"transferred\":false,\"error\":\"not leader\"}", .allocated = false };
            const owned = alloc.dupe(u8, body) catch
                return .{ .status = .bad_request, .body = "{\"transferred\":false,\"error\":\"not leader\"}", .allocated = false };
            return .{ .status = .bad_request, .body = owned, .allocated = true };
        }
        return .{ .status = .bad_request, .body = "{\"transferred\":false,\"error\":\"not leader\"}", .allocated = false };
    }
}

pub fn handleClusterVersion() Response {
    const body = "{\"protocol_version\":1,\"software_version\":\"" ++ version.string ++ "\"}";
    return .{ .status = .ok, .body = body, .allocated = false };
}

/// report this node's identity, wall clock, and software version. used by the
/// peers-info aggregator to gather per-node data for upgrade preflight.
pub fn handleClusterNodeInfo(alloc: std.mem.Allocator, ctx: RouteContext) Response {
    const id: u64 = if (ctx.cluster) |node| node.config.id else 0;
    var buf: [192]u8 = undefined;
    const body = std.fmt.bufPrint(
        &buf,
        "{{\"id\":{d},\"unix_ms\":{d},\"software_version\":\"{s}\"}}",
        .{ id, nowMilliseconds(), version.string },
    ) catch return common.internalError();
    const owned = alloc.dupe(u8, body) catch return common.internalError();
    return .{ .status = .ok, .body = owned, .allocated = true };
}

/// aggregate identity/clock/version for this node and every configured peer, so
/// `yoq upgrade preflight` (which only reaches the local agent) can detect
/// version- and clock-skew across the cluster. peers are queried at their api
/// port (same cluster-wide by convention); an unreachable peer is reported with
/// reachable=0. each peer call carries the configured api token and a 5s
/// connect timeout (from http_client), so the fan-out is bounded.
pub fn handleClusterPeersInfo(alloc: std.mem.Allocator, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return .{ .status = .ok, .body = "[]", .allocated = false };

    var buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer buf_writer.deinit();
    const writer = &buf_writer.writer;

    writer.writeByte('[') catch return common.internalError();
    // this node — always reachable, read locally.
    writer.print(
        "{{\"id\":{d},\"software_version\":\"{s}\",\"unix_ms\":{d},\"reachable\":1}}",
        .{ node.config.id, version.string, nowMilliseconds() },
    ) catch return common.internalError();

    for (node.config.peers) |peer| {
        writer.writeByte(',') catch return common.internalError();
        appendPeerInfo(alloc, writer, peer, node.config.api_port, ctx.api_token);
    }

    writer.writeByte(']') catch return common.internalError();
    const body = buf_writer.toOwnedSlice() catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

/// query one peer's /cluster/node-info and append its entry. on any failure the
/// peer is recorded as unreachable so preflight can surface it.
fn appendPeerInfo(alloc: std.mem.Allocator, writer: *std.Io.Writer, peer: cluster_node.PeerConfig, api_port: u16, token: ?[]const u8) void {
    var resp = http_client.getWithAuth(alloc, peer.addr, api_port, "/cluster/node-info", token) catch {
        writer.print("{{\"id\":{d},\"reachable\":0}}", .{peer.id}) catch {};
        return;
    };
    defer resp.deinit(alloc);

    const peer_version = json_helpers.extractJsonString(resp.body, "software_version");
    const peer_unix_ms = json_helpers.extractJsonInt(resp.body, "unix_ms");
    if (peer_version == null or peer_unix_ms == null) {
        writer.print("{{\"id\":{d},\"reachable\":0}}", .{peer.id}) catch {};
        return;
    }

    writer.print(
        "{{\"id\":{d},\"software_version\":\"{s}\",\"unix_ms\":{d},\"reachable\":1}}",
        .{ peer.id, peer_version.?, peer_unix_ms.? },
    ) catch {};
}

pub fn handleClusterStatus(alloc: std.mem.Allocator, ctx: RouteContext) Response {
    const node = ctx.cluster orelse {
        return .{ .status = .ok, .body = "{\"cluster\":false}", .allocated = false };
    };

    const role_str = switch (node.role()) {
        .follower => "follower",
        .candidate => "candidate",
        .leader => "leader",
    };

    return common.jsonOkWrite(alloc, ClusterStatusContext{
        .node = node,
        .role_str = role_str,
    }, writeClusterStatusJson);
}

pub fn handleClusterPropose(alloc: std.mem.Allocator, request: http.Request, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (request.body.len == 0) return common.badRequest("missing request body");

    _ = node.propose(request.body) catch {
        return common.notLeader(alloc, node);
    };

    return .{ .status = .ok, .body = "{\"status\":\"proposed\"}", .allocated = false };
}

test "cluster version reports current software version" {
    const resp = handleClusterVersion();
    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    const expected = "{\"protocol_version\":1,\"software_version\":\"" ++ version.string ++ "\"}";
    try std.testing.expectEqualStrings(expected, resp.body);
}

test "node info reports id, clock, and version" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const resp = handleClusterNodeInfo(std.testing.allocator, ctx);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"id\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"unix_ms\":") != null);
    const want_version = "\"software_version\":\"" ++ version.string ++ "\"";
    try std.testing.expect(std.mem.indexOf(u8, resp.body, want_version) != null);
}

test "peers info returns empty array without a cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const resp = handleClusterPeersInfo(std.testing.allocator, ctx);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expectEqualStrings("[]", resp.body);
}

fn writeClusterStatusJson(writer: *std.Io.Writer, ctx: ClusterStatusContext) !void {
    try writer.writeAll("{\"cluster\":true");
    try writer.print(",\"id\":{d}", .{ctx.node.config.id});
    try writer.writeAll(",\"role\":\"");
    try writer.writeAll(ctx.role_str);
    try writer.writeByte('"');
    try writer.print(",\"term\":{d}", .{ctx.node.currentTerm()});
    try writer.print(",\"peers\":{d}", .{ctx.node.config.peers.len});

    if (ctx.node.leaderId()) |leader_id| {
        try writer.print(",\"leader_id\":{d}", .{leader_id});
        var addr_buf: [64]u8 = undefined;
        if (ctx.node.leaderAddrBuf(&addr_buf)) |leader_addr| {
            try writer.writeAll(",\"leader\":\"");
            try writer.writeAll(leader_addr);
            try writer.writeByte('"');
        }
    }

    try writer.writeByte('}');
}
