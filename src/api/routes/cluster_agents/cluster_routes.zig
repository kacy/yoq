const std = @import("std");
const http = @import("../../http.zig");
const common = @import("../common.zig");
const cluster_node = @import("../../../cluster/node.zig");

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
    const version = cluster_node.Node.protocolVersion();
    _ = version;
    return .{ .status = .ok, .body = "{\"protocol_version\":1,\"software_version\":\"0.2.0\"}", .allocated = false };
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
    try std.testing.expectEqualStrings("{\"protocol_version\":1,\"software_version\":\"0.2.0\"}", resp.body);
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
