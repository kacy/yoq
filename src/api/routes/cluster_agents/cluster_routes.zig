const std = @import("std");
const http = @import("../../http.zig");
const common = @import("../common.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

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
    const cluster_node = @import("../../../cluster/node.zig");
    const version = cluster_node.Node.protocolVersion();
    _ = version;
    return .{ .status = .ok, .body = "{\"protocol_version\":1,\"software_version\":\"0.1.0\"}", .allocated = false };
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

    if (node.leaderId()) |lid| {
        std.fmt.format(writer, ",\"leader_id\":{d}", .{lid}) catch return common.internalError();
        var addr_buf: [64]u8 = undefined;
        if (node.leaderAddrBuf(&addr_buf)) |addr| {
            writer.writeAll(",\"leader\":\"") catch return common.internalError();
            writer.writeAll(addr) catch return common.internalError();
            writer.writeByte('"') catch return common.internalError();
        }
    }

    writer.writeByte('}') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleClusterPropose(alloc: std.mem.Allocator, request: http.Request, ctx: RouteContext) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    if (request.body.len == 0) return common.badRequest("missing request body");

    _ = node.propose(request.body) catch {
        return common.notLeader(alloc, node);
    };

    return .{ .status = .ok, .body = "{\"status\":\"proposed\"}", .allocated = false };
}
