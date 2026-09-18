const std = @import("std");
const common = @import("../common.zig");
const endpoints = @import("../../../cluster/api_endpoints.zig");

// peers use the configured cluster-wide api port, never their raft port. the
// caller already knows this server's reachable address from its connection.
pub fn attach(alloc: std.mem.Allocator, ctx: common.RouteContext, response: common.Response) common.Response {
    const node = ctx.cluster orelse return response;
    const token = ctx.join_token orelse return response;
    if (node.config.peers.len >= endpoints.max_endpoints or response.body.len == 0 or response.body[response.body.len - 1] != '}') return response;
    var members: [endpoints.max_endpoints]endpoints.Endpoint = undefined;
    for (node.config.peers, 0..) |peer, i| members[i] = .{ .address = peer.addr, .port = node.config.api_port };
    var writer = std.Io.Writer.Allocating.init(alloc);
    defer writer.deinit();
    writer.writer.writeAll(response.body[0 .. response.body.len - 1]) catch return response;
    writer.writer.writeByte(',') catch return response;
    endpoints.writeFields(&writer.writer, members[0..node.config.peers.len], token) catch return response;
    writer.writer.writeByte('}') catch return response;
    const body = writer.toOwnedSlice() catch return response;
    if (response.allocated) alloc.free(response.body);
    return .{ .status = response.status, .body = body, .allocated = true };
}
