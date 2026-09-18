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
    if (response.body.len > 2) writer.writer.writeByte(',') catch return response;
    endpoints.writeFields(&writer.writer, members[0..node.config.peers.len], token) catch return response;
    writer.writer.writeByte('}') catch return response;
    const body = writer.toOwnedSlice() catch return response;
    if (response.allocated) alloc.free(response.body);
    return .{ .status = response.status, .body = body, .allocated = true };
}

test "agent recovery discovery publishes the configured api port" {
    const alloc = std.testing.allocator;
    var node = try @import("../../../cluster/node.zig").Node.initForTests(alloc, .{
        .id = 1,
        .port = 9700,
        .api_port = 8800,
        .peers = &.{.{ .id = 2, .addr = .{ 127, 0, 0, 2 }, .port = 9701 }},
        .shared_key = [_]u8{7} ** 32,
        .data_dir = "/unused",
    });
    defer node.deinit();
    const response = attach(alloc, .{ .cluster = &node, .join_token = "cluster-token" }, .{ .status = .ok, .body = "{}", .allocated = false });
    defer if (response.allocated) alloc.free(response.body);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, response.body, .{});
    defer parsed.deinit();
    var trusted: endpoints.Set = .{};
    try trusted.add(.{ .address = .{ 127, 0, 0, 1 }, .port = 8800 });
    try std.testing.expect(try trusted.learn(alloc, response.body, "cluster-token"));
    try std.testing.expect(trusted.select(.{ .address = .{ 127, 0, 0, 2 }, .port = 8800 }));
    try std.testing.expect(!trusted.select(.{ .address = .{ 127, 0, 0, 2 }, .port = 9701 }));
}
