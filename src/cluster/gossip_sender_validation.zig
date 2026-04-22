const std = @import("std");
const gossip_mod = @import("gossip.zig");
const transport_mod = @import("transport.zig");

pub fn isTrustedSender(gossip: *gossip_mod.Gossip, recv: transport_mod.GossipReceiveResult) bool {
    const expected = gossip.getMemberAddr(recv.sender_id) orelse return false;
    return matchesMemberAddr(expected, recv.from_addr);
}

pub fn matchesMemberAddr(expected: gossip_mod.MemberAddr, actual: @import("compat").net.Address) bool {
    if (actual.any.family != std.posix.AF.INET) return false;

    const actual_ip: [4]u8 = @bitCast(actual.in.addr);
    const actual_port = std.mem.bigToNative(u16, actual.in.port);
    return std.mem.eql(u8, &expected.ip, &actual_ip) and expected.port == actual_port;
}

test "isTrustedSender matches configured gossip member endpoint" {
    var gossip = gossip_mod.Gossip.init(std.testing.allocator, 1, .{
        .ip = .{ 127, 0, 0, 1 },
        .port = 9800,
    }, .{});
    defer gossip.deinit();

    try gossip.addMember(2, .{
        .ip = .{ 10, 0, 0, 2 },
        .port = 9800,
    });

    const trusted = transport_mod.GossipReceiveResult{
        .sender_id = 2,
        .from_addr = @import("compat").net.Address.initIp4(.{ 10, 0, 0, 2 }, 9800),
        .payload = "ping",
    };
    try std.testing.expect(isTrustedSender(&gossip, trusted));

    const spoofed_ip = transport_mod.GossipReceiveResult{
        .sender_id = 2,
        .from_addr = @import("compat").net.Address.initIp4(.{ 10, 0, 0, 9 }, 9800),
        .payload = "ping",
    };
    try std.testing.expect(!isTrustedSender(&gossip, spoofed_ip));

    const spoofed_port = transport_mod.GossipReceiveResult{
        .sender_id = 2,
        .from_addr = @import("compat").net.Address.initIp4(.{ 10, 0, 0, 2 }, 9810),
        .payload = "ping",
    };
    try std.testing.expect(!isTrustedSender(&gossip, spoofed_port));
}
