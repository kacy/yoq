const std = @import("std");
const cluster_config = @import("../../cluster/config.zig");
const nat = @import("../nat.zig");

pub const SetupError = error{
    BridgeFailed,
    IpAllocationFailed,
    VethFailed,
    NatFailed,
    ConfigFailed,
    DbFailed,
};

pub const ClusterNetworkConfig = struct {
    node_id: u16,
    private_key: []const u8,
    listen_port: u16,
    overlay_ip: [4]u8,
    peers: []const PeerInfo,
    role: cluster_config.NodeRole = .both,
};

pub const PeerInfo = struct {
    public_key: []const u8,
    endpoint: []const u8,
    overlay_ip: [4]u8,
    container_subnet_node: u16,
    is_hub: bool = false,
};

pub const NetworkConfig = struct {
    enabled: bool = true,
    port_maps: []const PortMap = &.{},
    skip_dns: bool = false,
    node_id: ?u16 = null,
    network_name: ?[]const u8 = null,
};

pub const PortMap = struct {
    host_ip: ?[4]u8 = null,
    host_port: u16,
    container_port: u16,
    protocol: Protocol = .tcp,

    pub fn jsonStringify(self: PortMap, writer: anytype) !void {
        const address = self.bindIp() orelse .{ 0, 0, 0, 0 };
        var buf: [16]u8 = undefined;
        const text = try std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{ address[0], address[1], address[2], address[3] });
        try writer.write(.{ .host_ip = text, .host_port = self.host_port, .container_port = self.container_port, .protocol = self.protocol });
    }

    pub fn bindIp(self: PortMap) ?[4]u8 {
        const address = self.host_ip orelse return null;
        return if (std.mem.eql(u8, &address, &.{ 0, 0, 0, 0 })) null else address;
    }
};

pub const Protocol = enum {
    tcp,
    udp,

    pub fn toNat(self: Protocol) nat.Protocol {
        return switch (self) {
            .tcp => .tcp,
            .udp => .udp,
        };
    }
};

pub const NetworkInfo = struct {
    ip: [4]u8,
    veth_host: [32]u8,
    veth_host_len: usize,

    pub fn vethName(self: *const NetworkInfo) []const u8 {
        return self.veth_host[0..self.veth_host_len];
    }
};

pub const wg_interface = "wg-yoq";

test "published port JSON uses readable host addresses" {
    const alloc = std.testing.allocator;
    const output = try std.json.Stringify.valueAlloc(alloc, PortMap{ .host_ip = .{ 127, 0, 0, 1 }, .host_port = 5300, .container_port = 53, .protocol = .udp }, .{});
    defer alloc.free(output);
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, output, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("127.0.0.1", parsed.value.object.get("host_ip").?.string);
    try std.testing.expectEqualStrings("udp", parsed.value.object.get("protocol").?.string);
    try std.testing.expectEqual(@as(i64, 5300), parsed.value.object.get("host_port").?.integer);
}
