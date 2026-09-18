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
};

pub const PortMap = struct {
    host_ip: ?[4]u8 = null,
    host_port: u16,
    container_port: u16,
    protocol: Protocol = .tcp,

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
