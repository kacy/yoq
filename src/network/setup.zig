// setup — network setup orchestrator
//
// this file keeps the stable public API while the implementation lives
// in smaller modules under `network/setup/`.

const std = @import("std");
const platform = @import("platform");
const posix = std.posix;
const sqlite = @import("sqlite");
const nat = @import("nat.zig");

const common = @import("setup/common.zig");
const cluster_runtime = @import("setup/cluster_runtime.zig");
const container_runtime = @import("setup/container_runtime.zig");
const file_support = @import("setup/file_support.zig");

pub const SetupError = common.SetupError;
pub const ClusterNetworkConfig = common.ClusterNetworkConfig;
pub const PeerInfo = common.PeerInfo;
pub const NetworkConfig = common.NetworkConfig;
pub const PortMap = common.PortMap;
pub const Protocol = common.Protocol;
pub const NetworkInfo = common.NetworkInfo;

pub const setupClusterNetworking = cluster_runtime.setupClusterNetworking;
pub const addClusterPeer = cluster_runtime.addClusterPeer;
pub const removeClusterPeer = cluster_runtime.removeClusterPeer;
pub const teardownClusterNetworking = cluster_runtime.teardownClusterNetworking;

pub const setupContainer = container_runtime.setupContainer;
pub const teardownContainer = container_runtime.teardownContainer;
pub const writeNetworkFiles = file_support.writeNetworkFiles;

const wg_interface = common.wg_interface;
const containerSubnetBase = cluster_runtime.containerSubnetBase;
const isValidHostname = file_support.isValidHostname;

test "network config defaults" {
    const config = NetworkConfig{};
    try std.testing.expect(config.enabled);
    try std.testing.expectEqual(@as(usize, 0), config.port_maps.len);
}

test "port map defaults to tcp" {
    const pm = PortMap{ .host_port = 8080, .container_port = 80 };
    try std.testing.expectEqual(Protocol.tcp, pm.protocol);
}

test "network info veth name" {
    var info = NetworkInfo{
        .ip = .{ 10, 42, 0, 2 },
        .veth_host = undefined,
        .veth_host_len = 11,
    };
    const name = "veth_abc123";
    @memcpy(info.veth_host[0..name.len], name);
    try std.testing.expectEqualStrings("veth_abc123", info.vethName());
}

test "protocol conversion" {
    try std.testing.expectEqual(nat.Protocol.tcp, Protocol.tcp.toNat());
    try std.testing.expectEqual(nat.Protocol.udp, Protocol.udp.toNat());
}

test "writeNetworkFiles sets resolv.conf to bridge gateway" {
    const alloc = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var path_buf: [512]u8 = undefined;
    const rootfs_path = platform.Dir.from(tmp_dir.dir).realpath(".", &path_buf) catch return;

    writeNetworkFiles(rootfs_path, .{ 10, 42, 0, 5 }, .{ 10, 42, 0, 1 }, "myhost");

    var resolv_path_buf: [600]u8 = undefined;
    const resolv_path = std.fmt.bufPrint(&resolv_path_buf, "{s}/etc/resolv.conf", .{rootfs_path}) catch return;
    const content = platform.cwd().readFileAlloc(alloc, resolv_path, 4096) catch return;
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "10.42.0.1") != null);
}

test "writeNetworkFiles sets etc/hosts with hostname" {
    const alloc = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var path_buf: [512]u8 = undefined;
    const rootfs_path = platform.Dir.from(tmp_dir.dir).realpath(".", &path_buf) catch return;

    writeNetworkFiles(rootfs_path, .{ 10, 42, 0, 7 }, .{ 10, 42, 0, 1 }, "dbserver");

    var hosts_path_buf: [600]u8 = undefined;
    const hosts_path = std.fmt.bufPrint(&hosts_path_buf, "{s}/etc/hosts", .{rootfs_path}) catch return;
    const content = platform.cwd().readFileAlloc(alloc, hosts_path, 4096) catch return;
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "dbserver") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "10.42.0.7") != null);
}

test "NetworkConfig defaults to single-node mode" {
    const config = NetworkConfig{};
    try std.testing.expect(config.node_id == null);
    try std.testing.expect(config.enabled);
}

test "NetworkConfig with node_id for cluster mode" {
    const config = NetworkConfig{ .node_id = 5 };
    try std.testing.expectEqual(@as(?u16, 5), config.node_id);
    try std.testing.expect(config.enabled);
}

test "containerSubnetBase for nodes 1-254" {
    try std.testing.expectEqual([3]u8{ 10, 42, 1 }, containerSubnetBase(1));
    try std.testing.expectEqual([3]u8{ 10, 42, 254 }, containerSubnetBase(254));
}

test "containerSubnetBase for extended nodes" {
    try std.testing.expectEqual([3]u8{ 10, 42, 255 }, containerSubnetBase(255));
    try std.testing.expectEqual([3]u8{ 10, 43, 0 }, containerSubnetBase(256));
    try std.testing.expectEqual([3]u8{ 10, 45, 232 }, containerSubnetBase(1000));
}

test "ClusterNetworkConfig struct" {
    const config = ClusterNetworkConfig{
        .node_id = 3,
        .private_key = "base64privatekey==",
        .listen_port = 51820,
        .overlay_ip = .{ 10, 40, 0, 3 },
        .peers = &.{},
    };
    try std.testing.expectEqual(@as(u16, 3), config.node_id);
    try std.testing.expectEqual(@as(u16, 51820), config.listen_port);
    try std.testing.expectEqual([4]u8{ 10, 40, 0, 3 }, config.overlay_ip);
    try std.testing.expectEqual(@as(usize, 0), config.peers.len);
}

test "PeerInfo struct" {
    const peer = PeerInfo{
        .public_key = "peerpubkey==",
        .endpoint = "10.0.0.5:51820",
        .overlay_ip = .{ 10, 40, 0, 5 },
        .container_subnet_node = 5,
    };
    try std.testing.expectEqualStrings("peerpubkey==", peer.public_key);
    try std.testing.expectEqualStrings("10.0.0.5:51820", peer.endpoint);
    try std.testing.expectEqual([4]u8{ 10, 40, 0, 5 }, peer.overlay_ip);
    try std.testing.expectEqual(@as(u16, 5), peer.container_subnet_node);
}

test "PeerInfo with empty endpoint" {
    const peer = PeerInfo{
        .public_key = "key==",
        .endpoint = "",
        .overlay_ip = .{ 10, 40, 0, 1 },
        .container_subnet_node = 1,
    };
    try std.testing.expectEqual(@as(usize, 0), peer.endpoint.len);
}

test "wg_interface constant" {
    try std.testing.expectEqualStrings("wg-yoq", wg_interface);
}

test "hostname validation — valid hostnames" {
    try std.testing.expect(isValidHostname("myhost"));
    try std.testing.expect(isValidHostname("web-server"));
    try std.testing.expect(isValidHostname("db.internal"));
    try std.testing.expect(isValidHostname("a"));
}

test "hostname validation — rejects invalid hostnames" {
    try std.testing.expect(!isValidHostname(""));
    try std.testing.expect(!isValidHostname("host\nname"));
    try std.testing.expect(!isValidHostname("host\rname"));
    try std.testing.expect(!isValidHostname("host\tname"));
    try std.testing.expect(!isValidHostname("host name"));
    try std.testing.expect(!isValidHostname("a" ** 254));
}

test "hostname validation — rejects control characters" {
    try std.testing.expect(!isValidHostname(&[_]u8{ 'a', 0x00, 'b' }));
    try std.testing.expect(!isValidHostname(&[_]u8{ 0x01, 'a' }));
    try std.testing.expect(!isValidHostname(&[_]u8{ 'a', 0x7f }));
}
