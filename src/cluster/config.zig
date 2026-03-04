// config — cluster node configuration
//
// loads cluster configuration from CLI flags. peers are specified
// as comma-separated id@host:port strings.
//
// examples:
//   yoq init-server --id 1 --port 9700 --peers 2@10.0.0.2:9700,3@10.0.0.3:9700
//   yoq cluster status --api http://localhost:7700

const std = @import("std");
const node_mod = @import("node.zig");
const paths = @import("../lib/paths.zig");

pub const NodeConfig = node_mod.NodeConfig;
pub const PeerConfig = node_mod.PeerConfig;

pub const ConfigError = error{
    InvalidPeerFormat,
    InvalidPort,
    DataDirFailed,
};

/// parse a peers string like "2@10.0.0.1:9700,3@10.0.0.2:9700"
pub fn parsePeers(alloc: std.mem.Allocator, peers_str: []const u8) ![]PeerConfig {
    if (peers_str.len == 0) return &.{};

    var peers: std.ArrayList(PeerConfig) = .{};

    var iter = std.mem.splitScalar(u8, peers_str, ',');
    while (iter.next()) |peer_str| {
        const trimmed = std.mem.trim(u8, peer_str, " ");
        if (trimmed.len == 0) continue;

        const peer = parseSinglePeer(trimmed) catch return ConfigError.InvalidPeerFormat;
        peers.append(alloc, peer) catch return ConfigError.InvalidPeerFormat;
    }

    return peers.toOwnedSlice(alloc) catch return ConfigError.InvalidPeerFormat;
}

/// parse a single peer spec like "2@10.0.0.1:9700"
fn parseSinglePeer(s: []const u8) !PeerConfig {
    // split on '@'
    const at_pos = std.mem.indexOf(u8, s, "@") orelse return error.InvalidFormat;
    const id_str = s[0..at_pos];
    const addr_str = s[at_pos + 1 ..];

    const id = std.fmt.parseInt(u64, id_str, 10) catch return error.InvalidFormat;

    // split address on ':'
    const colon_pos = std.mem.lastIndexOf(u8, addr_str, ":") orelse return error.InvalidFormat;
    const host_str = addr_str[0..colon_pos];
    const port_str = addr_str[colon_pos + 1 ..];

    const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidFormat;

    // parse IP address (simple dotted-quad for now)
    const addr = parseIpv4(host_str) catch return error.InvalidFormat;

    return .{
        .id = id,
        .addr = addr,
        .port = port,
    };
}

fn parseIpv4(s: []const u8) ![4]u8 {
    var result: [4]u8 = undefined;
    var iter = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (iter.next()) |octet_str| {
        if (i >= 4) return error.InvalidFormat;
        result[i] = std.fmt.parseInt(u8, octet_str, 10) catch return error.InvalidFormat;
        i += 1;
    }
    if (i != 4) return error.InvalidFormat;
    return result;
}

/// get the default data directory for cluster state
pub fn defaultDataDir(buf: *[512]u8) ![]const u8 {
    paths.ensureDataDir("cluster") catch return ConfigError.DataDirFailed;
    const path = paths.dataPath(buf, "cluster") catch return ConfigError.DataDirFailed;
    return path;
}

// -- tests --

test "parsePeers single peer" {
    const alloc = std.testing.allocator;
    const peers = try parsePeers(alloc, "2@10.0.0.2:9700");
    defer alloc.free(peers);

    try std.testing.expectEqual(@as(usize, 1), peers.len);
    try std.testing.expectEqual(@as(u64, 2), peers[0].id);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 2 }, peers[0].addr);
    try std.testing.expectEqual(@as(u16, 9700), peers[0].port);
}

test "parsePeers multiple peers" {
    const alloc = std.testing.allocator;
    const peers = try parsePeers(alloc, "2@10.0.0.2:9700,3@10.0.0.3:9700");
    defer alloc.free(peers);

    try std.testing.expectEqual(@as(usize, 2), peers.len);
    try std.testing.expectEqual(@as(u64, 2), peers[0].id);
    try std.testing.expectEqual(@as(u64, 3), peers[1].id);
}

test "parsePeers empty string" {
    const alloc = std.testing.allocator;
    const peers = try parsePeers(alloc, "");
    try std.testing.expectEqual(@as(usize, 0), peers.len);
}

test "parseIpv4 valid" {
    const addr = try parseIpv4("192.168.1.1");
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 1 }, addr);
}

test "parseIpv4 localhost" {
    const addr = try parseIpv4("127.0.0.1");
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, addr);
}
