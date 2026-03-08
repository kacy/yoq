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
const ip_mod = @import("../network/ip.zig");

pub const NodeConfig = node_mod.NodeConfig;
pub const PeerConfig = node_mod.PeerConfig;

/// node role in the cluster. small clusters use 'both' (default).
/// large clusters separate servers (raft consensus) from agents (workloads).
pub const NodeRole = enum {
    /// participates in raft consensus and runs workloads
    both,
    /// raft consensus only — no workloads
    server,
    /// workloads only — uses gossip for membership, not raft
    agent,

    pub fn toString(self: NodeRole) []const u8 {
        return switch (self) {
            .both => "both",
            .server => "server",
            .agent => "agent",
        };
    }

    pub fn fromString(s: []const u8) ?NodeRole {
        if (std.mem.eql(u8, s, "both")) return .both;
        if (std.mem.eql(u8, s, "server")) return .server;
        if (std.mem.eql(u8, s, "agent")) return .agent;
        return null;
    }
};

/// cluster-wide settings for scaling behavior.
/// auto mode: ≤50 agents = all 'both', no gossip. >50 = gossip active.
pub const ClusterSettings = struct {
    role: NodeRole = .both,
    region: ?[]const u8 = null,

    /// gossip tick interval in milliseconds (default 500ms)
    gossip_tick_ms: u32 = 500,

    /// threshold for auto-activating gossip (agent count)
    gossip_threshold: u32 = 50,
};

pub const ConfigError = error{
    /// peer string does not match the expected id@host:port format
    InvalidPeerFormat,
    /// port number is out of the valid u16 range
    InvalidPort,
    /// could not create or access the cluster data directory
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
    const addr = ip_mod.parseIp(host_str) orelse return error.InvalidFormat;

    return .{
        .id = id,
        .addr = addr,
        .port = port,
    };
}

/// how many committed entries since the last snapshot before we
/// trigger a new one. 10000 is a reasonable default — snapshots
/// are cheap (sqlite backup API) and keep the log from growing
/// unbounded.
pub const snapshot_threshold: u64 = 10000;

/// get the default data directory for cluster state
pub fn defaultDataDir(buf: *[paths.max_path]u8) ![]const u8 {
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

test "parsePeers rejects missing @ separator" {
    const alloc = std.testing.allocator;
    const result = parsePeers(alloc, "2_10.0.0.2:9700");
    try std.testing.expectError(ConfigError.InvalidPeerFormat, result);
}

test "parsePeers rejects missing port" {
    const alloc = std.testing.allocator;
    const result = parsePeers(alloc, "2@10.0.0.2");
    try std.testing.expectError(ConfigError.InvalidPeerFormat, result);
}

test "NodeRole round-trip" {
    const roles = [_]NodeRole{ .both, .server, .agent };
    for (roles) |r| {
        const str = r.toString();
        const parsed = NodeRole.fromString(str).?;
        try std.testing.expectEqual(r, parsed);
    }
}

test "NodeRole unknown returns null" {
    try std.testing.expect(NodeRole.fromString("leader") == null);
}

test "ClusterSettings defaults" {
    const settings = ClusterSettings{};
    try std.testing.expectEqual(NodeRole.both, settings.role);
    try std.testing.expect(settings.region == null);
    try std.testing.expectEqual(@as(u32, 500), settings.gossip_tick_ms);
    try std.testing.expectEqual(@as(u32, 50), settings.gossip_threshold);
}
