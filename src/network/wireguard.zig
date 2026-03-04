// wireguard — WireGuard mesh interface management
//
// manages WireGuard interfaces for cross-node container networking.
// uses std.crypto for key generation (no shelling out for keys),
// and shells out to `wg` for interface configuration (matches the
// iptables pattern in nat.zig).
//
// network operations (IP assignment, routing) use netlink via
// the existing netlink.zig module.

const std = @import("std");
const posix = std.posix;
const nl = @import("netlink.zig");

pub const WireguardError = error{
    KeyGenFailed,
    DeviceCreateFailed,
    DeviceDeleteFailed,
    PeerAddFailed,
    PeerRemoveFailed,
    AddressFailed,
    RouteFailed,
    ExecFailed,
};

// base64-encoded 32-byte key is always 44 characters (with padding)
const encoded_key_len = 44;

/// a WireGuard keypair with base64-encoded keys.
/// generated locally using X25519 — no shelling out needed.
pub const KeyPair = struct {
    private_key: [encoded_key_len]u8,
    public_key: [encoded_key_len]u8,
    private_key_len: usize,
    public_key_len: usize,

    pub fn privateKeySlice(self: *const KeyPair) []const u8 {
        return self.private_key[0..self.private_key_len];
    }

    pub fn publicKeySlice(self: *const KeyPair) []const u8 {
        return self.public_key[0..self.public_key_len];
    }
};

/// configuration for a WireGuard peer (remote node).
pub const PeerConfig = struct {
    public_key: []const u8, // base64-encoded
    endpoint: ?[]const u8, // "host:port" or null for listen-only
    allowed_ips: []const u8, // CIDR notation, e.g. "10.42.1.0/24,10.40.0.1/32"
    persistent_keepalive: u16 = 25,
};

// -- argument builders --
//
// these build command argument arrays without executing them.
// separate from exec so we can test argument construction
// (same pattern as nat.zig).

const max_args = 20;
const ArgList = [max_args]?[]const u8;

/// build args for: ip link add <name> type wireguard
fn buildCreateArgs(name: []const u8) ArgList {
    var args: ArgList = .{null} ** max_args;
    args[0] = "ip";
    args[1] = "link";
    args[2] = "add";
    args[3] = name;
    args[4] = "type";
    args[5] = "wireguard";
    return args;
}

/// build args for: ip link del <name>
fn buildDeleteArgs(name: []const u8) ArgList {
    var args: ArgList = .{null} ** max_args;
    args[0] = "ip";
    args[1] = "link";
    args[2] = "del";
    args[3] = name;
    return args;
}

/// build args for: wg set <name> private-key <path> listen-port <port>
fn buildWgSetArgs(name: []const u8, private_key_path: []const u8, listen_port: u16) ArgList {
    var args: ArgList = .{null} ** max_args;
    args[0] = "wg";
    args[1] = "set";
    args[2] = name;
    args[3] = "private-key";
    args[4] = private_key_path;
    args[5] = "listen-port";
    args[6] = portStr(listen_port);
    return args;
}

/// build args for: wg set <name> peer <pubkey> allowed-ips <ips> [endpoint <ep>] persistent-keepalive <ka>
fn buildAddPeerArgs(name: []const u8, peer: PeerConfig) ArgList {
    var args: ArgList = .{null} ** max_args;
    var i: usize = 0;

    args[i] = "wg";
    i += 1;
    args[i] = "set";
    i += 1;
    args[i] = name;
    i += 1;
    args[i] = "peer";
    i += 1;
    args[i] = peer.public_key;
    i += 1;
    args[i] = "allowed-ips";
    i += 1;
    args[i] = peer.allowed_ips;
    i += 1;

    if (peer.endpoint) |ep| {
        args[i] = "endpoint";
        i += 1;
        args[i] = ep;
        i += 1;
    }

    args[i] = "persistent-keepalive";
    i += 1;
    args[i] = portStr(peer.persistent_keepalive);

    return args;
}

/// build args for: wg set <name> peer <pubkey> remove
fn buildRemovePeerArgs(name: []const u8, public_key: []const u8) ArgList {
    var args: ArgList = .{null} ** max_args;
    args[0] = "wg";
    args[1] = "set";
    args[2] = name;
    args[3] = "peer";
    args[4] = public_key;
    args[5] = "remove";
    return args;
}

/// build args for: ip link set <name> up
fn buildLinkUpArgs(name: []const u8) ArgList {
    var args: ArgList = .{null} ** max_args;
    args[0] = "ip";
    args[1] = "link";
    args[2] = "set";
    args[3] = name;
    args[4] = "up";
    return args;
}

// -- string formatting helpers --
// use thread-local buffers since these are consumed immediately by exec

threadlocal var port_buf: [8]u8 = undefined;

fn portStr(port: u16) []const u8 {
    return std.fmt.bufPrint(&port_buf, "{d}", .{port}) catch "0";
}

/// generate an X25519 keypair for WireGuard.
/// uses zig's std.crypto — no external tools needed.
pub fn generateKeyPair() WireguardError!KeyPair {
    const X25519 = std.crypto.dh.X25519;
    const raw_kp = X25519.KeyPair.generate();

    var kp: KeyPair = undefined;
    const encoder = std.base64.standard.Encoder;

    const priv_slice = encoder.encode(&kp.private_key, &raw_kp.secret_key);
    kp.private_key_len = priv_slice.len;

    const pub_slice = encoder.encode(&kp.public_key, &raw_kp.public_key);
    kp.public_key_len = pub_slice.len;

    return kp;
}

// -- tests --

test "generateKeyPair returns valid base64 keys" {
    const kp = try generateKeyPair();

    // base64 of 32 bytes = 44 chars (with padding)
    try std.testing.expectEqual(@as(usize, 44), kp.private_key_len);
    try std.testing.expectEqual(@as(usize, 44), kp.public_key_len);

    // should be valid base64 — decode should succeed
    const decoder = std.base64.standard.Decoder;
    var priv_decoded: [32]u8 = undefined;
    decoder.decode(&priv_decoded, kp.privateKeySlice()) catch {
        return error.KeyGenFailed;
    };

    var pub_decoded: [32]u8 = undefined;
    decoder.decode(&pub_decoded, kp.publicKeySlice()) catch {
        return error.KeyGenFailed;
    };
}

test "generateKeyPair returns different keys each call" {
    const kp1 = try generateKeyPair();
    const kp2 = try generateKeyPair();

    // private keys should differ (astronomically unlikely to match)
    try std.testing.expect(!std.mem.eql(u8, kp1.privateKeySlice(), kp2.privateKeySlice()));
    // public keys should also differ
    try std.testing.expect(!std.mem.eql(u8, kp1.publicKeySlice(), kp2.publicKeySlice()));
}

test "base64 round-trip: decode then re-encode matches" {
    const kp = try generateKeyPair();

    const decoder = std.base64.standard.Decoder;
    const encoder = std.base64.standard.Encoder;

    // round-trip private key
    var raw: [32]u8 = undefined;
    decoder.decode(&raw, kp.privateKeySlice()) catch {
        return error.KeyGenFailed;
    };
    var re_encoded: [encoded_key_len]u8 = undefined;
    const result = encoder.encode(&re_encoded, &raw);
    try std.testing.expectEqualStrings(kp.privateKeySlice(), result);
}

test "KeyPair slice accessors" {
    const kp = try generateKeyPair();

    // slices should be the correct length
    try std.testing.expectEqual(@as(usize, 44), kp.privateKeySlice().len);
    try std.testing.expectEqual(@as(usize, 44), kp.publicKeySlice().len);
}

test "buildCreateArgs produces correct ip link add command" {
    const args = buildCreateArgs("wg0");
    try std.testing.expectEqualStrings("ip", args[0].?);
    try std.testing.expectEqualStrings("link", args[1].?);
    try std.testing.expectEqualStrings("add", args[2].?);
    try std.testing.expectEqualStrings("wg0", args[3].?);
    try std.testing.expectEqualStrings("type", args[4].?);
    try std.testing.expectEqualStrings("wireguard", args[5].?);
    try std.testing.expect(args[6] == null);
}

test "buildDeleteArgs produces correct ip link del command" {
    const args = buildDeleteArgs("wg0");
    try std.testing.expectEqualStrings("ip", args[0].?);
    try std.testing.expectEqualStrings("link", args[1].?);
    try std.testing.expectEqualStrings("del", args[2].?);
    try std.testing.expectEqualStrings("wg0", args[3].?);
    try std.testing.expect(args[4] == null);
}

test "buildWgSetArgs produces correct wg set command" {
    const args = buildWgSetArgs("wg0", "/tmp/wg-key", 51820);
    try std.testing.expectEqualStrings("wg", args[0].?);
    try std.testing.expectEqualStrings("set", args[1].?);
    try std.testing.expectEqualStrings("wg0", args[2].?);
    try std.testing.expectEqualStrings("private-key", args[3].?);
    try std.testing.expectEqualStrings("/tmp/wg-key", args[4].?);
    try std.testing.expectEqualStrings("listen-port", args[5].?);
    try std.testing.expectEqualStrings("51820", args[6].?);
    try std.testing.expect(args[7] == null);
}

test "buildAddPeerArgs with endpoint" {
    const peer = PeerConfig{
        .public_key = "dGVzdHB1YmtleQ==",
        .endpoint = "10.0.0.2:51820",
        .allowed_ips = "10.42.1.0/24",
        .persistent_keepalive = 25,
    };
    const args = buildAddPeerArgs("wg0", peer);
    try std.testing.expectEqualStrings("wg", args[0].?);
    try std.testing.expectEqualStrings("set", args[1].?);
    try std.testing.expectEqualStrings("wg0", args[2].?);
    try std.testing.expectEqualStrings("peer", args[3].?);
    try std.testing.expectEqualStrings("dGVzdHB1YmtleQ==", args[4].?);
    try std.testing.expectEqualStrings("allowed-ips", args[5].?);
    try std.testing.expectEqualStrings("10.42.1.0/24", args[6].?);
    try std.testing.expectEqualStrings("endpoint", args[7].?);
    try std.testing.expectEqualStrings("10.0.0.2:51820", args[8].?);
    try std.testing.expectEqualStrings("persistent-keepalive", args[9].?);
    try std.testing.expectEqualStrings("25", args[10].?);
    try std.testing.expect(args[11] == null);
}

test "buildAddPeerArgs without endpoint" {
    const peer = PeerConfig{
        .public_key = "dGVzdHB1YmtleQ==",
        .endpoint = null,
        .allowed_ips = "10.42.1.0/24,10.40.0.1/32",
        .persistent_keepalive = 30,
    };
    const args = buildAddPeerArgs("wg0", peer);
    try std.testing.expectEqualStrings("wg", args[0].?);
    try std.testing.expectEqualStrings("set", args[1].?);
    try std.testing.expectEqualStrings("wg0", args[2].?);
    try std.testing.expectEqualStrings("peer", args[3].?);
    try std.testing.expectEqualStrings("dGVzdHB1YmtleQ==", args[4].?);
    try std.testing.expectEqualStrings("allowed-ips", args[5].?);
    try std.testing.expectEqualStrings("10.42.1.0/24,10.40.0.1/32", args[6].?);
    // no endpoint, so next should be persistent-keepalive
    try std.testing.expectEqualStrings("persistent-keepalive", args[7].?);
    try std.testing.expectEqualStrings("30", args[8].?);
    try std.testing.expect(args[9] == null);
}

test "buildRemovePeerArgs produces correct command" {
    const args = buildRemovePeerArgs("wg0", "dGVzdHB1YmtleQ==");
    try std.testing.expectEqualStrings("wg", args[0].?);
    try std.testing.expectEqualStrings("set", args[1].?);
    try std.testing.expectEqualStrings("wg0", args[2].?);
    try std.testing.expectEqualStrings("peer", args[3].?);
    try std.testing.expectEqualStrings("dGVzdHB1YmtleQ==", args[4].?);
    try std.testing.expectEqualStrings("remove", args[5].?);
    try std.testing.expect(args[6] == null);
}

test "buildLinkUpArgs produces correct command" {
    const args = buildLinkUpArgs("wg0");
    try std.testing.expectEqualStrings("ip", args[0].?);
    try std.testing.expectEqualStrings("link", args[1].?);
    try std.testing.expectEqualStrings("set", args[2].?);
    try std.testing.expectEqualStrings("wg0", args[3].?);
    try std.testing.expectEqualStrings("up", args[4].?);
    try std.testing.expect(args[5] == null);
}

test "PeerConfig default persistent_keepalive" {
    const peer = PeerConfig{
        .public_key = "key",
        .endpoint = null,
        .allowed_ips = "10.42.0.0/24",
    };
    try std.testing.expectEqual(@as(u16, 25), peer.persistent_keepalive);
}
