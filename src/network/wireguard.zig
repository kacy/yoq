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
