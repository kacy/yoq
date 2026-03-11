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
const cmd = @import("../lib/cmd.zig");
const log = std.log;

pub const WireguardError = error{
    /// failed to generate an X25519 keypair for WireGuard
    KeyGenFailed,
    /// failed to create the WireGuard interface or configure its private key
    DeviceCreateFailed,
    /// failed to delete a WireGuard interface
    DeviceDeleteFailed,
    /// failed to add a peer to the WireGuard interface
    PeerAddFailed,
    /// failed to remove a peer from the WireGuard interface
    PeerRemoveFailed,
    /// failed to assign an overlay IP address to the WireGuard interface
    AddressFailed,
    /// failed to add or remove a route through the WireGuard tunnel
    RouteFailed,
    /// a subprocess (ip or wg) failed to execute
    ExecFailed,
};

// base64-encoded 32-byte key is always 44 characters (with padding)
const encoded_key_len = 44;

/// a WireGuard keypair with base64-encoded keys.
/// generated locally using X25519 — no shelling out needed.
/// X25519 keys are always 32 bytes, which base64-encodes to exactly 44 chars.
pub const KeyPair = struct {
    private_key: [encoded_key_len]u8,
    public_key: [encoded_key_len]u8,

    /// zero the private key material. call this after the key has been
    /// passed to createInterface() and is no longer needed.
    pub fn secureZero(self: *KeyPair) void {
        std.crypto.secureZero(u8, &self.private_key);
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

const max_args = cmd.max_args;
const ArgList = cmd.ArgList;

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
fn buildWgSetArgs(name: []const u8, private_key_path: []const u8, listen_port: u16, port_buf: *[8]u8) ArgList {
    var args: ArgList = .{null} ** max_args;
    args[0] = "wg";
    args[1] = "set";
    args[2] = name;
    args[3] = "private-key";
    args[4] = private_key_path;
    args[5] = "listen-port";
    args[6] = cmd.portStr(port_buf, listen_port);
    return args;
}

/// build args for: wg set <name> peer <pubkey> allowed-ips <ips> [endpoint <ep>] persistent-keepalive <ka>
fn buildAddPeerArgs(name: []const u8, peer: PeerConfig, ka_buf: *[8]u8) ArgList {
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
    args[i] = cmd.portStr(ka_buf, peer.persistent_keepalive);

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

// -- exec helper --

fn exec(args: *const ArgList) WireguardError!void {
    cmd.exec(args) catch return WireguardError.ExecFailed;
}

// -- interface management --

/// create a WireGuard interface, set its private key and listen port, and bring it up.
///
/// this writes the private key to a temporary file (deleted immediately after),
/// matching WireGuard's requirement that `wg set` reads the key from a file path.
///
/// equivalent to:
///   ip link add <name> type wireguard
///   wg set <name> private-key /dev/shm/yoq-wg-<random> listen-port <port>
///   ip link set <name> up
pub fn createInterface(name: []const u8, private_key: []const u8, listen_port: u16) WireguardError!void {
    // step 1: create the wireguard interface
    const create_args = buildCreateArgs(name);
    exec(&create_args) catch return WireguardError.DeviceCreateFailed;

    // step 2: write private key to a temp file on tmpfs (RAM-only, never hits disk).
    // wg set requires reading the key from a file path.
    // /dev/shm is a standard Linux tmpfs — the key only exists in memory.
    // SECURITY: Use 64-bit random for stronger collision resistance
    var tmp_path_buf: [64]u8 = undefined;
    const random_val = std.crypto.random.int(u64);
    const tmp_path = std.fmt.bufPrint(&tmp_path_buf, "/dev/shm/yoq-wg-{x:016}", .{random_val}) catch
        return WireguardError.DeviceCreateFailed;

    // write the key, configure wg, then delete the file
    // SECURITY: Create with 0o600 permissions (owner read/write only)
    const tmp_file = std.fs.cwd().createFile(tmp_path, .{ .mode = 0o600 }) catch |e| {
        log.err("wireguard: failed to create temp key file: {}", .{e});
        return WireguardError.DeviceCreateFailed;
    };

    tmp_file.writeAll(private_key) catch |e| {
        log.err("wireguard: failed to write private key: {}", .{e});
        tmp_file.close();
        std.fs.cwd().deleteFile(tmp_path) catch {};
        return WireguardError.DeviceCreateFailed;
    };
    tmp_file.close();
    defer {
        std.fs.cwd().deleteFile(tmp_path) catch |e| {
            log.warn("wireguard: failed to cleanup temp key file: {}", .{e});
        };
    }

    // step 3: configure the interface with wg set
    var port_buf: [8]u8 = undefined;
    const wg_args = buildWgSetArgs(name, tmp_path, listen_port, &port_buf);
    exec(&wg_args) catch |e| {
        log.err("wireguard: failed to configure interface: {}", .{e});
        // try to clean up the interface we created
        const del_args = buildDeleteArgs(name);
        exec(&del_args) catch |del_e| {
            log.warn("wireguard: failed to cleanup interface after config error: {}", .{del_e});
        };
        return WireguardError.DeviceCreateFailed;
    };

    // step 4: bring the interface up
    const up_args = buildLinkUpArgs(name);
    exec(&up_args) catch |e| {
        log.err("wireguard: failed to bring interface up: {}", .{e});
        const del_args = buildDeleteArgs(name);
        exec(&del_args) catch |del_e| {
            log.warn("wireguard: failed to cleanup interface after link-up error: {}", .{del_e});
        };
        return WireguardError.DeviceCreateFailed;
    };
}

/// delete a WireGuard interface.
///
/// equivalent to: ip link del <name>
pub fn deleteInterface(name: []const u8) WireguardError!void {
    const args = buildDeleteArgs(name);
    exec(&args) catch return WireguardError.DeviceDeleteFailed;
}

// -- peer management --

/// add a peer to a WireGuard interface.
///
/// equivalent to:
///   wg set <name> peer <pubkey> allowed-ips <ips> [endpoint <ep>] persistent-keepalive <ka>
pub fn addPeer(name: []const u8, peer: PeerConfig) WireguardError!void {
    var ka_buf: [8]u8 = undefined;
    const args = buildAddPeerArgs(name, peer, &ka_buf);
    exec(&args) catch return WireguardError.PeerAddFailed;
}

/// remove a peer from a WireGuard interface.
///
/// equivalent to: wg set <name> peer <pubkey> remove
pub fn removePeer(name: []const u8, public_key: []const u8) WireguardError!void {
    const args = buildRemovePeerArgs(name, public_key);
    exec(&args) catch return WireguardError.PeerRemoveFailed;
}

// -- network operations (netlink) --

/// assign an overlay IP address to a WireGuard interface.
pub fn assignOverlayIp(name: []const u8, overlay_ip: [4]u8, prefix_len: u8) WireguardError!void {
    const fd = nl.openSocket() catch return WireguardError.AddressFailed;
    defer posix.close(fd);

    const if_index = nl.getIfIndex(fd, name) catch return WireguardError.AddressFailed;
    if (if_index == 0) return WireguardError.AddressFailed;

    nl.addAddress(fd, if_index, &overlay_ip, prefix_len) catch return WireguardError.AddressFailed;
}

/// add a route for a remote node's container subnet through the WireGuard tunnel.
///
/// for example, to route 10.42.1.0/24 via 10.40.0.2 (the remote node's
/// overlay IP on the WireGuard interface).
pub fn addRoute(dest: [4]u8, prefix_len: u8, via: [4]u8) WireguardError!void {
    const fd = nl.openSocket() catch return WireguardError.RouteFailed;
    defer posix.close(fd);

    nl.addRoute(fd, &dest, prefix_len, &via) catch return WireguardError.RouteFailed;
}

/// remove a route for a remote node's container subnet.
pub fn removeRoute(dest: [4]u8, prefix_len: u8) WireguardError!void {
    const fd = nl.openSocket() catch return WireguardError.RouteFailed;
    defer posix.close(fd);

    nl.removeRoute(fd, &dest, prefix_len) catch return WireguardError.RouteFailed;
}

// -- key generation --

/// generate an X25519 keypair for WireGuard.
/// uses zig's std.crypto — no external tools needed.
pub fn generateKeyPair() WireguardError!KeyPair {
    const X25519 = std.crypto.dh.X25519;
    var raw_kp = X25519.KeyPair.generate();
    defer std.crypto.secureZero(u8, &raw_kp.secret_key);

    var kp: KeyPair = undefined;
    const encoder = std.base64.standard.Encoder;

    _ = encoder.encode(&kp.private_key, &raw_kp.secret_key);
    _ = encoder.encode(&kp.public_key, &raw_kp.public_key);

    return kp;
}

// -- tests --

test "generateKeyPair returns valid base64 keys" {
    const kp = try generateKeyPair();

    // X25519 base64 is always exactly 44 chars
    try std.testing.expectEqual(@as(usize, 44), kp.private_key.len);
    try std.testing.expectEqual(@as(usize, 44), kp.public_key.len);

    // should be valid base64 — decode should succeed
    const decoder = std.base64.standard.Decoder;
    var priv_decoded: [32]u8 = undefined;
    decoder.decode(&priv_decoded, &kp.private_key) catch {
        return error.KeyGenFailed;
    };

    var pub_decoded: [32]u8 = undefined;
    decoder.decode(&pub_decoded, &kp.public_key) catch {
        return error.KeyGenFailed;
    };
}

test "generateKeyPair returns different keys each call" {
    const kp1 = try generateKeyPair();
    const kp2 = try generateKeyPair();

    // private keys should differ (astronomically unlikely to match)
    try std.testing.expect(!std.mem.eql(u8, &kp1.private_key, &kp2.private_key));
    // public keys should also differ
    try std.testing.expect(!std.mem.eql(u8, &kp1.public_key, &kp2.public_key));
}

test "base64 round-trip: decode then re-encode matches" {
    const kp = try generateKeyPair();

    const decoder = std.base64.standard.Decoder;
    const encoder = std.base64.standard.Encoder;

    // round-trip private key
    var raw: [32]u8 = undefined;
    decoder.decode(&raw, &kp.private_key) catch {
        return error.KeyGenFailed;
    };
    var re_encoded: [encoded_key_len]u8 = undefined;
    const result = encoder.encode(&re_encoded, &raw);
    try std.testing.expectEqualStrings(&kp.private_key, result);
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
    var port_buf: [8]u8 = undefined;
    const args = buildWgSetArgs("wg0", "/tmp/wg-key", 51820, &port_buf);
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
    var ka_buf: [8]u8 = undefined;
    const args = buildAddPeerArgs("wg0", peer, &ka_buf);
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
    var ka_buf: [8]u8 = undefined;
    const args = buildAddPeerArgs("wg0", peer, &ka_buf);
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
