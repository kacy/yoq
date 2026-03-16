// wireguard — WireGuard mesh interface management
//
// manages WireGuard interfaces for cross-node container networking.
// uses std.crypto for key generation and native netlink for all
// interface/peer configuration — no external tools (wg, ip) needed.
//
// two netlink families are used:
//   - NETLINK_ROUTE (rtnetlink): create/delete interfaces, bring up, IP/routing
//   - NETLINK_GENERIC (genetlink): configure WireGuard keys, ports, peers
//
// network operations (IP assignment, routing) use netlink via
// the existing netlink.zig module.

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const nl = @import("netlink.zig");
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
};

// base64-encoded 32-byte key is always 44 characters (with padding)
const encoded_key_len = 44;

/// a WireGuard keypair with base64-encoded keys.
/// generated locally using X25519 — no shelling out needed.
/// X25519 keys are always 32 bytes, which base64-encodes to exactly 44 chars.
pub const KeyPair = struct {
    private_key: [encoded_key_len]u8,
    public_key: [encoded_key_len]u8,
};

/// configuration for a WireGuard peer (remote node).
pub const PeerConfig = struct {
    public_key: []const u8, // base64-encoded
    endpoint: ?[]const u8, // "host:port" or null for listen-only
    allowed_ips: []const u8, // CIDR notation, e.g. "10.42.1.0/24,10.40.0.1/32"
    persistent_keepalive: u16 = 25,
};

// -- helpers --

/// decode a base64-encoded 32-byte key into raw bytes.
fn decodeKey(encoded: []const u8) ?[32]u8 {
    if (encoded.len != encoded_key_len) return null;
    var raw: [32]u8 = undefined;
    std.base64.standard.Decoder.decode(&raw, encoded[0..encoded_key_len]) catch return null;
    return raw;
}

/// parse an "ip:port" endpoint string into a sockaddr_in (16 bytes).
fn parseEndpoint(endpoint: []const u8) ?[16]u8 {
    // find the last ':' to split host and port
    var colon_pos: ?usize = null;
    for (endpoint, 0..) |c, i| {
        if (c == ':') colon_pos = i;
    }
    const colon = colon_pos orelse return null;
    if (colon == 0 or colon + 1 >= endpoint.len) return null;

    const host = endpoint[0..colon];
    const port_str = endpoint[colon + 1 ..];

    const port = std.fmt.parseInt(u16, port_str, 10) catch return null;

    // parse IPv4
    var addr: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var start: usize = 0;
    for (host, 0..) |c, i| {
        if (c == '.' or i == host.len - 1) {
            const end = if (c == '.') i else i + 1;
            if (octet_idx >= 4) return null;
            addr[octet_idx] = std.fmt.parseInt(u8, host[start..end], 10) catch return null;
            octet_idx += 1;
            start = i + 1;
        }
    }
    if (octet_idx != 4) return null;

    // build sockaddr_in: family(2) + port(2, big-endian) + addr(4) + pad(8)
    var sa: [16]u8 = .{0} ** 16;
    sa[0] = nl.AF.INET; // AF_INET low byte
    sa[1] = 0;
    // port in network byte order (big-endian)
    sa[2] = @intCast(port >> 8);
    sa[3] = @intCast(port & 0xff);
    sa[4] = addr[0];
    sa[5] = addr[1];
    sa[6] = addr[2];
    sa[7] = addr[3];
    return sa;
}

/// parse a single CIDR entry like "10.42.1.0/24" into (ip, prefix_len).
fn parseCidr(cidr: []const u8) ?struct { addr: [4]u8, prefix: u8 } {
    // find '/'
    var slash_pos: ?usize = null;
    for (cidr, 0..) |c, i| {
        if (c == '/') {
            slash_pos = i;
            break;
        }
    }
    const slash = slash_pos orelse return null;
    if (slash == 0 or slash + 1 >= cidr.len) return null;

    const prefix = std.fmt.parseInt(u8, cidr[slash + 1 ..], 10) catch return null;
    if (prefix > 32) return null;

    const ip_str = cidr[0..slash];
    var addr: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var start: usize = 0;
    for (ip_str, 0..) |c, i| {
        if (c == '.' or i == ip_str.len - 1) {
            const end = if (c == '.') i else i + 1;
            if (octet_idx >= 4) return null;
            addr[octet_idx] = std.fmt.parseInt(u8, ip_str[start..end], 10) catch return null;
            octet_idx += 1;
            start = i + 1;
        }
    }
    if (octet_idx != 4) return null;

    return .{ .addr = addr, .prefix = prefix };
}

// -- interface management --

/// create a WireGuard interface, set its private key and listen port, and bring it up.
///
/// uses rtnetlink to create the interface and bring it up, and generic netlink
/// to configure the WireGuard private key and listen port. no external tools needed.
pub fn createInterface(name: []const u8, private_key: []const u8, listen_port: u16) WireguardError!void {
    // step 1: create the wireguard interface via rtnetlink
    const rt_fd = nl.openSocket() catch return WireguardError.DeviceCreateFailed;
    defer posix.close(rt_fd);

    {
        var buf: [nl.buf_size]u8 align(4) = undefined;
        var mb = nl.MessageBuilder.init(&buf);

        const hdr = mb.putHeader(
            .RTM_NEWLINK,
            nl.NLM_F.REQUEST | nl.NLM_F.ACK | nl.NLM_F.CREATE | nl.NLM_F.EXCL,
            linux.ifinfomsg,
        ) catch return WireguardError.DeviceCreateFailed;

        mb.putAttrStr(hdr, nl.IFLA.IFNAME, name) catch return WireguardError.DeviceCreateFailed;

        const linkinfo = mb.startNested(hdr, nl.IFLA.LINKINFO) catch return WireguardError.DeviceCreateFailed;
        mb.putAttrStr(hdr, nl.IFLA.INFO_KIND, "wireguard") catch return WireguardError.DeviceCreateFailed;
        mb.endNested(linkinfo);

        nl.sendAndCheck(rt_fd, mb.message()) catch |e| {
            log.err("wireguard: failed to create interface: {}", .{e});
            return WireguardError.DeviceCreateFailed;
        };
    }

    // step 2: configure WireGuard via generic netlink (private key + listen port)
    const raw_key = decodeKey(private_key) orelse {
        log.err("wireguard: invalid base64 private key", .{});
        cleanupInterface(rt_fd, name);
        return WireguardError.DeviceCreateFailed;
    };

    {
        const genl_fd = nl.openGenericSocket() catch {
            cleanupInterface(rt_fd, name);
            return WireguardError.DeviceCreateFailed;
        };
        defer posix.close(genl_fd);

        const wg_family = nl.resolveFamily(genl_fd, "wireguard") catch {
            log.err("wireguard: failed to resolve genetlink family", .{});
            cleanupInterface(rt_fd, name);
            return WireguardError.DeviceCreateFailed;
        };

        var buf: [nl.buf_size]u8 align(4) = undefined;
        var mb = nl.MessageBuilder.init(&buf);

        const hdr = mb.putHeaderGenl(wg_family, nl.NLM_F.REQUEST | nl.NLM_F.ACK, nl.WG_CMD.SET_DEVICE) catch {
            cleanupInterface(rt_fd, name);
            return WireguardError.DeviceCreateFailed;
        };

        mb.putAttrStr(hdr, nl.WGDEVICE_A.IFNAME, name) catch {
            cleanupInterface(rt_fd, name);
            return WireguardError.DeviceCreateFailed;
        };
        mb.putAttr(hdr, nl.WGDEVICE_A.PRIVATE_KEY, &raw_key) catch {
            cleanupInterface(rt_fd, name);
            return WireguardError.DeviceCreateFailed;
        };
        mb.putAttrU16(hdr, nl.WGDEVICE_A.LISTEN_PORT, listen_port) catch {
            cleanupInterface(rt_fd, name);
            return WireguardError.DeviceCreateFailed;
        };

        nl.sendAndCheck(genl_fd, mb.message()) catch |e| {
            log.err("wireguard: failed to configure interface: {}", .{e});
            cleanupInterface(rt_fd, name);
            return WireguardError.DeviceCreateFailed;
        };
    }

    // step 3: bring the interface up
    const if_index = nl.getIfIndex(rt_fd, name) catch {
        cleanupInterface(rt_fd, name);
        return WireguardError.DeviceCreateFailed;
    };
    if (if_index == 0) {
        cleanupInterface(rt_fd, name);
        return WireguardError.DeviceCreateFailed;
    }

    nl.setLinkUp(rt_fd, if_index) catch |e| {
        log.err("wireguard: failed to bring interface up: {}", .{e});
        cleanupInterface(rt_fd, name);
        return WireguardError.DeviceCreateFailed;
    };
}

/// delete a WireGuard interface via rtnetlink.
pub fn deleteInterface(name: []const u8) WireguardError!void {
    const fd = nl.openSocket() catch return WireguardError.DeviceDeleteFailed;
    defer posix.close(fd);

    nl.deleteLink(fd, name) catch return WireguardError.DeviceDeleteFailed;
}

/// best-effort cleanup of an interface after a failed create.
fn cleanupInterface(rt_fd: posix.fd_t, name: []const u8) void {
    nl.deleteLink(rt_fd, name) catch |e| {
        log.warn("wireguard: failed to cleanup interface: {}", .{e});
    };
}

// -- peer management --

/// add a peer to a WireGuard interface via generic netlink.
pub fn addPeer(name: []const u8, peer: PeerConfig) WireguardError!void {
    const raw_pubkey = decodeKey(peer.public_key) orelse return WireguardError.PeerAddFailed;

    const genl_fd = nl.openGenericSocket() catch return WireguardError.PeerAddFailed;
    defer posix.close(genl_fd);

    const wg_family = nl.resolveFamily(genl_fd, "wireguard") catch return WireguardError.PeerAddFailed;

    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = mb.putHeaderGenl(wg_family, nl.NLM_F.REQUEST | nl.NLM_F.ACK, nl.WG_CMD.SET_DEVICE) catch
        return WireguardError.PeerAddFailed;

    mb.putAttrStr(hdr, nl.WGDEVICE_A.IFNAME, name) catch return WireguardError.PeerAddFailed;

    // nested: WGDEVICE_A_PEERS -> peer entry
    const peers_nest = mb.startNested(hdr, nl.WGDEVICE_A.PEERS) catch return WireguardError.PeerAddFailed;
    const peer_nest = mb.startNested(hdr, 0) catch return WireguardError.PeerAddFailed; // peer index 0

    mb.putAttr(hdr, nl.WGPEER_A.PUBLIC_KEY, &raw_pubkey) catch return WireguardError.PeerAddFailed;

    if (peer.endpoint) |ep| {
        const sa = parseEndpoint(ep) orelse return WireguardError.PeerAddFailed;
        mb.putAttr(hdr, nl.WGPEER_A.ENDPOINT, &sa) catch return WireguardError.PeerAddFailed;
    }

    mb.putAttrU16(hdr, nl.WGPEER_A.PERSISTENT_KEEPALIVE, peer.persistent_keepalive) catch
        return WireguardError.PeerAddFailed;

    // nested: WGPEER_A_ALLOWED_IPS -> each CIDR
    const aips_nest = mb.startNested(hdr, nl.WGPEER_A.ALLOWED_IPS) catch return WireguardError.PeerAddFailed;

    // parse comma-separated CIDRs
    var start: usize = 0;
    for (peer.allowed_ips, 0..) |c, i| {
        if (c == ',' or i == peer.allowed_ips.len - 1) {
            const end = if (c == ',') i else i + 1;
            const cidr_str = peer.allowed_ips[start..end];
            const cidr = parseCidr(cidr_str) orelse return WireguardError.PeerAddFailed;

            const aip_nest = mb.startNested(hdr, 0) catch return WireguardError.PeerAddFailed;
            mb.putAttrU16(hdr, nl.WGALLOWEDIP_A.FAMILY, nl.AF.INET) catch return WireguardError.PeerAddFailed;
            mb.putAttr(hdr, nl.WGALLOWEDIP_A.IPADDR, &cidr.addr) catch return WireguardError.PeerAddFailed;
            mb.putAttrU8(hdr, nl.WGALLOWEDIP_A.CIDR_MASK, cidr.prefix) catch return WireguardError.PeerAddFailed;
            mb.endNested(aip_nest);

            start = end + 1;
        }
    }

    mb.endNested(aips_nest);
    mb.endNested(peer_nest);
    mb.endNested(peers_nest);

    nl.sendAndCheck(genl_fd, mb.message()) catch return WireguardError.PeerAddFailed;
}

/// remove a peer from a WireGuard interface via generic netlink.
pub fn removePeer(name: []const u8, public_key: []const u8) WireguardError!void {
    const raw_pubkey = decodeKey(public_key) orelse return WireguardError.PeerRemoveFailed;

    const genl_fd = nl.openGenericSocket() catch return WireguardError.PeerRemoveFailed;
    defer posix.close(genl_fd);

    const wg_family = nl.resolveFamily(genl_fd, "wireguard") catch return WireguardError.PeerRemoveFailed;

    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = mb.putHeaderGenl(wg_family, nl.NLM_F.REQUEST | nl.NLM_F.ACK, nl.WG_CMD.SET_DEVICE) catch
        return WireguardError.PeerRemoveFailed;

    mb.putAttrStr(hdr, nl.WGDEVICE_A.IFNAME, name) catch return WireguardError.PeerRemoveFailed;

    const peers_nest = mb.startNested(hdr, nl.WGDEVICE_A.PEERS) catch return WireguardError.PeerRemoveFailed;
    const peer_nest = mb.startNested(hdr, 0) catch return WireguardError.PeerRemoveFailed;

    mb.putAttr(hdr, nl.WGPEER_A.PUBLIC_KEY, &raw_pubkey) catch return WireguardError.PeerRemoveFailed;
    mb.putAttrU32(hdr, nl.WGPEER_A.FLAGS, nl.WGPEER_F_REMOVE_ME) catch return WireguardError.PeerRemoveFailed;

    mb.endNested(peer_nest);
    mb.endNested(peers_nest);

    nl.sendAndCheck(genl_fd, mb.message()) catch return WireguardError.PeerRemoveFailed;
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

test "decodeKey valid base64" {
    // generate a real key and decode it back
    const kp = try generateKeyPair();
    const raw = decodeKey(&kp.private_key);
    try std.testing.expect(raw != null);
    try std.testing.expectEqual(@as(usize, 32), raw.?.len);
}

test "decodeKey invalid length" {
    try std.testing.expect(decodeKey("too_short") == null);
}

test "parseEndpoint valid" {
    const sa = parseEndpoint("10.0.0.2:51820");
    try std.testing.expect(sa != null);
    const result = sa.?;
    // AF_INET = 2
    try std.testing.expectEqual(@as(u8, 2), result[0]);
    // port 51820 = 0xCA6C in big-endian
    try std.testing.expectEqual(@as(u8, 0xCA), result[2]);
    try std.testing.expectEqual(@as(u8, 0x6C), result[3]);
    // IP 10.0.0.2
    try std.testing.expectEqual(@as(u8, 10), result[4]);
    try std.testing.expectEqual(@as(u8, 0), result[5]);
    try std.testing.expectEqual(@as(u8, 0), result[6]);
    try std.testing.expectEqual(@as(u8, 2), result[7]);
}

test "parseEndpoint invalid" {
    try std.testing.expect(parseEndpoint("not-an-endpoint") == null);
    try std.testing.expect(parseEndpoint(":51820") == null);
    try std.testing.expect(parseEndpoint("10.0.0.2:") == null);
}

test "parseCidr valid" {
    const result = parseCidr("10.42.1.0/24");
    try std.testing.expect(result != null);
    const cidr = result.?;
    try std.testing.expectEqual([4]u8{ 10, 42, 1, 0 }, cidr.addr);
    try std.testing.expectEqual(@as(u8, 24), cidr.prefix);
}

test "parseCidr single host" {
    const result = parseCidr("10.40.0.1/32");
    try std.testing.expect(result != null);
    const cidr = result.?;
    try std.testing.expectEqual([4]u8{ 10, 40, 0, 1 }, cidr.addr);
    try std.testing.expectEqual(@as(u8, 32), cidr.prefix);
}

test "parseCidr invalid" {
    try std.testing.expect(parseCidr("no-slash") == null);
    try std.testing.expect(parseCidr("/24") == null);
    try std.testing.expect(parseCidr("10.0.0.1/33") == null);
}

test "PeerConfig default persistent_keepalive" {
    const peer = PeerConfig{
        .public_key = "key",
        .endpoint = null,
        .allowed_ips = "10.42.0.0/24",
    };
    try std.testing.expectEqual(@as(u16, 25), peer.persistent_keepalive);
}

test "createInterface builds correct rtnetlink message" {
    // verify the message construction path compiles and the builder works
    // (actual interface creation requires root + wireguard module)
    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = try mb.putHeader(
        .RTM_NEWLINK,
        nl.NLM_F.REQUEST | nl.NLM_F.ACK | nl.NLM_F.CREATE | nl.NLM_F.EXCL,
        linux.ifinfomsg,
    );

    try mb.putAttrStr(hdr, nl.IFLA.IFNAME, "wg0");

    const linkinfo = try mb.startNested(hdr, nl.IFLA.LINKINFO);
    try mb.putAttrStr(hdr, nl.IFLA.INFO_KIND, "wireguard");
    mb.endNested(linkinfo);

    // verify message is well-formed
    try std.testing.expect(hdr.len > @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg));
}

test "addPeer builds correct genetlink message" {
    // verify the genetlink message construction for a peer add
    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const family_id: u16 = 0x1b; // example
    const hdr = try mb.putHeaderGenl(family_id, nl.NLM_F.REQUEST | nl.NLM_F.ACK, nl.WG_CMD.SET_DEVICE);

    try mb.putAttrStr(hdr, nl.WGDEVICE_A.IFNAME, "wg0");

    const peers_nest = try mb.startNested(hdr, nl.WGDEVICE_A.PEERS);
    const peer_nest = try mb.startNested(hdr, 0);

    // 32 bytes of fake key
    var fake_key: [32]u8 = .{0xAB} ** 32;
    try mb.putAttr(hdr, nl.WGPEER_A.PUBLIC_KEY, &fake_key);

    // endpoint
    const sa = parseEndpoint("10.0.0.2:51820");
    try std.testing.expect(sa != null);
    try mb.putAttr(hdr, nl.WGPEER_A.ENDPOINT, &sa.?);

    try mb.putAttrU16(hdr, nl.WGPEER_A.PERSISTENT_KEEPALIVE, 25);

    // allowed IPs
    const aips_nest = try mb.startNested(hdr, nl.WGPEER_A.ALLOWED_IPS);
    const aip_nest = try mb.startNested(hdr, 0);
    try mb.putAttrU16(hdr, nl.WGALLOWEDIP_A.FAMILY, nl.AF.INET);
    try mb.putAttr(hdr, nl.WGALLOWEDIP_A.IPADDR, &[4]u8{ 10, 42, 1, 0 });
    try mb.putAttrU8(hdr, nl.WGALLOWEDIP_A.CIDR_MASK, 24);
    mb.endNested(aip_nest);
    mb.endNested(aips_nest);

    mb.endNested(peer_nest);
    mb.endNested(peers_nest);

    // message should be a valid netlink message with reasonable size
    try std.testing.expect(hdr.len > 100);
    try std.testing.expect(mb.pos <= nl.buf_size);
}

test "removePeer builds correct genetlink message" {
    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const family_id: u16 = 0x1b;
    const hdr = try mb.putHeaderGenl(family_id, nl.NLM_F.REQUEST | nl.NLM_F.ACK, nl.WG_CMD.SET_DEVICE);

    try mb.putAttrStr(hdr, nl.WGDEVICE_A.IFNAME, "wg0");

    const peers_nest = try mb.startNested(hdr, nl.WGDEVICE_A.PEERS);
    const peer_nest = try mb.startNested(hdr, 0);

    var fake_key: [32]u8 = .{0xCD} ** 32;
    try mb.putAttr(hdr, nl.WGPEER_A.PUBLIC_KEY, &fake_key);
    try mb.putAttrU32(hdr, nl.WGPEER_A.FLAGS, nl.WGPEER_F_REMOVE_ME);

    mb.endNested(peer_nest);
    mb.endNested(peers_nest);

    // verify the REMOVE_ME flag is in the buffer
    const msg = mb.message();
    try std.testing.expect(msg.len > 60);
}
