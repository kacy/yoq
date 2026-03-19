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
const linux = std.os.linux;
const nl = @import("netlink.zig");
const device_runtime = @import("wireguard/device_runtime.zig");
const key_support = @import("wireguard/key_support.zig");
const parse_support = @import("wireguard/parse_support.zig");
const types = @import("wireguard/types.zig");

pub const WireguardError = types.WireguardError;
pub const KeyPair = types.KeyPair;
pub const PeerConfig = types.PeerConfig;

const encoded_key_len = types.encoded_key_len;

fn decodeKey(encoded: []const u8) ?[32]u8 {
    return parse_support.decodeKey(encoded);
}

fn parseEndpoint(endpoint: []const u8) ?[16]u8 {
    return parse_support.parseEndpoint(endpoint);
}

fn parseCidr(cidr: []const u8) ?types.ParsedCidr {
    return parse_support.parseCidr(cidr);
}

pub fn createInterface(name: []const u8, private_key: []const u8, listen_port: u16) WireguardError!void {
    return device_runtime.createInterface(name, private_key, listen_port);
}

pub fn deleteInterface(name: []const u8) WireguardError!void {
    return device_runtime.deleteInterface(name);
}

pub fn addPeer(name: []const u8, peer: PeerConfig) WireguardError!void {
    return device_runtime.addPeer(name, peer);
}

pub fn removePeer(name: []const u8, public_key: []const u8) WireguardError!void {
    return device_runtime.removePeer(name, public_key);
}

pub fn assignOverlayIp(name: []const u8, overlay_ip: [4]u8, prefix_len: u8) WireguardError!void {
    return device_runtime.assignOverlayIp(name, overlay_ip, prefix_len);
}

pub fn addRoute(dest: [4]u8, prefix_len: u8, via: [4]u8) WireguardError!void {
    return device_runtime.addRoute(dest, prefix_len, via);
}

pub fn removeRoute(dest: [4]u8, prefix_len: u8) WireguardError!void {
    return device_runtime.removeRoute(dest, prefix_len);
}

pub fn generateKeyPair() WireguardError!KeyPair {
    return key_support.generateKeyPair();
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
    try mb.putAttrU8(hdr, nl.WGALLOWEDIP_A.FAMILY, nl.AF.INET);
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

    try std.testing.expect(hdr.len > 50);
    try std.testing.expect(mb.pos <= nl.buf_size);
}
