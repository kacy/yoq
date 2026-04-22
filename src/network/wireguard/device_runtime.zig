const std = @import("std");
const platform = @import("platform");
const posix = std.posix;
const linux = std.os.linux;
const mem = std.mem;
const log = std.log;
const nl = @import("../netlink.zig");
const parse_support = @import("parse_support.zig");
const types = @import("types.zig");

pub fn createInterface(name: []const u8, private_key: []const u8, listen_port: u16) types.WireguardError!void {
    const rt_fd = nl.openSocket() catch return types.WireguardError.DeviceCreateFailed;
    defer platform.posix.close(rt_fd);

    {
        var buf: [nl.buf_size]u8 align(4) = undefined;
        var mb = nl.MessageBuilder.init(&buf);

        const hdr = mb.putHeader(
            .RTM_NEWLINK,
            nl.NLM_F.REQUEST | nl.NLM_F.ACK | nl.NLM_F.CREATE | nl.NLM_F.EXCL,
            linux.ifinfomsg,
        ) catch return types.WireguardError.DeviceCreateFailed;

        mb.putAttrStr(hdr, nl.IFLA.IFNAME, name) catch return types.WireguardError.DeviceCreateFailed;

        const linkinfo = mb.startNested(hdr, nl.IFLA.LINKINFO) catch return types.WireguardError.DeviceCreateFailed;
        mb.putAttrStr(hdr, nl.IFLA.INFO_KIND, "wireguard") catch return types.WireguardError.DeviceCreateFailed;
        mb.endNested(linkinfo);

        nl.sendAndCheck(rt_fd, mb.message()) catch |e| {
            log.err("wireguard: failed to create interface: {}", .{e});
            return types.WireguardError.DeviceCreateFailed;
        };
    }

    errdefer cleanupInterface(rt_fd, name);

    const raw_key = parse_support.decodeKey(private_key) orelse {
        log.err("wireguard: invalid base64 private key", .{});
        return types.WireguardError.DeviceCreateFailed;
    };

    {
        const genl_fd = nl.openGenericSocket() catch return types.WireguardError.DeviceCreateFailed;
        defer platform.posix.close(genl_fd);

        const wg_family = nl.resolveFamily(genl_fd, "wireguard") catch {
            log.err("wireguard: failed to resolve genetlink family", .{});
            return types.WireguardError.DeviceCreateFailed;
        };

        var buf: [nl.buf_size]u8 align(4) = undefined;
        var mb = nl.MessageBuilder.init(&buf);

        const hdr = mb.putHeaderGenl(wg_family, nl.NLM_F.REQUEST | nl.NLM_F.ACK, nl.WG_CMD.SET_DEVICE) catch
            return types.WireguardError.DeviceCreateFailed;

        mb.putAttrStr(hdr, nl.WGDEVICE_A.IFNAME, name) catch return types.WireguardError.DeviceCreateFailed;
        mb.putAttr(hdr, nl.WGDEVICE_A.PRIVATE_KEY, &raw_key) catch return types.WireguardError.DeviceCreateFailed;
        mb.putAttrU16(hdr, nl.WGDEVICE_A.LISTEN_PORT, listen_port) catch return types.WireguardError.DeviceCreateFailed;

        nl.sendAndCheck(genl_fd, mb.message()) catch |e| {
            log.err("wireguard: failed to configure interface: {}", .{e});
            return types.WireguardError.DeviceCreateFailed;
        };
    }

    const if_index = nl.getIfIndex(rt_fd, name) catch return types.WireguardError.DeviceCreateFailed;
    if (if_index == 0) return types.WireguardError.DeviceCreateFailed;

    nl.setLinkUp(rt_fd, if_index) catch |e| {
        log.err("wireguard: failed to bring interface up: {}", .{e});
        return types.WireguardError.DeviceCreateFailed;
    };
}

pub fn deleteInterface(name: []const u8) types.WireguardError!void {
    const fd = nl.openSocket() catch return types.WireguardError.DeviceDeleteFailed;
    defer platform.posix.close(fd);

    nl.deleteLink(fd, name) catch return types.WireguardError.DeviceDeleteFailed;
}

fn cleanupInterface(rt_fd: posix.fd_t, name: []const u8) void {
    nl.deleteLink(rt_fd, name) catch |e| {
        log.warn("wireguard: failed to cleanup interface: {}", .{e});
    };
}

pub fn addPeer(name: []const u8, peer: types.PeerConfig) types.WireguardError!void {
    const raw_pubkey = parse_support.decodeKey(peer.public_key) orelse return types.WireguardError.PeerAddFailed;

    const genl_fd = nl.openGenericSocket() catch return types.WireguardError.PeerAddFailed;
    defer platform.posix.close(genl_fd);

    const wg_family = nl.resolveFamily(genl_fd, "wireguard") catch return types.WireguardError.PeerAddFailed;

    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = mb.putHeaderGenl(wg_family, nl.NLM_F.REQUEST | nl.NLM_F.ACK, nl.WG_CMD.SET_DEVICE) catch
        return types.WireguardError.PeerAddFailed;

    mb.putAttrStr(hdr, nl.WGDEVICE_A.IFNAME, name) catch return types.WireguardError.PeerAddFailed;

    const peers_nest = mb.startNested(hdr, nl.WGDEVICE_A.PEERS) catch return types.WireguardError.PeerAddFailed;
    const peer_nest = mb.startNested(hdr, 0) catch return types.WireguardError.PeerAddFailed;

    mb.putAttr(hdr, nl.WGPEER_A.PUBLIC_KEY, &raw_pubkey) catch return types.WireguardError.PeerAddFailed;

    if (peer.endpoint) |ep| {
        const sa = parse_support.parseEndpoint(ep) orelse return types.WireguardError.PeerAddFailed;
        mb.putAttr(hdr, nl.WGPEER_A.ENDPOINT, &sa) catch return types.WireguardError.PeerAddFailed;
    }

    mb.putAttrU16(hdr, nl.WGPEER_A.PERSISTENT_KEEPALIVE, peer.persistent_keepalive) catch
        return types.WireguardError.PeerAddFailed;

    const aips_nest = mb.startNested(hdr, nl.WGPEER_A.ALLOWED_IPS) catch return types.WireguardError.PeerAddFailed;

    var it = mem.splitScalar(u8, peer.allowed_ips, ',');
    while (it.next()) |cidr_str| {
        const cidr = parse_support.parseCidr(cidr_str) orelse return types.WireguardError.PeerAddFailed;

        const aip_nest = mb.startNested(hdr, 0) catch return types.WireguardError.PeerAddFailed;
        mb.putAttrU8(hdr, nl.WGALLOWEDIP_A.FAMILY, nl.AF.INET) catch return types.WireguardError.PeerAddFailed;
        mb.putAttr(hdr, nl.WGALLOWEDIP_A.IPADDR, &cidr.addr) catch return types.WireguardError.PeerAddFailed;
        mb.putAttrU8(hdr, nl.WGALLOWEDIP_A.CIDR_MASK, cidr.prefix) catch return types.WireguardError.PeerAddFailed;
        mb.endNested(aip_nest);
    }

    mb.endNested(aips_nest);
    mb.endNested(peer_nest);
    mb.endNested(peers_nest);

    nl.sendAndCheck(genl_fd, mb.message()) catch return types.WireguardError.PeerAddFailed;
}

pub fn removePeer(name: []const u8, public_key: []const u8) types.WireguardError!void {
    const raw_pubkey = parse_support.decodeKey(public_key) orelse return types.WireguardError.PeerRemoveFailed;

    const genl_fd = nl.openGenericSocket() catch return types.WireguardError.PeerRemoveFailed;
    defer platform.posix.close(genl_fd);

    const wg_family = nl.resolveFamily(genl_fd, "wireguard") catch return types.WireguardError.PeerRemoveFailed;

    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = mb.putHeaderGenl(wg_family, nl.NLM_F.REQUEST | nl.NLM_F.ACK, nl.WG_CMD.SET_DEVICE) catch
        return types.WireguardError.PeerRemoveFailed;

    mb.putAttrStr(hdr, nl.WGDEVICE_A.IFNAME, name) catch return types.WireguardError.PeerRemoveFailed;

    const peers_nest = mb.startNested(hdr, nl.WGDEVICE_A.PEERS) catch return types.WireguardError.PeerRemoveFailed;
    const peer_nest = mb.startNested(hdr, 0) catch return types.WireguardError.PeerRemoveFailed;

    mb.putAttr(hdr, nl.WGPEER_A.PUBLIC_KEY, &raw_pubkey) catch return types.WireguardError.PeerRemoveFailed;
    mb.putAttrU32(hdr, nl.WGPEER_A.FLAGS, nl.WGPEER_F_REMOVE_ME) catch return types.WireguardError.PeerRemoveFailed;

    mb.endNested(peer_nest);
    mb.endNested(peers_nest);

    nl.sendAndCheck(genl_fd, mb.message()) catch return types.WireguardError.PeerRemoveFailed;
}

pub fn assignOverlayIp(name: []const u8, overlay_ip: [4]u8, prefix_len: u8) types.WireguardError!void {
    const fd = nl.openSocket() catch return types.WireguardError.AddressFailed;
    defer platform.posix.close(fd);

    const if_index = nl.getIfIndex(fd, name) catch return types.WireguardError.AddressFailed;
    if (if_index == 0) return types.WireguardError.AddressFailed;

    nl.addAddress(fd, if_index, &overlay_ip, prefix_len) catch return types.WireguardError.AddressFailed;
}

pub fn addRoute(dest: [4]u8, prefix_len: u8, via: [4]u8) types.WireguardError!void {
    const fd = nl.openSocket() catch return types.WireguardError.RouteFailed;
    defer platform.posix.close(fd);

    nl.addRoute(fd, &dest, prefix_len, &via) catch return types.WireguardError.RouteFailed;
}

pub fn removeRoute(dest: [4]u8, prefix_len: u8) types.WireguardError!void {
    const fd = nl.openSocket() catch return types.WireguardError.RouteFailed;
    defer platform.posix.close(fd);

    nl.removeRoute(fd, &dest, prefix_len) catch return types.WireguardError.RouteFailed;
}
