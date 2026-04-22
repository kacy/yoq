const std = @import("std");
const wireguard = @import("../wireguard.zig");
const log = @import("../../lib/log.zig");
const common = @import("common.zig");

pub fn setupClusterNetworking(config: common.ClusterNetworkConfig) !void {
    log.info("setting up cluster networking (node_id={d}, overlay={d}.{d}.{d}.{d})", .{
        config.node_id,
        config.overlay_ip[0],
        config.overlay_ip[1],
        config.overlay_ip[2],
        config.overlay_ip[3],
    });

    wireguard.createInterface(common.wg_interface, config.private_key, config.listen_port) catch |e| {
        log.warn("failed to create wireguard interface: {}", .{e});
        return error.BridgeFailed;
    };
    errdefer wireguard.deleteInterface(common.wg_interface) catch {};
    var added_peers: usize = 0;
    errdefer {
        while (added_peers > 0) {
            added_peers -= 1;
            removeClusterPeer(config.peers[added_peers]);
        }
    }

    wireguard.assignOverlayIp(common.wg_interface, config.overlay_ip, 24) catch |e| {
        log.warn("failed to assign overlay IP to {s}: {}", .{ common.wg_interface, e });
        return error.ConfigFailed;
    };

    for (config.peers) |peer| {
        addClusterPeerInternal(peer) catch |e| {
            log.warn("failed to add peer (node {d}): {}", .{ peer.container_subnet_node, e });
            return error.ConfigFailed;
        };
        added_peers += 1;
    }

    if (config.role == .server) {
        const fwd_path = "/proc/sys/net/ipv4/conf/wg-yoq/forwarding";
        if (@import("compat").cwd().openFile(fwd_path, .{ .mode = .write_only })) |file| {
            defer file.close();
            file.writeAll("1") catch return error.ConfigFailed;
            log.info("IP forwarding enabled on wg-yoq (server role)", .{});
        } else |e| {
            log.warn("failed to enable IP forwarding on wg-yoq: {}", .{e});
            return error.ConfigFailed;
        }
    }

    log.info("cluster networking ready ({d} peers)", .{config.peers.len});
}

pub fn addClusterPeer(peer: common.PeerInfo) !void {
    return addClusterPeerInternal(peer);
}

fn addClusterPeerInternal(peer: common.PeerInfo) !void {
    const subnet_base = containerSubnetBase(peer.container_subnet_node);

    var allowed_buf: [128]u8 = undefined;
    const allowed_ips = if (peer.is_hub)
        std.fmt.bufPrint(&allowed_buf, "{d}.{d}.{d}.{d}/32,10.42.0.0/16,10.40.0.0/24", .{
            peer.overlay_ip[0], peer.overlay_ip[1], peer.overlay_ip[2], peer.overlay_ip[3],
        }) catch return error.ConfigFailed
    else
        std.fmt.bufPrint(&allowed_buf, "{d}.{d}.{d}.{d}/32,{d}.{d}.{d}.0/24", .{
            peer.overlay_ip[0], peer.overlay_ip[1], peer.overlay_ip[2], peer.overlay_ip[3],
            subnet_base[0],     subnet_base[1],     subnet_base[2],
        }) catch return error.ConfigFailed;

    wireguard.addPeer(common.wg_interface, .{
        .public_key = peer.public_key,
        .endpoint = if (peer.endpoint.len > 0) peer.endpoint else null,
        .allowed_ips = allowed_ips,
    }) catch |e| {
        log.warn("failed to add wireguard peer: {}", .{e});
        return error.ConfigFailed;
    };
    errdefer wireguard.removePeer(common.wg_interface, peer.public_key) catch |e| {
        log.warn("failed to roll back wireguard peer: {}", .{e});
    };

    const dest = [4]u8{ subnet_base[0], subnet_base[1], subnet_base[2], 0 };
    wireguard.addRoute(dest, 24, peer.overlay_ip) catch |e| {
        log.warn("failed to add route for {d}.{d}.{d}.0/24: {}", .{ subnet_base[0], subnet_base[1], subnet_base[2], e });
        return error.ConfigFailed;
    };
}

pub fn removeClusterPeer(peer: common.PeerInfo) void {
    wireguard.removePeer(common.wg_interface, peer.public_key) catch |e| {
        log.warn("failed to remove wireguard peer: {}", .{e});
    };

    const subnet_base = containerSubnetBase(peer.container_subnet_node);
    const dest = [4]u8{ subnet_base[0], subnet_base[1], subnet_base[2], 0 };
    wireguard.removeRoute(dest, 24) catch |e| {
        log.warn("failed to remove route for {d}.{d}.{d}.0/24: {}", .{ subnet_base[0], subnet_base[1], subnet_base[2], e });
    };
}

pub fn teardownClusterNetworking() void {
    wireguard.deleteInterface(common.wg_interface) catch |e| {
        log.warn("failed to delete wireguard interface: {}", .{e});
    };
    log.info("cluster networking torn down", .{});
}

pub fn containerSubnetBase(node_id: u16) [3]u8 {
    if (node_id <= 254) {
        return .{ 10, 42, @intCast(node_id) };
    }
    const high: u8 = @intCast(@as(u16, 42) + (node_id >> 8));
    const low: u8 = @intCast(node_id & 0xFF);
    return .{ 10, high, low };
}
