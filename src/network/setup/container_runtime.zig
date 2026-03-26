const std = @import("std");
const posix = std.posix;
const sqlite = @import("sqlite");
const bridge = @import("../bridge.zig");
const dns = @import("../dns.zig");
const ip = @import("../ip.zig");
const nat = @import("../nat.zig");
const log = @import("../../lib/log.zig");
const common = @import("common.zig");
const cluster_runtime = @import("cluster_runtime.zig");
const file_support = @import("file_support.zig");
const ebpf = @import("ebpf_module.zig").ebpf;
const ebpf_support = @import("ebpf_support.zig");
const service_registry_bridge = @import("../service_registry_bridge.zig");

pub fn setupContainer(
    container_id: []const u8,
    pid: posix.pid_t,
    config: common.NetworkConfig,
    db: *sqlite.Db,
    hostname: []const u8,
) common.SetupError!common.NetworkInfo {
    const subnet_config: ?ip.SubnetConfig = if (config.node_id) |nid|
        ip.subnetForNode(nid) catch return common.SetupError.BridgeFailed
    else
        null;

    if (subnet_config) |sc| {
        bridge.ensureBridgeWithConfig(.{
            .gateway_ip = sc.gateway,
            .prefix_len = sc.prefix_len,
        }) catch return common.SetupError.BridgeFailed;
    } else {
        bridge.ensureBridge(bridge.default_bridge) catch return common.SetupError.BridgeFailed;
    }

    const container_ip = if (subnet_config) |sc|
        ip.allocateWithSubnet(db, container_id, sc) catch return common.SetupError.IpAllocationFailed
    else
        ip.allocate(db, container_id) catch return common.SetupError.IpAllocationFailed;
    errdefer ip.release(db, container_id) catch {};

    var veth_buf: [32]u8 = undefined;
    const host_veth = bridge.vethName(container_id, &veth_buf);

    bridge.createVethPair(host_veth, "eth0", bridge.default_bridge) catch {
        return common.SetupError.VethFailed;
    };
    errdefer {
        bridge.deleteVeth(host_veth) catch |e| {
            log.warn("setup: failed to clean up veth {s} after error: {}", .{ host_veth, e });
        };
    }

    bridge.moveToNamespace("eth0", pid) catch |e| {
        log.err("setup: failed to move veth to container namespace: {}", .{e});
        return common.SetupError.VethFailed;
    };

    if (subnet_config) |sc| {
        bridge.configurableContainer(pid, container_ip, sc.gateway, sc.prefix_len) catch {
            return common.SetupError.ConfigFailed;
        };
    } else {
        bridge.configureContainer(pid, container_ip, bridge.gateway_ip) catch {
            return common.SetupError.ConfigFailed;
        };
    }

    nat.enableForwarding() catch |e| {
        log.warn("failed to enable IP forwarding: {}", .{e});
        return common.SetupError.NatFailed;
    };
    nat.ensureMasquerade(bridge.default_bridge, "10.42.0.0/16") catch |e| {
        log.warn("failed to set up masquerade on {s}: {}", .{ bridge.default_bridge, e });
        return common.SetupError.NatFailed;
    };

    var ip_str_buf: [16]u8 = undefined;
    const ip_str = ip.formatIp(container_ip, &ip_str_buf);
    var configured_port_maps: usize = 0;
    errdefer {
        var idx: usize = 0;
        while (idx < configured_port_maps) : (idx += 1) {
            const pm = config.port_maps[idx];
            if (ebpf.getPortMapper()) |mapper| {
                const proto: u8 = switch (pm.protocol) {
                    .tcp => 6,
                    .udp => 17,
                };
                mapper.removeMapping(pm.host_port, proto);
            }
            nat.removePortMap(pm.host_port, ip_str, pm.container_port, pm.protocol.toNat());
        }
    }

    for (config.port_maps) |pm| {
        if (ebpf.getPortMapper()) |mapper| {
            const proto: u8 = switch (pm.protocol) {
                .tcp => 6,
                .udp => 17,
            };
            mapper.addMapping(pm.host_port, proto, container_ip, pm.container_port);
        }
        nat.addPortMap(pm.host_port, ip_str, pm.container_port, pm.protocol.toNat()) catch |e| {
            log.warn("failed to add port map {}:{} for {s}: {}", .{ pm.host_port, pm.container_port, container_id, e });
            return common.SetupError.NatFailed;
        };
        configured_port_maps += 1;
    }

    dns.startResolver();
    if (!config.skip_dns and !dns.resolverRunning()) {
        return common.SetupError.ConfigFailed;
    }
    ebpf_support.loadDnsInterceptorOnBridge();

    if (!config.skip_dns) {
        service_registry_bridge.registerContainerService(hostname, container_id, container_ip);
    }

    var info = common.NetworkInfo{
        .ip = container_ip,
        .veth_host = undefined,
        .veth_host_len = host_veth.len,
    };
    @memcpy(info.veth_host[0..host_veth.len], host_veth);
    return info;
}

pub fn teardownContainer(
    container_id: []const u8,
    net_info: *const common.NetworkInfo,
    config: common.NetworkConfig,
    db: *sqlite.Db,
) void {
    service_registry_bridge.unregisterContainerService(container_id);

    var ip_str_buf: [16]u8 = undefined;
    const ip_str = ip.formatIp(net_info.ip, &ip_str_buf);

    for (config.port_maps) |pm| {
        if (ebpf.getPortMapper()) |mapper| {
            const proto: u8 = switch (pm.protocol) {
                .tcp => 6,
                .udp => 17,
            };
            mapper.removeMapping(pm.host_port, proto);
        }
        nat.removePortMap(pm.host_port, ip_str, pm.container_port, pm.protocol.toNat());
    }

    bridge.deleteVeth(net_info.vethName()) catch |e| {
        log.warn("setup: failed to delete veth for {s}: {}", .{ container_id, e });
    };

    ip.release(db, container_id) catch |e| {
        log.warn("setup: failed to release IP for {s}: {}", .{ container_id, e });
    };
}

pub const writeNetworkFiles = file_support.writeNetworkFiles;
pub const isValidHostname = file_support.isValidHostname;
pub const containerSubnetBase = cluster_runtime.containerSubnetBase;
