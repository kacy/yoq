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
const ebpf_support = @import("ebpf_support.zig");
const service_registry_bridge = @import("../service_registry_bridge.zig");
const service_reconciler = @import("../service_reconciler.zig");
const policy = @import("../policy.zig");
const local_networks = @import("../local_networks.zig");
const local_rules = @import("../local_network_rules.zig");
const port_mappings = @import("port_mappings.zig");

pub fn setupContainer(
    container_id: []const u8,
    pid: posix.pid_t,
    config: common.NetworkConfig,
    db: *sqlite.Db,
    hostname: []const u8,
) common.SetupError!common.NetworkInfo {
    if (config.network_name) |name| return setupNamedContainer(container_id, pid, config, db, name);
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

    bridge.createVethPairForContainer(host_veth, "eth0", bridge.default_bridge, pid) catch {
        return common.SetupError.VethFailed;
    };
    errdefer {
        bridge.deleteVeth(host_veth) catch |e| {
            log.warn("setup: failed to clean up veth {s} after error: {}", .{ host_veth, e });
        };
    }

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
    nat.ensureContainerForwarding(bridge.default_bridge, "10.42.0.0/16") catch |e| {
        log.warn("failed to permit container forwarding on {s}: {}", .{ bridge.default_bridge, e });
        return common.SetupError.NatFailed;
    };
    nat.ensureMasquerade(bridge.default_bridge, "10.42.0.0/16") catch |e| {
        log.warn("failed to set up masquerade on {s}: {}", .{ bridge.default_bridge, e });
        return common.SetupError.NatFailed;
    };

    var ip_str_buf: [16]u8 = undefined;
    const ip_str = ip.formatIp(container_ip, &ip_str_buf);
    const mappings: port_mappings.Mapping = .{ .address = container_ip, .address_text = ip_str };
    port_mappings.install(config.port_maps, mappings) catch |err| {
        log.warn("failed to publish ports for {s}: {}", .{ container_id, err });
        return common.SetupError.NatFailed;
    };
    errdefer for (config.port_maps) |port| mappings.remove(port);

    const gateway = if (subnet_config) |sc| sc.gateway else bridge.gateway_ip;
    dns.startResolverAt(gateway);
    if (!config.skip_dns and !dns.resolverRunningAt(gateway)) {
        return common.SetupError.ConfigFailed;
    }
    if (dns.resolverOwnedByCurrentProcess()) {
        ebpf_support.loadDnsInterceptorOnBridge();
    }
    service_reconciler.refreshComponentStateIfEnabled();
    // every supervisor must retry DNS ownership if the current listener exits.
    service_reconciler.startAuditLoopIfEnabled();

    if (!config.skip_dns) {
        service_registry_bridge.registerContainerService(
            hostname,
            container_id,
            container_ip,
            if (config.node_id) |node_id| @as(i64, node_id) else null,
        );
    }

    errdefer if (!config.skip_dns) service_registry_bridge.unregisterContainerService(container_id);
    policy.requireForContainer(hostname, container_ip, std.heap.page_allocator) catch |err| {
        log.err("network policy must be enforced before container startup: {}", .{err});
        return common.SetupError.ConfigFailed;
    };

    var info = common.NetworkInfo{
        .ip = container_ip,
        .veth_host = undefined,
        .veth_host_len = host_veth.len,
    };
    @memcpy(info.veth_host[0..host_veth.len], host_veth);
    return info;
}

pub fn teardownContainer(container_id: []const u8, net_info: *const common.NetworkInfo, config: common.NetworkConfig, db: *sqlite.Db) void {
    teardownContainerChecked(container_id, net_info, config, db) catch |err| {
        log.warn("setup: network teardown incomplete for {s}: {}", .{ container_id, err });
    };
}

pub fn teardownContainerChecked(container_id: []const u8, net_info: *const common.NetworkInfo, config: common.NetworkConfig, db: *sqlite.Db) common.SetupError!void {
    if (config.network_name != null) {
        local_networks.deactivate(container_id) catch return error.DbFailed;
    } else service_registry_bridge.unregisterContainerService(container_id);
    var ip_str_buf: [16]u8 = undefined;
    const ip_str = ip.formatIp(net_info.ip, &ip_str_buf);
    const mapping: port_mappings.Mapping = .{ .address = net_info.ip, .address_text = ip_str, .use_xdp = config.network_name == null };
    for (config.port_maps) |pm| mapping.removeChecked(pm) catch return error.NatFailed;
    bridge.deleteVethChecked(net_info.vethName()) catch return error.VethFailed;
    ip.release(db, container_id) catch return error.IpAllocationFailed;
}

pub const writeNetworkFiles = file_support.writeNetworkFiles;
pub const isValidHostname = file_support.isValidHostname;
pub const containerSubnetBase = cluster_runtime.containerSubnetBase;

fn setupNamedContainer(container_id: []const u8, pid: posix.pid_t, config: common.NetworkConfig, db: *sqlite.Db, name: []const u8) common.SetupError!common.NetworkInfo {
    const owned_lock = local_networks.lock(name) catch return error.DbFailed;
    defer owned_lock.deinit();
    const network = local_networks.inspect(std.heap.page_allocator, name) catch return error.DbFailed;
    defer network.deinit(std.heap.page_allocator);
    local_networks.requireReference(name, container_id) catch return error.DbFailed;
    const subnet = network.subnet;
    // Persist ownership before the first kernel mutation so network rm can
    // clean up a bridge left by an interrupted setup.
    local_networks.markProvisioned(name) catch return error.DbFailed;
    bridge.ensureBridgeWithConfig(.{ .name = network.bridge_name, .gateway_ip = subnet.gateway, .prefix_len = subnet.prefix_len }) catch return error.BridgeFailed;
    local_rules.ensure(network.bridge_name, subnet.base) catch return error.NatFailed;
    const address = ip.allocateWithSubnet(db, container_id, subnet) catch return error.IpAllocationFailed;
    errdefer ip.release(db, container_id) catch {};
    var veth_buf: [32]u8 = undefined;
    const host_veth = bridge.vethName(container_id, &veth_buf);
    bridge.createVethPairForContainer(host_veth, "eth0", network.bridge_name, pid) catch return error.VethFailed;
    errdefer bridge.deleteVeth(host_veth) catch {};
    bridge.configurableContainer(pid, address, subnet.gateway, subnet.prefix_len) catch return error.ConfigFailed;
    var address_buf: [16]u8 = undefined;
    const mappings: port_mappings.Mapping = .{ .address = address, .address_text = ip.formatIp(address, &address_buf), .bridge_name = network.bridge_name, .use_xdp = false };
    port_mappings.install(config.port_maps, mappings) catch return error.NatFailed;
    errdefer for (config.port_maps) |port| mappings.remove(port);
    if (!config.skip_dns) {
        dns.startScopedResolverAt(subnet.gateway, network.bridge_name, name);
        if (!dns.resolverRunningAt(subnet.gateway)) return error.ConfigFailed;
    }
    local_networks.activate(container_id, address) catch return error.DbFailed;
    var info: common.NetworkInfo = .{ .ip = address, .veth_host = undefined, .veth_host_len = host_veth.len };
    @memcpy(info.veth_host[0..host_veth.len], host_veth);
    return info;
}
