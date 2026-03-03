// setup — network setup orchestrator
//
// single entry point for container networking. composes bridge, ip,
// and nat modules into setupContainer / teardownContainer calls.
//
// the container runtime calls setupContainer() after spawning the
// child process (it needs the child PID to move the veth into the
// right namespace). it calls teardownContainer() on stop/rm.
//
// all operations are non-fatal — containers can run without
// networking if permissions are insufficient.

const std = @import("std");
const posix = std.posix;
const sqlite = @import("sqlite");

const bridge = @import("bridge.zig");
const ip = @import("ip.zig");
const nat = @import("nat.zig");
const schema = @import("../state/schema.zig");

pub const SetupError = error{
    BridgeFailed,
    IpAllocationFailed,
    VethFailed,
    NatFailed,
    ConfigFailed,
    DbFailed,
};

/// network configuration for a container
pub const NetworkConfig = struct {
    enabled: bool = true,
    port_maps: []const PortMap = &.{},
};

/// port mapping from host to container
pub const PortMap = struct {
    host_port: u16,
    container_port: u16,
    protocol: Protocol = .tcp,
};

pub const Protocol = enum {
    tcp,
    udp,

    fn toNat(self: Protocol) nat.Protocol {
        return switch (self) {
            .tcp => .tcp,
            .udp => .udp,
        };
    }
};

/// result of setting up networking for a container.
/// stores the allocated IP and veth name for later teardown.
pub const NetworkInfo = struct {
    ip: [4]u8,
    veth_host: [32]u8,
    veth_host_len: usize,

    pub fn vethName(self: *const NetworkInfo) []const u8 {
        return self.veth_host[0..self.veth_host_len];
    }
};

/// set up networking for a container.
///
/// 1. ensure the yoq0 bridge exists
/// 2. allocate an IP from the 10.42.0.0/16 pool
/// 3. create a veth pair, attach host end to bridge
/// 4. move peer into container namespace
/// 5. configure IP, routes, loopback inside container
/// 6. enable forwarding and masquerade
/// 7. set up port mappings
///
/// returns NetworkInfo with the allocated IP and veth name,
/// or an error if setup fails.
pub fn setupContainer(
    container_id: []const u8,
    pid: posix.pid_t,
    config: NetworkConfig,
    db: *sqlite.Db,
) SetupError!NetworkInfo {
    // 1. create bridge (idempotent)
    bridge.ensureBridge(bridge.default_bridge) catch return SetupError.BridgeFailed;

    // 2. allocate IP
    const container_ip = ip.allocate(db, container_id) catch return SetupError.IpAllocationFailed;
    errdefer ip.release(db, container_id) catch {};

    // 3. create veth pair
    var veth_buf: [32]u8 = undefined;
    const host_veth = bridge.vethName(container_id, &veth_buf);

    bridge.createVethPair(host_veth, "eth0", bridge.default_bridge) catch {
        return SetupError.VethFailed;
    };
    errdefer bridge.deleteVeth(host_veth) catch {};

    // 4. move peer into container namespace
    bridge.moveToNamespace("eth0", pid) catch return SetupError.VethFailed;

    // 5. configure inside container namespace
    bridge.configureContainer(pid, container_ip, bridge.gateway_ip) catch {
        return SetupError.ConfigFailed;
    };

    // 6. NAT setup (non-fatal — containers still work on the bridge without NAT)
    nat.enableForwarding() catch {};
    nat.ensureMasquerade(bridge.default_bridge, "10.42.0.0/16") catch {};

    // 7. port mappings
    var ip_str_buf: [16]u8 = undefined;
    const ip_str = ip.formatIp(container_ip, &ip_str_buf);

    for (config.port_maps) |pm| {
        nat.addPortMap(pm.host_port, ip_str, pm.container_port, pm.protocol.toNat()) catch {};
    }

    // build result
    var info = NetworkInfo{
        .ip = container_ip,
        .veth_host = undefined,
        .veth_host_len = host_veth.len,
    };
    @memcpy(info.veth_host[0..host_veth.len], host_veth);

    return info;
}

/// tear down networking for a container.
/// removes port mappings, deletes veth pair, releases IP.
pub fn teardownContainer(
    container_id: []const u8,
    net_info: *const NetworkInfo,
    config: NetworkConfig,
    db: *sqlite.Db,
) void {
    // remove port mapping rules
    var ip_str_buf: [16]u8 = undefined;
    const ip_str = ip.formatIp(net_info.ip, &ip_str_buf);

    for (config.port_maps) |pm| {
        nat.removePortMap(pm.host_port, ip_str, pm.container_port, pm.protocol.toNat());
    }

    // delete host-side veth (kernel removes peer automatically)
    bridge.deleteVeth(net_info.vethName()) catch {};

    // release IP allocation
    ip.release(db, container_id) catch {};
}

/// write /etc/resolv.conf and /etc/hosts into a container's rootfs.
/// called with the merged overlay path before the container starts.
pub fn writeNetworkFiles(rootfs_path: []const u8, container_ip: [4]u8, hostname: []const u8) void {
    // write /etc/resolv.conf — use host's DNS for now
    writeFileInRootfs(rootfs_path, "etc/resolv.conf",
        \\nameserver 8.8.8.8
        \\nameserver 8.8.4.4
        \\
    );

    // write /etc/hosts
    var hosts_buf: [256]u8 = undefined;
    var ip_buf: [16]u8 = undefined;
    const ip_str = ip.formatIp(container_ip, &ip_buf);
    const hosts = std.fmt.bufPrint(
        &hosts_buf,
        "127.0.0.1\tlocalhost\n{s}\t{s}\n",
        .{ ip_str, hostname },
    ) catch return;

    writeFileInRootfs(rootfs_path, "etc/hosts", hosts);
}

fn writeFileInRootfs(rootfs: []const u8, rel_path: []const u8, content: []const u8) void {
    var path_buf: [512]u8 = undefined;
    const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ rootfs, rel_path }) catch return;

    // ensure parent directory exists
    if (std.fs.path.dirname(full_path)) |dir| {
        std.fs.cwd().makePath(dir) catch {};
    }

    const file = std.fs.cwd().createFile(full_path, .{}) catch return;
    defer file.close();
    file.writeAll(content) catch {};
}

// -- tests --

test "network config defaults" {
    const config = NetworkConfig{};
    try std.testing.expect(config.enabled);
    try std.testing.expectEqual(@as(usize, 0), config.port_maps.len);
}

test "port map defaults to tcp" {
    const pm = PortMap{ .host_port = 8080, .container_port = 80 };
    try std.testing.expectEqual(Protocol.tcp, pm.protocol);
}

test "network info veth name" {
    var info = NetworkInfo{
        .ip = .{ 10, 42, 0, 2 },
        .veth_host = undefined,
        .veth_host_len = 11,
    };
    const name = "veth_abc123";
    @memcpy(info.veth_host[0..name.len], name);
    try std.testing.expectEqualStrings("veth_abc123", info.vethName());
}

test "protocol conversion" {
    try std.testing.expectEqual(nat.Protocol.tcp, Protocol.tcp.toNat());
    try std.testing.expectEqual(nat.Protocol.udp, Protocol.udp.toNat());
}
