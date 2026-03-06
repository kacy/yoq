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
const builtin = @import("builtin");
const posix = std.posix;
const sqlite = @import("sqlite");

const bridge = @import("bridge.zig");
const dns = @import("dns.zig");
const ebpf = if (builtin.os.tag == .linux) @import("ebpf.zig") else struct {
    pub const PortMapper = struct {
        pub fn addMapping(_: *@This(), _: u16, _: u8, _: [4]u8, _: u16) void {}
        pub fn removeMapping(_: *@This(), _: u16, _: u8) void {}
    };

    var port_mapper: PortMapper = .{};

    pub fn getPortMapper() ?*PortMapper {
        return &port_mapper;
    }

    pub fn getDnsInterceptor() ?*anyopaque {
        return null;
    }

    pub fn getPolicyEnforcer() ?*anyopaque {
        return null;
    }

    pub fn loadPolicyEnforcer(_: u32) error{NotSupported}!void {
        return error.NotSupported;
    }

    pub fn loadDnsInterceptor(_: u32) error{NotSupported}!void {
        return error.NotSupported;
    }

    pub fn loadLoadBalancer(_: u32) error{NotSupported}!void {
        return error.NotSupported;
    }

    pub fn loadPortMapper(_: u32) error{NotSupported}!void {
        return error.NotSupported;
    }
};
const ip = @import("ip.zig");
const nat = @import("nat.zig");
const nl = @import("netlink.zig");
const policy = @import("policy.zig");
const wireguard = @import("wireguard.zig");
const schema = @import("../state/schema.zig");
const log = @import("../lib/log.zig");

pub const SetupError = error{
    /// failed to create or configure the yoq0 bridge interface
    BridgeFailed,
    /// failed to allocate an IP address for the container
    IpAllocationFailed,
    /// failed to create a veth pair or move it into the container namespace
    VethFailed,
    /// failed to set up iptables NAT rules (forwarding or masquerade)
    NatFailed,
    /// failed to configure networking inside the container namespace
    ConfigFailed,
    /// failed to open or query the state database
    DbFailed,
};

// -- cluster networking --
//
// these functions manage the WireGuard mesh overlay that connects
// container networks across nodes. each node runs a "wg-yoq" interface
// with an overlay IP (10.40.0.{node_id}). routes for remote container
// subnets (10.42.{peer_node_id}.0/24) go through the WireGuard tunnel.
//
// setupClusterNetworking() is called once during agent startup.
// addClusterPeer() / removeClusterPeer() handle dynamic membership.
// teardownClusterNetworking() is called on agent shutdown.

const wg_interface = "wg-yoq";

/// configuration for setting up the cross-node WireGuard mesh.
/// passed to setupClusterNetworking() during agent startup.
pub const ClusterNetworkConfig = struct {
    node_id: u8,
    private_key: []const u8,
    listen_port: u16,
    overlay_ip: [4]u8,
    peers: []const PeerInfo,
};

/// information about a remote node in the WireGuard mesh.
/// used for both initial setup and dynamic peer add/remove.
pub const PeerInfo = struct {
    public_key: []const u8,
    endpoint: []const u8,
    overlay_ip: [4]u8,
    /// the remote node's ID, used to derive its container subnet
    /// (10.42.{container_subnet_node}.0/24).
    container_subnet_node: u8,
};

/// set up the WireGuard mesh interface for cluster networking.
///
/// creates the "wg-yoq" interface, assigns the overlay IP, and adds
/// all known peers with routes to their container subnets. called
/// once during agent startup after registration returns the peer list.
///
/// the overlay network uses 10.40.0.0/24 — each node gets 10.40.0.{node_id}.
/// container traffic for remote nodes (10.42.{node_id}.0/24) is routed
/// through the WireGuard tunnel via the remote node's overlay IP.
pub fn setupClusterNetworking(config: ClusterNetworkConfig) !void {
    log.info("setting up cluster networking (node_id={d}, overlay={d}.{d}.{d}.{d})", .{
        config.node_id,
        config.overlay_ip[0],
        config.overlay_ip[1],
        config.overlay_ip[2],
        config.overlay_ip[3],
    });

    // create the wireguard interface, set private key + listen port, bring it up
    wireguard.createInterface(wg_interface, config.private_key, config.listen_port) catch |e| {
        log.warn("failed to create wireguard interface: {}", .{e});
        return error.BridgeFailed;
    };
    errdefer wireguard.deleteInterface(wg_interface) catch {};

    // assign our overlay IP to the interface
    wireguard.assignOverlayIp(wg_interface, config.overlay_ip, 24) catch |e| {
        log.warn("failed to assign overlay IP to {s}: {}", .{ wg_interface, e });
        return error.ConfigFailed;
    };

    // add each peer and its route
    for (config.peers) |peer| {
        addClusterPeerInternal(peer) catch |e| {
            // non-fatal — log and continue with remaining peers.
            // the agent will retry via reconcilePeers on the next heartbeat.
            log.warn("failed to add peer (node {d}): {}", .{ peer.container_subnet_node, e });
        };
    }

    log.info("cluster networking ready ({d} peers)", .{config.peers.len});
}

/// add a single peer to the WireGuard mesh.
///
/// adds the peer to the "wg-yoq" interface with allowed-ips covering
/// both the peer's overlay IP (/32) and its container subnet (/24),
/// then adds a route for the container subnet through the peer's
/// overlay IP.
pub fn addClusterPeer(peer: PeerInfo) !void {
    return addClusterPeerInternal(peer);
}

/// internal peer add — shared by setupClusterNetworking and addClusterPeer.
fn addClusterPeerInternal(peer: PeerInfo) !void {
    // build allowed-ips: "overlay_ip/32,container_subnet/24"
    var allowed_buf: [64]u8 = undefined;
    const allowed_ips = std.fmt.bufPrint(&allowed_buf, "{d}.{d}.{d}.{d}/32,10.42.{d}.0/24", .{
        peer.overlay_ip[0],         peer.overlay_ip[1],
        peer.overlay_ip[2],         peer.overlay_ip[3],
        peer.container_subnet_node,
    }) catch return error.ConfigFailed;

    wireguard.addPeer(wg_interface, .{
        .public_key = peer.public_key,
        .endpoint = if (peer.endpoint.len > 0) peer.endpoint else null,
        .allowed_ips = allowed_ips,
    }) catch |e| {
        log.warn("failed to add wireguard peer: {}", .{e});
        return error.ConfigFailed;
    };

    // add route for the peer's container subnet via their overlay IP
    const dest = [4]u8{ 10, 42, peer.container_subnet_node, 0 };
    wireguard.addRoute(dest, 24, peer.overlay_ip) catch |e| {
        log.warn("failed to add route for 10.42.{d}.0/24: {}", .{ peer.container_subnet_node, e });
        // route failure is non-fatal — the peer is still added and may
        // work if there's already a matching route from a previous run
    };
}

/// remove a peer from the WireGuard mesh.
///
/// removes the WireGuard peer from "wg-yoq" and deletes the route
/// for their container subnet. best-effort — errors are logged.
pub fn removeClusterPeer(peer: PeerInfo) void {
    wireguard.removePeer(wg_interface, peer.public_key) catch |e| {
        log.warn("failed to remove wireguard peer: {}", .{e});
    };

    const dest = [4]u8{ 10, 42, peer.container_subnet_node, 0 };
    wireguard.removeRoute(dest, 24) catch |e| {
        log.warn("failed to remove route for 10.42.{d}.0/24: {}", .{ peer.container_subnet_node, e });
    };
}

/// tear down cluster networking.
/// deletes the "wg-yoq" interface — kernel removes all peers and routes.
pub fn teardownClusterNetworking() void {
    wireguard.deleteInterface(wg_interface) catch |e| {
        log.warn("failed to delete wireguard interface: {}", .{e});
    };
    log.info("cluster networking torn down", .{});
}

/// network configuration for a container
pub const NetworkConfig = struct {
    enabled: bool = true,
    port_maps: []const PortMap = &.{},
    /// when true, skip DNS registration on startup. used for services
    /// with health checks — DNS is registered by the health checker
    /// only after the service becomes healthy (readiness gating).
    skip_dns: bool = false,
    /// cluster node ID for per-node subnet allocation.
    /// null means single-node mode (flat 10.42.0.0/16).
    /// 1-254 means cluster mode (10.42.{node_id}.0/24 per node).
    node_id: ?u8 = null,
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
    hostname: []const u8,
) SetupError!NetworkInfo {
    // determine subnet config based on node_id.
    // null = single-node mode (flat /16), otherwise per-node /24.
    const subnet_config: ?ip.SubnetConfig = if (config.node_id) |nid|
        ip.subnetForNode(nid)
    else
        null;

    // 1. create bridge (idempotent)
    if (subnet_config) |sc| {
        bridge.ensureBridgeWithConfig(.{
            .gateway_ip = sc.gateway,
            .prefix_len = sc.prefix_len,
        }) catch return SetupError.BridgeFailed;
    } else {
        bridge.ensureBridge(bridge.default_bridge) catch return SetupError.BridgeFailed;
    }

    // 2. allocate IP — from node subnet if in cluster mode
    const container_ip = if (subnet_config) |sc|
        ip.allocateWithSubnet(db, container_id, sc) catch return SetupError.IpAllocationFailed
    else
        ip.allocate(db, container_id) catch return SetupError.IpAllocationFailed;
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
    if (subnet_config) |sc| {
        bridge.configurableContainer(pid, container_ip, sc.gateway, sc.prefix_len) catch {
            return SetupError.ConfigFailed;
        };
    } else {
        bridge.configureContainer(pid, container_ip, bridge.gateway_ip) catch {
            return SetupError.ConfigFailed;
        };
    }

    // 6. NAT setup (non-fatal — containers still work on the bridge without NAT)
    nat.enableForwarding() catch |e| {
        log.warn("failed to enable IP forwarding: {}", .{e});
    };
    nat.ensureMasquerade(bridge.default_bridge, "10.42.0.0/16") catch |e| {
        log.warn("failed to set up masquerade on {s}: {}", .{ bridge.default_bridge, e });
    };

    // 7. port mappings
    var ip_str_buf: [16]u8 = undefined;
    const ip_str = ip.formatIp(container_ip, &ip_str_buf);

    for (config.port_maps) |pm| {
        // try XDP port mapping first (faster path)
        if (ebpf.getPortMapper()) |mapper| {
            const proto: u8 = switch (pm.protocol) {
                .tcp => 6, // IPPROTO_TCP
                .udp => 17, // IPPROTO_UDP
            };
            mapper.addMapping(pm.host_port, proto, container_ip, pm.container_port);
        }
        // always set up iptables as fallback / for return traffic SNAT
        nat.addPortMap(pm.host_port, ip_str, pm.container_port, pm.protocol.toNat()) catch |e| {
            log.warn("failed to add port map {}:{} for {s}: {}", .{ pm.host_port, pm.container_port, container_id, e });
        };
    }

    // register with DNS resolver for service discovery.
    // skip if the service has a health check — the health checker will
    // register it only after it becomes healthy (readiness gating).
    dns.startResolver();

    // load the BPF DNS interceptor on the bridge (idempotent).
    // this gives us in-kernel DNS resolution for known services.
    // if BPF isn't available, we fall back to the userspace resolver.
    loadDnsInterceptorOnBridge();

    if (!config.skip_dns) {
        dns.registerService(hostname, container_id, container_ip);
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
/// removes port mappings, deletes veth pair, releases IP, unregisters DNS.
pub fn teardownContainer(
    container_id: []const u8,
    net_info: *const NetworkInfo,
    config: NetworkConfig,
    db: *sqlite.Db,
) void {
    // unregister from DNS
    dns.unregisterService(container_id);

    // remove port mapping rules
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

    // delete host-side veth (kernel removes peer automatically)
    bridge.deleteVeth(net_info.vethName()) catch {};

    // release IP allocation
    ip.release(db, container_id) catch {};
}

/// validate a hostname per RFC 1123: printable ASCII (0x21-0x7e),
/// no control characters, whitespace, or newlines, max 253 characters.
/// rejects hostnames that could inject content into /etc/hosts.
fn isValidHostname(name: []const u8) bool {
    if (name.len == 0 or name.len > 253) return false;
    for (name) |c| {
        if (c < 0x21 or c > 0x7e) return false;
    }
    return true;
}

/// write /etc/resolv.conf and /etc/hosts into a container's rootfs.
/// called with the merged overlay path before the container starts.
pub fn writeNetworkFiles(rootfs_path: []const u8, container_ip: [4]u8, hostname: []const u8) void {
    // validate hostname to prevent injection into /etc/hosts.
    // hostnames with newlines, control characters, or whitespace could
    // inject arbitrary entries into /etc/hosts.
    const valid_hostname = isValidHostname(hostname);
    if (!valid_hostname) {
        log.warn("invalid hostname, using container ID prefix instead", .{});
    }

    // write /etc/resolv.conf — use the bridge gateway DNS resolver
    // for service discovery, with 8.8.8.8 as fallback
    writeFileInRootfs(rootfs_path, "etc/resolv.conf",
        \\nameserver 10.42.0.1
        \\nameserver 8.8.8.8
        \\
    );

    // write /etc/hosts
    if (valid_hostname) {
        var hosts_buf: [256]u8 = undefined;
        var ip_buf: [16]u8 = undefined;
        const ip_str = ip.formatIp(container_ip, &ip_buf);
        const hosts = std.fmt.bufPrint(
            &hosts_buf,
            "127.0.0.1\tlocalhost\n{s}\t{s}\n",
            .{ ip_str, hostname },
        ) catch return;

        writeFileInRootfs(rootfs_path, "etc/hosts", hosts);
    } else {
        writeFileInRootfs(rootfs_path, "etc/hosts", "127.0.0.1\tlocalhost\n");
    }
}

fn writeFileInRootfs(rootfs: []const u8, rel_path: []const u8, content: []const u8) void {
    // defense-in-depth: reject paths that could escape the rootfs.
    // currently only called with hardcoded "etc/resolv.conf" and "etc/hosts",
    // but guard against future misuse.
    if (std.mem.indexOf(u8, rel_path, "..") != null) return;
    if (rel_path.len > 0 and rel_path[0] == '/') return;

    var path_buf: [512]u8 = undefined;
    const full_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ rootfs, rel_path }) catch return;

    // ensure parent directory exists
    if (std.fs.path.dirname(full_path)) |dir| {
        std.fs.cwd().makePath(dir) catch {};
    }

    const file = std.fs.cwd().createFile(full_path, .{}) catch |e| {
        log.warn("failed to create {s}: {}", .{ full_path, e });
        return;
    };
    defer file.close();
    file.writeAll(content) catch |e| {
        log.warn("failed to write {s}: {}", .{ full_path, e });
    };
}

// -- BPF DNS interceptor --
//
// loads the eBPF DNS interceptor on the yoq0 bridge. this gives us
// in-kernel DNS resolution for known services — queries for registered
// names are answered without leaving the kernel, while unknown names
// fall through to the userspace resolver.

/// try to load BPF programs on the bridge. non-fatal.
/// loads the policy enforcer, DNS interceptor, and load balancer if BPF is available.
fn loadDnsInterceptorOnBridge() void {
    if (ebpf.getDnsInterceptor() != null) return; // already loaded

    // look up the bridge interface index
    const sock = nl.openSocket() catch return;
    defer posix.close(sock);

    const if_index = nl.getIfIndex(sock, bridge.default_bridge) catch return;
    if (if_index == 0) return;

    // load policy enforcer first (priority 0 — runs before everything)
    ebpf.loadPolicyEnforcer(if_index) catch |e| {
        log.info("ebpf policy enforcer not loaded: {}", .{e});
    };

    ebpf.loadDnsInterceptor(if_index) catch |e| {
        // BPF not available — fall back to userspace-only DNS.
        // this is expected on systems without CAP_BPF or old kernels.
        log.info("ebpf DNS interceptor not loaded (falling back to userspace): {}", .{e});
        return; // if DNS interceptor fails, skip LB too
    };

    ebpf.loadLoadBalancer(if_index) catch |e| {
        log.info("ebpf load balancer not loaded: {}", .{e});
    };

    // try loading XDP port mapper for fast port forwarding.
    // falls back to iptables-only if XDP isn't available.
    ebpf.loadPortMapper(if_index) catch |e| {
        log.info("ebpf port mapper not loaded (using iptables): {}", .{e});
    };

    // sync existing network policies into BPF maps
    if (ebpf.getPolicyEnforcer() != null) {
        policy.syncPolicies(std.heap.page_allocator);
    }
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

test "writeNetworkFiles sets resolv.conf to bridge gateway" {
    const alloc = std.testing.allocator;

    // create a temporary directory for the rootfs
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var path_buf: [512]u8 = undefined;
    const rootfs_path = tmp_dir.dir.realpath(".", &path_buf) catch return;

    writeNetworkFiles(rootfs_path, .{ 10, 42, 0, 5 }, "myhost");

    // read the resolv.conf we wrote
    var resolv_path_buf: [600]u8 = undefined;
    const resolv_path = std.fmt.bufPrint(&resolv_path_buf, "{s}/etc/resolv.conf", .{rootfs_path}) catch return;
    const content = std.fs.cwd().readFileAlloc(alloc, resolv_path, 4096) catch return;
    defer alloc.free(content);

    // should point to bridge gateway, not 8.8.8.8
    try std.testing.expect(std.mem.indexOf(u8, content, "10.42.0.1") != null);
}

test "writeNetworkFiles sets etc/hosts with hostname" {
    const alloc = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var path_buf: [512]u8 = undefined;
    const rootfs_path = tmp_dir.dir.realpath(".", &path_buf) catch return;

    writeNetworkFiles(rootfs_path, .{ 10, 42, 0, 7 }, "dbserver");

    var hosts_path_buf: [600]u8 = undefined;
    const hosts_path = std.fmt.bufPrint(&hosts_path_buf, "{s}/etc/hosts", .{rootfs_path}) catch return;
    const content = std.fs.cwd().readFileAlloc(alloc, hosts_path, 4096) catch return;
    defer alloc.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "dbserver") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "10.42.0.7") != null);
}

test "NetworkConfig defaults to single-node mode" {
    const config = NetworkConfig{};
    try std.testing.expect(config.node_id == null);
    try std.testing.expect(config.enabled);
}

test "NetworkConfig with node_id for cluster mode" {
    const config = NetworkConfig{ .node_id = 5 };
    try std.testing.expectEqual(@as(?u8, 5), config.node_id);
    try std.testing.expect(config.enabled);
}

// -- cluster networking tests --

test "ClusterNetworkConfig struct" {
    const config = ClusterNetworkConfig{
        .node_id = 3,
        .private_key = "base64privatekey==",
        .listen_port = 51820,
        .overlay_ip = .{ 10, 40, 0, 3 },
        .peers = &.{},
    };
    try std.testing.expectEqual(@as(u8, 3), config.node_id);
    try std.testing.expectEqual(@as(u16, 51820), config.listen_port);
    try std.testing.expectEqual([4]u8{ 10, 40, 0, 3 }, config.overlay_ip);
    try std.testing.expectEqual(@as(usize, 0), config.peers.len);
}

test "PeerInfo struct" {
    const peer = PeerInfo{
        .public_key = "peerpubkey==",
        .endpoint = "10.0.0.5:51820",
        .overlay_ip = .{ 10, 40, 0, 5 },
        .container_subnet_node = 5,
    };
    try std.testing.expectEqualStrings("peerpubkey==", peer.public_key);
    try std.testing.expectEqualStrings("10.0.0.5:51820", peer.endpoint);
    try std.testing.expectEqual([4]u8{ 10, 40, 0, 5 }, peer.overlay_ip);
    try std.testing.expectEqual(@as(u8, 5), peer.container_subnet_node);
}

test "PeerInfo with empty endpoint" {
    const peer = PeerInfo{
        .public_key = "key==",
        .endpoint = "",
        .overlay_ip = .{ 10, 40, 0, 1 },
        .container_subnet_node = 1,
    };
    try std.testing.expectEqual(@as(usize, 0), peer.endpoint.len);
}

test "wg_interface constant" {
    try std.testing.expectEqualStrings("wg-yoq", wg_interface);
}

test "hostname validation — valid hostnames" {
    try std.testing.expect(isValidHostname("myhost"));
    try std.testing.expect(isValidHostname("web-server"));
    try std.testing.expect(isValidHostname("db.internal"));
    try std.testing.expect(isValidHostname("a")); // single char
}

test "hostname validation — rejects invalid hostnames" {
    try std.testing.expect(!isValidHostname("")); // empty
    try std.testing.expect(!isValidHostname("host\nname")); // newline
    try std.testing.expect(!isValidHostname("host\rname")); // carriage return
    try std.testing.expect(!isValidHostname("host\tname")); // tab
    try std.testing.expect(!isValidHostname("host name")); // space
    try std.testing.expect(!isValidHostname("a" ** 254)); // too long
}

test "hostname validation — rejects control characters" {
    try std.testing.expect(!isValidHostname(&[_]u8{ 'a', 0x00, 'b' })); // null byte
    try std.testing.expect(!isValidHostname(&[_]u8{ 0x01, 'a' })); // SOH
    try std.testing.expect(!isValidHostname(&[_]u8{ 'a', 0x7f })); // DEL
}
