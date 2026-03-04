// bridge — bridge and veth pair management
//
// creates and manages the yoq0 bridge for container networking.
// each container gets a veth pair: one end attached to the bridge
// (named veth_<container-id-prefix>), the other end moved into the
// container's network namespace as eth0.
//
// uses netlink.zig for all kernel interactions. for operations
// inside the container's namespace (assigning IP, setting routes),
// we setns() into /proc/<pid>/ns/net, do the work, then setns() back.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const nl = @import("netlink.zig");
const log = @import("../lib/log.zig");

pub const BridgeError = error{
    CreateFailed,
    DeleteFailed,
    VethCreateFailed,
    VethDeleteFailed,
    InterfaceNotFound,
    AddressFailed,
    RouteFailed,
    LinkSetFailed,
    NamespaceFailed,
};

/// default bridge name for yoq containers
pub const default_bridge = "yoq0";

/// default bridge gateway address (10.42.0.1)
pub const gateway_ip = [4]u8{ 10, 42, 0, 1 };

/// default subnet prefix length
pub const prefix_len: u8 = 16;

// -- bridge operations --

/// create a bridge interface if it doesn't already exist.
/// assigns the gateway IP and brings it up.
pub fn ensureBridge(name: []const u8) BridgeError!void {
    const fd = nl.openSocket() catch return BridgeError.CreateFailed;
    defer posix.close(fd);

    // check if bridge already exists
    const existing = nl.getIfIndex(fd, name) catch 0;
    if (existing != 0) return; // already exists

    // create bridge
    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = mb.putHeader(
        .RTM_NEWLINK,
        nl.NLM_F.REQUEST | nl.NLM_F.ACK | nl.NLM_F.CREATE | nl.NLM_F.EXCL,
        linux.ifinfomsg,
    ) catch return BridgeError.CreateFailed;

    mb.putAttrStr(hdr, nl.IFLA.IFNAME, name) catch return BridgeError.CreateFailed;

    // set IFLA_LINKINFO with kind = "bridge"
    const linkinfo = mb.startNested(hdr, nl.IFLA.LINKINFO) catch return BridgeError.CreateFailed;
    mb.putAttrStr(hdr, nl.IFLA.INFO_KIND, "bridge") catch return BridgeError.CreateFailed;
    mb.endNested(linkinfo);

    nl.sendAndCheck(fd, mb.message()) catch return BridgeError.CreateFailed;

    // assign IP address to bridge
    const bridge_idx = nl.getIfIndex(fd, name) catch return BridgeError.CreateFailed;
    if (bridge_idx == 0) return BridgeError.CreateFailed;

    addAddress(fd, bridge_idx, &gateway_ip, prefix_len) catch return BridgeError.AddressFailed;

    // bring bridge up
    nl.setLinkUp(fd, bridge_idx) catch return BridgeError.LinkSetFailed;
}

/// delete a bridge interface
pub fn deleteBridge(name: []const u8) BridgeError!void {
    const fd = nl.openSocket() catch return BridgeError.DeleteFailed;
    defer posix.close(fd);

    const idx = nl.getIfIndex(fd, name) catch return;
    if (idx == 0) return; // doesn't exist

    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = mb.putHeader(
        .RTM_DELLINK,
        nl.NLM_F.REQUEST | nl.NLM_F.ACK,
        linux.ifinfomsg,
    ) catch return BridgeError.DeleteFailed;

    const info = mb.getPayload(hdr, linux.ifinfomsg);
    info.index = @bitCast(idx);

    nl.sendAndCheck(fd, mb.message()) catch return BridgeError.DeleteFailed;
}

// -- veth pair operations --

/// create a veth pair and attach the host end to the bridge.
/// host_name: name of the host-side veth (e.g. "veth_abc123")
/// peer_name: name of the container-side veth (e.g. "eth0")
/// bridge_name: bridge to attach host end to (e.g. "yoq0")
pub fn createVethPair(host_name: []const u8, peer_name: []const u8, bridge_name: []const u8) BridgeError!void {
    const fd = nl.openSocket() catch return BridgeError.VethCreateFailed;
    defer posix.close(fd);

    // look up bridge index for attaching host end
    const bridge_idx = nl.getIfIndex(fd, bridge_name) catch return BridgeError.InterfaceNotFound;
    if (bridge_idx == 0) return BridgeError.InterfaceNotFound;

    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = mb.putHeader(
        .RTM_NEWLINK,
        nl.NLM_F.REQUEST | nl.NLM_F.ACK | nl.NLM_F.CREATE | nl.NLM_F.EXCL,
        linux.ifinfomsg,
    ) catch return BridgeError.VethCreateFailed;

    // host-side interface name
    mb.putAttrStr(hdr, nl.IFLA.IFNAME, host_name) catch return BridgeError.VethCreateFailed;

    // attach to bridge
    mb.putAttrU32(hdr, nl.IFLA.MASTER, bridge_idx) catch return BridgeError.VethCreateFailed;

    // IFLA_LINKINFO: type = "veth", data = { VETH_INFO_PEER: { ifinfomsg + IFLA_IFNAME } }
    const linkinfo = mb.startNested(hdr, nl.IFLA.LINKINFO) catch return BridgeError.VethCreateFailed;
    mb.putAttrStr(hdr, nl.IFLA.INFO_KIND, "veth") catch return BridgeError.VethCreateFailed;

    const data = mb.startNested(hdr, nl.IFLA.INFO_DATA) catch return BridgeError.VethCreateFailed;

    // peer info: starts with a nested rtattr containing ifinfomsg + attrs
    const peer = mb.startNested(hdr, nl.VETH.INFO_PEER) catch return BridgeError.VethCreateFailed;

    // peer needs an ifinfomsg struct before its attributes.
    // we write it manually since it's inside a nested attribute.
    const ifinfo_size = @sizeOf(linux.ifinfomsg);
    const aligned_size = nl.nlmsgAlignPub(ifinfo_size);
    if (mb.pos + aligned_size > nl.buf_size) return BridgeError.VethCreateFailed;
    @memset(mb.buf[mb.pos..][0..aligned_size], 0);
    mb.pos += aligned_size;
    hdr.len = @intCast(@as(usize, hdr.len) + aligned_size);

    mb.putAttrStr(hdr, nl.IFLA.IFNAME, peer_name) catch return BridgeError.VethCreateFailed;

    mb.endNested(peer);
    mb.endNested(data);
    mb.endNested(linkinfo);

    nl.sendAndCheck(fd, mb.message()) catch return BridgeError.VethCreateFailed;

    // bring host end up
    const host_idx = nl.getIfIndex(fd, host_name) catch return BridgeError.VethCreateFailed;
    if (host_idx == 0) return BridgeError.VethCreateFailed;
    nl.setLinkUp(fd, host_idx) catch return BridgeError.LinkSetFailed;
}

/// move an interface into a container's network namespace
pub fn moveToNamespace(if_name: []const u8, pid: posix.pid_t) BridgeError!void {
    const fd = nl.openSocket() catch return BridgeError.NamespaceFailed;
    defer posix.close(fd);

    const idx = nl.getIfIndex(fd, if_name) catch return BridgeError.InterfaceNotFound;
    if (idx == 0) return BridgeError.InterfaceNotFound;

    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = mb.putHeader(
        .RTM_NEWLINK,
        nl.NLM_F.REQUEST | nl.NLM_F.ACK,
        linux.ifinfomsg,
    ) catch return BridgeError.NamespaceFailed;

    const info = mb.getPayload(hdr, linux.ifinfomsg);
    info.index = @bitCast(idx);

    // IFLA_NET_NS_PID moves the interface to the target's net namespace
    mb.putAttrU32(hdr, nl.IFLA.NET_NS_PID, @intCast(pid)) catch return BridgeError.NamespaceFailed;

    nl.sendAndCheck(fd, mb.message()) catch return BridgeError.NamespaceFailed;
}

/// delete a veth pair by removing the host-side interface.
/// the kernel automatically removes the peer when one end is deleted.
pub fn deleteVeth(host_name: []const u8) BridgeError!void {
    const fd = nl.openSocket() catch return BridgeError.VethDeleteFailed;
    defer posix.close(fd);

    const idx = nl.getIfIndex(fd, host_name) catch return;
    if (idx == 0) return; // already gone

    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = mb.putHeader(
        .RTM_DELLINK,
        nl.NLM_F.REQUEST | nl.NLM_F.ACK,
        linux.ifinfomsg,
    ) catch return BridgeError.VethDeleteFailed;

    const info = mb.getPayload(hdr, linux.ifinfomsg);
    info.index = @bitCast(idx);

    nl.sendAndCheck(fd, mb.message()) catch return BridgeError.VethDeleteFailed;
}

// -- container namespace operations --
//
// these functions operate inside the container's network namespace.
// the caller should use withContainerNetns() to wrap them, or call
// them after setns() into the container's netns.

/// configure networking inside a container's namespace.
/// enters the namespace, assigns IP, sets up lo, adds default route.
pub fn configureContainer(pid: posix.pid_t, ip: [4]u8, gw: [4]u8) BridgeError!void {
    // open netns file before switching
    var ns_path_buf: [64]u8 = undefined;
    const ns_path = std.fmt.bufPrint(&ns_path_buf, "/proc/{d}/ns/net", .{pid}) catch
        return BridgeError.NamespaceFailed;

    // save current namespace
    const self_ns = std.fs.cwd().openFile("/proc/self/ns/net", .{}) catch
        return BridgeError.NamespaceFailed;
    defer self_ns.close();

    // open target namespace
    const target_ns = std.fs.cwd().openFile(ns_path, .{}) catch
        return BridgeError.NamespaceFailed;
    defer target_ns.close();

    // enter container namespace
    setns(target_ns.handle) catch return BridgeError.NamespaceFailed;

    // do all configuration, then restore namespace
    defer setns(self_ns.handle) catch {
        log.warn("failed to restore host network namespace", .{});
    };

    const fd = nl.openSocket() catch return BridgeError.CreateFailed;
    defer posix.close(fd);

    // bring up loopback
    bringUpLoopback(fd) catch |e| {
        log.warn("failed to bring up loopback: {}", .{e});
    };

    // bring up eth0 and assign IP
    const eth0_idx = nl.getIfIndex(fd, "eth0") catch return BridgeError.InterfaceNotFound;
    if (eth0_idx == 0) return BridgeError.InterfaceNotFound;

    addAddress(fd, eth0_idx, &ip, prefix_len) catch return BridgeError.AddressFailed;
    nl.setLinkUp(fd, eth0_idx) catch return BridgeError.LinkSetFailed;

    // add default route via gateway
    addDefaultRoute(fd, &gw) catch return BridgeError.RouteFailed;
}

/// enter a network namespace via setns(2)
fn setns(fd: posix.fd_t) !void {
    const CLONE_NEWNET: c_int = 0x40000000;
    const rc = linux.syscall2(.setns, @intCast(@as(u64, @bitCast(@as(i64, fd)))), @intCast(@as(u64, @bitCast(@as(i64, CLONE_NEWNET)))));
    if (nl.isError(rc)) return error.SetNsFailed;
}

/// bring up the loopback interface inside a namespace
fn bringUpLoopback(fd: posix.fd_t) !void {
    const lo_idx = nl.getIfIndex(fd, "lo") catch return;
    if (lo_idx == 0) return;
    nl.setLinkUp(fd, lo_idx) catch |e| {
        log.warn("failed to set loopback up: {}", .{e});
    };
}

// -- shared netlink helpers --

/// add an IPv4 address to an interface
fn addAddress(fd: posix.fd_t, if_index: u32, ip: *const [4]u8, plen: u8) BridgeError!void {
    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = mb.putHeader(
        .RTM_NEWADDR,
        nl.NLM_F.REQUEST | nl.NLM_F.ACK | nl.NLM_F.CREATE | nl.NLM_F.EXCL,
        nl.IfAddrMsg,
    ) catch return BridgeError.AddressFailed;

    const addr_msg = mb.getPayload(hdr, nl.IfAddrMsg);
    addr_msg.family = nl.AF.INET;
    addr_msg.prefixlen = plen;
    addr_msg.scope = nl.RT_SCOPE.UNIVERSE;
    addr_msg.index = if_index;

    mb.putAttr(hdr, nl.IFA.LOCAL, ip) catch return BridgeError.AddressFailed;
    mb.putAttr(hdr, nl.IFA.ADDRESS, ip) catch return BridgeError.AddressFailed;

    nl.sendAndCheck(fd, mb.message()) catch return BridgeError.AddressFailed;
}

/// add a default route via a gateway
fn addDefaultRoute(fd: posix.fd_t, gw: *const [4]u8) BridgeError!void {
    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = mb.putHeader(
        .RTM_NEWROUTE,
        nl.NLM_F.REQUEST | nl.NLM_F.ACK | nl.NLM_F.CREATE,
        nl.RtMsg,
    ) catch return BridgeError.RouteFailed;

    const rt = mb.getPayload(hdr, nl.RtMsg);
    rt.family = nl.AF.INET;
    rt.dst_len = 0; // default route (0.0.0.0/0)
    rt.table = nl.RT_TABLE.MAIN;
    rt.protocol = nl.RTPROT.BOOT;
    rt.scope = nl.RT_SCOPE.UNIVERSE;
    rt.type = nl.RTN.UNICAST;

    mb.putAttr(hdr, nl.RTA.GATEWAY, gw) catch return BridgeError.RouteFailed;

    nl.sendAndCheck(fd, mb.message()) catch return BridgeError.RouteFailed;
}

// -- naming helpers --

/// generate the host-side veth name from a container id.
/// format: "veth_" + first 10 chars of container id.
/// linux interface names are limited to 15 chars (IFNAMSIZ - 1).
/// "veth_" is 5 chars, leaving room for 10 ID chars. using 10 instead
/// of 6 reduces collision probability from ~1/16M to ~1/1T.
pub fn vethName(container_id: []const u8, buf: *[32]u8) []const u8 {
    const id_chars = @min(container_id.len, 10);
    const name = std.fmt.bufPrint(buf, "veth_{s}", .{container_id[0..id_chars]}) catch "veth_err";
    return name;
}

// -- tests --

test "veth name generation" {
    var buf: [32]u8 = undefined;
    const name = vethName("abc123def456", &buf);
    try std.testing.expectEqualStrings("veth_abc123def4", name);
}

test "veth name short id" {
    var buf: [32]u8 = undefined;
    const name = vethName("ab", &buf);
    try std.testing.expectEqualStrings("veth_ab", name);
}

test "gateway ip is correct" {
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 1 }, gateway_ip);
}

test "prefix length" {
    try std.testing.expectEqual(@as(u8, 16), prefix_len);
}

test "veth name with empty container id" {
    var buf: [32]u8 = undefined;
    const name = vethName("", &buf);
    try std.testing.expectEqualStrings("veth_", name);
}

test "veth name with 3-char id" {
    var buf: [32]u8 = undefined;
    const name = vethName("xyz", &buf);
    try std.testing.expectEqualStrings("veth_xyz", name);
}
