// netlink — low-level netlink socket abstraction
//
// this file keeps the stable public surface and tests while the
// implementation lives in smaller modules under `network/netlink/`.

const std = @import("std");
const linux = std.os.linux;

const common = @import("netlink/common.zig");
const builder_mod = @import("netlink/message_builder.zig");
const socket_ops = @import("netlink/socket_ops.zig");
const link_ops = @import("netlink/link_ops.zig");
const route_ops = @import("netlink/route_ops.zig");

pub const NetlinkError = common.NetlinkError;

pub const NETLINK_GENERIC = common.NETLINK_GENERIC;
pub const GENL_ID_CTRL = common.GENL_ID_CTRL;
pub const GenlMsgHdr = common.GenlMsgHdr;
pub const CTRL_CMD_GETFAMILY = common.CTRL_CMD_GETFAMILY;
pub const CTRL_ATTR_FAMILY_NAME = common.CTRL_ATTR_FAMILY_NAME;
pub const CTRL_ATTR_FAMILY_ID = common.CTRL_ATTR_FAMILY_ID;
pub const WG_CMD = common.WG_CMD;
pub const WGDEVICE_A = common.WGDEVICE_A;
pub const WGPEER_A = common.WGPEER_A;
pub const WGALLOWEDIP_A = common.WGALLOWEDIP_A;
pub const WGPEER_F_REMOVE_ME = common.WGPEER_F_REMOVE_ME;
pub const RtAttr = common.RtAttr;
pub const IfAddrMsg = common.IfAddrMsg;
pub const RtMsg = common.RtMsg;
pub const AF = common.AF;
pub const RTM = common.RTM;
pub const NLM_F = common.NLM_F;
pub const IFLA = common.IFLA;
pub const IFLA_XDP = common.IFLA_XDP;
pub const XDP_FLAGS = common.XDP_FLAGS;
pub const VETH = common.VETH;
pub const IFA = common.IFA;
pub const RTA = common.RTA;
pub const RTPROT = common.RTPROT;
pub const RT_SCOPE = common.RT_SCOPE;
pub const RTN = common.RTN;
pub const RT_TABLE = common.RT_TABLE;
pub const TCA = common.TCA;
pub const TC_H = common.TC_H;
pub const TCA_BPF = common.TCA_BPF;
pub const TcMsg = common.TcMsg;
pub const IFF = common.IFF;
pub const buf_size = common.buf_size;

pub const MessageBuilder = builder_mod.MessageBuilder;

pub const openSocket = socket_ops.openSocket;
pub const openGenericSocket = socket_ops.openGenericSocket;
pub const resolveFamily = socket_ops.resolveFamily;
pub const sendAndCheck = socket_ops.sendAndCheck;
pub const sendOnly = socket_ops.sendOnly;

pub const getIfIndex = link_ops.getIfIndex;
pub const setLinkUp = link_ops.setLinkUp;
pub const deleteLink = link_ops.deleteLink;

pub const addAddress = route_ops.addAddress;
pub const hasAddress = route_ops.hasAddress;
pub const addRoute = route_ops.addRoute;
pub const removeRoute = route_ops.removeRoute;

pub const nlmsgAlign = common.nlmsgAlign;
pub const isError = common.isError;

test "nlmsg alignment" {
    try std.testing.expectEqual(@as(usize, 0), nlmsgAlign(0));
    try std.testing.expectEqual(@as(usize, 4), nlmsgAlign(1));
    try std.testing.expectEqual(@as(usize, 4), nlmsgAlign(4));
    try std.testing.expectEqual(@as(usize, 8), nlmsgAlign(5));
}

test "message builder header size" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);
    const hdr = try mb.putHeader(.RTM_NEWLINK, NLM_F.REQUEST, linux.ifinfomsg);
    try std.testing.expectEqual(@as(u32, @intCast(nlmsgAlign(@sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg)))), hdr.len);
}

test "message builder attributes" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);
    const hdr = try mb.putHeader(.RTM_NEWLINK, NLM_F.REQUEST, linux.ifinfomsg);
    try mb.putAttrU32(hdr, IFLA.MTU, 1500);
    try std.testing.expect(hdr.len > @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg));
}

test "message builder string attribute" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);
    const hdr = try mb.putHeader(.RTM_NEWLINK, NLM_F.REQUEST, linux.ifinfomsg);
    try mb.putAttrStr(hdr, IFLA.IFNAME, "yoq0");
    try std.testing.expect(hdr.len > @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg));
}

test "ifaddrmsg struct layout" {
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(IfAddrMsg));
}

test "rtmsg struct layout" {
    try std.testing.expectEqual(@as(usize, 12), @sizeOf(RtMsg));
}

test "rtattr struct layout" {
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(RtAttr));
}

test "nested attributes" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);
    const hdr = try mb.putHeader(.RTM_NEWLINK, NLM_F.REQUEST, linux.ifinfomsg);
    const nested = try mb.startNested(hdr, IFLA.LINKINFO);
    try mb.putAttrStr(hdr, IFLA.INFO_KIND, "bridge");
    mb.endNested(nested);
    try std.testing.expect(hdr.len > @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg));
}

test "tcmsg struct layout" {
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(TcMsg));
}

test "tc message builder" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);
    const hdr = try mb.putHeader(@enumFromInt(44), NLM_F.REQUEST | NLM_F.ACK, TcMsg);
    const msg = mb.getPayload(hdr, TcMsg);
    msg.ifindex = 3;
    msg.parent = TC_H.CLSACT;
    try mb.putAttrStr(hdr, TCA.KIND, "clsact");
    try std.testing.expect(hdr.len > @sizeOf(linux.nlmsghdr) + @sizeOf(TcMsg));
}

test "genl header size" {
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(GenlMsgHdr));
}

test "putHeaderGenl builds correct message" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);
    const hdr = try mb.putHeaderGenl(42, NLM_F.REQUEST, CTRL_CMD_GETFAMILY);
    const genl = mb.getPayload(hdr, GenlMsgHdr);
    try std.testing.expectEqual(@as(u8, CTRL_CMD_GETFAMILY), genl.cmd);
    try std.testing.expectEqual(@as(u16, 42), @intFromEnum(hdr.type));
}

test "putAttrU16 and putAttrU8" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);
    const hdr = try mb.putHeader(.RTM_NEWLINK, NLM_F.REQUEST, linux.ifinfomsg);
    try mb.putAttrU16(hdr, 100, 1234);
    try mb.putAttrU8(hdr, 101, 12);
    try std.testing.expect(hdr.len > @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg));
}
