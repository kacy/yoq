const posix = @import("std").posix;
const common = @import("common.zig");
const builder_mod = @import("message_builder.zig");
const socket_ops = @import("socket_ops.zig");

const MessageBuilder = builder_mod.MessageBuilder;

pub fn addAddress(fd: posix.fd_t, if_index: u32, ip: *const [4]u8, prefix_len: u8) common.NetlinkError!void {
    var buf_storage: [common.buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf_storage);

    const hdr = try mb.putHeader(
        .RTM_NEWADDR,
        common.NLM_F.REQUEST | common.NLM_F.ACK | common.NLM_F.CREATE | common.NLM_F.EXCL,
        common.IfAddrMsg,
    );

    const addr_msg = mb.getPayload(hdr, common.IfAddrMsg);
    addr_msg.family = common.AF.INET;
    addr_msg.prefixlen = prefix_len;
    addr_msg.scope = common.RT_SCOPE.UNIVERSE;
    addr_msg.index = if_index;

    try mb.putAttr(hdr, common.IFA.LOCAL, ip);
    try mb.putAttr(hdr, common.IFA.ADDRESS, ip);

    try socket_ops.sendAndCheck(fd, mb.message());
}

pub fn addRoute(fd: posix.fd_t, dest: ?*const [4]u8, dest_len: u8, gw: *const [4]u8) common.NetlinkError!void {
    var buf_storage: [common.buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf_storage);

    const hdr = try mb.putHeader(
        .RTM_NEWROUTE,
        common.NLM_F.REQUEST | common.NLM_F.ACK | common.NLM_F.CREATE,
        common.RtMsg,
    );

    const rt = mb.getPayload(hdr, common.RtMsg);
    rt.family = common.AF.INET;
    rt.dst_len = dest_len;
    rt.table = common.RT_TABLE.MAIN;
    rt.protocol = common.RTPROT.BOOT;
    rt.scope = common.RT_SCOPE.UNIVERSE;
    rt.type = common.RTN.UNICAST;

    if (dest) |d| try mb.putAttr(hdr, common.RTA.DST, d);
    try mb.putAttr(hdr, common.RTA.GATEWAY, gw);

    try socket_ops.sendAndCheck(fd, mb.message());
}

pub fn removeRoute(fd: posix.fd_t, dest: *const [4]u8, dest_len: u8) common.NetlinkError!void {
    var buf_storage: [common.buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf_storage);

    const hdr = try mb.putHeader(
        .RTM_DELROUTE,
        common.NLM_F.REQUEST | common.NLM_F.ACK,
        common.RtMsg,
    );

    const rt = mb.getPayload(hdr, common.RtMsg);
    rt.family = common.AF.INET;
    rt.dst_len = dest_len;
    rt.table = common.RT_TABLE.MAIN;
    rt.protocol = common.RTPROT.BOOT;
    rt.scope = common.RT_SCOPE.UNIVERSE;
    rt.type = common.RTN.UNICAST;

    try mb.putAttr(hdr, common.RTA.DST, dest);

    try socket_ops.sendAndCheck(fd, mb.message());
}
