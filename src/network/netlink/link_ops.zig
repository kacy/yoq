const std = @import("std");
const linux_platform = @import("linux_platform");
const linux = std.os.linux;
const posix = std.posix;
const common = @import("common.zig");
const builder_mod = @import("message_builder.zig");
const socket_ops = @import("socket_ops.zig");

const MessageBuilder = builder_mod.MessageBuilder;

pub fn getIfIndex(fd: posix.fd_t, name: []const u8) common.NetlinkError!u32 {
    var buf: [common.buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);

    const hdr = try mb.putHeader(.RTM_GETLINK, common.NLM_F.REQUEST, linux.ifinfomsg);
    const info = mb.getPayload(hdr, linux.ifinfomsg);
    info.family = 0;
    try mb.putAttrStr(hdr, common.IFLA.IFNAME, name);

    socket_ops.sendOnly(fd, mb.message()) catch return 0;

    var recv_buf: [common.buf_size]u8 align(4) = undefined;
    const recv_len = linux_platform.posix.recv(fd, &recv_buf, 0) catch return 0;
    if (recv_len < @sizeOf(linux.nlmsghdr)) return 0;

    const resp_hdr: *const linux.nlmsghdr = @ptrCast(@alignCast(&recv_buf));
    if (resp_hdr.type == .ERROR) return 0;
    if (resp_hdr.type != .RTM_NEWLINK) return 0;
    if (recv_len < @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg)) return 0;

    const resp_info: *const linux.ifinfomsg = @ptrCast(@alignCast(&recv_buf[@sizeOf(linux.nlmsghdr)]));
    return @bitCast(resp_info.index);
}

pub fn setLinkUp(fd: posix.fd_t, if_index: u32) common.NetlinkError!void {
    var buf: [common.buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);

    const hdr = try mb.putHeader(.RTM_NEWLINK, common.NLM_F.REQUEST | common.NLM_F.ACK, linux.ifinfomsg);
    const info = mb.getPayload(hdr, linux.ifinfomsg);
    info.family = 0;
    info.index = @bitCast(if_index);
    info.flags = common.IFF.UP;
    info.change = common.IFF.UP;

    try socket_ops.sendAndCheck(fd, mb.message());
}

pub fn deleteLink(fd: posix.fd_t, name: []const u8) common.NetlinkError!void {
    var buf_storage: [common.buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf_storage);

    const hdr = try mb.putHeader(.RTM_DELLINK, common.NLM_F.REQUEST | common.NLM_F.ACK, linux.ifinfomsg);
    try mb.putAttrStr(hdr, common.IFLA.IFNAME, name);
    try socket_ops.sendAndCheck(fd, mb.message());
}
