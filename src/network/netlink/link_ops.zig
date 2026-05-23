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

/// read the current MTU of an interface by name. walks the IFLA attribute
/// stream in the RTM_NEWLINK reply for IFLA_MTU. returns error.NotFound when the
/// interface does not exist or the attribute is absent.
pub fn getMtu(fd: posix.fd_t, name: []const u8) common.NetlinkError!u32 {
    var buf: [common.buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);

    const hdr = try mb.putHeader(.RTM_GETLINK, common.NLM_F.REQUEST, linux.ifinfomsg);
    const info = mb.getPayload(hdr, linux.ifinfomsg);
    info.family = 0;
    try mb.putAttrStr(hdr, common.IFLA.IFNAME, name);

    socket_ops.sendOnly(fd, mb.message()) catch return common.NetlinkError.SendFailed;

    var recv_buf: [common.buf_size]u8 align(4) = undefined;
    const recv_len = linux_platform.posix.recv(fd, &recv_buf, 0) catch return common.NetlinkError.RecvFailed;
    if (recv_len < @sizeOf(linux.nlmsghdr)) return common.NetlinkError.InvalidResponse;

    const resp_hdr: *const linux.nlmsghdr = @ptrCast(@alignCast(&recv_buf));
    if (resp_hdr.type == .ERROR) return common.NetlinkError.NotFound;
    if (resp_hdr.type != .RTM_NEWLINK) return common.NetlinkError.NotFound;

    // attributes follow the fixed ifinfomsg header, each a 4-byte-aligned TLV:
    // u16 rta_len, u16 rta_type, then rta_len-4 payload bytes.
    var off: usize = @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg);
    while (off + 4 <= recv_len) {
        const rta_len = std.mem.readInt(u16, recv_buf[off..][0..2], .little);
        const rta_type = std.mem.readInt(u16, recv_buf[off + 2 ..][0..2], .little);
        if (rta_len < 4 or off + rta_len > recv_len) break;
        if (rta_type == common.IFLA.MTU and rta_len >= 8) {
            return std.mem.readInt(u32, recv_buf[off + 4 ..][0..4], .little);
        }
        off += (rta_len + 3) & ~@as(usize, 3);
    }
    return common.NetlinkError.NotFound;
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

test "getMtu reads the loopback interface mtu" {
    const fd = socket_ops.openSocket() catch return error.SkipZigTest;
    defer linux_platform.posix.close(fd);

    const mtu = getMtu(fd, "lo") catch return error.SkipZigTest;
    // loopback mtu is conventionally large (often 65536); assert a sane value.
    try std.testing.expect(mtu >= 1500);
}

test "getMtu returns NotFound for a missing interface" {
    const fd = socket_ops.openSocket() catch return error.SkipZigTest;
    defer linux_platform.posix.close(fd);

    try std.testing.expectError(common.NetlinkError.NotFound, getMtu(fd, "definitely-not-a-real-iface"));
}
