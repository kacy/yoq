const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const common = @import("common.zig");
const builder_mod = @import("message_builder.zig");

const MessageBuilder = builder_mod.MessageBuilder;

pub fn openSocket() common.NetlinkError!posix.fd_t {
    const NETLINK_ROUTE = 0;
    return posix.socket(
        linux.AF.NETLINK,
        posix.SOCK.RAW | posix.SOCK.CLOEXEC,
        NETLINK_ROUTE,
    ) catch common.NetlinkError.SocketFailed;
}

pub fn openGenericSocket() common.NetlinkError!posix.fd_t {
    return posix.socket(
        linux.AF.NETLINK,
        posix.SOCK.RAW | posix.SOCK.CLOEXEC,
        common.NETLINK_GENERIC,
    ) catch common.NetlinkError.SocketFailed;
}

pub fn resolveFamily(fd: posix.fd_t, name: []const u8) common.NetlinkError!u16 {
    var msg_buf: [common.buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&msg_buf);

    const hdr = try mb.putHeaderGenl(common.GENL_ID_CTRL, common.NLM_F.REQUEST, common.CTRL_CMD_GETFAMILY);
    try mb.putAttrStr(hdr, common.CTRL_ATTR_FAMILY_NAME, name);

    const msg = mb.message();
    const sent = posix.send(fd, msg, 0) catch return common.NetlinkError.SendFailed;
    if (sent != msg.len) return common.NetlinkError.SendFailed;

    var recv_buf: [common.buf_size]u8 align(4) = undefined;
    const recv_len = posix.recv(fd, &recv_buf, 0) catch return common.NetlinkError.RecvFailed;

    const min_resp = @sizeOf(linux.nlmsghdr) + @sizeOf(common.GenlMsgHdr);
    if (recv_len < min_resp) return common.NetlinkError.InvalidResponse;

    const resp_hdr: *const linux.nlmsghdr = @ptrCast(@alignCast(&recv_buf));
    if (resp_hdr.type == .ERROR) {
        if (recv_len < @sizeOf(linux.nlmsghdr) + 4) return common.NetlinkError.InvalidResponse;
        const err_code: *const i32 = @ptrCast(@alignCast(&recv_buf[@sizeOf(linux.nlmsghdr)]));
        if (err_code.* != 0) return common.NetlinkError.NotFound;
    }

    var offset: usize = min_resp;
    while (offset + @sizeOf(common.RtAttr) <= recv_len) {
        const rta: *const common.RtAttr = @ptrCast(@alignCast(&recv_buf[offset]));
        if (rta.len < @sizeOf(common.RtAttr)) break;

        if (rta.type == common.CTRL_ATTR_FAMILY_ID and rta.len >= @sizeOf(common.RtAttr) + 2) {
            const id: *const u16 = @ptrCast(@alignCast(&recv_buf[offset + @sizeOf(common.RtAttr)]));
            return id.*;
        }

        offset += common.nlmsgAlign(@as(usize, rta.len));
    }

    return common.NetlinkError.InvalidResponse;
}

pub fn sendAndCheck(fd: posix.fd_t, msg: []const u8) common.NetlinkError!void {
    const sent = posix.send(fd, msg, 0) catch return common.NetlinkError.SendFailed;
    if (sent != msg.len) return common.NetlinkError.SendFailed;

    var recv_buf: [common.buf_size]u8 align(4) = undefined;
    const recv_len = posix.recv(fd, &recv_buf, 0) catch return common.NetlinkError.RecvFailed;
    if (recv_len < @sizeOf(linux.nlmsghdr)) return common.NetlinkError.InvalidResponse;

    const resp_hdr: *const linux.nlmsghdr = @ptrCast(@alignCast(&recv_buf));
    if (resp_hdr.type == .ERROR) {
        if (recv_len < @sizeOf(linux.nlmsghdr) + 4) return common.NetlinkError.InvalidResponse;
        const err_code: *const i32 = @ptrCast(@alignCast(&recv_buf[@sizeOf(linux.nlmsghdr)]));
        if (err_code.* == 0) return;

        const errno_value = -err_code.*;
        return switch (errno_value) {
            1 => common.NetlinkError.PermissionDenied,
            2 => common.NetlinkError.NotFound,
            12 => common.NetlinkError.OutOfMemory,
            13 => common.NetlinkError.PermissionDenied,
            else => common.NetlinkError.KernelError,
        };
    }
}

pub fn sendOnly(fd: posix.fd_t, msg: []const u8) common.NetlinkError!void {
    const sent = posix.send(fd, msg, 0) catch return common.NetlinkError.SendFailed;
    if (sent != msg.len) return common.NetlinkError.SendFailed;
}
