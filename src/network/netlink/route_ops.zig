const std = @import("std");
const posix = std.posix;
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

pub fn hasAddress(fd: posix.fd_t, if_index: u32, ip: *const [4]u8, prefix_len: u8) common.NetlinkError!bool {
    var buf_storage: [common.buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf_storage);

    const hdr = try mb.putHeader(
        .RTM_GETADDR,
        common.NLM_F.REQUEST | common.NLM_F.DUMP,
        common.IfAddrMsg,
    );

    const addr_msg = mb.getPayload(hdr, common.IfAddrMsg);
    addr_msg.family = common.AF.INET;
    addr_msg.prefixlen = 0;
    addr_msg.flags = 0;
    addr_msg.scope = 0;
    addr_msg.index = 0;

    try socket_ops.sendOnly(fd, mb.message());

    var recv_buf: [common.buf_size]u8 align(4) = undefined;
    while (true) {
        const recv_len = posix.recv(fd, &recv_buf, 0) catch return common.NetlinkError.RecvFailed;
        if (recv_len < @sizeOf(std.os.linux.nlmsghdr)) return common.NetlinkError.InvalidResponse;

        var offset: usize = 0;
        while (offset + @sizeOf(std.os.linux.nlmsghdr) <= recv_len) {
            const msg_hdr: *const std.os.linux.nlmsghdr = @ptrCast(@alignCast(&recv_buf[offset]));
            const msg_len: usize = msg_hdr.len;
            if (msg_len < @sizeOf(std.os.linux.nlmsghdr) or offset + msg_len > recv_len) {
                return common.NetlinkError.InvalidResponse;
            }

            if (msg_hdr.type == .DONE) return false;
            if (msg_hdr.type == .ERROR) {
                if (msg_len < @sizeOf(std.os.linux.nlmsghdr) + 4) return common.NetlinkError.InvalidResponse;
                const err_code: *const i32 = @ptrCast(@alignCast(&recv_buf[offset + @sizeOf(std.os.linux.nlmsghdr)]));
                if (err_code.* == 0) return false;
                return common.NetlinkError.KernelError;
            }

            if (msg_hdr.type == .RTM_NEWADDR) {
                if (msg_len < @sizeOf(std.os.linux.nlmsghdr) + @sizeOf(common.IfAddrMsg)) {
                    return common.NetlinkError.InvalidResponse;
                }

                const msg_offset = offset + @sizeOf(std.os.linux.nlmsghdr);
                const msg: *const common.IfAddrMsg = @ptrCast(@alignCast(&recv_buf[msg_offset]));
                if (msg.family == common.AF.INET and msg.index == if_index and msg.prefixlen == prefix_len) {
                    var attr_offset = msg_offset + @sizeOf(common.IfAddrMsg);
                    const msg_end = offset + msg_len;
                    while (attr_offset + @sizeOf(common.RtAttr) <= msg_end) {
                        const attr: *const common.RtAttr = @ptrCast(@alignCast(&recv_buf[attr_offset]));
                        const attr_len: usize = attr.len;
                        if (attr_len < @sizeOf(common.RtAttr) or attr_offset + attr_len > msg_end) break;

                        if ((attr.type == common.IFA.LOCAL or attr.type == common.IFA.ADDRESS) and
                            attr_len >= @sizeOf(common.RtAttr) + @sizeOf([4]u8))
                        {
                            const attr_ip: *const [4]u8 = @ptrCast(@alignCast(&recv_buf[attr_offset + @sizeOf(common.RtAttr)]));
                            if (std.mem.eql(u8, attr_ip, ip)) return true;
                        }

                        attr_offset += common.nlmsgAlign(attr_len);
                    }
                }
            }

            offset += common.nlmsgAlign(msg_len);
        }
    }
}

pub fn getFirstIpv4Address(fd: posix.fd_t, if_index: u32) common.NetlinkError!?[4]u8 {
    var buf_storage: [common.buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf_storage);

    const hdr = try mb.putHeader(
        .RTM_GETADDR,
        common.NLM_F.REQUEST | common.NLM_F.DUMP,
        common.IfAddrMsg,
    );

    const addr_msg = mb.getPayload(hdr, common.IfAddrMsg);
    addr_msg.family = common.AF.INET;
    addr_msg.prefixlen = 0;
    addr_msg.flags = 0;
    addr_msg.scope = 0;
    addr_msg.index = 0;

    try socket_ops.sendOnly(fd, mb.message());

    var recv_buf: [common.buf_size]u8 align(4) = undefined;
    while (true) {
        const recv_len = posix.recv(fd, &recv_buf, 0) catch return common.NetlinkError.RecvFailed;
        const parse_result = try parseFirstIpv4AddressMessage(recv_buf[0..recv_len], if_index);
        switch (parse_result) {
            .pending => continue,
            .done => |address| return address,
        }
    }
}

const ParseResult = union(enum) {
    pending,
    done: ?[4]u8,
};

fn parseFirstIpv4AddressMessage(buf: []const u8, if_index: u32) common.NetlinkError!ParseResult {
    if (buf.len < @sizeOf(std.os.linux.nlmsghdr)) return common.NetlinkError.InvalidResponse;

    var offset: usize = 0;
    while (offset + @sizeOf(std.os.linux.nlmsghdr) <= buf.len) {
        const msg_hdr: *const std.os.linux.nlmsghdr = @ptrCast(@alignCast(&buf[offset]));
        const msg_len: usize = msg_hdr.len;
        if (msg_len < @sizeOf(std.os.linux.nlmsghdr) or offset + msg_len > buf.len) {
            return common.NetlinkError.InvalidResponse;
        }

        if (msg_hdr.type == .DONE) return .{ .done = null };
        if (msg_hdr.type == .ERROR) {
            if (msg_len < @sizeOf(std.os.linux.nlmsghdr) + 4) return common.NetlinkError.InvalidResponse;
            const err_code: *const i32 = @ptrCast(@alignCast(&buf[offset + @sizeOf(std.os.linux.nlmsghdr)]));
            if (err_code.* == 0) return .{ .done = null };
            return common.NetlinkError.KernelError;
        }

        if (msg_hdr.type == .RTM_NEWADDR) {
            if (msg_len < @sizeOf(std.os.linux.nlmsghdr) + @sizeOf(common.IfAddrMsg)) {
                return common.NetlinkError.InvalidResponse;
            }

            const msg_offset = offset + @sizeOf(std.os.linux.nlmsghdr);
            const msg: *const common.IfAddrMsg = @ptrCast(@alignCast(&buf[msg_offset]));
            if (msg.family == common.AF.INET and msg.index == if_index) {
                var attr_offset = msg_offset + @sizeOf(common.IfAddrMsg);
                const msg_end = offset + msg_len;
                while (attr_offset + @sizeOf(common.RtAttr) <= msg_end) {
                    const attr: *const common.RtAttr = @ptrCast(@alignCast(&buf[attr_offset]));
                    const attr_len: usize = attr.len;
                    if (attr_len < @sizeOf(common.RtAttr) or attr_offset + attr_len > msg_end) break;

                    if ((attr.type == common.IFA.LOCAL or attr.type == common.IFA.ADDRESS) and
                        attr_len >= @sizeOf(common.RtAttr) + @sizeOf([4]u8))
                    {
                        const attr_ip: *const [4]u8 = @ptrCast(@alignCast(&buf[attr_offset + @sizeOf(common.RtAttr)]));
                        return .{ .done = attr_ip.* };
                    }

                    attr_offset += common.nlmsgAlign(attr_len);
                }
            }
        }

        offset += common.nlmsgAlign(msg_len);
    }

    return .pending;
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
