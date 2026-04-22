const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const nl = @import("../netlink.zig");
const log = @import("../../lib/log.zig");
const common = @import("common.zig");

pub fn attachTC(
    if_index: u32,
    direction: common.Direction,
    prog_fd: posix.fd_t,
    priority: u32,
) common.EbpfError!void {
    const fd = nl.openSocket() catch return common.EbpfError.AttachFailed;
    defer @import("compat").posix.close(fd);

    createClsactQdisc(fd, if_index) catch |e| {
        log.warn("ebpf: failed to create clsact qdisc on ifindex {d}: {}", .{ if_index, e });
        return common.EbpfError.AttachFailed;
    };

    addBpfFilter(fd, if_index, direction, prog_fd, priority) catch |e| {
        log.warn("ebpf: failed to add BPF filter on ifindex {d}: {}", .{ if_index, e });
        return common.EbpfError.AttachFailed;
    };
}

pub fn detachTC(if_index: u32) common.EbpfError!void {
    const fd = nl.openSocket() catch return common.EbpfError.DetachFailed;
    defer @import("compat").posix.close(fd);

    deleteClsactQdisc(fd, if_index) catch |e| {
        log.warn("ebpf: failed to delete clsact qdisc on ifindex {d}: {}", .{ if_index, e });
        return common.EbpfError.DetachFailed;
    };
}

pub fn attachXdp(if_index: u32, prog_fd: posix.fd_t) common.EbpfError!void {
    const fd = nl.openSocket() catch return common.EbpfError.AttachFailed;
    defer @import("compat").posix.close(fd);

    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = mb.putHeader(
        .RTM_NEWLINK,
        nl.NLM_F.REQUEST | nl.NLM_F.ACK,
        linux.ifinfomsg,
    ) catch return common.EbpfError.AttachFailed;

    const info = mb.getPayload(hdr, linux.ifinfomsg);
    info.family = 0;
    info.index = @bitCast(if_index);

    const xdp_attr = mb.startNested(hdr, nl.IFLA.XDP) catch return common.EbpfError.AttachFailed;
    mb.putAttrU32(hdr, nl.IFLA_XDP.FD, @intCast(prog_fd)) catch return common.EbpfError.AttachFailed;
    mb.putAttrU32(hdr, nl.IFLA_XDP.FLAGS, nl.XDP_FLAGS.SKB_MODE) catch return common.EbpfError.AttachFailed;
    mb.endNested(xdp_attr);

    nl.sendAndCheck(fd, mb.message()) catch |e| {
        log.warn("ebpf: XDP attach failed on ifindex {d}: {}", .{ if_index, e });
        return common.EbpfError.AttachFailed;
    };
}

pub fn detachXdp(if_index: u32) common.EbpfError!void {
    const fd = nl.openSocket() catch return common.EbpfError.DetachFailed;
    defer @import("compat").posix.close(fd);

    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = mb.putHeader(
        .RTM_NEWLINK,
        nl.NLM_F.REQUEST | nl.NLM_F.ACK,
        linux.ifinfomsg,
    ) catch return common.EbpfError.DetachFailed;

    const info = mb.getPayload(hdr, linux.ifinfomsg);
    info.family = 0;
    info.index = @bitCast(if_index);

    const xdp_attr = mb.startNested(hdr, nl.IFLA.XDP) catch return common.EbpfError.DetachFailed;
    const neg_one: u32 = @bitCast(@as(i32, -1));
    mb.putAttrU32(hdr, nl.IFLA_XDP.FD, neg_one) catch return common.EbpfError.DetachFailed;
    mb.putAttrU32(hdr, nl.IFLA_XDP.FLAGS, nl.XDP_FLAGS.SKB_MODE) catch return common.EbpfError.DetachFailed;
    mb.endNested(xdp_attr);

    nl.sendAndCheck(fd, mb.message()) catch |e| {
        log.warn("ebpf: XDP detach failed on ifindex {d}: {}", .{ if_index, e });
        return common.EbpfError.DetachFailed;
    };
}

fn createClsactQdisc(fd: posix.fd_t, if_index: u32) nl.NetlinkError!void {
    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = try mb.putHeader(
        .RTM_NEWQDISC,
        nl.NLM_F.REQUEST | nl.NLM_F.ACK | nl.NLM_F.CREATE,
        nl.TcMsg,
    );
    const tc = mb.getPayload(hdr, nl.TcMsg);
    tc.family = 0;
    tc._pad1 = 0;
    tc._pad2 = 0;
    tc.ifindex = @intCast(if_index);
    tc.handle = nl.TC_H.CLSACT;
    tc.parent = nl.TC_H.INGRESS;
    tc.info = 0;

    try mb.putAttrStr(hdr, nl.TCA.KIND, "clsact");

    nl.sendAndCheck(fd, mb.message()) catch |e| {
        if (e == nl.NetlinkError.KernelError) return;
        return e;
    };
}

fn deleteClsactQdisc(fd: posix.fd_t, if_index: u32) nl.NetlinkError!void {
    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const hdr = try mb.putHeader(
        .RTM_DELQDISC,
        nl.NLM_F.REQUEST | nl.NLM_F.ACK,
        nl.TcMsg,
    );
    const tc = mb.getPayload(hdr, nl.TcMsg);
    tc.family = 0;
    tc._pad1 = 0;
    tc._pad2 = 0;
    tc.ifindex = @intCast(if_index);
    tc.handle = nl.TC_H.CLSACT;
    tc.parent = nl.TC_H.INGRESS;
    tc.info = 0;

    try nl.sendAndCheck(fd, mb.message());
}

fn addBpfFilter(
    fd: posix.fd_t,
    if_index: u32,
    direction: common.Direction,
    prog_fd: posix.fd_t,
    priority: u32,
) nl.NetlinkError!void {
    var buf: [nl.buf_size]u8 align(4) = undefined;
    var mb = nl.MessageBuilder.init(&buf);

    const parent = switch (direction) {
        .ingress => nl.TC_H.CLSACT | nl.TC_H.MIN_INGRESS,
        .egress => nl.TC_H.CLSACT | nl.TC_H.MIN_EGRESS,
    };

    const eth_p_all: u16 = 0x0003;
    const info: u32 = (priority << 16) | @as(u32, std.mem.nativeToBig(u16, eth_p_all));

    const hdr = try mb.putHeader(
        .RTM_NEWTFILTER,
        nl.NLM_F.REQUEST | nl.NLM_F.ACK | nl.NLM_F.CREATE | nl.NLM_F.EXCL,
        nl.TcMsg,
    );
    const tc = mb.getPayload(hdr, nl.TcMsg);
    tc.family = 0;
    tc._pad1 = 0;
    tc._pad2 = 0;
    tc.ifindex = @intCast(if_index);
    tc.handle = 0;
    tc.parent = parent;
    tc.info = info;

    try mb.putAttrStr(hdr, nl.TCA.KIND, "bpf");

    const options = try mb.startNested(hdr, nl.TCA.OPTIONS);
    try mb.putAttrU32(hdr, nl.TCA_BPF.FD, @intCast(prog_fd));
    try mb.putAttrStr(hdr, nl.TCA_BPF.NAME, "yoq");
    try mb.putAttrU32(hdr, nl.TCA_BPF.FLAGS, nl.TCA_BPF.FLAG_ACT_DIRECT);
    mb.endNested(options);

    try nl.sendAndCheck(fd, mb.message());
}
