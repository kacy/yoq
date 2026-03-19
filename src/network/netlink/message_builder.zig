const std = @import("std");
const linux = std.os.linux;
const common = @import("common.zig");

pub const MessageBuilder = struct {
    buf: *[common.buf_size]u8,
    pos: usize,

    pub fn init(buf: *align(4) [common.buf_size]u8) MessageBuilder {
        return .{ .buf = buf, .pos = 0 };
    }

    pub fn putHeader(self: *MessageBuilder, msg_type: common.RTM, flags: u16, comptime PayloadT: type) common.NetlinkError!*linux.nlmsghdr {
        const hdr_size = @sizeOf(linux.nlmsghdr);
        const payload_size = @sizeOf(PayloadT);
        const total = common.nlmsgAlign(@as(usize, hdr_size + payload_size));

        if (self.pos + total > self.buf.len) return common.NetlinkError.BufferFull;

        const hdr: *linux.nlmsghdr = @ptrCast(@alignCast(&self.buf[self.pos]));
        hdr.len = @intCast(total);
        hdr.type = msg_type;
        hdr.flags = flags;
        hdr.seq = 1;
        hdr.pid = 0;

        const payload_start = self.pos + hdr_size;
        @memset(self.buf[payload_start..][0..payload_size], 0);

        self.pos += total;
        return hdr;
    }

    pub fn putHeaderGenl(self: *MessageBuilder, family_id: u16, flags: u16, cmd: u8) common.NetlinkError!*linux.nlmsghdr {
        const hdr_size = @sizeOf(linux.nlmsghdr);
        const genl_size = @sizeOf(common.GenlMsgHdr);
        const total = common.nlmsgAlign(@as(usize, hdr_size + genl_size));

        if (self.pos + total > self.buf.len) return common.NetlinkError.BufferFull;

        const hdr: *linux.nlmsghdr = @ptrCast(@alignCast(&self.buf[self.pos]));
        hdr.len = @intCast(total);
        hdr.type = @enumFromInt(family_id);
        hdr.flags = flags;
        hdr.seq = 1;
        hdr.pid = 0;

        const genl: *common.GenlMsgHdr = @ptrCast(@alignCast(&self.buf[self.pos + hdr_size]));
        genl.cmd = cmd;
        genl.version = 1;
        genl.reserved = 0;

        self.pos += total;
        return hdr;
    }

    pub fn getPayload(_: *MessageBuilder, hdr: *linux.nlmsghdr, comptime PayloadT: type) *PayloadT {
        const hdr_ptr: [*]u8 = @ptrCast(hdr);
        const payload_ptr = hdr_ptr + @sizeOf(linux.nlmsghdr);
        return @ptrCast(@alignCast(payload_ptr));
    }

    pub fn putAttr(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16, data: []const u8) common.NetlinkError!void {
        const rta_size = @sizeOf(common.RtAttr);
        const total_len = @as(usize, rta_size) + data.len;
        if (total_len > 65535) return common.NetlinkError.BufferFull;

        const attr_len: u16 = @intCast(total_len);
        const padded = common.nlmsgAlign(total_len);

        if (self.pos + padded > self.buf.len) return common.NetlinkError.BufferFull;

        const new_hdr_len = @as(usize, hdr.len) + padded;
        if (new_hdr_len > 4294967295) return common.NetlinkError.BufferFull;

        const rta: *common.RtAttr = @ptrCast(@alignCast(&self.buf[self.pos]));
        rta.len = attr_len;
        rta.type = attr_type;

        if (data.len > 0) {
            @memcpy(self.buf[self.pos + rta_size ..][0..data.len], data);
        }

        if (padded > attr_len) {
            @memset(self.buf[self.pos + attr_len ..][0 .. padded - attr_len], 0);
        }

        self.pos += padded;
        hdr.len = @intCast(new_hdr_len);
    }

    pub fn putAttrU32(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16, value: u32) common.NetlinkError!void {
        try self.putAttr(hdr, attr_type, std.mem.asBytes(&value));
    }

    pub fn putAttrU16(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16, value: u16) common.NetlinkError!void {
        try self.putAttr(hdr, attr_type, std.mem.asBytes(&value));
    }

    pub fn putAttrU8(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16, value: u8) common.NetlinkError!void {
        try self.putAttr(hdr, attr_type, std.mem.asBytes(&value));
    }

    pub fn putAttrStr(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16, str: []const u8) common.NetlinkError!void {
        const rta_size = @sizeOf(common.RtAttr);
        const total_len = @as(usize, rta_size) + str.len + 1;
        if (total_len > 65535) return common.NetlinkError.BufferFull;

        const attr_len: u16 = @intCast(total_len);
        const padded = common.nlmsgAlign(total_len);

        if (self.pos + padded > self.buf.len) return common.NetlinkError.BufferFull;

        const new_hdr_len = @as(usize, hdr.len) + padded;
        if (new_hdr_len > 4294967295) return common.NetlinkError.BufferFull;

        const rta: *common.RtAttr = @ptrCast(@alignCast(&self.buf[self.pos]));
        rta.len = attr_len;
        rta.type = attr_type;

        @memcpy(self.buf[self.pos + rta_size ..][0..str.len], str);
        self.buf[self.pos + rta_size + str.len] = 0;

        if (padded > attr_len) {
            @memset(self.buf[self.pos + attr_len ..][0 .. padded - attr_len], 0);
        }

        self.pos += padded;
        hdr.len = @intCast(new_hdr_len);
    }

    pub fn startNested(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16) common.NetlinkError!*common.RtAttr {
        const rta_size = @sizeOf(common.RtAttr);
        if (self.pos + rta_size > self.buf.len) return common.NetlinkError.BufferFull;

        const rta: *common.RtAttr = @ptrCast(@alignCast(&self.buf[self.pos]));
        rta.len = @intCast(rta_size);
        rta.type = attr_type;

        self.pos += rta_size;
        hdr.len = @intCast(@as(usize, hdr.len) + rta_size);

        return rta;
    }

    pub fn endNested(self: *MessageBuilder, nested: *common.RtAttr) void {
        const start = @intFromPtr(nested);
        const end = @intFromPtr(&self.buf[self.pos]);
        const len = end - start;

        if (len > 65535) {
            nested.len = 65535;
        } else {
            nested.len = @intCast(len);
        }

        const aligned = common.nlmsgAlign(self.pos);
        if (aligned > self.pos and aligned <= self.buf.len) {
            @memset(self.buf[self.pos..aligned], 0);
            self.pos = aligned;
        }
    }

    pub fn message(self: *const MessageBuilder) []const u8 {
        return self.buf[0..self.pos];
    }
};
