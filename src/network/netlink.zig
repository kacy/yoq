// netlink — low-level netlink socket abstraction
//
// wraps AF_NETLINK sockets for talking to the kernel's networking
// subsystem. handles message construction, attribute packing, and
// response parsing. used by bridge.zig for creating bridges, veth
// pairs, assigning IPs, and setting routes.
//
// we build raw netlink messages instead of depending on libnl.
// zig's std.os.linux has nlmsghdr and ifinfomsg. we define our
// own rtattr (the stdlib version uses a union for the type field
// which makes it awkward for arbitrary attribute types) and the
// missing ifaddrmsg/rtmsg structs.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

pub const NetlinkError = error{
    SocketFailed,
    SendFailed,
    RecvFailed,
    KernelError,
    BufferFull,
    InvalidResponse,
};

// -- kernel structs --
// we define our own rtattr because the zig stdlib version uses
// an extern union for the type field, which only covers IFLA and IFA.
// we need to write arbitrary attribute types (RTA, VETH, etc).

/// simple rtattr — matches the kernel's 4-byte { len, type } header
pub const RtAttr = extern struct {
    len: u16,
    type: u16,
};

/// from linux/if_addr.h — used for IP address operations
pub const IfAddrMsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: u32,
};

/// from linux/rtmsg.h — used for routing operations
pub const RtMsg = extern struct {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    protocol: u8,
    scope: u8,
    type: u8,
    flags: u32,
};

// -- netlink constants not in zig stdlib --

/// address families for netlink messages
pub const AF = struct {
    pub const INET: u8 = 2;
    pub const INET6: u8 = 10;
};

/// rtnetlink message types — re-exported from the stdlib enum
/// for convenience so callers don't need to type the full path.
pub const RTM = linux.NetlinkMessageType;

/// netlink message flags
pub const NLM_F = struct {
    pub const REQUEST: u16 = 0x01;
    pub const ACK: u16 = 0x04;
    pub const CREATE: u16 = 0x400;
    pub const EXCL: u16 = 0x200;
};

/// interface link attribute types (IFLA_*)
pub const IFLA = struct {
    pub const IFNAME: u16 = 3;
    pub const MTU: u16 = 4;
    pub const LINK: u16 = 5;
    pub const MASTER: u16 = 10;
    pub const LINKINFO: u16 = 18;
    pub const NET_NS_PID: u16 = 19;
    pub const INFO_KIND: u16 = 1;
    pub const INFO_DATA: u16 = 2;
};

/// veth-specific attribute
pub const VETH = struct {
    pub const INFO_PEER: u16 = 1;
};

/// interface address attribute types (IFA_*)
pub const IFA = struct {
    pub const ADDRESS: u16 = 1;
    pub const LOCAL: u16 = 2;
};

/// route attribute types (RTA_*)
pub const RTA = struct {
    pub const DST: u16 = 1;
    pub const GATEWAY: u16 = 5;
    pub const OIF: u16 = 4;
};

/// route protocol/scope/type constants
pub const RTPROT = struct {
    pub const BOOT: u8 = 3;
};

pub const RT_SCOPE = struct {
    pub const UNIVERSE: u8 = 0;
    pub const LINK: u8 = 253;
};

pub const RTN = struct {
    pub const UNICAST: u8 = 1;
};

pub const RT_TABLE = struct {
    pub const MAIN: u8 = 254;
};

/// interface flags
pub const IFF = struct {
    pub const UP: u32 = 0x1;
};

// -- message builder --

/// builds a netlink message in a stack-allocated buffer.
/// messages are built sequentially: header, then attributes.
/// buffer size for netlink messages
pub const buf_size = 4096;

pub const MessageBuilder = struct {
    buf: *[buf_size]u8,
    pos: usize,

    /// initialize with a buffer. the buffer MUST be 4-byte aligned
    /// (declare with: var buf: [nl.buf_size]u8 align(4) = undefined;)
    pub fn init(buf: *align(4) [buf_size]u8) MessageBuilder {
        return .{ .buf = buf, .pos = 0 };
    }

    /// write the nlmsghdr + payload struct (ifinfomsg, ifaddrmsg, etc).
    /// returns a pointer to the header so we can patch the length later.
    pub fn putHeader(self: *MessageBuilder, msg_type: RTM, flags: u16, comptime PayloadT: type) NetlinkError!*linux.nlmsghdr {
        const hdr_size = @sizeOf(linux.nlmsghdr);
        const payload_size = @sizeOf(PayloadT);
        const total = nlmsgAlign(@as(usize, hdr_size + payload_size));

        if (self.pos + total > self.buf.len) return NetlinkError.BufferFull;

        // write nlmsghdr
        const hdr: *linux.nlmsghdr = @ptrCast(@alignCast(&self.buf[self.pos]));
        hdr.len = @intCast(total);
        hdr.type = msg_type;
        hdr.flags = flags;
        hdr.seq = 1;
        hdr.pid = 0;

        // zero the payload
        const payload_start = self.pos + hdr_size;
        @memset(self.buf[payload_start..][0..payload_size], 0);

        self.pos = self.pos + total;
        return hdr;
    }

    /// get a typed pointer to the payload area right after the nlmsghdr
    pub fn getPayload(_: *MessageBuilder, hdr: *linux.nlmsghdr, comptime PayloadT: type) *PayloadT {
        const hdr_ptr: [*]u8 = @ptrCast(hdr);
        const payload_ptr = hdr_ptr + @sizeOf(linux.nlmsghdr);
        return @ptrCast(@alignCast(payload_ptr));
    }

    /// add a rtattr with raw bytes value
    pub fn putAttr(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16, data: []const u8) NetlinkError!void {
        const rta_size = @sizeOf(RtAttr);
        const attr_len: u16 = @intCast(rta_size + data.len);
        const padded = nlmsgAlign(@as(usize, attr_len));

        if (self.pos + padded > self.buf.len) return NetlinkError.BufferFull;

        const rta: *RtAttr = @ptrCast(@alignCast(&self.buf[self.pos]));
        rta.len = attr_len;
        rta.type = attr_type;

        // copy data right after the rtattr header
        if (data.len > 0) {
            @memcpy(self.buf[self.pos + rta_size ..][0..data.len], data);
        }

        // zero padding bytes
        if (padded > attr_len) {
            @memset(self.buf[self.pos + attr_len ..][0 .. padded - attr_len], 0);
        }

        self.pos += padded;
        hdr.len = @intCast(@as(usize, hdr.len) + padded);
    }

    /// add a rtattr with a u32 value
    pub fn putAttrU32(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16, value: u32) NetlinkError!void {
        try self.putAttr(hdr, attr_type, std.mem.asBytes(&value));
    }

    /// add a rtattr with a null-terminated string value
    pub fn putAttrStr(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16, str: []const u8) NetlinkError!void {
        // netlink string attributes include the null terminator
        const rta_size = @sizeOf(RtAttr);
        const attr_len: u16 = @intCast(rta_size + str.len + 1);
        const padded = nlmsgAlign(@as(usize, attr_len));

        if (self.pos + padded > self.buf.len) return NetlinkError.BufferFull;

        const rta: *RtAttr = @ptrCast(@alignCast(&self.buf[self.pos]));
        rta.len = attr_len;
        rta.type = attr_type;

        @memcpy(self.buf[self.pos + rta_size ..][0..str.len], str);
        self.buf[self.pos + rta_size + str.len] = 0;

        // zero padding
        if (padded > attr_len) {
            @memset(self.buf[self.pos + attr_len ..][0 .. padded - attr_len], 0);
        }

        self.pos += padded;
        hdr.len = @intCast(@as(usize, hdr.len) + padded);
    }

    /// start a nested attribute (e.g. IFLA_LINKINFO containing IFLA_INFO_KIND).
    /// returns the rtattr pointer so you can close the nesting later.
    pub fn startNested(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16) NetlinkError!*RtAttr {
        const rta_size = @sizeOf(RtAttr);
        if (self.pos + rta_size > self.buf.len) return NetlinkError.BufferFull;

        const rta: *RtAttr = @ptrCast(@alignCast(&self.buf[self.pos]));
        rta.len = @intCast(rta_size); // will be updated in endNested
        rta.type = attr_type;

        self.pos += rta_size;
        hdr.len = @intCast(@as(usize, hdr.len) + rta_size);

        return rta;
    }

    /// close a nested attribute, updating its length to include all children.
    pub fn endNested(self: *MessageBuilder, nested: *RtAttr) void {
        const start: usize = @intFromPtr(nested);
        const end: usize = @intFromPtr(&self.buf[self.pos]);
        nested.len = @intCast(end - start);

        // align position
        const aligned = nlmsgAlign(self.pos);
        if (aligned > self.pos and aligned <= self.buf.len) {
            @memset(self.buf[self.pos..aligned], 0);
            self.pos = aligned;
        }
    }

    /// return the built message as a slice
    pub fn message(self: *const MessageBuilder) []const u8 {
        return self.buf[0..self.pos];
    }
};

// -- socket operations --

/// open a netlink route socket
pub fn openSocket() NetlinkError!posix.fd_t {
    const NETLINK_ROUTE = 0;
    const fd = posix.socket(
        linux.AF.NETLINK,
        posix.SOCK.RAW | posix.SOCK.CLOEXEC,
        NETLINK_ROUTE,
    ) catch return NetlinkError.SocketFailed;
    return fd;
}

/// send a netlink message and check for errors in the ACK response
pub fn sendAndCheck(fd: posix.fd_t, msg: []const u8) NetlinkError!void {
    // send the message
    const sent = posix.send(fd, msg, 0) catch return NetlinkError.SendFailed;
    if (sent != msg.len) return NetlinkError.SendFailed;

    // read the response
    var recv_buf: [buf_size]u8 align(4) = undefined;
    const n = posix.recv(fd, &recv_buf, 0) catch return NetlinkError.RecvFailed;
    if (n < @sizeOf(linux.nlmsghdr)) return NetlinkError.InvalidResponse;

    // check for NLMSG_ERROR
    const resp_hdr: *const linux.nlmsghdr = @ptrCast(@alignCast(&recv_buf));
    if (resp_hdr.type == .ERROR) {
        // error payload is a 32-bit errno right after the header
        if (n < @sizeOf(linux.nlmsghdr) + 4) return NetlinkError.InvalidResponse;
        const err_code: *const i32 = @ptrCast(@alignCast(&recv_buf[@sizeOf(linux.nlmsghdr)]));
        if (err_code.* == 0) return; // success (ACK)
        return NetlinkError.KernelError;
    }
}

/// send a netlink message without waiting for ACK.
/// used when we don't need NLM_F_ACK (e.g. queries).
pub fn sendOnly(fd: posix.fd_t, msg: []const u8) NetlinkError!void {
    const sent = posix.send(fd, msg, 0) catch return NetlinkError.SendFailed;
    if (sent != msg.len) return NetlinkError.SendFailed;
}

/// get the interface index for a named interface.
/// returns 0 if not found.
pub fn getIfIndex(fd: posix.fd_t, name: []const u8) NetlinkError!u32 {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);

    const hdr = try mb.putHeader(.RTM_GETLINK, NLM_F.REQUEST, linux.ifinfomsg);
    const info = mb.getPayload(hdr, linux.ifinfomsg);
    info.family = 0; // AF_UNSPEC
    try mb.putAttrStr(hdr, IFLA.IFNAME, name);

    sendOnly(fd, mb.message()) catch return 0;

    var recv_buf: [buf_size]u8 align(4) = undefined;
    const n = posix.recv(fd, &recv_buf, 0) catch return 0;
    if (n < @sizeOf(linux.nlmsghdr)) return 0;

    const resp_hdr: *const linux.nlmsghdr = @ptrCast(@alignCast(&recv_buf));
    if (resp_hdr.type == .ERROR) return 0;
    if (resp_hdr.type != .RTM_NEWLINK) return 0;
    if (n < @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg)) return 0;

    const resp_info: *const linux.ifinfomsg = @ptrCast(@alignCast(&recv_buf[@sizeOf(linux.nlmsghdr)]));
    return @bitCast(resp_info.index);
}

/// bring an interface up by index
pub fn setLinkUp(fd: posix.fd_t, if_index: u32) NetlinkError!void {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);

    const hdr = try mb.putHeader(.RTM_NEWLINK, NLM_F.REQUEST | NLM_F.ACK, linux.ifinfomsg);
    const info = mb.getPayload(hdr, linux.ifinfomsg);
    info.family = 0;
    info.index = @bitCast(if_index);
    info.flags = IFF.UP;
    info.change = IFF.UP;

    try sendAndCheck(fd, mb.message());
}

// -- alignment + syscall helpers --

/// align a length to 4-byte boundary (NLMSG_ALIGN).
/// public so bridge.zig can use it for manual struct padding.
pub fn nlmsgAlignPub(len: usize) usize {
    return nlmsgAlign(len);
}

/// align a value to 4-byte boundary (NLMSG_ALIGN)
fn nlmsgAlign(len: usize) usize {
    return (len + 3) & ~@as(usize, 3);
}

/// check if a raw syscall return value indicates an error
pub fn isError(rc: usize) bool {
    const signed: isize = @bitCast(rc);
    return signed < 0;
}

// -- tests --

test "nlmsg alignment" {
    try std.testing.expectEqual(@as(usize, 0), nlmsgAlign(0));
    try std.testing.expectEqual(@as(usize, 4), nlmsgAlign(1));
    try std.testing.expectEqual(@as(usize, 4), nlmsgAlign(4));
    try std.testing.expectEqual(@as(usize, 8), nlmsgAlign(5));
    try std.testing.expectEqual(@as(usize, 16), nlmsgAlign(16));
    try std.testing.expectEqual(@as(usize, 20), nlmsgAlign(17));
}

test "message builder header size" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);

    const hdr = try mb.putHeader(.RTM_NEWLINK, NLM_F.REQUEST, linux.ifinfomsg);
    // nlmsghdr (16 bytes) + ifinfomsg (16 bytes) = 32 bytes
    try std.testing.expectEqual(@as(u32, 32), hdr.len);
    try std.testing.expectEqual(@as(usize, 32), mb.pos);
}

test "message builder attributes" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);

    const hdr = try mb.putHeader(.RTM_NEWLINK, NLM_F.REQUEST, linux.ifinfomsg);
    const initial_len = hdr.len;

    try mb.putAttrU32(hdr, IFLA.MTU, 1500);
    // rtattr (4 bytes) + u32 (4 bytes) = 8 bytes
    try std.testing.expectEqual(@as(u32, initial_len + 8), hdr.len);
}

test "message builder string attribute" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);

    const hdr = try mb.putHeader(.RTM_NEWLINK, NLM_F.REQUEST, linux.ifinfomsg);
    const initial_len = hdr.len;

    try mb.putAttrStr(hdr, IFLA.IFNAME, "eth0");
    // rtattr (4 bytes) + "eth0\0" (5 bytes) = 9, aligned to 12
    try std.testing.expectEqual(@as(u32, initial_len + 12), hdr.len);
}

test "ifaddrmsg struct layout" {
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(IfAddrMsg));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(IfAddrMsg, "family"));
    try std.testing.expectEqual(@as(usize, 1), @offsetOf(IfAddrMsg, "prefixlen"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(IfAddrMsg, "index"));
}

test "rtmsg struct layout" {
    try std.testing.expectEqual(@as(usize, 12), @sizeOf(RtMsg));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(RtMsg, "family"));
    try std.testing.expectEqual(@as(usize, 1), @offsetOf(RtMsg, "dst_len"));
}

test "rtattr struct layout" {
    // must match the kernel's rtattr: 4 bytes total
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(RtAttr));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(RtAttr, "len"));
    try std.testing.expectEqual(@as(usize, 2), @offsetOf(RtAttr, "type"));
}

test "nested attributes" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);

    const hdr = try mb.putHeader(.RTM_NEWLINK, NLM_F.REQUEST, linux.ifinfomsg);
    const nested = try mb.startNested(hdr, IFLA.LINKINFO);
    try mb.putAttrStr(hdr, IFLA.INFO_KIND, "bridge");
    mb.endNested(nested);

    // nested should contain: rtattr header (4) + inner attr
    // inner attr: rtattr (4) + "bridge\0" (7) = 11, aligned to 12
    // nested total: 4 + 12 = 16
    try std.testing.expectEqual(@as(u16, 16), nested.len);
}
