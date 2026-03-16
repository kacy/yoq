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
    /// failed to open an AF_NETLINK socket
    SocketFailed,
    /// failed to send a netlink message to the kernel
    SendFailed,
    /// failed to receive a response from the kernel
    RecvFailed,
    /// the kernel returned a non-zero error code in the ACK
    KernelError,
    /// permission denied (EPERM/EACCES)
    PermissionDenied,
    /// resource not found (ENOENT)
    NotFound,
    /// out of memory (ENOMEM)
    OutOfMemory,
    /// the message buffer is too small for the header or attributes
    BufferFull,
    /// the kernel response was too short or had an unexpected type
    InvalidResponse,
};

// -- generic netlink --

pub const NETLINK_GENERIC: u32 = 16;
pub const GENL_ID_CTRL: u16 = 0x10;

pub const GenlMsgHdr = extern struct {
    cmd: u8,
    version: u8,
    reserved: u16,
};

// generic netlink controller commands/attributes (for family resolution)
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;

// WireGuard generic netlink constants (from uapi/linux/wireguard.h)
pub const WG_CMD = struct {
    pub const SET_DEVICE: u8 = 1;
};

pub const WGDEVICE_A = struct {
    pub const IFNAME: u16 = 1;
    pub const PRIVATE_KEY: u16 = 3;
    pub const LISTEN_PORT: u16 = 6;
    pub const PEERS: u16 = 8;
};

pub const WGPEER_A = struct {
    pub const PUBLIC_KEY: u16 = 1;
    pub const FLAGS: u16 = 3;
    pub const ENDPOINT: u16 = 4;
    pub const PERSISTENT_KEEPALIVE: u16 = 5;
    pub const ALLOWED_IPS: u16 = 7;
};

pub const WGALLOWEDIP_A = struct {
    pub const FAMILY: u16 = 1;
    pub const IPADDR: u16 = 2;
    pub const CIDR_MASK: u16 = 3;
};

pub const WGPEER_F_REMOVE_ME: u32 = 1;

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
    pub const XDP: u16 = 43;
    pub const INFO_KIND: u16 = 1;
    pub const INFO_DATA: u16 = 2;
};

/// XDP attribute types (IFLA_XDP_*)
pub const IFLA_XDP = struct {
    pub const FD: u16 = 1;
    pub const ATTACHED: u16 = 2;
    pub const FLAGS: u16 = 3;
};

/// XDP attachment flags
pub const XDP_FLAGS = struct {
    pub const SKB_MODE: u32 = 1 << 1;
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

/// TC (traffic control) attribute types (TCA_*)
pub const TCA = struct {
    pub const KIND: u16 = 1;
    pub const OPTIONS: u16 = 2;
};

/// TC handle/parent constants
pub const TC_H = struct {
    pub const INGRESS: u32 = 0xFFFFFFF1;
    pub const CLSACT: u32 = 0xFFFF0000;
    pub const MIN_INGRESS: u32 = 0xFFF2;
    pub const MIN_EGRESS: u32 = 0xFFF3;
};

/// TCA_BPF attributes — nested inside TCA_OPTIONS when kind="bpf".
/// values must match the kernel's TCA_BPF_* enum in pkt_cls.h.
pub const TCA_BPF = struct {
    pub const FLAG_ACT_DIRECT: u32 = 1;
    pub const FD: u16 = 6;
    pub const NAME: u16 = 7;
    pub const FLAGS: u16 = 8;
    pub const FLAGS_GEN: u16 = 9;
};

/// from linux/pkt_sched.h — used for TC qdisc/filter operations
pub const TcMsg = extern struct {
    family: u8,
    _pad1: u8,
    _pad2: u16,
    ifindex: i32,
    handle: u32,
    parent: u32,
    info: u32,
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

    /// write a nlmsghdr with a raw u16 message type (for generic netlink).
    /// the payload is a GenlMsgHdr instead of ifinfomsg/etc.
    pub fn putHeaderGenl(self: *MessageBuilder, family_id: u16, flags: u16, cmd: u8) NetlinkError!*linux.nlmsghdr {
        const hdr_size = @sizeOf(linux.nlmsghdr);
        const genl_size = @sizeOf(GenlMsgHdr);
        const total = nlmsgAlign(@as(usize, hdr_size + genl_size));

        if (self.pos + total > self.buf.len) return NetlinkError.BufferFull;

        const hdr: *linux.nlmsghdr = @ptrCast(@alignCast(&self.buf[self.pos]));
        hdr.len = @intCast(total);
        hdr.type = @enumFromInt(family_id);
        hdr.flags = flags;
        hdr.seq = 1;
        hdr.pid = 0;

        // write genl header
        const genl: *GenlMsgHdr = @ptrCast(@alignCast(&self.buf[self.pos + hdr_size]));
        genl.cmd = cmd;
        genl.version = 1;
        genl.reserved = 0;

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

        // SECURITY: Check for integer overflow before casting
        const total_len = @as(usize, rta_size) + data.len;
        if (total_len > 65535) return NetlinkError.BufferFull; // u16 max

        const attr_len: u16 = @intCast(total_len);
        const padded = nlmsgAlign(total_len);

        if (self.pos + padded > self.buf.len) return NetlinkError.BufferFull;

        // SECURITY: Check for header length overflow
        const new_hdr_len = @as(usize, hdr.len) + padded;
        if (new_hdr_len > 4294967295) return NetlinkError.BufferFull; // u32 max

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
        hdr.len = @intCast(new_hdr_len);
    }

    /// add a rtattr with a u32 value
    pub fn putAttrU32(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16, value: u32) NetlinkError!void {
        try self.putAttr(hdr, attr_type, std.mem.asBytes(&value));
    }

    /// add a rtattr with a u16 value
    pub fn putAttrU16(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16, value: u16) NetlinkError!void {
        try self.putAttr(hdr, attr_type, std.mem.asBytes(&value));
    }

    /// add a rtattr with a u8 value
    pub fn putAttrU8(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16, value: u8) NetlinkError!void {
        try self.putAttr(hdr, attr_type, std.mem.asBytes(&value));
    }

    /// add a rtattr with a null-terminated string value
    pub fn putAttrStr(self: *MessageBuilder, hdr: *linux.nlmsghdr, attr_type: u16, str: []const u8) NetlinkError!void {
        // netlink string attributes include the null terminator
        const rta_size = @sizeOf(RtAttr);

        // SECURITY: Check for integer overflow before casting
        const total_len = @as(usize, rta_size) + str.len + 1;
        if (total_len > 65535) return NetlinkError.BufferFull; // u16 max

        const attr_len: u16 = @intCast(total_len);
        const padded = nlmsgAlign(total_len);

        if (self.pos + padded > self.buf.len) return NetlinkError.BufferFull;

        // SECURITY: Check for header length overflow
        const new_hdr_len = @as(usize, hdr.len) + padded;
        if (new_hdr_len > 4294967295) return NetlinkError.BufferFull; // u32 max

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
        hdr.len = @intCast(new_hdr_len);
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
        const len = end - start;

        // SECURITY: Check for u16 overflow
        if (len > 65535) {
            // This is a serious error - nested attribute too large
            // In production, we'd want to handle this more gracefully
            nested.len = 65535; // cap at max
        } else {
            nested.len = @intCast(len);
        }

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

/// open a generic netlink socket (for WireGuard, etc.)
pub fn openGenericSocket() NetlinkError!posix.fd_t {
    const fd = posix.socket(
        linux.AF.NETLINK,
        posix.SOCK.RAW | posix.SOCK.CLOEXEC,
        NETLINK_GENERIC,
    ) catch return NetlinkError.SocketFailed;
    return fd;
}

/// resolve a generic netlink family name to its dynamic ID.
/// e.g. resolveFamily(fd, "wireguard") -> family_id
pub fn resolveFamily(fd: posix.fd_t, name: []const u8) NetlinkError!u16 {
    var msg_buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&msg_buf);

    const hdr = try mb.putHeaderGenl(GENL_ID_CTRL, NLM_F.REQUEST, CTRL_CMD_GETFAMILY);
    try mb.putAttrStr(hdr, CTRL_ATTR_FAMILY_NAME, name);

    const sent = posix.send(fd, mb.message(), 0) catch return NetlinkError.SendFailed;
    if (sent != mb.message().len) return NetlinkError.SendFailed;

    var recv_buf: [buf_size]u8 align(4) = undefined;
    const recv_len = posix.recv(fd, &recv_buf, 0) catch return NetlinkError.RecvFailed;

    const min_resp = @sizeOf(linux.nlmsghdr) + @sizeOf(GenlMsgHdr);
    if (recv_len < min_resp) return NetlinkError.InvalidResponse;

    const resp_hdr: *const linux.nlmsghdr = @ptrCast(@alignCast(&recv_buf));
    if (resp_hdr.type == .ERROR) {
        if (recv_len < @sizeOf(linux.nlmsghdr) + 4) return NetlinkError.InvalidResponse;
        const err_code: *const i32 = @ptrCast(@alignCast(&recv_buf[@sizeOf(linux.nlmsghdr)]));
        if (err_code.* != 0) return NetlinkError.NotFound;
    }

    // parse attributes after nlmsghdr + genlmsghdr
    var offset: usize = min_resp;
    while (offset + @sizeOf(RtAttr) <= recv_len) {
        const rta: *const RtAttr = @ptrCast(@alignCast(&recv_buf[offset]));
        if (rta.len < @sizeOf(RtAttr)) break;

        if (rta.type == CTRL_ATTR_FAMILY_ID) {
            if (rta.len >= @sizeOf(RtAttr) + 2) {
                const id: *const u16 = @ptrCast(@alignCast(&recv_buf[offset + @sizeOf(RtAttr)]));
                return id.*;
            }
        }

        offset += nlmsgAlign(@as(usize, rta.len));
    }

    return NetlinkError.InvalidResponse;
}

/// send a netlink message and check for errors in the ACK response
pub fn sendAndCheck(fd: posix.fd_t, msg: []const u8) NetlinkError!void {
    // send the message
    const sent = posix.send(fd, msg, 0) catch return NetlinkError.SendFailed;
    if (sent != msg.len) return NetlinkError.SendFailed;

    // read the response
    var recv_buf: [buf_size]u8 align(4) = undefined;
    const recv_len = posix.recv(fd, &recv_buf, 0) catch return NetlinkError.RecvFailed;
    if (recv_len < @sizeOf(linux.nlmsghdr)) return NetlinkError.InvalidResponse;

    // check for NLMSG_ERROR
    const resp_hdr: *const linux.nlmsghdr = @ptrCast(@alignCast(&recv_buf));
    if (resp_hdr.type == .ERROR) {
        // error payload is a 32-bit errno right after the header
        if (recv_len < @sizeOf(linux.nlmsghdr) + 4) return NetlinkError.InvalidResponse;
        const err_code: *const i32 = @ptrCast(@alignCast(&recv_buf[@sizeOf(linux.nlmsghdr)]));
        if (err_code.* == 0) return; // success (ACK)

        // SECURITY: Map specific errno values to error types for better handling
        const errno_value = -err_code.*; // errno is negative in netlink
        return switch (errno_value) {
            1 => NetlinkError.PermissionDenied, // EPERM
            2 => NetlinkError.NotFound, // ENOENT
            12 => NetlinkError.OutOfMemory, // ENOMEM
            13 => NetlinkError.PermissionDenied, // EACCES
            else => NetlinkError.KernelError,
        };
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
    const recv_len = posix.recv(fd, &recv_buf, 0) catch return 0;
    if (recv_len < @sizeOf(linux.nlmsghdr)) return 0;

    const resp_hdr: *const linux.nlmsghdr = @ptrCast(@alignCast(&recv_buf));
    if (resp_hdr.type == .ERROR) return 0;
    if (resp_hdr.type != .RTM_NEWLINK) return 0;
    if (recv_len < @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg)) return 0;

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

/// delete an interface by name via RTM_DELLINK.
pub fn deleteLink(fd: posix.fd_t, name: []const u8) NetlinkError!void {
    var buf_storage: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf_storage);

    const hdr = try mb.putHeader(
        .RTM_DELLINK,
        NLM_F.REQUEST | NLM_F.ACK,
        linux.ifinfomsg,
    );

    const info = mb.getPayload(hdr, linux.ifinfomsg);
    info.family = 0;

    try mb.putAttrStr(hdr, IFLA.IFNAME, name);
    try sendAndCheck(fd, mb.message());
}

// -- alignment + syscall helpers --

/// align a value to 4-byte boundary (NLMSG_ALIGN)
pub fn nlmsgAlign(len: usize) usize {
    return (len + 3) & ~@as(usize, 3);
}

/// check if a raw syscall return value indicates an error
pub fn isError(rc: usize) bool {
    const signed: isize = @bitCast(rc);
    return signed < 0;
}

// -- shared network helpers --
//
// common netlink operations used by bridge.zig and wireguard.zig.
// centralized here to avoid duplicating the message construction.

/// add an IPv4 address to an interface via RTM_NEWADDR.
pub fn addAddress(fd: posix.fd_t, if_index: u32, ip: *const [4]u8, prefix_len: u8) NetlinkError!void {
    var buf_storage: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf_storage);

    const hdr = try mb.putHeader(
        .RTM_NEWADDR,
        NLM_F.REQUEST | NLM_F.ACK | NLM_F.CREATE | NLM_F.EXCL,
        IfAddrMsg,
    );

    const addr_msg = mb.getPayload(hdr, IfAddrMsg);
    addr_msg.family = AF.INET;
    addr_msg.prefixlen = prefix_len;
    addr_msg.scope = RT_SCOPE.UNIVERSE;
    addr_msg.index = if_index;

    try mb.putAttr(hdr, IFA.LOCAL, ip);
    try mb.putAttr(hdr, IFA.ADDRESS, ip);

    try sendAndCheck(fd, mb.message());
}

/// add a route via RTM_NEWROUTE.
/// dest/dest_len define the destination prefix (0.0.0.0/0 for default).
/// gw is the gateway address.
pub fn addRoute(fd: posix.fd_t, dest: ?*const [4]u8, dest_len: u8, gw: *const [4]u8) NetlinkError!void {
    var buf_storage: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf_storage);

    const hdr = try mb.putHeader(
        .RTM_NEWROUTE,
        NLM_F.REQUEST | NLM_F.ACK | NLM_F.CREATE,
        RtMsg,
    );

    const rt = mb.getPayload(hdr, RtMsg);
    rt.family = AF.INET;
    rt.dst_len = dest_len;
    rt.table = RT_TABLE.MAIN;
    rt.protocol = RTPROT.BOOT;
    rt.scope = RT_SCOPE.UNIVERSE;
    rt.type = RTN.UNICAST;

    if (dest) |d| try mb.putAttr(hdr, RTA.DST, d);
    try mb.putAttr(hdr, RTA.GATEWAY, gw);

    try sendAndCheck(fd, mb.message());
}

/// remove a route via RTM_DELROUTE.
pub fn removeRoute(fd: posix.fd_t, dest: *const [4]u8, dest_len: u8) NetlinkError!void {
    var buf_storage: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf_storage);

    const hdr = try mb.putHeader(
        .RTM_DELROUTE,
        NLM_F.REQUEST | NLM_F.ACK,
        RtMsg,
    );

    const rt = mb.getPayload(hdr, RtMsg);
    rt.family = AF.INET;
    rt.dst_len = dest_len;
    rt.table = RT_TABLE.MAIN;
    rt.protocol = RTPROT.BOOT;
    rt.scope = RT_SCOPE.UNIVERSE;
    rt.type = RTN.UNICAST;

    try mb.putAttr(hdr, RTA.DST, dest);

    try sendAndCheck(fd, mb.message());
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

test "tcmsg struct layout" {
    // TcMsg must be 20 bytes to match the kernel's tc_msg
    try std.testing.expectEqual(@as(usize, 20), @sizeOf(TcMsg));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(TcMsg, "family"));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(TcMsg, "ifindex"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(TcMsg, "handle"));
    try std.testing.expectEqual(@as(usize, 12), @offsetOf(TcMsg, "parent"));
    try std.testing.expectEqual(@as(usize, 16), @offsetOf(TcMsg, "info"));
}

test "tc message builder" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);

    // build a TC qdisc add message (similar to what ebpf.zig does)
    const hdr = try mb.putHeader(.RTM_NEWQDISC, NLM_F.REQUEST | NLM_F.ACK | NLM_F.CREATE, TcMsg);
    const tc = mb.getPayload(hdr, TcMsg);
    tc.family = 0;
    tc.ifindex = 5;
    tc.handle = TC_H.CLSACT;
    tc.parent = TC_H.INGRESS;

    try mb.putAttrStr(hdr, TCA.KIND, "clsact");

    // header (16) + TcMsg (20) = 36, plus "clsact\0" attr (4 + 7 = 11, aligned 12) = 48
    try std.testing.expectEqual(@as(u32, 48), hdr.len);
}

test "genl header size" {
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(GenlMsgHdr));
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(GenlMsgHdr, "cmd"));
    try std.testing.expectEqual(@as(usize, 1), @offsetOf(GenlMsgHdr, "version"));
    try std.testing.expectEqual(@as(usize, 2), @offsetOf(GenlMsgHdr, "reserved"));
}

test "putHeaderGenl builds correct message" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);

    const family_id: u16 = 0x1b; // example WireGuard family ID
    const hdr = try mb.putHeaderGenl(family_id, NLM_F.REQUEST | NLM_F.ACK, WG_CMD.SET_DEVICE);

    // nlmsghdr (16) + genlmsghdr (4) = 20 bytes
    try std.testing.expectEqual(@as(u32, 20), hdr.len);
    try std.testing.expectEqual(@as(usize, 20), mb.pos);

    // verify genl header fields
    const genl: *const GenlMsgHdr = @ptrCast(@alignCast(&buf[@sizeOf(linux.nlmsghdr)]));
    try std.testing.expectEqual(WG_CMD.SET_DEVICE, genl.cmd);
    try std.testing.expectEqual(@as(u8, 1), genl.version);
    try std.testing.expectEqual(@as(u16, 0), genl.reserved);
}

test "putAttrU16 and putAttrU8" {
    var buf: [buf_size]u8 align(4) = undefined;
    var mb = MessageBuilder.init(&buf);

    const hdr = try mb.putHeaderGenl(0x1b, NLM_F.REQUEST, WG_CMD.SET_DEVICE);
    const base_len = hdr.len;

    try mb.putAttrU16(hdr, WGDEVICE_A.LISTEN_PORT, 51820);
    // rtattr (4) + u16 (2) = 6, aligned to 8
    try std.testing.expectEqual(@as(u32, base_len + 8), hdr.len);

    try mb.putAttrU8(hdr, WGALLOWEDIP_A.CIDR_MASK, 24);
    // rtattr (4) + u8 (1) = 5, aligned to 8
    try std.testing.expectEqual(@as(u32, base_len + 16), hdr.len);
}
