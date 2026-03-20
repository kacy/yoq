const std = @import("std");
const linux = std.os.linux;

pub const NetlinkError = error{
    SocketFailed,
    SendFailed,
    RecvFailed,
    KernelError,
    PermissionDenied,
    NotFound,
    OutOfMemory,
    BufferFull,
    InvalidResponse,
};

pub const NETLINK_GENERIC: u32 = 16;
pub const GENL_ID_CTRL: u16 = 0x10;

pub const GenlMsgHdr = extern struct {
    cmd: u8,
    version: u8,
    reserved: u16,
};

pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;

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

pub const RtAttr = extern struct {
    len: u16,
    type: u16,
};

pub const IfAddrMsg = extern struct {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    index: u32,
};

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

pub const AF = struct {
    pub const INET: u8 = 2;
    pub const INET6: u8 = 10;
};

pub const RTM = linux.NetlinkMessageType;

pub const NLM_F = struct {
    pub const REQUEST: u16 = 0x01;
    pub const ACK: u16 = 0x04;
    pub const ROOT: u16 = 0x100;
    pub const MATCH: u16 = 0x200;
    pub const DUMP: u16 = ROOT | MATCH;
    pub const CREATE: u16 = 0x400;
    pub const EXCL: u16 = 0x200;
};

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

pub const IFLA_XDP = struct {
    pub const FD: u16 = 1;
    pub const ATTACHED: u16 = 2;
    pub const FLAGS: u16 = 3;
};

pub const XDP_FLAGS = struct {
    pub const SKB_MODE: u32 = 1 << 1;
};

pub const VETH = struct {
    pub const INFO_PEER: u16 = 1;
};

pub const IFA = struct {
    pub const ADDRESS: u16 = 1;
    pub const LOCAL: u16 = 2;
};

pub const RTA = struct {
    pub const DST: u16 = 1;
    pub const GATEWAY: u16 = 5;
    pub const OIF: u16 = 4;
};

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

pub const TCA = struct {
    pub const KIND: u16 = 1;
    pub const OPTIONS: u16 = 2;
};

pub const TC_H = struct {
    pub const INGRESS: u32 = 0xFFFFFFF1;
    pub const CLSACT: u32 = 0xFFFF0000;
    pub const MIN_INGRESS: u32 = 0xFFF2;
    pub const MIN_EGRESS: u32 = 0xFFF3;
};

pub const TCA_BPF = struct {
    pub const FLAG_ACT_DIRECT: u32 = 1;
    pub const FD: u16 = 6;
    pub const NAME: u16 = 7;
    pub const FLAGS: u16 = 8;
    pub const FLAGS_GEN: u16 = 9;
};

pub const TcMsg = extern struct {
    family: u8,
    _pad1: u8,
    _pad2: u16,
    ifindex: i32,
    handle: u32,
    parent: u32,
    info: u32,
};

pub const IFF = struct {
    pub const UP: u32 = 0x1;
};

pub const buf_size = 4096;

pub fn nlmsgAlign(len: usize) usize {
    return (len + 3) & ~@as(usize, 3);
}

pub fn isError(rc: usize) bool {
    const signed: isize = @bitCast(rc);
    return signed < 0;
}
