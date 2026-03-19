pub const IpError = error{
    AllocationFailed,
    ReleaseFailed,
    NotFound,
    SubnetExhausted,
    DbOpenFailed,
};

pub const SubnetConfig = struct {
    node_id: u16,
    base: [4]u8,
    gateway: [4]u8,
    prefix_len: u8,
    range_start: [4]u8,
    range_end: [4]u8,
};
