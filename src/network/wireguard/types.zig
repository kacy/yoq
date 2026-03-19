pub const WireguardError = error{
    KeyGenFailed,
    DeviceCreateFailed,
    DeviceDeleteFailed,
    PeerAddFailed,
    PeerRemoveFailed,
    AddressFailed,
    RouteFailed,
};

pub const encoded_key_len = 44;

pub const KeyPair = struct {
    private_key: [encoded_key_len]u8,
    public_key: [encoded_key_len]u8,
};

pub const PeerConfig = struct {
    public_key: []const u8,
    endpoint: ?[]const u8,
    allowed_ips: []const u8,
    persistent_keepalive: u16 = 25,
};

pub const ParsedCidr = struct {
    addr: [4]u8,
    prefix: u8,
};
