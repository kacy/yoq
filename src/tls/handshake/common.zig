const std = @import("std");
const record = @import("../record.zig");

pub const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
pub const X25519 = std.crypto.dh.X25519;
pub const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
pub const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(HmacSha384);
pub const Sha384 = std.crypto.hash.sha2.Sha384;
pub const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const HandshakeError = error{
    InvalidClientHello,
    UnsupportedCipherSuite,
    UnsupportedKeyShare,
    MissingExtension,
    KeyExchangeFailed,
    DerivationFailed,
    BufferTooSmall,
    InvalidFinished,
    AllocFailed,
};

pub const cipher_suite_aes_256_gcm: u16 = 0x1302;
pub const hash_len = Sha384.digest_length;

pub const TrafficKeys = struct {
    key: [record.aead_key_size]u8,
    iv: [record.aead_nonce_size]u8,
};

pub const HandshakeKeys = struct {
    client_handshake_traffic_secret: [hash_len]u8,
    server_handshake_traffic_secret: [hash_len]u8,
    handshake_secret: [hash_len]u8,
};

pub const ApplicationKeys = struct {
    client: TrafficKeys,
    server: TrafficKeys,
};

pub fn readU16(data: []const u8) usize {
    return (@as(usize, data[0]) << 8) | @as(usize, data[1]);
}

pub fn writeU16(dest: []u8, val: u16) void {
    dest[0] = @intCast(val >> 8);
    dest[1] = @intCast(val & 0xFF);
}

pub fn writeU24(dest: []u8, val: u24) void {
    dest[0] = @intCast(val >> 16);
    dest[1] = @intCast((val >> 8) & 0xFF);
    dest[2] = @intCast(val & 0xFF);
}
