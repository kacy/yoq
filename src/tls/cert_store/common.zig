const std = @import("std");

const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const key_length = XChaCha20Poly1305.key_length;
pub const nonce_length = XChaCha20Poly1305.nonce_length;
pub const tag_length = XChaCha20Poly1305.tag_length;

pub const CertError = error{
    KeyLoadFailed,
    KeyCreateFailed,
    EncryptionFailed,
    DecryptionFailed,
    WriteFailed,
    ReadFailed,
    NotFound,
    PathTooLong,
    HomeDirNotFound,
    AllocFailed,
    InvalidCert,
};

pub const CertInfo = struct {
    domain: []const u8,
    not_after: i64,
    source: []const u8,
    created_at: i64,

    pub fn deinit(self: CertInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.domain);
        allocator.free(self.source);
    }
};
