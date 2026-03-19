const std = @import("std");

const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const key_length = XChaCha20Poly1305.key_length;
pub const nonce_length = XChaCha20Poly1305.nonce_length;
pub const tag_length = XChaCha20Poly1305.tag_length;

pub const SecretsError = error{
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
};

pub const EncryptResult = struct {
    ciphertext: []u8,
    nonce: [nonce_length]u8,
    tag: [tag_length]u8,
};
