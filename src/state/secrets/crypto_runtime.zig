const std = @import("std");
const common = @import("common.zig");

const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub fn encrypt(allocator: std.mem.Allocator, plaintext: []const u8, key: [common.key_length]u8) !common.EncryptResult {
    const ciphertext = try allocator.alloc(u8, plaintext.len);
    errdefer allocator.free(ciphertext);

    var nonce: [common.nonce_length]u8 = undefined;
    @import("compat").randomBytes(&nonce);

    var tag: [common.tag_length]u8 = undefined;
    XChaCha20Poly1305.encrypt(ciphertext, &tag, plaintext, "", nonce, key);

    return .{
        .ciphertext = ciphertext,
        .nonce = nonce,
        .tag = tag,
    };
}

pub fn decrypt(
    allocator: std.mem.Allocator,
    ciphertext: []const u8,
    nonce: [common.nonce_length]u8,
    tag: [common.tag_length]u8,
    key: [common.key_length]u8,
) ![]u8 {
    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);

    XChaCha20Poly1305.decrypt(plaintext, ciphertext, tag, "", nonce, key) catch
        return error.AuthenticationFailed;

    return plaintext;
}
