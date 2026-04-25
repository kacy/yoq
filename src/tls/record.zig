// record — TLS 1.3 record layer
//
// handles reading and writing TLS records with encryption. provides a
// TlsRecord abstraction for framing, and encrypt/decrypt functions for
// the application data layer using AES-256-GCM.
//
// TLS 1.3 records have a 5-byte header:
//   content_type(1) + legacy_version(2) + length(2)
// followed by the payload. encrypted records use content type 0x17
// (application_data) regardless of actual content, with the real
// content type appended as the last byte inside the ciphertext.
//
// references:
//   RFC 8446 §5 (Record Protocol)
//   RFC 8446 §5.2 (Record Payload Protection)

const std = @import("std");
const linux_platform = @import("linux_platform");

const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const max_record_size = 16384; // 2^14, per RFC 8446 §5.1
pub const max_ciphertext_size = max_record_size + 256; // with overhead
pub const record_header_size = 5;
pub const aead_tag_size = Aes256Gcm.tag_length; // 16
pub const aead_nonce_size = Aes256Gcm.nonce_length; // 12
pub const aead_key_size = Aes256Gcm.key_length; // 32

pub const ContentType = enum(u8) {
    change_cipher_spec = 20,
    alert = 21,
    handshake = 22,
    application_data = 23,
    _,
};

pub const RecordError = error{
    BufferTooShort,
    RecordTooLarge,
    DecryptionFailed,
    InvalidContentType,
    UnexpectedEof,
};

pub const RecordHeader = struct {
    content_type: ContentType,
    length: u16,
};

/// parse a TLS record header from the first 5 bytes.
pub fn parseHeader(data: []const u8) RecordError!RecordHeader {
    if (data.len < record_header_size) return RecordError.BufferTooShort;

    const length = (@as(u16, data[3]) << 8) | @as(u16, data[4]);
    if (length > max_ciphertext_size) return RecordError.RecordTooLarge;

    return .{
        .content_type = @enumFromInt(data[0]),
        .length = length,
    };
}

/// write a TLS record header into the buffer.
/// returns the 5-byte header.
pub fn writeHeader(buf: []u8, content_type: ContentType, payload_len: u16) RecordError!void {
    if (buf.len < record_header_size) return RecordError.BufferTooShort;

    buf[0] = @intFromEnum(content_type);
    buf[1] = 0x03; // legacy: TLS 1.2
    buf[2] = 0x03;
    buf[3] = @intCast(payload_len >> 8);
    buf[4] = @intCast(payload_len & 0xFF);
}

/// per-record nonce construction for TLS 1.3.
/// XORs the 64-bit sequence number with the IV (per RFC 8446 §5.3).
pub fn buildNonce(iv: [aead_nonce_size]u8, seq: u64) [aead_nonce_size]u8 {
    var nonce = iv;

    // XOR sequence number into the last 8 bytes of the IV
    const seq_bytes = std.mem.toBytes(std.mem.nativeTo(u64, seq, .big));
    for (0..8) |i| {
        nonce[4 + i] ^= seq_bytes[i];
    }

    return nonce;
}

/// encrypt a TLS 1.3 record payload.
///
/// the inner plaintext has the real content type appended as the last byte.
/// the output is: encrypted_data(N) + tag(16).
/// returns the total ciphertext length (plaintext_len + 1 + tag_size).
pub fn encryptRecord(
    key: [aead_key_size]u8,
    iv: [aead_nonce_size]u8,
    seq: u64,
    plaintext: []const u8,
    inner_type: ContentType,
    out: []u8,
) RecordError!usize {
    const inner_len = plaintext.len + 1; // +1 for content type byte
    const total_len = inner_len + aead_tag_size;

    if (out.len < total_len) return RecordError.BufferTooShort;
    if (inner_len > max_record_size) return RecordError.RecordTooLarge;

    // build inner plaintext: data + content_type byte
    @memcpy(out[0..plaintext.len], plaintext);
    out[plaintext.len] = @intFromEnum(inner_type);

    const nonce = buildNonce(iv, seq);

    // additional data is the record header (outer type 0x17 + version + length)
    const record_len: u16 = @intCast(total_len);
    const aad = [_]u8{
        0x17,                      0x03,                        0x03,
        @intCast(record_len >> 8), @intCast(record_len & 0xFF),
    };

    var tag: [aead_tag_size]u8 = undefined;
    Aes256Gcm.encrypt(
        out[0..inner_len],
        &tag,
        out[0..inner_len],
        &aad,
        nonce,
        key,
    );
    @memcpy(out[inner_len .. inner_len + aead_tag_size], &tag);

    return total_len;
}

/// decrypt a TLS 1.3 record payload.
///
/// `ciphertext` includes the authentication tag at the end.
/// returns the decrypted inner plaintext and the real content type.
/// the caller's buffer is written in-place.
pub fn decryptRecord(
    key: [aead_key_size]u8,
    iv: [aead_nonce_size]u8,
    seq: u64,
    ciphertext: []u8,
    record_header: [record_header_size]u8,
) RecordError!struct { plaintext: []u8, content_type: ContentType } {
    if (ciphertext.len < aead_tag_size + 1) return RecordError.BufferTooShort;

    const nonce = buildNonce(iv, seq);

    const ct_len = ciphertext.len - aead_tag_size;
    const tag = ciphertext[ct_len..][0..aead_tag_size];

    Aes256Gcm.decrypt(
        ciphertext[0..ct_len],
        ciphertext[0..ct_len],
        tag.*,
        &record_header,
        nonce,
        key,
    ) catch return RecordError.DecryptionFailed;

    // last byte of decrypted inner plaintext is the real content type
    // strip trailing zero padding (if any) per RFC 8446 §5.4
    var inner_len = ct_len;
    while (inner_len > 0 and ciphertext[inner_len - 1] == 0) {
        inner_len -= 1;
    }

    if (inner_len == 0) return RecordError.InvalidContentType;

    const real_type: ContentType = @enumFromInt(ciphertext[inner_len - 1]);
    return .{
        .plaintext = ciphertext[0 .. inner_len - 1],
        .content_type = real_type,
    };
}

// -- tests --

test "encrypt and decrypt round-trip" {
    var key: [aead_key_size]u8 = undefined;
    linux_platform.randomBytes(&key);

    var iv: [aead_nonce_size]u8 = undefined;
    linux_platform.randomBytes(&iv);

    const plaintext = "hello, TLS 1.3!";
    var out: [plaintext.len + 1 + aead_tag_size]u8 = undefined;

    const ct_len = try encryptRecord(key, iv, 0, plaintext, .application_data, &out);
    try std.testing.expectEqual(plaintext.len + 1 + aead_tag_size, ct_len);

    const record_len: u16 = @intCast(ct_len);
    const header = [_]u8{
        0x17,                      0x03,                        0x03,
        @intCast(record_len >> 8), @intCast(record_len & 0xFF),
    };

    const result = try decryptRecord(key, iv, 0, out[0..ct_len], header);
    try std.testing.expectEqualStrings(plaintext, result.plaintext);
    try std.testing.expectEqual(ContentType.application_data, result.content_type);
}

test "decrypt fails with wrong key" {
    var key: [aead_key_size]u8 = undefined;
    linux_platform.randomBytes(&key);
    var wrong_key: [aead_key_size]u8 = undefined;
    linux_platform.randomBytes(&wrong_key);

    var iv: [aead_nonce_size]u8 = undefined;
    linux_platform.randomBytes(&iv);

    const plaintext = "secret data";
    var out: [plaintext.len + 1 + aead_tag_size]u8 = undefined;
    const ct_len = try encryptRecord(key, iv, 0, plaintext, .application_data, &out);

    const record_len: u16 = @intCast(ct_len);
    const header = [_]u8{
        0x17,                      0x03,                        0x03,
        @intCast(record_len >> 8), @intCast(record_len & 0xFF),
    };

    try std.testing.expectError(
        RecordError.DecryptionFailed,
        decryptRecord(wrong_key, iv, 0, out[0..ct_len], header),
    );
}

test "decrypt fails with wrong sequence number" {
    var key: [aead_key_size]u8 = undefined;
    linux_platform.randomBytes(&key);
    var iv: [aead_nonce_size]u8 = undefined;
    linux_platform.randomBytes(&iv);

    const plaintext = "data";
    var out: [plaintext.len + 1 + aead_tag_size]u8 = undefined;
    const ct_len = try encryptRecord(key, iv, 42, plaintext, .application_data, &out);

    const record_len: u16 = @intCast(ct_len);
    const header = [_]u8{
        0x17,                      0x03,                        0x03,
        @intCast(record_len >> 8), @intCast(record_len & 0xFF),
    };

    // wrong sequence number
    try std.testing.expectError(
        RecordError.DecryptionFailed,
        decryptRecord(key, iv, 43, out[0..ct_len], header),
    );
}

test "nonce construction" {
    const iv = [_]u8{0} ** aead_nonce_size;

    const nonce0 = buildNonce(iv, 0);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** aead_nonce_size), &nonce0);

    const nonce1 = buildNonce(iv, 1);
    // last byte should be 1
    try std.testing.expectEqual(@as(u8, 1), nonce1[11]);
    try std.testing.expectEqual(@as(u8, 0), nonce1[10]);
}

test "nonce XOR with IV" {
    const iv = [_]u8{0xFF} ** aead_nonce_size;
    const nonce = buildNonce(iv, 0);

    // first 4 bytes unchanged (seq only affects last 8)
    try std.testing.expectEqual(@as(u8, 0xFF), nonce[0]);
    try std.testing.expectEqual(@as(u8, 0xFF), nonce[3]);
    // last 8 bytes: 0xFF XOR 0x00 = 0xFF
    try std.testing.expectEqual(@as(u8, 0xFF), nonce[11]);
}

test "record header parse" {
    const data = [_]u8{ 23, 0x03, 0x03, 0x00, 0x10 };
    const hdr = try parseHeader(&data);
    try std.testing.expectEqual(ContentType.application_data, hdr.content_type);
    try std.testing.expectEqual(@as(u16, 16), hdr.length);
}

test "record header too short" {
    const data = [_]u8{ 23, 0x03 };
    try std.testing.expectError(RecordError.BufferTooShort, parseHeader(&data));
}

test "encrypt preserves content type" {
    var key: [aead_key_size]u8 = undefined;
    linux_platform.randomBytes(&key);
    var iv: [aead_nonce_size]u8 = undefined;
    linux_platform.randomBytes(&iv);

    const plaintext = "handshake data";
    var out: [plaintext.len + 1 + aead_tag_size]u8 = undefined;
    const ct_len = try encryptRecord(key, iv, 5, plaintext, .handshake, &out);

    const record_len: u16 = @intCast(ct_len);
    const header = [_]u8{
        0x17,                      0x03,                        0x03,
        @intCast(record_len >> 8), @intCast(record_len & 0xFF),
    };

    const result = try decryptRecord(key, iv, 5, out[0..ct_len], header);
    try std.testing.expectEqual(ContentType.handshake, result.content_type);
    try std.testing.expectEqualStrings(plaintext, result.plaintext);
}
