// message_parse — TLS 1.3 handshake message parsers.
//
// these mirror the senders in `message_build.zig`. they cover the messages
// the client driver in PR 4 needs to read off the wire (ServerHello,
// EncryptedExtensions, Certificate, CertificateVerify, Finished,
// CertificateRequest) and a small "walk a handshake-stream" iterator since
// TLS 1.3 packs several handshake messages into a single encrypted record.
//
// scope is intentionally narrow: we only accept the AES-256-GCM /
// X25519 / TLS 1.3 / ECDSA-SHA256 profile that the existing server speaks.
// anything else is rejected as malformed.

const std = @import("std");
const common = @import("common.zig");

pub const ParseError = error{
    Truncated,
    UnsupportedMessageType,
    UnsupportedVersion,
    UnsupportedCipher,
    UnsupportedKeyShare,
    MissingKeyShare,
    InvalidLength,
    InvalidStructure,
};

pub const HandshakeType = enum(u8) {
    server_hello = 0x02,
    encrypted_extensions = 0x08,
    certificate = 0x0B,
    certificate_request = 0x0D,
    certificate_verify = 0x0F,
    finished = 0x14,
};

pub const Message = struct {
    msg_type: u8,
    body: []const u8,
    /// the full message bytes including the 4-byte header. the transcript
    /// hash is computed over this slice on both sides of the handshake.
    raw: []const u8,
};

/// step through a stream of concatenated handshake messages (e.g. the
/// plaintext that came out of a single decrypted record). returns null when
/// the stream is exhausted. on a truncated tail this returns `Truncated`.
pub fn nextMessage(stream: []const u8, pos: *usize) ParseError!?Message {
    if (pos.* == stream.len) return null;
    if (pos.* + 4 > stream.len) return ParseError.Truncated;

    const t = stream[pos.*];
    const body_len = (@as(usize, stream[pos.* + 1]) << 16) |
        (@as(usize, stream[pos.* + 2]) << 8) |
        @as(usize, stream[pos.* + 3]);

    const total = 4 + body_len;
    if (pos.* + total > stream.len) return ParseError.Truncated;

    const msg: Message = .{
        .msg_type = t,
        .body = stream[pos.* + 4 .. pos.* + total],
        .raw = stream[pos.* .. pos.* + total],
    };
    pos.* += total;
    return msg;
}

pub const ServerHelloFields = struct {
    server_random: [32]u8,
    /// the server's X25519 share (always 32 bytes for X25519).
    x25519_pub: [32]u8,
    cipher_suite: u16,
};

/// parse a ServerHello body (i.e. the bytes after the 4-byte handshake
/// header). enforces TLS 1.3, AES-256-GCM, and an X25519 key share —
/// anything else is rejected.
pub fn parseServerHello(body: []const u8) ParseError!ServerHelloFields {
    if (body.len < 2 + 32 + 1) return ParseError.Truncated;
    var pos: usize = 0;

    // legacy_version (must be TLS 1.2 on the wire; supported_versions
    // extension carries the real version)
    if (body[pos] != 0x03 or body[pos + 1] != 0x03) return ParseError.UnsupportedVersion;
    pos += 2;

    var server_random: [32]u8 = undefined;
    @memcpy(&server_random, body[pos .. pos + 32]);
    pos += 32;

    const sid_len = body[pos];
    pos += 1;
    if (pos + sid_len > body.len) return ParseError.Truncated;
    pos += sid_len;

    if (pos + 2 + 1 + 2 > body.len) return ParseError.Truncated;
    const cipher = common.readU16(body[pos..]);
    pos += 2;
    if (cipher != common.cipher_suite_aes_256_gcm) return ParseError.UnsupportedCipher;

    if (body[pos] != 0) return ParseError.InvalidStructure; // legacy_compression_method
    pos += 1;

    const ext_len = common.readU16(body[pos..]);
    pos += 2;
    if (pos + ext_len > body.len) return ParseError.Truncated;
    const exts = body[pos .. pos + ext_len];

    var found_tls13 = false;
    var x25519_pub: ?[32]u8 = null;

    var ep: usize = 0;
    while (ep < exts.len) {
        if (ep + 4 > exts.len) return ParseError.Truncated;
        const ext_type = common.readU16(exts[ep..]);
        ep += 2;
        const ext_data_len = common.readU16(exts[ep..]);
        ep += 2;
        if (ep + ext_data_len > exts.len) return ParseError.Truncated;
        const ext_data = exts[ep .. ep + ext_data_len];
        ep += ext_data_len;

        switch (ext_type) {
            0x002B => {
                // supported_versions — server picks one. 2 bytes, must be 0x0304.
                if (ext_data.len != 2) return ParseError.InvalidStructure;
                if (common.readU16(ext_data) != 0x0304) return ParseError.UnsupportedVersion;
                found_tls13 = true;
            },
            0x0033 => {
                // key_share — server's chosen share: u16 group, u16 len, bytes
                if (ext_data.len < 4) return ParseError.InvalidStructure;
                const group = common.readU16(ext_data);
                if (group != 0x001D) return ParseError.UnsupportedKeyShare; // X25519
                const key_len = common.readU16(ext_data[2..]);
                if (key_len != 32 or 4 + key_len != ext_data.len) return ParseError.InvalidStructure;
                var pk: [32]u8 = undefined;
                @memcpy(&pk, ext_data[4 .. 4 + 32]);
                x25519_pub = pk;
            },
            else => {},
        }
    }

    if (!found_tls13) return ParseError.UnsupportedVersion;
    return .{
        .server_random = server_random,
        .x25519_pub = x25519_pub orelse return ParseError.MissingKeyShare,
        .cipher_suite = @intCast(cipher),
    };
}

pub const EncryptedExtensionsFields = struct {
    selected_alpn: ?[]const u8,
};

/// parse EncryptedExtensions. only ALPN is recognized; everything else is
/// skipped without complaint (server might send extensions we don't care
/// about).
pub fn parseEncryptedExtensions(body: []const u8) ParseError!EncryptedExtensionsFields {
    if (body.len < 2) return ParseError.Truncated;
    const ext_len = common.readU16(body);
    if (2 + ext_len > body.len) return ParseError.Truncated;
    const exts = body[2 .. 2 + ext_len];

    var selected_alpn: ?[]const u8 = null;
    var ep: usize = 0;
    while (ep < exts.len) {
        if (ep + 4 > exts.len) return ParseError.Truncated;
        const ext_type = common.readU16(exts[ep..]);
        ep += 2;
        const ext_data_len = common.readU16(exts[ep..]);
        ep += 2;
        if (ep + ext_data_len > exts.len) return ParseError.Truncated;
        const ext_data = exts[ep .. ep + ext_data_len];
        ep += ext_data_len;

        if (ext_type == 0x0010 and ext_data.len >= 3) {
            // ALPN: u16 list_len, u8 proto_len, proto_bytes
            const list_len = common.readU16(ext_data);
            if (2 + list_len > ext_data.len) return ParseError.InvalidStructure;
            const proto_len = ext_data[2];
            if (3 + proto_len > ext_data.len) return ParseError.InvalidStructure;
            selected_alpn = ext_data[3 .. 3 + proto_len];
        }
    }

    return .{ .selected_alpn = selected_alpn };
}

/// parse a TLS 1.3 Certificate message body. returns the leaf cert DER
/// (the first cert in the chain). PR 4 only supports single-cert chains —
/// matches what x509_gen issues and what the existing server emits.
pub fn parseCertificateMessage(body: []const u8) ParseError![]const u8 {
    if (body.len < 1 + 3 + 3 + 2) return ParseError.Truncated;
    var pos: usize = 0;
    const ctx_len = body[pos];
    pos += 1;
    if (pos + ctx_len > body.len) return ParseError.Truncated;
    pos += ctx_len;

    if (pos + 3 > body.len) return ParseError.Truncated;
    const list_len = readU24(body[pos..]);
    pos += 3;
    if (pos + list_len > body.len) return ParseError.Truncated;
    const list_end = pos + list_len;

    if (pos + 3 > list_end) return ParseError.Truncated;
    const cert_len = readU24(body[pos..]);
    pos += 3;
    if (pos + cert_len > list_end) return ParseError.Truncated;
    const cert = body[pos .. pos + cert_len];
    pos += cert_len;

    if (pos + 2 > list_end) return ParseError.Truncated;
    // skip per-cert extensions

    return cert;
}

pub const CertificateVerifyFields = struct {
    algorithm: u16,
    signature_der: []const u8,
};

pub fn parseCertificateVerify(body: []const u8) ParseError!CertificateVerifyFields {
    if (body.len < 4) return ParseError.Truncated;
    const algo = common.readU16(body);
    const sig_len = common.readU16(body[2..]);
    if (4 + sig_len != body.len) return ParseError.InvalidLength;
    return .{
        .algorithm = @intCast(algo),
        .signature_der = body[4 .. 4 + sig_len],
    };
}

pub const FinishedFields = struct {
    verify_data: []const u8,
};

pub fn parseFinished(body: []const u8) ParseError!FinishedFields {
    if (body.len == 0) return ParseError.Truncated;
    return .{ .verify_data = body };
}

pub const CertificateRequestFields = struct {
    /// the request context — typically empty in TLS 1.3.
    context: []const u8,
    /// raw SignatureSchemeList bytes (each scheme is 2 bytes). PR 4 only
    /// inspects whether ECDSA P-256 SHA-256 is offered.
    signature_algorithms: []const u8,
};

pub fn parseCertificateRequest(body: []const u8) ParseError!CertificateRequestFields {
    if (body.len < 1) return ParseError.Truncated;
    const ctx_len = body[0];
    if (1 + ctx_len + 2 > body.len) return ParseError.Truncated;
    const context = body[1 .. 1 + ctx_len];

    var pos: usize = 1 + ctx_len;
    const ext_len = common.readU16(body[pos..]);
    pos += 2;
    if (pos + ext_len > body.len) return ParseError.Truncated;
    const exts = body[pos .. pos + ext_len];

    var sigs: []const u8 = &.{};
    var ep: usize = 0;
    while (ep < exts.len) {
        if (ep + 4 > exts.len) return ParseError.Truncated;
        const ext_type = common.readU16(exts[ep..]);
        ep += 2;
        const ext_data_len = common.readU16(exts[ep..]);
        ep += 2;
        if (ep + ext_data_len > exts.len) return ParseError.Truncated;
        const ext_data = exts[ep .. ep + ext_data_len];
        ep += ext_data_len;

        if (ext_type == 0x000D) {
            if (ext_data.len < 2) return ParseError.InvalidStructure;
            const list_len = common.readU16(ext_data);
            if (2 + list_len > ext_data.len) return ParseError.InvalidStructure;
            sigs = ext_data[2 .. 2 + list_len];
        }
    }

    return .{ .context = context, .signature_algorithms = sigs };
}

/// returns true when the server's CertificateRequest advertised ECDSA P-256
/// with SHA-256 — the only scheme our cert minter produces.
pub fn certRequestOffersEcdsaP256Sha256(req: CertificateRequestFields) bool {
    var i: usize = 0;
    while (i + 2 <= req.signature_algorithms.len) : (i += 2) {
        const scheme = common.readU16(req.signature_algorithms[i..]);
        if (scheme == 0x0403) return true; // ecdsa_secp256r1_sha256
    }
    return false;
}

fn readU24(data: []const u8) usize {
    return (@as(usize, data[0]) << 16) | (@as(usize, data[1]) << 8) | @as(usize, data[2]);
}

// --- tests ---

const message_build = @import("message_build.zig");

test "ServerHello round-trips through the builder" {
    var buf: [256]u8 = undefined;
    const server_random = [_]u8{0xAB} ** 32;
    const server_pub = [_]u8{0xCD} ** 32;
    const len = try message_build.buildServerHello(&buf, [_]u8{0} ** 32, server_random, &.{}, server_pub);

    // skip the 4-byte handshake header (type + u24 len) to get the body
    const got = try parseServerHello(buf[4..len]);
    try std.testing.expectEqualSlices(u8, &server_random, &got.server_random);
    try std.testing.expectEqualSlices(u8, &server_pub, &got.x25519_pub);
    try std.testing.expectEqual(@as(u16, common.cipher_suite_aes_256_gcm), got.cipher_suite);
}

test "EncryptedExtensions round-trips with ALPN" {
    var buf: [128]u8 = undefined;
    const alpn = "h2";
    const len = try message_build.buildEncryptedExtensions(&buf, alpn);
    const got = try parseEncryptedExtensions(buf[4..len]);
    try std.testing.expect(got.selected_alpn != null);
    try std.testing.expectEqualStrings(alpn, got.selected_alpn.?);
}

test "EncryptedExtensions with no ALPN" {
    var buf: [128]u8 = undefined;
    const len = try message_build.buildEncryptedExtensions(&buf, null);
    const got = try parseEncryptedExtensions(buf[4..len]);
    try std.testing.expect(got.selected_alpn == null);
}

test "Certificate round-trips a single leaf" {
    var buf: [256]u8 = undefined;
    const cert_der = [_]u8{ 0x30, 0x81, 0x80, 0xAA, 0xBB, 0xCC, 0xDD };
    const len = try message_build.buildCertificate(&buf, &cert_der);
    const got = try parseCertificateMessage(buf[4..len]);
    try std.testing.expectEqualSlices(u8, &cert_der, got);
}

test "nextMessage walks a packed stream" {
    var buf: [512]u8 = undefined;
    const cert_der = [_]u8{ 0x30, 0x42 };
    var pos: usize = 0;
    const a = try message_build.buildEncryptedExtensions(buf[pos..], "h2");
    pos += a;
    const b = try message_build.buildCertificate(buf[pos..], &cert_der);
    pos += b;
    const c = try message_build.buildFinished(buf[pos..], [_]u8{0xFF} ** common.hash_len);
    pos += c;

    var rp: usize = 0;
    const m1 = (try nextMessage(buf[0..pos], &rp)).?;
    try std.testing.expectEqual(@as(u8, 0x08), m1.msg_type);
    const m2 = (try nextMessage(buf[0..pos], &rp)).?;
    try std.testing.expectEqual(@as(u8, 0x0B), m2.msg_type);
    const m3 = (try nextMessage(buf[0..pos], &rp)).?;
    try std.testing.expectEqual(@as(u8, 0x14), m3.msg_type);
    try std.testing.expect((try nextMessage(buf[0..pos], &rp)) == null);
}

test "Finished returns the verify data slice" {
    var buf: [128]u8 = undefined;
    const verify = [_]u8{0x42} ** common.hash_len;
    const len = try message_build.buildFinished(&buf, verify);
    const got = try parseFinished(buf[4..len]);
    try std.testing.expectEqualSlices(u8, &verify, got.verify_data);
}

test "Truncated message returns error" {
    var pos: usize = 0;
    try std.testing.expectError(ParseError.Truncated, nextMessage(&[_]u8{ 0x08, 0x00 }, &pos));

    // a header that promises more body than the buffer contains
    var pos2: usize = 0;
    try std.testing.expectError(ParseError.Truncated, nextMessage(&[_]u8{ 0x08, 0x00, 0x00, 0x05, 0x00 }, &pos2));
}

test "CertificateRequest with ecdsa-sha256 offer parses and matches" {
    // hand-build a CertificateRequest body: empty context, single
    // signature_algorithms extension carrying just 0x0403.
    var body_buf: [32]u8 = undefined;
    var pos: usize = 0;
    body_buf[pos] = 0; // context len
    pos += 1;
    const ext_len: u16 = 2 + 2 + 2 + 2; // type + len + list_len + one scheme
    common.writeU16(body_buf[pos..], ext_len);
    pos += 2;
    common.writeU16(body_buf[pos..], 0x000D); // signature_algorithms
    pos += 2;
    common.writeU16(body_buf[pos..], 2 + 2); // ext_data_len = list_len + 2
    pos += 2;
    common.writeU16(body_buf[pos..], 2); // list_len
    pos += 2;
    common.writeU16(body_buf[pos..], 0x0403); // ecdsa_secp256r1_sha256
    pos += 2;

    const got = try parseCertificateRequest(body_buf[0..pos]);
    try std.testing.expectEqual(@as(usize, 0), got.context.len);
    try std.testing.expect(certRequestOffersEcdsaP256Sha256(got));
}
