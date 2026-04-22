// pem — PEM private key and certificate parser
//
// parses PEM-encoded EC P-256 private keys (SEC1 / PKCS#8) and
// X.509 certificates, extracting raw DER bytes suitable for TLS
// handshake operations.
//
// handles two private key formats:
//   - SEC1 (RFC 5915): "-----BEGIN EC PRIVATE KEY-----"
//     SEQUENCE { version, privateKey OCTET STRING(32), ... }
//   - PKCS#8 (RFC 5958): "-----BEGIN PRIVATE KEY-----"
//     SEQUENCE { version, algorithm, privateKey OCTET STRING { SEC1 } }
//
// uses a minimal ASN.1 TLV parser — just tag + length + content.
// all intermediate buffers containing key material are securely zeroed.
//
// references:
//   RFC 5915 (EC Private Key Structure)
//   RFC 5958 (PKCS#8)
//   RFC 7468 (PEM encoding)

const std = @import("std");
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const PemError = error{
    InvalidPem,
    InvalidDer,
    UnsupportedKeyType,
    Base64DecodeFailed,
    BufferTooSmall,
};

/// parse a PEM-encoded EC P-256 private key into a SecretKey.
///
/// accepts both SEC1 ("EC PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") formats.
/// securely zeroes intermediate buffers containing key material.
pub fn parseEcPrivateKey(pem: []const u8) PemError!EcdsaP256.SecretKey {
    // strip PEM headers and decode base64
    var der_buf: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &der_buf);

    const der = stripPemAndDecode(pem, "PRIVATE KEY", "EC PRIVATE KEY", &der_buf) catch
        return PemError.InvalidPem;

    // parse the DER to extract the 32-byte secret key
    const key_bytes = extractEcKeyBytes(der) catch return PemError.InvalidDer;

    var key_copy: [32]u8 = key_bytes[0..32].*;
    defer std.crypto.secureZero(u8, &key_copy);

    return EcdsaP256.SecretKey.fromBytes(key_copy) catch PemError.InvalidDer;
}

/// parse a PEM-encoded certificate and return the raw DER bytes.
///
/// caller owns the returned memory.
pub fn parseCertDer(allocator: std.mem.Allocator, pem: []const u8) ![]u8 {
    // certificates can be large — use a heap buffer
    const header = "-----BEGIN CERTIFICATE-----";
    const footer = "-----END CERTIFICATE-----";

    const header_end = std.mem.indexOf(u8, pem, header) orelse return error.InvalidPem;
    const body_start = header_end + header.len;
    const footer_start = std.mem.indexOfPos(u8, pem, body_start, footer) orelse return error.InvalidPem;

    // extract the base64 body, skipping whitespace
    const b64_body = pem[body_start..footer_start];

    // estimate decoded size (3/4 of base64 length, roughly)
    const max_decoded = b64_body.len;
    const decoded = try allocator.alloc(u8, max_decoded);
    errdefer allocator.free(decoded);

    // filter out whitespace and decode
    var filtered_buf = try allocator.alloc(u8, b64_body.len);
    defer allocator.free(filtered_buf);
    var filtered_len: usize = 0;
    for (b64_body) |c| {
        if (c != '\n' and c != '\r' and c != ' ' and c != '\t') {
            filtered_buf[filtered_len] = c;
            filtered_len += 1;
        }
    }

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(filtered_buf[0..filtered_len]) catch
        return error.Base64DecodeFailed;
    if (decoded_len > decoded.len) return error.BufferTooSmall;

    std.base64.standard.Decoder.decode(decoded[0..decoded_len], filtered_buf[0..filtered_len]) catch
        return error.Base64DecodeFailed;

    // shrink to actual size
    if (decoded_len < decoded.len) {
        const exact = try allocator.realloc(decoded, decoded_len);
        return exact;
    }

    return decoded[0..decoded_len];
}

// -- internal --

/// strip PEM header/footer and base64-decode into a stack buffer.
/// tries primary_type first, then fallback_type.
fn stripPemAndDecode(
    pem: []const u8,
    comptime primary_type: []const u8,
    comptime fallback_type: []const u8,
    out: []u8,
) PemError![]u8 {
    const primary_header = "-----BEGIN " ++ primary_type ++ "-----";
    const primary_footer = "-----END " ++ primary_type ++ "-----";
    const fallback_header = "-----BEGIN " ++ fallback_type ++ "-----";
    const fallback_footer = "-----END " ++ fallback_type ++ "-----";

    var body_start: usize = undefined;
    var footer_start: usize = undefined;

    if (std.mem.indexOf(u8, pem, primary_header)) |h| {
        body_start = h + primary_header.len;
        footer_start = std.mem.indexOfPos(u8, pem, body_start, primary_footer) orelse
            return PemError.InvalidPem;
    } else if (std.mem.indexOf(u8, pem, fallback_header)) |h| {
        body_start = h + fallback_header.len;
        footer_start = std.mem.indexOfPos(u8, pem, body_start, fallback_footer) orelse
            return PemError.InvalidPem;
    } else {
        return PemError.InvalidPem;
    }

    const b64_body = pem[body_start..footer_start];

    // filter whitespace
    var filtered: [2048]u8 = undefined;
    var flen: usize = 0;
    for (b64_body) |c| {
        if (c != '\n' and c != '\r' and c != ' ' and c != '\t') {
            if (flen >= filtered.len) return PemError.InvalidPem;
            filtered[flen] = c;
            flen += 1;
        }
    }

    const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(filtered[0..flen]) catch
        return PemError.Base64DecodeFailed;
    if (decoded_len > out.len) return PemError.BufferTooSmall;

    std.base64.standard.Decoder.decode(out[0..decoded_len], filtered[0..flen]) catch
        return PemError.Base64DecodeFailed;

    return out[0..decoded_len];
}

/// extract the raw 32-byte EC key from DER (handles both SEC1 and PKCS#8).
fn extractEcKeyBytes(der: []const u8) PemError![]const u8 {
    if (der.len < 2) return PemError.InvalidDer;

    // must start with SEQUENCE tag
    if (der[0] != 0x30) return PemError.InvalidDer;

    const seq_content = readTlvContent(der) catch return PemError.InvalidDer;

    // peek at first element — if it's an INTEGER with value 0 or 1,
    // we need to figure out if it's SEC1 or PKCS#8
    if (seq_content.len < 3) return PemError.InvalidDer;

    // check for INTEGER tag
    if (seq_content[0] != 0x02) return PemError.InvalidDer;
    const version_content = readTlvContent(seq_content) catch return PemError.InvalidDer;
    const version_len = tlvTotalLen(seq_content) catch return PemError.InvalidDer;

    if (version_content.len != 1) return PemError.InvalidDer;
    const version = version_content[0];

    const after_version = seq_content[version_len..];

    if (version == 1) {
        // SEC1: version 1, next element is OCTET STRING with the key
        return extractOctetString(after_version);
    } else if (version == 0) {
        // PKCS#8: version 0, next is algorithm SEQUENCE, then OCTET STRING
        // skip the algorithm identifier SEQUENCE
        if (after_version.len < 2 or after_version[0] != 0x30) return PemError.InvalidDer;
        const algo_len = tlvTotalLen(after_version) catch return PemError.InvalidDer;
        const after_algo = after_version[algo_len..];

        // next is OCTET STRING wrapping the SEC1 structure
        const inner_der = extractOctetString(after_algo) catch return PemError.InvalidDer;

        // the inner OCTET STRING contains a SEC1 ECPrivateKey
        if (inner_der.len < 2 or inner_der[0] != 0x30) return PemError.InvalidDer;
        const inner_seq = readTlvContent(inner_der) catch return PemError.InvalidDer;

        // skip version INTEGER
        if (inner_seq.len < 3 or inner_seq[0] != 0x02) return PemError.InvalidDer;
        const inner_ver_len = tlvTotalLen(inner_seq) catch return PemError.InvalidDer;
        const after_inner_ver = inner_seq[inner_ver_len..];

        return extractOctetString(after_inner_ver);
    }

    return PemError.UnsupportedKeyType;
}

/// read the content portion of a TLV (skip tag + length).
fn readTlvContent(data: []const u8) ![]const u8 {
    if (data.len < 2) return error.InvalidDer;

    const len_byte = data[1];
    if (len_byte < 0x80) {
        // short form
        const content_len = @as(usize, len_byte);
        const offset: usize = 2;
        if (offset + content_len > data.len) return error.InvalidDer;
        return data[offset .. offset + content_len];
    } else if (len_byte == 0x81) {
        // long form, 1 byte
        if (data.len < 3) return error.InvalidDer;
        const content_len = @as(usize, data[2]);
        const offset: usize = 3;
        if (offset + content_len > data.len) return error.InvalidDer;
        return data[offset .. offset + content_len];
    } else if (len_byte == 0x82) {
        // long form, 2 bytes
        if (data.len < 4) return error.InvalidDer;
        const content_len = (@as(usize, data[2]) << 8) | @as(usize, data[3]);
        const offset: usize = 4;
        if (offset + content_len > data.len) return error.InvalidDer;
        return data[offset .. offset + content_len];
    }

    return error.InvalidDer;
}

/// total length of a TLV element (tag + length bytes + content).
fn tlvTotalLen(data: []const u8) !usize {
    if (data.len < 2) return error.InvalidDer;

    const len_byte = data[1];
    if (len_byte < 0x80) {
        return 2 + @as(usize, len_byte);
    } else if (len_byte == 0x81) {
        if (data.len < 3) return error.InvalidDer;
        return 3 + @as(usize, data[2]);
    } else if (len_byte == 0x82) {
        if (data.len < 4) return error.InvalidDer;
        return 4 + ((@as(usize, data[2]) << 8) | @as(usize, data[3]));
    }

    return error.InvalidDer;
}

/// extract the content of an OCTET STRING (tag 0x04).
fn extractOctetString(data: []const u8) PemError![]const u8 {
    if (data.len < 2 or data[0] != 0x04) return PemError.InvalidDer;
    return readTlvContent(data) catch PemError.InvalidDer;
}

// -- tests --

test "parseEcPrivateKey round-trip with derKeyToPem" {
    const csr = @import("csr.zig");
    const alloc = std.testing.allocator;

    // generate a key and convert to PEM
    const kp = EcdsaP256.KeyPair.generate(@import("compat").io());
    const key_bytes = kp.secret_key.toBytes();
    const pem = try csr.derKeyToPem(alloc, &key_bytes);
    defer alloc.free(pem);

    // parse it back
    const recovered = try parseEcPrivateKey(pem);
    const recovered_bytes = recovered.toBytes();

    try std.testing.expectEqualSlices(u8, &key_bytes, &recovered_bytes);
}

test "parseEcPrivateKey rejects non-PEM input" {
    try std.testing.expectError(PemError.InvalidPem, parseEcPrivateKey("not a pem file"));
}

test "parseEcPrivateKey rejects RSA header" {
    const rsa_pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIB=\n-----END RSA PRIVATE KEY-----\n";
    try std.testing.expectError(PemError.InvalidPem, parseEcPrivateKey(rsa_pem));
}

test "parseCertDer strips PEM and decodes" {
    const alloc = std.testing.allocator;

    // construct a minimal PEM-wrapped cert (just base64 of a few bytes)
    const raw = [_]u8{ 0x30, 0x03, 0x01, 0x01, 0xFF }; // minimal SEQUENCE
    const encoder = std.base64.standard.Encoder;
    var b64_buf: [16]u8 = undefined;
    const b64 = encoder.encode(&b64_buf, &raw);

    const pem = try std.fmt.allocPrint(alloc, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{b64});
    defer alloc.free(pem);

    const der = try parseCertDer(alloc, pem);
    defer alloc.free(der);

    try std.testing.expectEqualSlices(u8, &raw, der);
}
