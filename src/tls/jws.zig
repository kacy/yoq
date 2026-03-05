// jws — JSON Web Signature for ACME protocol
//
// constructs JWS (RFC 7515) messages for ACME API interactions.
// ACME requires all requests to be signed using a JWS with a
// flattened JSON serialization.
//
// uses ECDSA P-256 with SHA-256 (ES256) — the most widely supported
// algorithm for ACME and the simplest to implement.
//
// references:
//   RFC 7515 (JSON Web Signature)
//   RFC 7517 (JSON Web Key)
//   RFC 7638 (JWK Thumbprint)
//   RFC 8555 §6.2 (ACME request authentication)

const std = @import("std");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const JwsError = error{
    SigningFailed,
    EncodingFailed,
    AllocFailed,
};

/// base64url-encode data (no padding, per RFC 7515 §2).
pub fn base64urlEncode(allocator: std.mem.Allocator, data: []const u8) JwsError![]u8 {
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const len = encoder.calcSize(data.len);
    const buf = allocator.alloc(u8, len) catch return JwsError.AllocFailed;
    _ = encoder.encode(buf, data);
    return buf;
}

/// compute the JWK thumbprint of an EC P-256 public key (RFC 7638).
/// this is the SHA-256 hash of the canonical JSON representation of
/// the JWK, with members sorted lexicographically.
///
/// for EC P-256: {"crv":"P-256","kty":"EC","x":"...","y":"..."}
pub fn jwkThumbprint(allocator: std.mem.Allocator, public_key: EcdsaP256.PublicKey) JwsError![]u8 {
    const uncompressed = public_key.toUncompressedSec1();
    // uncompressed SEC1: 0x04 + x(32) + y(32)
    const x = uncompressed[1..33];
    const y = uncompressed[33..65];

    const x_b64 = try base64urlEncode(allocator, x);
    defer allocator.free(x_b64);
    const y_b64 = try base64urlEncode(allocator, y);
    defer allocator.free(y_b64);

    // canonical JSON with lexicographic key order
    var json_buf: [256]u8 = undefined;
    const json = std.fmt.bufPrint(&json_buf, "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ x_b64, y_b64 }) catch
        return JwsError.EncodingFailed;

    var hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(json, &hash, .{});

    return base64urlEncode(allocator, &hash);
}

/// build the JWK (JSON Web Key) object for an EC P-256 public key.
/// returns a JSON string like {"kty":"EC","crv":"P-256","x":"...","y":"..."}.
pub fn buildJwk(allocator: std.mem.Allocator, public_key: EcdsaP256.PublicKey) JwsError![]u8 {
    const uncompressed = public_key.toUncompressedSec1();
    const x = uncompressed[1..33];
    const y = uncompressed[33..65];

    const x_b64 = try base64urlEncode(allocator, x);
    defer allocator.free(x_b64);
    const y_b64 = try base64urlEncode(allocator, y);
    defer allocator.free(y_b64);

    var buf: [256]u8 = undefined;
    const json = std.fmt.bufPrint(&buf, "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{s}\",\"y\":\"{s}\"}}", .{ x_b64, y_b64 }) catch
        return JwsError.EncodingFailed;

    return allocator.dupe(u8, json) catch return JwsError.AllocFailed;
}

/// build and sign a JWS with flattened JSON serialization.
///
/// ACME uses two header formats:
///   - new account: protected header has "jwk" (full public key)
///   - all others:  protected header has "kid" (account URL)
///
/// returns a JSON string: {"protected":"...","payload":"...","signature":"..."}
/// caller owns the returned memory.
pub fn signJws(
    allocator: std.mem.Allocator,
    key_pair: EcdsaP256.KeyPair,
    url: []const u8,
    nonce: []const u8,
    payload: []const u8,
    kid: ?[]const u8,
) JwsError![]u8 {
    // build protected header
    const protected = if (kid) |k|
        try buildProtectedWithKid(allocator, k, nonce, url)
    else
        try buildProtectedWithJwk(allocator, key_pair.public_key, nonce, url);
    defer allocator.free(protected);

    // base64url-encode protected header and payload
    const protected_b64 = try base64urlEncode(allocator, protected);
    defer allocator.free(protected_b64);

    const payload_b64 = try base64urlEncode(allocator, payload);
    defer allocator.free(payload_b64);

    // signing input: base64url(header) + "." + base64url(payload)
    const signing_input_len = protected_b64.len + 1 + payload_b64.len;
    const signing_input = allocator.alloc(u8, signing_input_len) catch
        return JwsError.AllocFailed;
    defer allocator.free(signing_input);

    @memcpy(signing_input[0..protected_b64.len], protected_b64);
    signing_input[protected_b64.len] = '.';
    @memcpy(signing_input[protected_b64.len + 1 ..], payload_b64);

    // sign with ECDSA P-256
    const sig = key_pair.sign(signing_input, null) catch
        return JwsError.SigningFailed;
    const sig_bytes = sig.toBytes();
    const sig_b64 = try base64urlEncode(allocator, &sig_bytes);
    defer allocator.free(sig_b64);

    // build flattened JWS JSON
    return std.fmt.allocPrint(allocator, "{{\"protected\":\"{s}\",\"payload\":\"{s}\",\"signature\":\"{s}\"}}", .{
        protected_b64,
        payload_b64,
        sig_b64,
    }) catch return JwsError.AllocFailed;
}

// -- internal --

fn buildProtectedWithJwk(
    allocator: std.mem.Allocator,
    public_key: EcdsaP256.PublicKey,
    nonce: []const u8,
    url: []const u8,
) JwsError![]u8 {
    const jwk = try buildJwk(allocator, public_key);
    defer allocator.free(jwk);

    return std.fmt.allocPrint(allocator, "{{\"alg\":\"ES256\",\"jwk\":{s},\"nonce\":\"{s}\",\"url\":\"{s}\"}}", .{
        jwk,
        nonce,
        url,
    }) catch return JwsError.AllocFailed;
}

fn buildProtectedWithKid(
    allocator: std.mem.Allocator,
    kid: []const u8,
    nonce: []const u8,
    url: []const u8,
) JwsError![]u8 {
    return std.fmt.allocPrint(allocator, "{{\"alg\":\"ES256\",\"kid\":\"{s}\",\"nonce\":\"{s}\",\"url\":\"{s}\"}}", .{
        kid,
        nonce,
        url,
    }) catch return JwsError.AllocFailed;
}

// -- tests --

test "base64url encode" {
    const alloc = std.testing.allocator;

    const result = try base64urlEncode(alloc, "hello");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("aGVsbG8", result);
}

test "base64url encode empty" {
    const alloc = std.testing.allocator;

    const result = try base64urlEncode(alloc, "");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "base64url no padding" {
    const alloc = std.testing.allocator;

    // "a" base64 would be "YQ==" but base64url-no-pad should be "YQ"
    const result = try base64urlEncode(alloc, "a");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("YQ", result);
}

test "buildJwk produces valid JSON" {
    const alloc = std.testing.allocator;

    const kp = EcdsaP256.KeyPair.generate();
    const jwk = try buildJwk(alloc, kp.public_key);
    defer alloc.free(jwk);

    // should contain required JWK fields
    try std.testing.expect(std.mem.indexOf(u8, jwk, "\"kty\":\"EC\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, jwk, "\"crv\":\"P-256\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, jwk, "\"x\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, jwk, "\"y\":\"") != null);
}

test "jwkThumbprint is deterministic" {
    const alloc = std.testing.allocator;

    const kp = EcdsaP256.KeyPair.generate();

    const t1 = try jwkThumbprint(alloc, kp.public_key);
    defer alloc.free(t1);
    const t2 = try jwkThumbprint(alloc, kp.public_key);
    defer alloc.free(t2);

    try std.testing.expectEqualStrings(t1, t2);
}

test "jwkThumbprint is base64url" {
    const alloc = std.testing.allocator;

    const kp = EcdsaP256.KeyPair.generate();
    const thumbprint = try jwkThumbprint(alloc, kp.public_key);
    defer alloc.free(thumbprint);

    // base64url uses A-Z a-z 0-9 - _ (no + / =)
    for (thumbprint) |c| {
        try std.testing.expect(std.ascii.isAlphanumeric(c) or c == '-' or c == '_');
    }
}

test "signJws with JWK header" {
    const alloc = std.testing.allocator;

    const kp = EcdsaP256.KeyPair.generate();

    const jws = try signJws(
        alloc,
        kp,
        "https://acme.example.com/new-acct",
        "test-nonce-123",
        "{\"termsOfServiceAgreed\":true}",
        null, // no kid — uses jwk header
    );
    defer alloc.free(jws);

    // should be valid flattened JWS JSON
    try std.testing.expect(std.mem.indexOf(u8, jws, "\"protected\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, jws, "\"payload\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, jws, "\"signature\":\"") != null);
}

test "signJws with kid header" {
    const alloc = std.testing.allocator;

    const kp = EcdsaP256.KeyPair.generate();

    const jws = try signJws(
        alloc,
        kp,
        "https://acme.example.com/new-order",
        "test-nonce-456",
        "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"example.com\"}]}",
        "https://acme.example.com/acct/12345",
    );
    defer alloc.free(jws);

    try std.testing.expect(std.mem.indexOf(u8, jws, "\"protected\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, jws, "\"payload\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, jws, "\"signature\":\"") != null);
}

test "signJws signature verifies" {
    const alloc = std.testing.allocator;

    const kp = EcdsaP256.KeyPair.generate();
    const payload = "test payload";
    const url = "https://example.com/acme";
    const nonce = "nonce1";

    const jws = try signJws(alloc, kp, url, nonce, payload, null);
    defer alloc.free(jws);

    // extract the protected, payload, and signature parts
    // find the base64url strings between quotes
    const prot_start = (std.mem.indexOf(u8, jws, "\"protected\":\"") orelse unreachable) + "\"protected\":\"".len;
    const prot_end = std.mem.indexOfPos(u8, jws, prot_start, "\"") orelse unreachable;
    const protected_b64 = jws[prot_start..prot_end];

    const pay_start = (std.mem.indexOf(u8, jws, "\"payload\":\"") orelse unreachable) + "\"payload\":\"".len;
    const pay_end = std.mem.indexOfPos(u8, jws, pay_start, "\"") orelse unreachable;
    const payload_b64 = jws[pay_start..pay_end];

    const sig_start = (std.mem.indexOf(u8, jws, "\"signature\":\"") orelse unreachable) + "\"signature\":\"".len;
    const sig_end = std.mem.indexOfPos(u8, jws, sig_start, "\"") orelse unreachable;
    const sig_b64 = jws[sig_start..sig_end];

    // reconstruct signing input
    const signing_input = try std.fmt.allocPrint(alloc, "{s}.{s}", .{ protected_b64, payload_b64 });
    defer alloc.free(signing_input);

    // decode and verify signature
    const decoder = std.base64.url_safe_no_pad.Decoder;
    var sig_bytes: [EcdsaP256.Signature.encoded_length]u8 = undefined;
    decoder.decode(&sig_bytes, sig_b64) catch unreachable;
    const sig = EcdsaP256.Signature.fromBytes(sig_bytes);

    // verify the signature with the public key
    sig.verify(signing_input, kp.public_key) catch {
        return error.TestUnexpectedResult;
    };
}
