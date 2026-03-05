// handshake — TLS 1.3 server-side handshake
//
// implements the TLS 1.3 full handshake (RFC 8446 §2):
//
//   Client                             Server
//   ------                             ------
//   ClientHello        -------->
//                                      ServerHello
//                                      EncryptedExtensions
//                                      Certificate
//                                      CertificateVerify
//                      <--------       Finished
//   Finished           -------->
//
// after the handshake, both sides derive application traffic keys
// for encrypted communication.
//
// supported:
//   - key exchange: X25519 (ECDHE)
//   - cipher: TLS_AES_256_GCM_SHA384 (0x1302)
//   - signature: ECDSA P-256 with SHA-256 (for CertificateVerify)
//
// this is a minimum viable TLS 1.3 implementation. it handles the
// common case (X25519 + AES-256-GCM) which covers the vast majority
// of real-world connections.
//
// references:
//   RFC 8446 (TLS 1.3)
//   RFC 7748 (X25519)

const std = @import("std");
const record = @import("record.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const X25519 = std.crypto.dh.X25519;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const HkdfSha384 = std.crypto.kdf.hkdf.Hkdf(HmacSha384);
const Sha384 = std.crypto.hash.sha2.Sha384;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

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

// -- cipher suite --

pub const cipher_suite_aes_256_gcm: u16 = 0x1302; // TLS_AES_256_GCM_SHA384

// -- key schedule --
//
// TLS 1.3 key schedule (RFC 8446 §7.1):
//
//   early_secret = HKDF-Extract(salt=0, IKM=0)      [no PSK]
//   handshake_secret = HKDF-Extract(salt=derived, IKM=shared_secret)
//   master_secret = HKDF-Extract(salt=derived, IKM=0)
//
// each stage derives traffic keys via HKDF-Expand-Label.

const hash_len = Sha384.digest_length; // 48

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

/// derive the early secret (no PSK — just zeros).
pub fn deriveEarlySecret() [hash_len]u8 {
    const zero_ikm = [_]u8{0} ** hash_len;
    const zero_salt = [_]u8{0} ** hash_len;
    return HkdfSha384.extract(&zero_salt, &zero_ikm);
}

/// derive the handshake secret from the shared ECDHE secret.
pub fn deriveHandshakeSecret(early_secret: [hash_len]u8, shared_secret: [32]u8) [hash_len]u8 {
    // derived_secret = Derive-Secret(early_secret, "derived", "")
    const empty_hash = hashEmpty();
    const derived = expandLabel(early_secret, "derived", &empty_hash, hash_len);

    // handshake_secret = HKDF-Extract(salt=derived, IKM=shared_secret)
    return HkdfSha384.extract(&derived, &shared_secret);
}

/// derive client and server handshake traffic secrets.
pub fn deriveHandshakeTrafficSecrets(
    handshake_secret: [hash_len]u8,
    transcript_hash: [hash_len]u8,
) HandshakeKeys {
    const c_hs = expandLabel(handshake_secret, "c hs traffic", &transcript_hash, hash_len);
    const s_hs = expandLabel(handshake_secret, "s hs traffic", &transcript_hash, hash_len);

    return .{
        .client_handshake_traffic_secret = c_hs,
        .server_handshake_traffic_secret = s_hs,
        .handshake_secret = handshake_secret,
    };
}

/// derive traffic keys (key + IV) from a traffic secret.
pub fn deriveTrafficKeys(secret: [hash_len]u8) TrafficKeys {
    const key = expandLabel(secret, "key", &.{}, record.aead_key_size);
    const iv = expandLabel(secret, "iv", &.{}, record.aead_nonce_size);

    return .{
        .key = key[0..record.aead_key_size].*,
        .iv = iv[0..record.aead_nonce_size].*,
    };
}

/// derive the master secret from the handshake secret.
pub fn deriveMasterSecret(handshake_secret: [hash_len]u8) [hash_len]u8 {
    const empty_hash = hashEmpty();
    const derived = expandLabel(handshake_secret, "derived", &empty_hash, hash_len);
    const zero_ikm = [_]u8{0} ** hash_len;
    return HkdfSha384.extract(&derived, &zero_ikm);
}

/// derive application traffic secrets from the master secret.
pub fn deriveApplicationSecrets(
    master_secret: [hash_len]u8,
    transcript_hash: [hash_len]u8,
) ApplicationKeys {
    const c_ap = expandLabel(master_secret, "c ap traffic", &transcript_hash, hash_len);
    const s_ap = expandLabel(master_secret, "s ap traffic", &transcript_hash, hash_len);

    return .{
        .client = deriveTrafficKeys(c_ap),
        .server = deriveTrafficKeys(s_ap),
    };
}

/// compute the finished verify_data for the Finished message.
/// verify_data = HMAC(finished_key, transcript_hash)
pub fn computeFinished(base_key: [hash_len]u8, transcript_hash: [hash_len]u8) [hash_len]u8 {
    const finished_key = expandLabel(base_key, "finished", &.{}, hash_len);
    var hmac = HmacSha384.init(&finished_key);
    hmac.update(&transcript_hash);
    var result: [hash_len]u8 = undefined;
    hmac.final(&result);
    return result;
}

// -- message construction --

/// build a ServerHello message.
/// returns the number of bytes written.
pub fn buildServerHello(
    buf: []u8,
    client_random: [32]u8,
    server_random: [32]u8,
    session_id: []const u8,
    server_public_key: [32]u8,
) HandshakeError!usize {
    // ServerHello structure:
    //   version(2) + random(32) + session_id_len(1) + session_id(N)
    //   + cipher_suites(2) + compression(1) + extensions_len(2)
    //   + supported_versions ext(6) + key_share ext(40)
    _ = client_random; // not used in construction, kept for API symmetry

    const extensions_len: usize = 6 + 40; // supported_versions + key_share
    const body_len = 2 + 32 + 1 + session_id.len + 2 + 1 + 2 + extensions_len;

    if (buf.len < 4 + body_len) return HandshakeError.BufferTooSmall;

    var pos: usize = 0;

    // handshake header: type(1) + length(3)
    buf[pos] = 0x02; // ServerHello
    pos += 1;
    writeU24(buf[pos..], @intCast(body_len));
    pos += 3;

    // server version (legacy: 0x0303 = TLS 1.2)
    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2;

    // server random
    @memcpy(buf[pos .. pos + 32], &server_random);
    pos += 32;

    // session ID (echo back client's)
    buf[pos] = @intCast(session_id.len);
    pos += 1;
    if (session_id.len > 0) {
        @memcpy(buf[pos .. pos + session_id.len], session_id);
        pos += session_id.len;
    }

    // cipher suite
    writeU16(buf[pos..], cipher_suite_aes_256_gcm);
    pos += 2;

    // compression method (null)
    buf[pos] = 0;
    pos += 1;

    // extensions length
    writeU16(buf[pos..], @intCast(extensions_len));
    pos += 2;

    // supported_versions extension (type 0x002B)
    writeU16(buf[pos..], 0x002B);
    pos += 2;
    writeU16(buf[pos..], 2); // length
    pos += 2;
    writeU16(buf[pos..], 0x0304); // TLS 1.3
    pos += 2;

    // key_share extension (type 0x0033)
    writeU16(buf[pos..], 0x0033);
    pos += 2;
    writeU16(buf[pos..], 36); // length: group(2) + key_len(2) + key(32)
    pos += 2;
    writeU16(buf[pos..], 0x001D); // x25519
    pos += 2;
    writeU16(buf[pos..], 32); // key length
    pos += 2;
    @memcpy(buf[pos .. pos + 32], &server_public_key);
    pos += 32;

    return pos;
}

/// build an EncryptedExtensions message (empty — no extensions needed).
pub fn buildEncryptedExtensions(buf: []u8) HandshakeError!usize {
    if (buf.len < 6) return HandshakeError.BufferTooSmall;

    buf[0] = 0x08; // EncryptedExtensions
    writeU24(buf[1..], 2); // length of extensions list
    writeU16(buf[4..], 0); // empty extensions list

    return 6;
}

/// build a Certificate message from PEM certificate data.
/// includes the certificate request context (empty for server) and
/// a single certificate entry with no extensions.
pub fn buildCertificate(buf: []u8, cert_der: []const u8) HandshakeError!usize {
    // Certificate message:
    //   certificate_request_context_len(1) = 0
    //   certificate_list_len(3)
    //     cert_data_len(3) + cert_data(N) + extensions_len(2) = 0
    const entry_len = 3 + cert_der.len + 2; // cert_len(3) + cert + ext_len(2)
    const list_len = entry_len;
    const body_len = 1 + 3 + list_len;

    if (buf.len < 4 + body_len) return HandshakeError.BufferTooSmall;

    var pos: usize = 0;

    buf[pos] = 0x0B; // Certificate
    pos += 1;
    writeU24(buf[pos..], @intCast(body_len));
    pos += 3;

    // certificate request context (empty for server cert)
    buf[pos] = 0;
    pos += 1;

    // certificate list
    writeU24(buf[pos..], @intCast(list_len));
    pos += 3;

    // certificate entry
    writeU24(buf[pos..], @intCast(cert_der.len));
    pos += 3;
    @memcpy(buf[pos .. pos + cert_der.len], cert_der);
    pos += cert_der.len;

    // certificate extensions (none)
    writeU16(buf[pos..], 0);
    pos += 2;

    return pos;
}

/// build a CertificateVerify message (RFC 8446 §4.4.3).
///
/// signs the transcript hash with the server's private key.
/// signature algorithm: ecdsa_secp256r1_sha256 (0x0403).
///
/// signed content = 64 × 0x20 + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
pub fn buildCertificateVerify(
    buf: []u8,
    transcript_hash: [hash_len]u8,
    private_key: EcdsaP256.SecretKey,
) HandshakeError!usize {
    // build the content to sign (RFC 8446 §4.4.3)
    var signed_content: [64 + 33 + 1 + hash_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &signed_content);

    @memset(signed_content[0..64], 0x20); // 64 spaces
    const context = "TLS 1.3, server CertificateVerify";
    @memcpy(signed_content[64 .. 64 + context.len], context);
    signed_content[64 + context.len] = 0x00; // separator
    @memcpy(signed_content[64 + context.len + 1 ..], &transcript_hash);

    // sign with ECDSA P-256
    const kp = EcdsaP256.KeyPair.fromSecretKey(private_key) catch
        return HandshakeError.KeyExchangeFailed;
    const sig = kp.sign(&signed_content, null) catch
        return HandshakeError.KeyExchangeFailed;

    // DER-encode the signature
    var der_sig_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = sig.toDer(&der_sig_buf);

    // message format: type(1) + length(3) + algorithm(2) + sig_len(2) + sig(N)
    const body_len = 2 + 2 + der_sig.len;
    const total = 4 + body_len;
    if (buf.len < total) return HandshakeError.BufferTooSmall;

    var pos: usize = 0;

    // handshake header
    buf[pos] = 0x0F; // CertificateVerify
    pos += 1;
    writeU24(buf[pos..], @intCast(body_len));
    pos += 3;

    // signature algorithm: ecdsa_secp256r1_sha256 (0x0403)
    writeU16(buf[pos..], 0x0403);
    pos += 2;

    // signature length + data
    writeU16(buf[pos..], @intCast(der_sig.len));
    pos += 2;
    @memcpy(buf[pos .. pos + der_sig.len], der_sig);
    pos += der_sig.len;

    return pos;
}

/// build a Finished message.
pub fn buildFinished(buf: []u8, verify_data: [hash_len]u8) HandshakeError!usize {
    if (buf.len < 4 + hash_len) return HandshakeError.BufferTooSmall;

    buf[0] = 0x14; // Finished
    writeU24(buf[1..], hash_len);
    @memcpy(buf[4 .. 4 + hash_len], &verify_data);

    return 4 + hash_len;
}

// -- ClientHello parsing --

pub const ClientHelloInfo = struct {
    client_random: [32]u8,
    session_id: []const u8,
    has_aes_256_gcm: bool,
    x25519_key_share: ?[32]u8,
    supported_versions_has_tls13: bool,
};

/// parse key fields from a ClientHello message body (after the handshake header).
pub fn parseClientHelloFields(msg: []const u8) HandshakeError!ClientHelloInfo {
    var pos: usize = 0;

    // version (2)
    if (pos + 2 > msg.len) return HandshakeError.InvalidClientHello;
    pos += 2;

    // random (32)
    if (pos + 32 > msg.len) return HandshakeError.InvalidClientHello;
    var client_random: [32]u8 = undefined;
    @memcpy(&client_random, msg[pos .. pos + 32]);
    pos += 32;

    // session ID
    if (pos >= msg.len) return HandshakeError.InvalidClientHello;
    const sid_len = msg[pos];
    pos += 1;
    if (pos + sid_len > msg.len) return HandshakeError.InvalidClientHello;
    const session_id = msg[pos .. pos + sid_len];
    pos += sid_len;

    // cipher suites
    if (pos + 2 > msg.len) return HandshakeError.InvalidClientHello;
    const cs_len = readU16(msg[pos..]);
    pos += 2;
    if (pos + cs_len > msg.len) return HandshakeError.InvalidClientHello;
    var has_aes_256_gcm = false;
    var cs_pos: usize = pos;
    while (cs_pos + 2 <= pos + cs_len) : (cs_pos += 2) {
        const suite = readU16(msg[cs_pos..]);
        if (suite == cipher_suite_aes_256_gcm) has_aes_256_gcm = true;
    }
    pos += cs_len;

    // compression methods
    if (pos >= msg.len) return HandshakeError.InvalidClientHello;
    const comp_len = msg[pos];
    pos += 1;
    if (pos + comp_len > msg.len) return HandshakeError.InvalidClientHello;
    pos += comp_len;

    // extensions
    var x25519_key_share: ?[32]u8 = null;
    var has_tls13 = false;

    if (pos + 2 <= msg.len) {
        const ext_len = readU16(msg[pos..]);
        pos += 2;
        const ext_end = @min(pos + ext_len, msg.len);

        while (pos + 4 <= ext_end) {
            const ext_type = readU16(msg[pos..]);
            const ext_data_len = readU16(msg[pos + 2 ..]);
            pos += 4;
            if (pos + ext_data_len > ext_end) break;

            if (ext_type == 0x002B) {
                // supported_versions
                has_tls13 = parseSupportedVersions(msg[pos .. pos + ext_data_len]);
            } else if (ext_type == 0x0033) {
                // key_share
                x25519_key_share = parseKeyShare(msg[pos .. pos + ext_data_len]);
            }

            pos += ext_data_len;
        }
    }

    return .{
        .client_random = client_random,
        .session_id = session_id,
        .has_aes_256_gcm = has_aes_256_gcm,
        .x25519_key_share = x25519_key_share,
        .supported_versions_has_tls13 = has_tls13,
    };
}

/// check if supported_versions extension includes TLS 1.3 (0x0304).
fn parseSupportedVersions(data: []const u8) bool {
    if (data.len < 1) return false;
    const list_len = data[0];
    var pos: usize = 1;
    while (pos + 2 <= 1 + @as(usize, list_len) and pos + 2 <= data.len) : (pos += 2) {
        if (readU16(data[pos..]) == 0x0304) return true;
    }
    return false;
}

/// extract X25519 key share from key_share extension.
fn parseKeyShare(data: []const u8) ?[32]u8 {
    if (data.len < 2) return null;
    const list_len = readU16(data[0..]);
    var pos: usize = 2;
    const end = @min(2 + list_len, data.len);
    while (pos + 4 <= end) {
        const group = readU16(data[pos..]);
        const key_len = readU16(data[pos + 2 ..]);
        pos += 4;
        if (pos + key_len > end) break;
        if (group == 0x001D and key_len == 32) { // x25519
            var key: [32]u8 = undefined;
            @memcpy(&key, data[pos .. pos + 32]);
            return key;
        }
        pos += key_len;
    }
    return null;
}

// -- HKDF-Expand-Label --
//
// HKDF-Expand-Label(Secret, Label, Context, Length) =
//   HKDF-Expand(Secret, HkdfLabel, Length)
//
// HkdfLabel = length(2) + "tls13 " + label + context_len(1) + context

fn expandLabel(secret: [hash_len]u8, comptime label: []const u8, context: []const u8, comptime length: usize) [length]u8 {
    const full_label = "tls13 " ++ label;

    // HkdfLabel: length(2) + label_len(1) + label + context_len(1) + context
    // max context is a hash digest (48 bytes), so 256 is plenty
    var info: [256]u8 = undefined;
    var pos: usize = 0;

    // length (2 bytes, big-endian)
    info[pos] = @intCast(length >> 8);
    info[pos + 1] = @intCast(length & 0xFF);
    pos += 2;

    // label with "tls13 " prefix
    info[pos] = @intCast(full_label.len);
    pos += 1;
    @memcpy(info[pos .. pos + full_label.len], full_label);
    pos += full_label.len;

    // context
    info[pos] = @intCast(context.len);
    pos += 1;
    if (context.len > 0) {
        @memcpy(info[pos .. pos + context.len], context);
        pos += context.len;
    }

    var out: [length]u8 = undefined;
    HkdfSha384.expand(&out, info[0..pos], secret);
    return out;
}

/// hash of empty input (used in key derivation).
fn hashEmpty() [hash_len]u8 {
    var h = Sha384.init(.{});
    var result: [hash_len]u8 = undefined;
    h.final(&result);
    return result;
}

// -- helpers --

fn readU16(data: []const u8) usize {
    return (@as(usize, data[0]) << 8) | @as(usize, data[1]);
}

fn writeU16(dest: []u8, val: u16) void {
    dest[0] = @intCast(val >> 8);
    dest[1] = @intCast(val & 0xFF);
}

fn writeU24(dest: []u8, val: u24) void {
    dest[0] = @intCast(val >> 16);
    dest[1] = @intCast((val >> 8) & 0xFF);
    dest[2] = @intCast(val & 0xFF);
}

// -- tests --

test "key schedule: early secret is deterministic" {
    const s1 = deriveEarlySecret();
    const s2 = deriveEarlySecret();
    try std.testing.expectEqualSlices(u8, &s1, &s2);
}

test "key schedule: handshake secret varies with shared secret" {
    const early = deriveEarlySecret();

    var ss1: [32]u8 = undefined;
    @memset(&ss1, 0x01);
    const hs1 = deriveHandshakeSecret(early, ss1);

    var ss2: [32]u8 = undefined;
    @memset(&ss2, 0x02);
    const hs2 = deriveHandshakeSecret(early, ss2);

    try std.testing.expect(!std.mem.eql(u8, &hs1, &hs2));
}

test "key schedule: traffic keys are different for client and server" {
    const early = deriveEarlySecret();
    var shared: [32]u8 = undefined;
    std.crypto.random.bytes(&shared);
    const hs = deriveHandshakeSecret(early, shared);

    var transcript: [hash_len]u8 = undefined;
    std.crypto.random.bytes(&transcript);

    const keys = deriveHandshakeTrafficSecrets(hs, transcript);

    try std.testing.expect(!std.mem.eql(
        u8,
        &keys.client_handshake_traffic_secret,
        &keys.server_handshake_traffic_secret,
    ));
}

test "key schedule: full derivation produces valid keys" {
    const early = deriveEarlySecret();
    var shared: [32]u8 = undefined;
    std.crypto.random.bytes(&shared);
    const hs = deriveHandshakeSecret(early, shared);

    var transcript: [hash_len]u8 = undefined;
    std.crypto.random.bytes(&transcript);

    const hs_keys = deriveHandshakeTrafficSecrets(hs, transcript);
    const server_traffic = deriveTrafficKeys(hs_keys.server_handshake_traffic_secret);

    // keys should be non-zero
    var all_zero = true;
    for (server_traffic.key) |b| {
        if (b != 0) all_zero = false;
    }
    try std.testing.expect(!all_zero);
}

test "key schedule: application keys derivation" {
    const early = deriveEarlySecret();
    var shared: [32]u8 = undefined;
    std.crypto.random.bytes(&shared);
    const hs = deriveHandshakeSecret(early, shared);
    const master = deriveMasterSecret(hs);

    var transcript: [hash_len]u8 = undefined;
    std.crypto.random.bytes(&transcript);

    const app_keys = deriveApplicationSecrets(master, transcript);

    // client and server keys should differ
    try std.testing.expect(!std.mem.eql(u8, &app_keys.client.key, &app_keys.server.key));
    try std.testing.expect(!std.mem.eql(u8, &app_keys.client.iv, &app_keys.server.iv));
}

test "finished computation is deterministic" {
    var key: [hash_len]u8 = undefined;
    std.crypto.random.bytes(&key);
    var transcript: [hash_len]u8 = undefined;
    std.crypto.random.bytes(&transcript);

    const f1 = computeFinished(key, transcript);
    const f2 = computeFinished(key, transcript);
    try std.testing.expectEqualSlices(u8, &f1, &f2);
}

test "finished changes with different transcript" {
    var key: [hash_len]u8 = undefined;
    std.crypto.random.bytes(&key);
    var t1: [hash_len]u8 = undefined;
    std.crypto.random.bytes(&t1);
    var t2: [hash_len]u8 = undefined;
    std.crypto.random.bytes(&t2);

    const f1 = computeFinished(key, t1);
    const f2 = computeFinished(key, t2);
    try std.testing.expect(!std.mem.eql(u8, &f1, &f2));
}

test "buildServerHello produces valid structure" {
    var buf: [512]u8 = undefined;
    var client_random: [32]u8 = undefined;
    std.crypto.random.bytes(&client_random);
    var server_random: [32]u8 = undefined;
    std.crypto.random.bytes(&server_random);
    var server_key: [32]u8 = undefined;
    std.crypto.random.bytes(&server_key);

    const session_id = &[_]u8{};
    const len = try buildServerHello(&buf, client_random, server_random, session_id, server_key);

    // verify handshake type
    try std.testing.expectEqual(@as(u8, 0x02), buf[0]);

    // verify we can read the length
    const body_len = (@as(usize, buf[1]) << 16) | (@as(usize, buf[2]) << 8) | @as(usize, buf[3]);
    try std.testing.expectEqual(len - 4, body_len);
}

test "buildEncryptedExtensions" {
    var buf: [16]u8 = undefined;
    const len = try buildEncryptedExtensions(&buf);
    try std.testing.expectEqual(@as(usize, 6), len);
    try std.testing.expectEqual(@as(u8, 0x08), buf[0]); // EncryptedExtensions type
}

test "buildFinished size" {
    var buf: [256]u8 = undefined;
    var verify_data: [hash_len]u8 = undefined;
    std.crypto.random.bytes(&verify_data);
    const len = try buildFinished(&buf, verify_data);
    try std.testing.expectEqual(@as(usize, 4 + hash_len), len);
    try std.testing.expectEqual(@as(u8, 0x14), buf[0]); // Finished type
}

test "parseClientHelloFields with X25519 and TLS 1.3" {
    // build a minimal ClientHello body (without handshake header)
    var msg: [256]u8 = undefined;
    var pos: usize = 0;

    // version
    msg[pos] = 0x03;
    msg[pos + 1] = 0x03;
    pos += 2;

    // random
    @memset(msg[pos .. pos + 32], 0xAA);
    pos += 32;

    // session ID (empty)
    msg[pos] = 0;
    pos += 1;

    // cipher suites: AES_256_GCM
    writeU16(msg[pos..], 2);
    pos += 2;
    writeU16(msg[pos..], cipher_suite_aes_256_gcm);
    pos += 2;

    // compression
    msg[pos] = 1;
    pos += 1;
    msg[pos] = 0;
    pos += 1;

    // extensions
    const ext_start = pos;
    pos += 2; // skip extensions length, fill later

    // supported_versions extension
    writeU16(msg[pos..], 0x002B);
    pos += 2;
    writeU16(msg[pos..], 3); // ext data len
    pos += 2;
    msg[pos] = 2; // versions list len
    pos += 1;
    writeU16(msg[pos..], 0x0304); // TLS 1.3
    pos += 2;

    // key_share extension with X25519
    writeU16(msg[pos..], 0x0033);
    pos += 2;
    writeU16(msg[pos..], 38); // ext data len: list_len(2) + group(2) + key_len(2) + key(32)
    pos += 2;
    writeU16(msg[pos..], 36); // key share list len
    pos += 2;
    writeU16(msg[pos..], 0x001D); // x25519
    pos += 2;
    writeU16(msg[pos..], 32); // key length
    pos += 2;
    @memset(msg[pos .. pos + 32], 0xBB); // client public key
    pos += 32;

    // fill extensions length
    writeU16(msg[ext_start..], @intCast(pos - ext_start - 2));

    const info = try parseClientHelloFields(msg[0..pos]);
    try std.testing.expect(info.has_aes_256_gcm);
    try std.testing.expect(info.supported_versions_has_tls13);
    try std.testing.expect(info.x25519_key_share != null);

    const expected_random = [_]u8{0xAA} ** 32;
    try std.testing.expectEqualSlices(u8, &expected_random, &info.client_random);
}

test "buildCertificateVerify produces valid structure" {
    var buf: [512]u8 = undefined;
    var transcript: [hash_len]u8 = undefined;
    std.crypto.random.bytes(&transcript);

    const kp = EcdsaP256.KeyPair.generate();
    const len = try buildCertificateVerify(&buf, transcript, kp.secret_key);

    // type byte: CertificateVerify (0x0F)
    try std.testing.expectEqual(@as(u8, 0x0F), buf[0]);
    // algorithm: ecdsa_secp256r1_sha256 (0x0403)
    try std.testing.expectEqual(@as(u8, 0x04), buf[4]);
    try std.testing.expectEqual(@as(u8, 0x03), buf[5]);
    // length should be reasonable
    try std.testing.expect(len > 10 and len < 200);
}

test "buildCertificateVerify different transcripts produce different output" {
    var buf1: [512]u8 = undefined;
    var buf2: [512]u8 = undefined;
    var t1: [hash_len]u8 = undefined;
    std.crypto.random.bytes(&t1);
    var t2: [hash_len]u8 = undefined;
    std.crypto.random.bytes(&t2);

    const kp = EcdsaP256.KeyPair.generate();
    const len1 = try buildCertificateVerify(&buf1, t1, kp.secret_key);
    const len2 = try buildCertificateVerify(&buf2, t2, kp.secret_key);

    // signatures should differ (different transcripts)
    try std.testing.expect(!std.mem.eql(u8, buf1[0..len1], buf2[0..len2]));
}

test "buildCertificateVerify buffer too small" {
    var buf: [4]u8 = undefined;
    var transcript: [hash_len]u8 = undefined;
    @memset(&transcript, 0);

    const kp = EcdsaP256.KeyPair.generate();
    try std.testing.expectError(
        HandshakeError.BufferTooSmall,
        buildCertificateVerify(&buf, transcript, kp.secret_key),
    );
}

test "X25519 key exchange produces shared secret" {
    // verify that zig's X25519 works end-to-end
    const client_kp = X25519.KeyPair.generate();
    const server_kp = X25519.KeyPair.generate();

    const client_shared = X25519.scalarmult(client_kp.secret_key, server_kp.public_key) catch unreachable;
    const server_shared = X25519.scalarmult(server_kp.secret_key, client_kp.public_key) catch unreachable;

    try std.testing.expectEqualSlices(u8, &client_shared, &server_shared);
}
