// handshake — TLS 1.3 server-side handshake
//
// this file keeps the stable public API and tests while the
// implementation lives in smaller modules under `tls/handshake/`.

const std = @import("std");

const common = @import("handshake/common.zig");
const key_schedule = @import("handshake/key_schedule.zig");
const message_build = @import("handshake/message_build.zig");
const client_hello = @import("handshake/client_hello.zig");

pub const EcdsaP256 = common.EcdsaP256;
pub const X25519 = common.X25519;
pub const HmacSha384 = common.HmacSha384;
pub const HkdfSha384 = common.HkdfSha384;
pub const Sha384 = common.Sha384;
pub const Aes256Gcm = common.Aes256Gcm;

pub const HandshakeError = common.HandshakeError;
pub const cipher_suite_aes_256_gcm = common.cipher_suite_aes_256_gcm;
pub const hash_len = common.hash_len;
pub const TrafficKeys = common.TrafficKeys;
pub const HandshakeKeys = common.HandshakeKeys;
pub const ApplicationKeys = common.ApplicationKeys;
pub const ClientHelloInfo = client_hello.ClientHelloInfo;

pub const deriveEarlySecret = key_schedule.deriveEarlySecret;
pub const deriveHandshakeSecret = key_schedule.deriveHandshakeSecret;
pub const deriveHandshakeTrafficSecrets = key_schedule.deriveHandshakeTrafficSecrets;
pub const deriveTrafficKeys = key_schedule.deriveTrafficKeys;
pub const deriveMasterSecret = key_schedule.deriveMasterSecret;
pub const deriveApplicationSecrets = key_schedule.deriveApplicationSecrets;
pub const computeFinished = key_schedule.computeFinished;

pub const buildServerHello = message_build.buildServerHello;
pub const buildEncryptedExtensions = message_build.buildEncryptedExtensions;
pub const buildCertificate = message_build.buildCertificate;
pub const buildCertificateVerify = message_build.buildCertificateVerify;
pub const buildFinished = message_build.buildFinished;

pub const parseClientHelloFields = client_hello.parseClientHelloFields;

const writeU16 = common.writeU16;

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
    @import("compat").randomBytes(&shared);
    const hs = deriveHandshakeSecret(early, shared);

    var transcript: [hash_len]u8 = undefined;
    @import("compat").randomBytes(&transcript);

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
    @import("compat").randomBytes(&shared);
    const hs = deriveHandshakeSecret(early, shared);

    var transcript: [hash_len]u8 = undefined;
    @import("compat").randomBytes(&transcript);

    const hs_keys = deriveHandshakeTrafficSecrets(hs, transcript);
    const server_traffic = deriveTrafficKeys(hs_keys.server_handshake_traffic_secret);

    var all_zero = true;
    for (server_traffic.key) |b| {
        if (b != 0) all_zero = false;
    }
    try std.testing.expect(!all_zero);
}

test "key schedule: application keys derivation" {
    const early = deriveEarlySecret();
    var shared: [32]u8 = undefined;
    @import("compat").randomBytes(&shared);
    const hs = deriveHandshakeSecret(early, shared);
    const master = deriveMasterSecret(hs);

    var transcript: [hash_len]u8 = undefined;
    @import("compat").randomBytes(&transcript);

    const app_keys = deriveApplicationSecrets(master, transcript);

    try std.testing.expect(!std.mem.eql(u8, &app_keys.client.key, &app_keys.server.key));
    try std.testing.expect(!std.mem.eql(u8, &app_keys.client.iv, &app_keys.server.iv));
}

test "finished computation is deterministic" {
    var key: [hash_len]u8 = undefined;
    @import("compat").randomBytes(&key);
    var transcript: [hash_len]u8 = undefined;
    @import("compat").randomBytes(&transcript);

    const f1 = computeFinished(key, transcript);
    const f2 = computeFinished(key, transcript);
    try std.testing.expectEqualSlices(u8, &f1, &f2);
}

test "finished changes with different transcript" {
    var key: [hash_len]u8 = undefined;
    @import("compat").randomBytes(&key);
    var t1: [hash_len]u8 = undefined;
    @import("compat").randomBytes(&t1);
    var t2: [hash_len]u8 = undefined;
    @import("compat").randomBytes(&t2);

    const f1 = computeFinished(key, t1);
    const f2 = computeFinished(key, t2);
    try std.testing.expect(!std.mem.eql(u8, &f1, &f2));
}

test "buildServerHello produces valid structure" {
    var buf: [512]u8 = undefined;
    var client_random: [32]u8 = undefined;
    @import("compat").randomBytes(&client_random);
    var server_random: [32]u8 = undefined;
    @import("compat").randomBytes(&server_random);
    var server_key: [32]u8 = undefined;
    @import("compat").randomBytes(&server_key);

    const session_id = &[_]u8{};
    const len = try buildServerHello(&buf, client_random, server_random, session_id, server_key);

    try std.testing.expectEqual(@as(u8, 0x02), buf[0]);

    const body_len = (@as(usize, buf[1]) << 16) | (@as(usize, buf[2]) << 8) | @as(usize, buf[3]);
    try std.testing.expectEqual(len - 4, body_len);
}

test "buildEncryptedExtensions without ALPN" {
    var buf: [16]u8 = undefined;
    const len = try buildEncryptedExtensions(&buf, null);
    try std.testing.expectEqual(@as(usize, 6), len);
    try std.testing.expectEqual(@as(u8, 0x08), buf[0]);
}

test "buildEncryptedExtensions with ALPN" {
    var buf: [32]u8 = undefined;
    const len = try buildEncryptedExtensions(&buf, "h2");
    try std.testing.expectEqual(@as(usize, 15), len);
    try std.testing.expectEqual(@as(u8, 0x08), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[6]);
    try std.testing.expectEqual(@as(u8, 0x10), buf[7]);
    try std.testing.expectEqual(@as(u8, 0x02), buf[12]);
    try std.testing.expectEqualStrings("h2", buf[13..15]);
}

test "buildFinished size" {
    var buf: [256]u8 = undefined;
    var verify_data: [hash_len]u8 = undefined;
    @import("compat").randomBytes(&verify_data);
    const len = try buildFinished(&buf, verify_data);
    try std.testing.expectEqual(@as(usize, 4 + hash_len), len);
    try std.testing.expectEqual(@as(u8, 0x14), buf[0]);
}

test "parseClientHelloFields with X25519 and TLS 1.3" {
    var msg: [256]u8 = undefined;
    var pos: usize = 0;

    msg[pos] = 0x03;
    msg[pos + 1] = 0x03;
    pos += 2;

    @memset(msg[pos .. pos + 32], 0xAA);
    pos += 32;

    msg[pos] = 0;
    pos += 1;

    writeU16(msg[pos..], 2);
    pos += 2;
    writeU16(msg[pos..], cipher_suite_aes_256_gcm);
    pos += 2;

    msg[pos] = 1;
    pos += 1;
    msg[pos] = 0;
    pos += 1;

    const ext_start = pos;
    pos += 2;

    writeU16(msg[pos..], 0x002B);
    pos += 2;
    writeU16(msg[pos..], 3);
    pos += 2;
    msg[pos] = 2;
    pos += 1;
    writeU16(msg[pos..], 0x0304);
    pos += 2;

    writeU16(msg[pos..], 0x0033);
    pos += 2;
    writeU16(msg[pos..], 38);
    pos += 2;
    writeU16(msg[pos..], 36);
    pos += 2;
    writeU16(msg[pos..], 0x001D);
    pos += 2;
    writeU16(msg[pos..], 32);
    pos += 2;
    @memset(msg[pos .. pos + 32], 0xBB);
    pos += 32;

    writeU16(msg[pos..], 0x0010);
    pos += 2;
    writeU16(msg[pos..], 14);
    pos += 2;
    writeU16(msg[pos..], 12);
    pos += 2;
    msg[pos] = 2;
    pos += 1;
    @memcpy(msg[pos .. pos + 2], "h2");
    pos += 2;
    msg[pos] = 8;
    pos += 1;
    @memcpy(msg[pos .. pos + 8], "http/1.1");
    pos += 8;

    writeU16(msg[ext_start..], @intCast(pos - ext_start - 2));

    const info = try parseClientHelloFields(msg[0..pos]);
    try std.testing.expect(info.has_aes_256_gcm);
    try std.testing.expect(info.supported_versions_has_tls13);
    try std.testing.expect(info.x25519_key_share != null);
    try std.testing.expect(info.offers_h2_alpn);
    try std.testing.expect(info.offers_http11_alpn);

    const expected_random = [_]u8{0xAA} ** 32;
    try std.testing.expectEqualSlices(u8, &expected_random, &info.client_random);
}

test "buildCertificateVerify produces valid structure" {
    var buf: [512]u8 = undefined;
    var transcript: [hash_len]u8 = undefined;
    @import("compat").randomBytes(&transcript);

    const kp = EcdsaP256.KeyPair.generate(@import("compat").io());
    const len = try buildCertificateVerify(&buf, transcript, kp.secret_key);

    try std.testing.expectEqual(@as(u8, 0x0F), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x04), buf[4]);
    try std.testing.expectEqual(@as(u8, 0x03), buf[5]);
    try std.testing.expect(len > 10 and len < 200);
}

test "buildCertificateVerify different transcripts produce different output" {
    var buf1: [512]u8 = undefined;
    var buf2: [512]u8 = undefined;
    var t1: [hash_len]u8 = undefined;
    @import("compat").randomBytes(&t1);
    var t2: [hash_len]u8 = undefined;
    @import("compat").randomBytes(&t2);

    const kp = EcdsaP256.KeyPair.generate(@import("compat").io());
    const len1 = try buildCertificateVerify(&buf1, t1, kp.secret_key);
    const len2 = try buildCertificateVerify(&buf2, t2, kp.secret_key);

    try std.testing.expect(!std.mem.eql(u8, buf1[0..len1], buf2[0..len2]));
}

test "buildCertificateVerify buffer too small" {
    var buf: [4]u8 = undefined;
    var transcript: [hash_len]u8 = undefined;
    @memset(&transcript, 0);

    const kp = EcdsaP256.KeyPair.generate(@import("compat").io());
    try std.testing.expectError(
        HandshakeError.BufferTooSmall,
        buildCertificateVerify(&buf, transcript, kp.secret_key),
    );
}

test "X25519 key exchange produces shared secret" {
    const client_kp = X25519.KeyPair.generate(@import("compat").io());
    const server_kp = X25519.KeyPair.generate(@import("compat").io());

    const client_shared = X25519.scalarmult(client_kp.secret_key, server_kp.public_key) catch unreachable;
    const server_shared = X25519.scalarmult(server_kp.secret_key, client_kp.public_key) catch unreachable;

    try std.testing.expectEqualSlices(u8, &client_shared, &server_shared);
}
