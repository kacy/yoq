const std = @import("std");
const common = @import("common.zig");

pub fn buildServerHello(
    buf: []u8,
    client_random: [32]u8,
    server_random: [32]u8,
    session_id: []const u8,
    server_public_key: [32]u8,
) common.HandshakeError!usize {
    _ = client_random;

    const extensions_len: usize = 6 + 40;
    const body_len = 2 + 32 + 1 + session_id.len + 2 + 1 + 2 + extensions_len;

    if (buf.len < 4 + body_len) return common.HandshakeError.BufferTooSmall;

    var pos: usize = 0;
    buf[pos] = 0x02;
    pos += 1;
    common.writeU24(buf[pos..], @intCast(body_len));
    pos += 3;

    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2;

    @memcpy(buf[pos .. pos + 32], &server_random);
    pos += 32;

    buf[pos] = @intCast(session_id.len);
    pos += 1;
    if (session_id.len > 0) {
        @memcpy(buf[pos .. pos + session_id.len], session_id);
        pos += session_id.len;
    }

    common.writeU16(buf[pos..], common.cipher_suite_aes_256_gcm);
    pos += 2;
    buf[pos] = 0;
    pos += 1;

    common.writeU16(buf[pos..], @intCast(extensions_len));
    pos += 2;

    common.writeU16(buf[pos..], 0x002B);
    pos += 2;
    common.writeU16(buf[pos..], 2);
    pos += 2;
    common.writeU16(buf[pos..], 0x0304);
    pos += 2;

    common.writeU16(buf[pos..], 0x0033);
    pos += 2;
    common.writeU16(buf[pos..], 36);
    pos += 2;
    common.writeU16(buf[pos..], 0x001D);
    pos += 2;
    common.writeU16(buf[pos..], 32);
    pos += 2;
    @memcpy(buf[pos .. pos + 32], &server_public_key);
    pos += 32;

    return pos;
}

pub fn buildEncryptedExtensions(buf: []u8, selected_alpn: ?[]const u8) common.HandshakeError!usize {
    const extensions_len: usize = if (selected_alpn) |protocol| 7 + protocol.len else 0;
    const body_len: usize = 2 + extensions_len;
    if (buf.len < 4 + body_len) return common.HandshakeError.BufferTooSmall;

    buf[0] = 0x08;
    common.writeU24(buf[1..], @intCast(body_len));
    common.writeU16(buf[4..], @intCast(extensions_len));

    var pos: usize = 6;
    if (selected_alpn) |protocol| {
        common.writeU16(buf[pos..], 0x0010);
        pos += 2;
        common.writeU16(buf[pos..], @intCast(3 + protocol.len));
        pos += 2;
        common.writeU16(buf[pos..], @intCast(1 + protocol.len));
        pos += 2;
        buf[pos] = @intCast(protocol.len);
        pos += 1;
        @memcpy(buf[pos .. pos + protocol.len], protocol);
        pos += protocol.len;
    }

    return pos;
}

pub fn buildCertificate(buf: []u8, cert_der: []const u8) common.HandshakeError!usize {
    const entry_len = 3 + cert_der.len + 2;
    const list_len = entry_len;
    const body_len = 1 + 3 + list_len;

    if (buf.len < 4 + body_len) return common.HandshakeError.BufferTooSmall;

    var pos: usize = 0;
    buf[pos] = 0x0B;
    pos += 1;
    common.writeU24(buf[pos..], @intCast(body_len));
    pos += 3;

    buf[pos] = 0;
    pos += 1;
    common.writeU24(buf[pos..], @intCast(list_len));
    pos += 3;
    common.writeU24(buf[pos..], @intCast(cert_der.len));
    pos += 3;
    @memcpy(buf[pos .. pos + cert_der.len], cert_der);
    pos += cert_der.len;
    common.writeU16(buf[pos..], 0);
    pos += 2;

    return pos;
}

pub fn buildCertificateVerify(
    buf: []u8,
    transcript_hash: [common.hash_len]u8,
    private_key: common.EcdsaP256.SecretKey,
) common.HandshakeError!usize {
    var signed_content: [64 + 33 + 1 + common.hash_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &signed_content);

    @memset(signed_content[0..64], 0x20);
    const context = "TLS 1.3, server CertificateVerify";
    @memcpy(signed_content[64 .. 64 + context.len], context);
    signed_content[64 + context.len] = 0x00;
    @memcpy(signed_content[64 + context.len + 1 ..], &transcript_hash);

    const kp = common.EcdsaP256.KeyPair.fromSecretKey(private_key) catch
        return common.HandshakeError.KeyExchangeFailed;
    const sig = kp.sign(&signed_content, null) catch
        return common.HandshakeError.KeyExchangeFailed;

    var der_sig_buf: [common.EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = sig.toDer(&der_sig_buf);

    const body_len = 2 + 2 + der_sig.len;
    const total = 4 + body_len;
    if (buf.len < total) return common.HandshakeError.BufferTooSmall;

    var pos: usize = 0;
    buf[pos] = 0x0F;
    pos += 1;
    common.writeU24(buf[pos..], @intCast(body_len));
    pos += 3;
    common.writeU16(buf[pos..], 0x0403);
    pos += 2;
    common.writeU16(buf[pos..], @intCast(der_sig.len));
    pos += 2;
    @memcpy(buf[pos .. pos + der_sig.len], der_sig);
    pos += der_sig.len;

    return pos;
}

pub fn buildFinished(buf: []u8, verify_data: [common.hash_len]u8) common.HandshakeError!usize {
    if (buf.len < 4 + common.hash_len) return common.HandshakeError.BufferTooSmall;

    buf[0] = 0x14;
    common.writeU24(buf[1..], common.hash_len);
    @memcpy(buf[4 .. 4 + common.hash_len], &verify_data);

    return 4 + common.hash_len;
}
