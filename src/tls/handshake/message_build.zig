const std = @import("std");
const common = @import("common.zig");

/// build a ClientHello compatible with what the existing server parses.
/// emits the AES-256-GCM cipher only, X25519 only, TLS 1.3 only, ALPN
/// (h2 + http/1.1), signature_algorithms (ecdsa_secp256r1_sha256), and
/// optionally an SNI extension. session_id is left empty (TLS 1.3 doesn't
/// resume via session IDs).
pub fn buildClientHello(
    buf: []u8,
    client_random: [32]u8,
    client_x25519_pub: [32]u8,
    server_name: ?[]const u8,
) common.HandshakeError!usize {
    // count extension bytes up front so we can write the u16 length later.
    var ext_len: usize = 0;
    if (server_name) |sni| ext_len += 2 + 2 + 2 + 1 + 2 + sni.len; // server_name
    ext_len += 2 + 2 + 1 + 2; // supported_versions: list_len + TLS 1.3
    ext_len += 2 + 2 + 2 + 2; // supported_groups: list_len + X25519
    ext_len += 2 + 2 + 2 + 2 + 2 + 32; // key_share: list_len + (group + len + 32 bytes)
    ext_len += 2 + 2 + 2 + 2; // signature_algorithms: list_len + scheme
    ext_len += 2 + 2 + 2 + (1 + 2) + (1 + 8); // alpn: list_len + ("h2" + "http/1.1")

    // body = legacy_version(2) + random(32) + session_id_len(1) +
    //        cipher_suites(2 len + 2) + comp(1 len + 1) + extensions(2 len + ext_len)
    const body_len: usize = 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + ext_len;
    const total = 4 + body_len;
    if (buf.len < total) return common.HandshakeError.BufferTooSmall;

    var pos: usize = 0;
    buf[pos] = 0x01;
    pos += 1;
    common.writeU24(buf[pos..], @intCast(body_len));
    pos += 3;

    // legacy_version = TLS 1.2 (real version is in supported_versions)
    buf[pos] = 0x03;
    buf[pos + 1] = 0x03;
    pos += 2;

    @memcpy(buf[pos .. pos + 32], &client_random);
    pos += 32;

    // empty session_id
    buf[pos] = 0;
    pos += 1;

    // cipher_suites: one entry, AES-256-GCM
    common.writeU16(buf[pos..], 2);
    pos += 2;
    common.writeU16(buf[pos..], common.cipher_suite_aes_256_gcm);
    pos += 2;

    // legacy_compression_methods: [null]
    buf[pos] = 1;
    buf[pos + 1] = 0;
    pos += 2;

    // extensions length
    common.writeU16(buf[pos..], @intCast(ext_len));
    pos += 2;

    if (server_name) |sni| {
        common.writeU16(buf[pos..], 0x0000); // server_name
        pos += 2;
        common.writeU16(buf[pos..], @intCast(2 + 1 + 2 + sni.len));
        pos += 2;
        // ServerNameList length
        common.writeU16(buf[pos..], @intCast(1 + 2 + sni.len));
        pos += 2;
        buf[pos] = 0; // name_type = host_name
        pos += 1;
        common.writeU16(buf[pos..], @intCast(sni.len));
        pos += 2;
        @memcpy(buf[pos .. pos + sni.len], sni);
        pos += sni.len;
    }

    // supported_versions: list_len(1) + TLS 1.3
    common.writeU16(buf[pos..], 0x002B);
    pos += 2;
    common.writeU16(buf[pos..], 1 + 2);
    pos += 2;
    buf[pos] = 2;
    pos += 1;
    common.writeU16(buf[pos..], 0x0304);
    pos += 2;

    // supported_groups: list_len(u16) + X25519
    common.writeU16(buf[pos..], 0x000A);
    pos += 2;
    common.writeU16(buf[pos..], 2 + 2);
    pos += 2;
    common.writeU16(buf[pos..], 2);
    pos += 2;
    common.writeU16(buf[pos..], 0x001D);
    pos += 2;

    // key_share: list_len(u16) + (group + key_len + key)
    common.writeU16(buf[pos..], 0x0033);
    pos += 2;
    common.writeU16(buf[pos..], 2 + 2 + 2 + 32);
    pos += 2;
    common.writeU16(buf[pos..], 2 + 2 + 32);
    pos += 2;
    common.writeU16(buf[pos..], 0x001D);
    pos += 2;
    common.writeU16(buf[pos..], 32);
    pos += 2;
    @memcpy(buf[pos .. pos + 32], &client_x25519_pub);
    pos += 32;

    // signature_algorithms: list_len(u16) + scheme
    common.writeU16(buf[pos..], 0x000D);
    pos += 2;
    common.writeU16(buf[pos..], 2 + 2);
    pos += 2;
    common.writeU16(buf[pos..], 2);
    pos += 2;
    common.writeU16(buf[pos..], 0x0403); // ecdsa_secp256r1_sha256
    pos += 2;

    // ALPN: list_len(u16) + (proto_len(u8) + proto_bytes) for h2 and http/1.1
    const alpn_inner_len: u16 = (1 + 2) + (1 + 8);
    common.writeU16(buf[pos..], 0x0010);
    pos += 2;
    common.writeU16(buf[pos..], 2 + alpn_inner_len);
    pos += 2;
    common.writeU16(buf[pos..], alpn_inner_len);
    pos += 2;
    buf[pos] = 2;
    pos += 1;
    @memcpy(buf[pos .. pos + 2], "h2");
    pos += 2;
    buf[pos] = 8;
    pos += 1;
    @memcpy(buf[pos .. pos + 8], "http/1.1");
    pos += 8;

    return pos;
}

/// build a CertificateRequest advertising just ECDSA P-256 + SHA-256 in
/// the signature_algorithms extension. context is empty (TLS 1.3 default).
pub fn buildCertificateRequest(buf: []u8) common.HandshakeError!usize {
    // body = context_len(1) + extensions_len(2) + signature_algorithms ext
    //   sig_algs ext = type(2) + len(2) + list_len(2) + scheme(2)
    const sig_ext_len: usize = 2 + 2 + 2 + 2;
    const body_len: usize = 1 + 2 + sig_ext_len;
    const total = 4 + body_len;
    if (buf.len < total) return common.HandshakeError.BufferTooSmall;

    var pos: usize = 0;
    buf[pos] = 0x0D;
    pos += 1;
    common.writeU24(buf[pos..], @intCast(body_len));
    pos += 3;
    buf[pos] = 0; // certificate_request_context = empty
    pos += 1;
    common.writeU16(buf[pos..], @intCast(sig_ext_len));
    pos += 2;
    common.writeU16(buf[pos..], 0x000D); // signature_algorithms
    pos += 2;
    common.writeU16(buf[pos..], 2 + 2); // ext_data_len
    pos += 2;
    common.writeU16(buf[pos..], 2); // SignatureSchemeList length
    pos += 2;
    common.writeU16(buf[pos..], 0x0403); // ecdsa_secp256r1_sha256
    pos += 2;

    return pos;
}

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

/// which side of the TLS handshake is signing. picks the context string
/// the spec mandates for that side — the bytes differ and the bug is
/// silent (handshake completes but no other implementation accepts).
pub const CertVerifySide = enum { server, client };

/// build a CertificateVerify. the context string is selected from `side`;
/// the rest of the message is identical across sides.
pub fn buildCertificateVerify(
    buf: []u8,
    side: CertVerifySide,
    transcript_hash: [common.hash_len]u8,
    private_key: common.EcdsaP256.SecretKey,
) common.HandshakeError!usize {
    var signed_content: [64 + 33 + 1 + common.hash_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &signed_content);

    @memset(signed_content[0..64], 0x20);
    const context = switch (side) {
        .server => "TLS 1.3, server CertificateVerify",
        .client => "TLS 1.3, client CertificateVerify",
    };
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
