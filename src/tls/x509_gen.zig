// x509_gen — mint X.509 v3 certificates: a self-signed CA, and leaves
// signed by it. ECDSA P-256 throughout.
//
// extends the DER/ASN.1 machinery from csr.zig (DerBuf + SPKI encoder +
// ecdsa signing) into a TBSCertificate builder and a Certificate signer.
// minimal but correct for openssl verify: each cert carries the extensions
// it needs (basicConstraints, keyUsage, leaf SAN + EKU).
//
// security-critical custom crypto — see tests at the bottom and the openssl
// cross-check in PR 1.
//
// references:
//   RFC 5280 §4.1, §4.2 (Certificate, TBSCertificate, extensions)
//   RFC 5280 §4.1.2.5 (UTCTime — valid for years 1950..2049)
//   RFC 8410 / 5915 (key formats)

const std = @import("std");
const csr = @import("csr.zig");
const linux_platform = @import("linux_platform");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const DerBuf = csr.DerBuf;

pub const X509Error = error{
    EncodingFailed,
    SigningFailed,
    AllocFailed,
    InvalidParameters,
};

/// the result of minting a certificate. `cert_pem` is the PEM-encoded cert
/// (caller owns); `key_pair` is the matching private key — the caller is
/// responsible for storing it (e.g. encrypted in the secrets store).
pub const MintedCert = struct {
    cert_pem: []u8,
    key_pair: EcdsaP256.KeyPair,
};

/// mint a self-signed CA cert with the given subject CN and validity window.
/// the returned key_pair is the CA's private key — store it encrypted; it
/// will sign every leaf.
pub fn generateCa(
    io: std.Io,
    alloc: std.mem.Allocator,
    common_name: []const u8,
    not_before_unix: i64,
    not_after_unix: i64,
) X509Error!MintedCert {
    try validateValidity(not_before_unix, not_after_unix);
    const kp = EcdsaP256.KeyPair.generate(io);
    const cert_pem = try buildAndSign(alloc, .{
        .subject_cn = common_name,
        .issuer_cn = common_name, // self-signed
        .subject_pub = kp.public_key,
        .signer_key = kp,
        .not_before = not_before_unix,
        .not_after = not_after_unix,
        .is_ca = true,
        .identity_uri = null,
    });
    return .{ .cert_pem = cert_pem, .key_pair = kp };
}

/// mint a leaf cert for a service: subject CN = `subject_cn`, SAN URI =
/// `identity_uri` (e.g. "spiffe://<cluster>/service/<name>"), issued and
/// signed by `ca_key_pair`. EKU includes both serverAuth and clientAuth
/// because services act on both sides of an mTLS connection.
pub fn issueLeaf(
    io: std.Io,
    alloc: std.mem.Allocator,
    ca_key_pair: EcdsaP256.KeyPair,
    ca_common_name: []const u8,
    subject_cn: []const u8,
    identity_uri: []const u8,
    not_before_unix: i64,
    not_after_unix: i64,
) X509Error!MintedCert {
    try validateValidity(not_before_unix, not_after_unix);
    const kp = EcdsaP256.KeyPair.generate(io);
    const cert_pem = try buildAndSign(alloc, .{
        .subject_cn = subject_cn,
        .issuer_cn = ca_common_name,
        .subject_pub = kp.public_key,
        .signer_key = ca_key_pair,
        .not_before = not_before_unix,
        .not_after = not_after_unix,
        .is_ca = false,
        .identity_uri = identity_uri,
    });
    return .{ .cert_pem = cert_pem, .key_pair = kp };
}

// --- internals ---

const BuildArgs = struct {
    subject_cn: []const u8,
    issuer_cn: []const u8,
    subject_pub: EcdsaP256.PublicKey,
    signer_key: EcdsaP256.KeyPair,
    not_before: i64,
    not_after: i64,
    is_ca: bool,
    identity_uri: ?[]const u8,
};

fn validateValidity(not_before: i64, not_after: i64) X509Error!void {
    if (not_after <= not_before) return X509Error.InvalidParameters;
    // UTCTime is valid for years < 2050.
    const max_unix = 2524608000; // 2050-01-01T00:00:00Z
    if (not_after >= max_unix or not_before < 0) return X509Error.InvalidParameters;
}

fn buildAndSign(alloc: std.mem.Allocator, args: BuildArgs) X509Error![]u8 {
    var tbs: DerBuf = .{};
    buildTbs(&tbs, args) catch return X509Error.EncodingFailed;

    const sig = args.signer_key.sign(tbs.slice(), null) catch return X509Error.SigningFailed;
    var der_sig_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = sig.toDer(&der_sig_buf);

    var outer: DerBuf = .{};
    // tbsCertificate
    outer.appendSlice(tbs.slice()) catch return X509Error.EncodingFailed;
    // signatureAlgorithm: ecdsa-with-SHA256
    outer.appendSlice(&ecdsa_with_sha256_alg) catch return X509Error.EncodingFailed;
    // signatureValue: BIT STRING wrapping ECDSA-Sig-Value DER
    var bitstr: DerBuf = .{};
    bitstr.appendByte(0x00) catch return X509Error.EncodingFailed;
    bitstr.appendSlice(der_sig) catch return X509Error.EncodingFailed;
    outer.appendTagged(0x03, bitstr.slice()) catch return X509Error.EncodingFailed;

    var cert: DerBuf = .{};
    cert.appendTagged(0x30, outer.slice()) catch return X509Error.EncodingFailed;

    return derCertToPem(alloc, cert.slice());
}

// reuse the AlgorithmIdentifier from csr; both CSRs and certs sign with
// ecdsa-with-SHA256 over ECDSA P-256 keys.
const ecdsa_with_sha256_alg = csr.ecdsa_with_sha256_alg;

// X.509 v3 extension OIDs (extnID values). named so the cert builder reads in
// english instead of hex.
const oid_basic_constraints = [_]u8{ 0x55, 0x1D, 0x13 }; // 2.5.29.19
const oid_key_usage = [_]u8{ 0x55, 0x1D, 0x0F }; // 2.5.29.15
const oid_subject_alt_name = [_]u8{ 0x55, 0x1D, 0x11 }; // 2.5.29.17
const oid_ext_key_usage = [_]u8{ 0x55, 0x1D, 0x25 }; // 2.5.29.37

// EKU purposes (TLS).
const oid_eku_server_auth = [_]u8{ 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 }; // 1.3.6.1.5.5.7.3.1
const oid_eku_client_auth = [_]u8{ 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 }; // 1.3.6.1.5.5.7.3.2

fn buildTbs(out: *DerBuf, args: BuildArgs) !void {
    var content: DerBuf = .{};

    // version [0] EXPLICIT INTEGER { v3(2) }
    try content.appendSlice(&[_]u8{
        0xA0, 0x03,
        0x02, 0x01,
        0x02,
    });

    // serialNumber: random 16-byte positive INTEGER.
    try appendSerial(&content);

    // signature AlgorithmIdentifier (must match the outer signatureAlgorithm)
    try content.appendSlice(&ecdsa_with_sha256_alg);

    // issuer Name
    try csr.appendSubject(&content, args.issuer_cn);

    // validity
    try appendValidity(&content, args.not_before, args.not_after);

    // subject Name
    try csr.appendSubject(&content, args.subject_cn);

    // subjectPublicKeyInfo
    try csr.appendSubjectPublicKeyInfo(&content, args.subject_pub);

    // extensions [3] EXPLICIT SEQUENCE OF Extension
    try appendExtensions(&content, args.is_ca, args.identity_uri);

    // wrap in SEQUENCE
    try out.appendTagged(0x30, content.slice());
}

fn appendSerial(out: *DerBuf) !void {
    var raw: [16]u8 = undefined;
    linux_platform.randomBytes(&raw);
    // INTEGER must be minimal and positive. if the high bit is set, prepend
    // 0x00 so the value is read as positive.
    if (raw[0] & 0x80 != 0) {
        var prefixed: [17]u8 = undefined;
        prefixed[0] = 0x00;
        @memcpy(prefixed[1..17], &raw);
        try out.appendTagged(0x02, &prefixed);
    } else {
        try out.appendTagged(0x02, &raw);
    }
}

/// validity ::= SEQUENCE { notBefore Time, notAfter Time }
fn appendValidity(out: *DerBuf, not_before: i64, not_after: i64) !void {
    var content: DerBuf = .{};
    const nb = formatUtcTime(not_before);
    const na = formatUtcTime(not_after);
    try content.appendTagged(0x17, &nb); // UTCTime
    try content.appendTagged(0x17, &na);
    try out.appendTagged(0x30, content.slice());
}

/// format a unix timestamp as UTCTime "YYMMDDHHMMSSZ" (13 bytes).
/// caller is responsible for ensuring year < 2050 (validateValidity).
fn formatUtcTime(unix: i64) [13]u8 {
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(unix) };
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    var buf: [13]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}{d:0>2}Z", .{
        yd.year % 100,
        md.month.numeric(),
        md.day_index + 1,
        ds.getHoursIntoDay(),
        ds.getMinutesIntoHour(),
        ds.getSecondsIntoMinute(),
    }) catch unreachable;
    return buf;
}

/// extensions [3] EXPLICIT SEQUENCE OF Extension.
/// CA: basicConstraints(CA:TRUE) + keyUsage(keyCertSign+cRLSign).
/// leaf: basicConstraints(CA:FALSE) + keyUsage(digitalSignature) +
///       extKeyUsage(serverAuth, clientAuth) + subjectAltName(URI).
fn appendExtensions(out: *DerBuf, is_ca: bool, identity_uri: ?[]const u8) !void {
    var exts: DerBuf = .{};

    if (is_ca) {
        try appendBasicConstraintsCa(&exts);
        try appendKeyUsage(&exts, key_usage_ca);
    } else {
        try appendBasicConstraintsLeaf(&exts);
        try appendKeyUsage(&exts, key_usage_leaf);
        try appendExtKeyUsage(&exts);
        if (identity_uri) |uri| try appendSanUri(&exts, uri);
    }

    var seq: DerBuf = .{};
    try seq.appendTagged(0x30, exts.slice());

    try out.appendTagged(0xA3, seq.slice()); // [3] EXPLICIT
}

/// basicConstraints { CA: TRUE } critical.
fn appendBasicConstraintsCa(out: *DerBuf) !void {
    var value: DerBuf = .{};
    try value.appendSlice(&[_]u8{ 0x30, 0x03, 0x01, 0x01, 0xFF }); // SEQUENCE { BOOLEAN TRUE }
    try appendExtension(out, &oid_basic_constraints, true, value.slice());
}

/// basicConstraints { CA: FALSE } critical (encoded as an empty SEQUENCE).
fn appendBasicConstraintsLeaf(out: *DerBuf) !void {
    try appendExtension(out, &oid_basic_constraints, true, &[_]u8{ 0x30, 0x00 });
}

/// keyUsage extension critical with the given named-bit mask.
fn appendKeyUsage(out: *DerBuf, bits: u8) !void {
    // BIT STRING: 1 unused-bit count byte, then the byte holding our bits.
    // (single-byte usage covers digitalSignature .. keyEncipherment.)
    const value = [_]u8{
        0x03, 0x02, // BIT STRING, length 2
        0x01, // 1 unused bit (we use 7 of 8 high bits)
        bits,
    };
    try appendExtension(out, &oid_key_usage, true, &value);
}

// keyUsage bit positions (high-bit-first as encoded in the BIT STRING).
const key_usage_ca: u8 = 0b0000_0110; // keyCertSign(5) | cRLSign(6)
const key_usage_leaf: u8 = 0b1000_0000; // digitalSignature(0)

/// extKeyUsage with serverAuth + clientAuth (non-critical).
fn appendExtKeyUsage(out: *DerBuf) !void {
    var inner: DerBuf = .{};
    try inner.appendSlice(&oid_eku_server_auth);
    try inner.appendSlice(&oid_eku_client_auth);

    var value: DerBuf = .{};
    try value.appendTagged(0x30, inner.slice());

    try appendExtension(out, &oid_ext_key_usage, false, value.slice());
}

/// subjectAltName with a single URI entry (critical for leaf identity).
fn appendSanUri(out: *DerBuf, uri: []const u8) !void {
    var names: DerBuf = .{};
    try names.appendTagged(0x86, uri); // [6] IMPLICIT IA5String — uniformResourceIdentifier

    var value: DerBuf = .{};
    try value.appendTagged(0x30, names.slice());

    try appendExtension(out, &oid_subject_alt_name, true, value.slice());
}

/// Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE,
///                          extnValue OCTET STRING }
fn appendExtension(out: *DerBuf, oid: []const u8, critical: bool, value_der: []const u8) !void {
    var ext: DerBuf = .{};
    try ext.appendTagged(0x06, oid); // OID
    if (critical) try ext.appendSlice(&[_]u8{ 0x01, 0x01, 0xFF }); // BOOLEAN TRUE
    try ext.appendTagged(0x04, value_der); // OCTET STRING

    var seq: DerBuf = .{};
    try seq.appendTagged(0x30, ext.slice());
    try out.appendSlice(seq.slice());
}

// --- PEM cert wrapping ---

const cert_header = "-----BEGIN CERTIFICATE-----\n";
const cert_footer = "-----END CERTIFICATE-----\n";

fn derCertToPem(alloc: std.mem.Allocator, der: []const u8) X509Error![]u8 {
    const encoder = std.base64.standard.Encoder;
    const b64_len = encoder.calcSize(der.len);
    const b64 = alloc.alloc(u8, b64_len) catch return X509Error.AllocFailed;
    defer alloc.free(b64);
    _ = encoder.encode(b64, der);

    const num_lines = (b64_len + 63) / 64;
    const pem_len = cert_header.len + b64_len + num_lines + cert_footer.len;

    const out = alloc.alloc(u8, pem_len) catch return X509Error.AllocFailed;
    var pos: usize = 0;
    @memcpy(out[pos .. pos + cert_header.len], cert_header);
    pos += cert_header.len;

    var b64_pos: usize = 0;
    while (b64_pos < b64_len) {
        const line_end = @min(b64_pos + 64, b64_len);
        const line_len = line_end - b64_pos;
        @memcpy(out[pos .. pos + line_len], b64[b64_pos..line_end]);
        pos += line_len;
        out[pos] = '\n';
        pos += 1;
        b64_pos = line_end;
    }

    @memcpy(out[pos .. pos + cert_footer.len], cert_footer);
    pos += cert_footer.len;
    std.debug.assert(pos == pem_len);
    return out;
}

// -- tests --

const pem = @import("pem.zig");
const x509_parse = @import("cert_store/x509_parse.zig");

test "generateCa produces a parseable PEM cert with expected validity" {
    const alloc = std.testing.allocator;
    const not_before: i64 = 1735689600; // 2025-01-01
    const not_after: i64 = 1798761600; // 2027-01-01
    const ca = try generateCa(std.testing.io, alloc, "yoq-test-ca", not_before, not_after);
    defer alloc.free(ca.cert_pem);

    // PEM headers present.
    try std.testing.expect(std.mem.indexOf(u8, ca.cert_pem, cert_header) != null);
    try std.testing.expect(std.mem.indexOf(u8, ca.cert_pem, cert_footer) != null);

    // round-trip: parsing the cert yields the notAfter we asked for.
    const expiry = try x509_parse.parseExpiryFromPem(ca.cert_pem);
    try std.testing.expectEqual(not_after, expiry);

    // and it parses as DER.
    const der = try pem.parseCertDer(alloc, ca.cert_pem);
    defer alloc.free(der);
    try std.testing.expect(der.len > 0);
}

test "issueLeaf signs a leaf cert that verifies against the CA's public key" {
    const alloc = std.testing.allocator;
    const not_before: i64 = 1735689600;
    const not_after: i64 = 1767225600; // 2026-01-01
    const ca = try generateCa(std.testing.io, alloc, "yoq-test-ca", not_before, not_after);
    defer alloc.free(ca.cert_pem);

    const leaf = try issueLeaf(
        std.testing.io,
        alloc,
        ca.key_pair,
        "yoq-test-ca",
        "api",
        "spiffe://test/service/api",
        not_before,
        not_after,
    );
    defer alloc.free(leaf.cert_pem);

    // parse the leaf to DER so we can extract the signature and TBS bytes.
    const der = try pem.parseCertDer(alloc, leaf.cert_pem);
    defer alloc.free(der);

    const tbs_and_sig = try extractTbsAndSignature(der);
    // verify the CA public key signed the leaf's TBS.
    var sig_bytes_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    @memcpy(sig_bytes_buf[0..tbs_and_sig.sig_der.len], tbs_and_sig.sig_der);
    const sig = try EcdsaP256.Signature.fromDer(sig_bytes_buf[0..tbs_and_sig.sig_der.len]);
    try sig.verify(tbs_and_sig.tbs, ca.key_pair.public_key);
}

test "validity bounds are enforced" {
    try std.testing.expectError(X509Error.InvalidParameters, generateCa(std.testing.io, std.testing.allocator, "x", 200, 100));
    try std.testing.expectError(X509Error.InvalidParameters, generateCa(std.testing.io, std.testing.allocator, "x", -1, 100));
}

/// pull the raw TBS bytes (including their SEQUENCE header) and the ECDSA
/// signature DER out of a parsed cert. used by the verify test above.
fn extractTbsAndSignature(der: []const u8) !struct { tbs: []const u8, sig_der: []const u8 } {
    var pos: usize = 0;
    const outer = try x509_parse.parseAsn1Tag(der, &pos);
    if (outer.tag != 0x30) return error.InvalidCert;
    const end = pos + outer.length;

    const tbs_start = pos;
    const tbs_hdr = try x509_parse.parseAsn1Tag(der, &pos);
    if (tbs_hdr.tag != 0x30) return error.InvalidCert;
    pos += tbs_hdr.length;
    const tbs = der[tbs_start..pos];

    // skip signatureAlgorithm
    const alg = try x509_parse.parseAsn1Tag(der, &pos);
    if (alg.tag != 0x30) return error.InvalidCert;
    pos += alg.length;

    // signatureValue BIT STRING
    const sig_bs = try x509_parse.parseAsn1Tag(der, &pos);
    if (sig_bs.tag != 0x03) return error.InvalidCert;
    if (pos >= end or der[pos] != 0x00) return error.InvalidCert; // unused-bits byte
    const sig_der = der[pos + 1 .. pos + sig_bs.length];
    return .{ .tbs = tbs, .sig_der = sig_der };
}
