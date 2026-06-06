// x509_verify — chain verification for the cluster mTLS use case.
//
// scope is narrow on purpose: a single CA signs a single leaf, both ECDSA
// P-256 / SHA-256. that covers the path PR 1's x509_gen mints today. there
// is no support here for cross-signed chains, RSA, RFC 5280 path
// validation, CRL/OCSP — none of which the data plane needs.
//
// the parser walks the DER tree by hand using the asn1 helpers that
// `cert_store/x509_parse.zig` exposes. it pulls just the fields verify
// needs: TBS bytes (including their SEQUENCE header — that's the signed
// input), signature DER, signature algorithm OID, validity window, the
// public key from the SubjectPublicKeyInfo, subject CN, issuer CN, and
// the SAN URIs. anything else in the cert is skipped.
//
// `verifyLeafAgainstCa` is the public entry point: parse both certs, check
// issuer-DN match, validity window, signature against the CA's public
// key, and (optionally) that a required identity URI appears in the
// leaf's SAN. that's all the data plane (PR 4 client + server mTLS) and
// PR 5 (proxy) need.

const std = @import("std");
const pem_mod = @import("pem.zig");
const x509_parse = @import("cert_store/x509_parse.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Error = error{
    InvalidCert,
    UnsupportedAlgorithm,
    IssuerMismatch,
    SignatureInvalid,
    NotYetValid,
    Expired,
    IdentityMismatch,
    InvalidPem,
    Base64DecodeFailed,
    BufferTooSmall,
    OutOfMemory,
};

/// fields extracted from a parsed X.509 cert. all slices reference into
/// the DER buffer the caller owns — callers must keep the DER alive for
/// as long as they hold a `Parsed`.
pub const Parsed = struct {
    tbs: []const u8,
    sig_der: []const u8,
    sig_algorithm_is_ecdsa_sha256: bool,
    not_before: i64,
    not_after: i64,
    subject_cn: []const u8,
    issuer_cn: []const u8,
    /// uncompressed P-256 point (65 bytes: 0x04 || X || Y). when the cert
    /// uses an algorithm we don't support, this is empty and verify rejects.
    public_key_point: []const u8,
    /// SAN URIs from the subjectAltName extension. up to a fixed cap.
    san_uris: []const []const u8,
};

/// result of a successful verification — owns nothing but tells the
/// caller which identity it accepted.
pub const Verified = struct {
    peer_subject_cn: []const u8,
    peer_san_uris: []const []const u8,
};

const max_san_uris = 8;

pub fn parseDer(der: []const u8, san_buf: *[max_san_uris][]const u8) Error!Parsed {
    var pos: usize = 0;
    const outer = x509_parse.parseAsn1Tag(der, &pos) catch return Error.InvalidCert;
    if (outer.tag != 0x30) return Error.InvalidCert;

    const tbs_start = pos;
    const tbs_hdr = x509_parse.parseAsn1Tag(der, &pos) catch return Error.InvalidCert;
    if (tbs_hdr.tag != 0x30) return Error.InvalidCert;
    const tbs_body_start = pos;
    if (tbs_body_start + tbs_hdr.length > der.len) return Error.InvalidCert;
    pos += tbs_hdr.length;
    const tbs = der[tbs_start..pos];

    // signatureAlgorithm AlgorithmIdentifier ::= SEQUENCE { OID, params? }
    const sig_alg = x509_parse.parseAsn1Tag(der, &pos) catch return Error.InvalidCert;
    if (sig_alg.tag != 0x30) return Error.InvalidCert;
    const sig_algo_body = der[pos .. pos + sig_alg.length];
    pos += sig_alg.length;
    const sig_oid = extractFirstOid(sig_algo_body) catch return Error.InvalidCert;

    // signatureValue BIT STRING
    const sig_bs = x509_parse.parseAsn1Tag(der, &pos) catch return Error.InvalidCert;
    if (sig_bs.tag != 0x03) return Error.InvalidCert;
    if (pos + sig_bs.length > der.len) return Error.InvalidCert;
    if (sig_bs.length == 0 or der[pos] != 0x00) return Error.InvalidCert; // unused-bits byte
    const sig_der = der[pos + 1 .. pos + sig_bs.length];

    var inner = TbsFields{};
    try parseTbsFields(der[tbs_body_start .. tbs_body_start + tbs_hdr.length], &inner, san_buf);

    return .{
        .tbs = tbs,
        .sig_der = sig_der,
        .sig_algorithm_is_ecdsa_sha256 = oidEquals(sig_oid, &oid_ecdsa_with_sha256),
        .not_before = inner.not_before,
        .not_after = inner.not_after,
        .subject_cn = inner.subject_cn,
        .issuer_cn = inner.issuer_cn,
        .public_key_point = inner.public_key_point,
        .san_uris = san_buf[0..inner.san_count],
    };
}

fn extractFirstOid(seq_body: []const u8) ![]const u8 {
    var pos: usize = 0;
    const hdr = try x509_parse.parseAsn1Tag(seq_body, &pos);
    if (hdr.tag != 0x06) return Error.InvalidCert;
    if (pos + hdr.length > seq_body.len) return Error.InvalidCert;
    return seq_body[pos .. pos + hdr.length];
}

/// verify a leaf cert is signed by `ca_cert_pem`, is currently valid, and
/// (optionally) carries a required SAN URI. on success returns the peer's
/// subject CN and SAN URIs, both referencing slices inside the caller's
/// own buffers — caller keeps the PEM strings + DER allocations alive for
/// as long as the result is used.
pub fn verifyLeafAgainstCa(
    alloc: std.mem.Allocator,
    leaf_cert_pem: []const u8,
    ca_cert_pem: []const u8,
    expected_identity_uri: ?[]const u8,
    now_unix: i64,
) Error!void {
    const leaf_der = pem_mod.parseCertDer(alloc, leaf_cert_pem) catch return Error.InvalidPem;
    defer alloc.free(leaf_der);
    const ca_der = pem_mod.parseCertDer(alloc, ca_cert_pem) catch return Error.InvalidPem;
    defer alloc.free(ca_der);

    var leaf_sans: [max_san_uris][]const u8 = undefined;
    var ca_sans: [max_san_uris][]const u8 = undefined;
    const leaf = try parseDer(leaf_der, &leaf_sans);
    const ca = try parseDer(ca_der, &ca_sans);

    // structural checks first — cheaper than crypto and just as conclusive.
    if (!std.mem.eql(u8, leaf.issuer_cn, ca.subject_cn)) return Error.IssuerMismatch;
    if (now_unix < leaf.not_before) return Error.NotYetValid;
    if (now_unix > leaf.not_after) return Error.Expired;
    if (!leaf.sig_algorithm_is_ecdsa_sha256) return Error.UnsupportedAlgorithm;
    if (ca.public_key_point.len != 65 or ca.public_key_point[0] != 0x04) return Error.UnsupportedAlgorithm;

    if (expected_identity_uri) |want| {
        var matched = false;
        for (leaf.san_uris) |uri| {
            if (std.mem.eql(u8, uri, want)) {
                matched = true;
                break;
            }
        }
        if (!matched) return Error.IdentityMismatch;
    }

    // verify the CA's pubkey signed the leaf's TBS with ECDSA P-256 / SHA-256.
    var sec1: [65]u8 = undefined;
    @memcpy(&sec1, ca.public_key_point[0..65]);
    const ca_pubkey = EcdsaP256.PublicKey.fromSec1(&sec1) catch return Error.SignatureInvalid;

    var sig_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    if (leaf.sig_der.len > sig_buf.len) return Error.SignatureInvalid;
    @memcpy(sig_buf[0..leaf.sig_der.len], leaf.sig_der);
    const sig = EcdsaP256.Signature.fromDer(sig_buf[0..leaf.sig_der.len]) catch return Error.SignatureInvalid;
    sig.verify(leaf.tbs, ca_pubkey) catch return Error.SignatureInvalid;
}

// --- internal: walking the TBSCertificate ---

const TbsFields = struct {
    not_before: i64 = 0,
    not_after: i64 = 0,
    subject_cn: []const u8 = &.{},
    issuer_cn: []const u8 = &.{},
    public_key_point: []const u8 = &.{},
    san_count: usize = 0,
};

/// walk a TBSCertificate body (i.e. the content after the SEQUENCE header,
/// not including it). fills `out` and writes SAN URIs into `san_buf` from
/// index 0 up to `out.san_count`.
fn parseTbsFields(body: []const u8, out: *TbsFields, san_buf: *[max_san_uris][]const u8) Error!void {
    var pos: usize = 0;

    // [0] EXPLICIT version — optional, skip if present
    if (pos < body.len and body[pos] == 0xA0) {
        const ver_outer = x509_parse.parseAsn1Tag(body, &pos) catch return Error.InvalidCert;
        pos += ver_outer.length;
    }

    // serialNumber INTEGER
    const serial = x509_parse.parseAsn1Tag(body, &pos) catch return Error.InvalidCert;
    if (serial.tag != 0x02) return Error.InvalidCert;
    pos += serial.length;

    // signature AlgorithmIdentifier SEQUENCE — skip (signature_algorithm
    // on the outer cert is the authoritative one and we already grabbed it)
    const sig_alg = x509_parse.parseAsn1Tag(body, &pos) catch return Error.InvalidCert;
    if (sig_alg.tag != 0x30) return Error.InvalidCert;
    pos += sig_alg.length;

    // issuer Name SEQUENCE
    const issuer_hdr = x509_parse.parseAsn1Tag(body, &pos) catch return Error.InvalidCert;
    if (issuer_hdr.tag != 0x30) return Error.InvalidCert;
    out.issuer_cn = try extractCnFromName(body[pos .. pos + issuer_hdr.length]);
    pos += issuer_hdr.length;

    // validity SEQUENCE { notBefore, notAfter }
    const validity_hdr = x509_parse.parseAsn1Tag(body, &pos) catch return Error.InvalidCert;
    if (validity_hdr.tag != 0x30) return Error.InvalidCert;
    var v_pos: usize = 0;
    const validity_body = body[pos .. pos + validity_hdr.length];
    const nb_hdr = x509_parse.parseAsn1Tag(validity_body, &v_pos) catch return Error.InvalidCert;
    out.not_before = try parseTimeBytes(validity_body[v_pos .. v_pos + nb_hdr.length], nb_hdr.tag);
    v_pos += nb_hdr.length;
    const na_hdr = x509_parse.parseAsn1Tag(validity_body, &v_pos) catch return Error.InvalidCert;
    out.not_after = try parseTimeBytes(validity_body[v_pos .. v_pos + na_hdr.length], na_hdr.tag);
    pos += validity_hdr.length;

    // subject Name SEQUENCE
    const subject_hdr = x509_parse.parseAsn1Tag(body, &pos) catch return Error.InvalidCert;
    if (subject_hdr.tag != 0x30) return Error.InvalidCert;
    out.subject_cn = try extractCnFromName(body[pos .. pos + subject_hdr.length]);
    pos += subject_hdr.length;

    // subjectPublicKeyInfo SEQUENCE
    const spki_hdr = x509_parse.parseAsn1Tag(body, &pos) catch return Error.InvalidCert;
    if (spki_hdr.tag != 0x30) return Error.InvalidCert;
    out.public_key_point = try extractEcPointFromSpki(body[pos .. pos + spki_hdr.length]);
    pos += spki_hdr.length;

    // extensions [3] EXPLICIT — optional. there can be other optional fields
    // (issuerUniqueID [1], subjectUniqueID [2]) but x509_gen doesn't emit
    // them. walk anything that looks like a context-specific tag.
    while (pos < body.len) {
        const tag = body[pos];
        const hdr = x509_parse.parseAsn1Tag(body, &pos) catch return Error.InvalidCert;
        if (tag == 0xA3) {
            // [3] EXPLICIT extensions
            try extractSanUrisFromExtensions(body[pos .. pos + hdr.length], out, san_buf);
        }
        pos += hdr.length;
    }
}

fn extractCnFromName(name_body: []const u8) Error![]const u8 {
    // Name ::= SEQUENCE OF RDN ; RDN ::= SET OF ATV ; ATV ::= SEQUENCE { OID, value }
    var pos: usize = 0;
    while (pos < name_body.len) {
        const rdn_hdr = x509_parse.parseAsn1Tag(name_body, &pos) catch return Error.InvalidCert;
        if (rdn_hdr.tag != 0x31) {
            pos += rdn_hdr.length;
            continue;
        }
        const rdn_body = name_body[pos .. pos + rdn_hdr.length];
        pos += rdn_hdr.length;

        var rp: usize = 0;
        while (rp < rdn_body.len) {
            const atv_hdr = x509_parse.parseAsn1Tag(rdn_body, &rp) catch return Error.InvalidCert;
            if (atv_hdr.tag != 0x30) {
                rp += atv_hdr.length;
                continue;
            }
            const atv_body = rdn_body[rp .. rp + atv_hdr.length];
            rp += atv_hdr.length;

            var ap: usize = 0;
            const oid_hdr = x509_parse.parseAsn1Tag(atv_body, &ap) catch return Error.InvalidCert;
            if (oid_hdr.tag != 0x06) continue;
            const oid_bytes = atv_body[ap .. ap + oid_hdr.length];
            ap += oid_hdr.length;
            if (!oidEquals(oid_bytes, &oid_common_name)) continue;
            const val_hdr = x509_parse.parseAsn1Tag(atv_body, &ap) catch return Error.InvalidCert;
            // utf8String (0x0C), printableString (0x13), or ia5String (0x16) are all fine.
            return atv_body[ap .. ap + val_hdr.length];
        }
    }
    return Error.InvalidCert;
}

fn extractEcPointFromSpki(spki_body: []const u8) Error![]const u8 {
    // SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
    var pos: usize = 0;
    const alg = x509_parse.parseAsn1Tag(spki_body, &pos) catch return Error.InvalidCert;
    if (alg.tag != 0x30) return Error.InvalidCert;
    pos += alg.length;
    const bs = x509_parse.parseAsn1Tag(spki_body, &pos) catch return Error.InvalidCert;
    if (bs.tag != 0x03) return Error.InvalidCert;
    if (bs.length == 0 or spki_body[pos] != 0x00) return Error.InvalidCert; // unused-bits byte
    return spki_body[pos + 1 .. pos + bs.length];
}

fn extractSanUrisFromExtensions(exts_body: []const u8, out: *TbsFields, san_buf: *[max_san_uris][]const u8) Error!void {
    // extensions [3] EXPLICIT wraps a SEQUENCE OF Extension. one inner SEQ.
    var pos: usize = 0;
    const seq = x509_parse.parseAsn1Tag(exts_body, &pos) catch return Error.InvalidCert;
    if (seq.tag != 0x30) return Error.InvalidCert;
    const exts = exts_body[pos .. pos + seq.length];

    var ep: usize = 0;
    while (ep < exts.len) {
        const ext = x509_parse.parseAsn1Tag(exts, &ep) catch return Error.InvalidCert;
        if (ext.tag != 0x30) {
            ep += ext.length;
            continue;
        }
        const ext_body = exts[ep .. ep + ext.length];
        ep += ext.length;

        var bp: usize = 0;
        const oid_hdr = x509_parse.parseAsn1Tag(ext_body, &bp) catch return Error.InvalidCert;
        if (oid_hdr.tag != 0x06) continue;
        const oid_bytes = ext_body[bp .. bp + oid_hdr.length];
        bp += oid_hdr.length;

        // skip optional critical BOOLEAN
        if (bp < ext_body.len and ext_body[bp] == 0x01) {
            const crit = x509_parse.parseAsn1Tag(ext_body, &bp) catch return Error.InvalidCert;
            bp += crit.length;
        }

        // extnValue OCTET STRING
        const octets = x509_parse.parseAsn1Tag(ext_body, &bp) catch return Error.InvalidCert;
        if (octets.tag != 0x04) continue;
        const inner = ext_body[bp .. bp + octets.length];

        if (oidEquals(oid_bytes, &oid_san)) {
            try fillSanUris(inner, out, san_buf);
        }
    }
}

fn fillSanUris(san_octets: []const u8, out: *TbsFields, san_buf: *[max_san_uris][]const u8) Error!void {
    var pos: usize = 0;
    const seq = x509_parse.parseAsn1Tag(san_octets, &pos) catch return Error.InvalidCert;
    if (seq.tag != 0x30) return Error.InvalidCert;
    const body = san_octets[pos .. pos + seq.length];

    var p: usize = 0;
    while (p < body.len) {
        const tag = body[p];
        const hdr = x509_parse.parseAsn1Tag(body, &p) catch return Error.InvalidCert;
        // [6] IMPLICIT IA5String → URI in CHOICE
        if (tag == 0x86) {
            if (out.san_count < max_san_uris) {
                san_buf[out.san_count] = body[p .. p + hdr.length];
                out.san_count += 1;
            }
        }
        p += hdr.length;
    }
}

fn parseTimeBytes(bytes: []const u8, tag: u8) Error!i64 {
    if (tag == 0x17) {
        return x509_parse.parseUtcTime(bytes) catch Error.InvalidCert;
    } else if (tag == 0x18) {
        return x509_parse.parseGeneralizedTime(bytes) catch Error.InvalidCert;
    }
    return Error.InvalidCert;
}

fn oidEquals(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

// OID constants. these are the DER-encoded contents of OBJECT IDENTIFIER
// (i.e. the bytes inside the tag-length wrapper).
const oid_common_name = [_]u8{ 0x55, 0x04, 0x03 }; // 2.5.4.3
const oid_san = [_]u8{ 0x55, 0x1d, 0x11 }; // 2.5.29.17
const oid_ecdsa_with_sha256 = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };

// --- tests ---

const x509_gen = @import("x509_gen.zig");

const test_ca_cn = "yoq-test-ca";
const test_leaf_cn = "api";
const test_san = "spiffe://yoq-cluster/service/api";
const test_now: i64 = 1_700_000_000;
const test_window: i64 = 24 * 3600;

fn mintCaAndLeaf(alloc: std.mem.Allocator) !struct { ca_pem: []u8, leaf_pem: []u8 } {
    const ca = try x509_gen.generateCa(std.testing.io, alloc, test_ca_cn, test_now - 3600, test_now + test_window);
    errdefer alloc.free(ca.cert_pem);
    const leaf = try x509_gen.issueLeaf(
        std.testing.io,
        alloc,
        ca.key_pair,
        test_ca_cn,
        test_leaf_cn,
        test_san,
        test_now - 60,
        test_now + test_window,
    );
    return .{ .ca_pem = ca.cert_pem, .leaf_pem = leaf.cert_pem };
}

test "verifyLeafAgainstCa accepts a freshly minted leaf" {
    const alloc = std.testing.allocator;
    const pair = try mintCaAndLeaf(alloc);
    defer alloc.free(pair.ca_pem);
    defer alloc.free(pair.leaf_pem);

    try verifyLeafAgainstCa(alloc, pair.leaf_pem, pair.ca_pem, test_san, test_now);
}

test "verifyLeafAgainstCa accepts without expected identity" {
    const alloc = std.testing.allocator;
    const pair = try mintCaAndLeaf(alloc);
    defer alloc.free(pair.ca_pem);
    defer alloc.free(pair.leaf_pem);

    try verifyLeafAgainstCa(alloc, pair.leaf_pem, pair.ca_pem, null, test_now);
}

test "rejects when identity URI does not match" {
    const alloc = std.testing.allocator;
    const pair = try mintCaAndLeaf(alloc);
    defer alloc.free(pair.ca_pem);
    defer alloc.free(pair.leaf_pem);

    try std.testing.expectError(
        Error.IdentityMismatch,
        verifyLeafAgainstCa(alloc, pair.leaf_pem, pair.ca_pem, "spiffe://yoq-cluster/service/billing", test_now),
    );
}

test "rejects when cert is not yet valid" {
    const alloc = std.testing.allocator;
    const pair = try mintCaAndLeaf(alloc);
    defer alloc.free(pair.ca_pem);
    defer alloc.free(pair.leaf_pem);

    try std.testing.expectError(
        Error.NotYetValid,
        verifyLeafAgainstCa(alloc, pair.leaf_pem, pair.ca_pem, null, test_now - 7200),
    );
}

test "rejects when cert has expired" {
    const alloc = std.testing.allocator;
    const pair = try mintCaAndLeaf(alloc);
    defer alloc.free(pair.ca_pem);
    defer alloc.free(pair.leaf_pem);

    try std.testing.expectError(
        Error.Expired,
        verifyLeafAgainstCa(alloc, pair.leaf_pem, pair.ca_pem, null, test_now + test_window + 7200),
    );
}

test "rejects when signed by a different CA" {
    const alloc = std.testing.allocator;
    const pair = try mintCaAndLeaf(alloc);
    defer alloc.free(pair.ca_pem);
    defer alloc.free(pair.leaf_pem);

    // mint a second, unrelated CA. issuer CN is the same string, so the
    // structural check passes — only the signature check should catch this.
    const other_ca = try x509_gen.generateCa(std.testing.io, alloc, test_ca_cn, test_now - 3600, test_now + test_window);
    defer alloc.free(other_ca.cert_pem);

    try std.testing.expectError(
        Error.SignatureInvalid,
        verifyLeafAgainstCa(alloc, pair.leaf_pem, other_ca.cert_pem, null, test_now),
    );
}

test "rejects when issuer CN does not match CA subject CN" {
    const alloc = std.testing.allocator;
    const ca = try x509_gen.generateCa(std.testing.io, alloc, "other-ca", test_now - 3600, test_now + test_window);
    defer alloc.free(ca.cert_pem);

    const pair = try mintCaAndLeaf(alloc);
    defer alloc.free(pair.ca_pem);
    defer alloc.free(pair.leaf_pem);

    try std.testing.expectError(
        Error.IssuerMismatch,
        verifyLeafAgainstCa(alloc, pair.leaf_pem, ca.cert_pem, null, test_now),
    );
}

test "rejects a tampered signature" {
    const alloc = std.testing.allocator;
    const pair = try mintCaAndLeaf(alloc);
    defer alloc.free(pair.ca_pem);

    // decode the leaf, flip the second-to-last value byte (well inside the
    // signature BIT STRING — structural parse still succeeds, but the ECDSA
    // verify rejects). flipping a TBS byte risks breaking length prefixes.
    const der = try pem_mod.parseCertDer(alloc, pair.leaf_pem);
    defer alloc.free(der);
    alloc.free(pair.leaf_pem);

    if (der.len < 4) return error.TestUnexpectedDer;
    const mutable = try alloc.dupe(u8, der);
    defer alloc.free(mutable);
    mutable[mutable.len - 2] ^= 0x01;

    var pem_out: std.ArrayList(u8) = .empty;
    defer pem_out.deinit(alloc);
    try pem_out.appendSlice(alloc, "-----BEGIN CERTIFICATE-----\n");
    var b64_buf: [4096]u8 = undefined;
    const b64_len = std.base64.standard.Encoder.calcSize(mutable.len);
    if (b64_len > b64_buf.len) return error.TestUnexpectedDer;
    _ = std.base64.standard.Encoder.encode(b64_buf[0..b64_len], mutable);
    try pem_out.appendSlice(alloc, b64_buf[0..b64_len]);
    try pem_out.appendSlice(alloc, "\n-----END CERTIFICATE-----\n");

    try std.testing.expectError(
        Error.SignatureInvalid,
        verifyLeafAgainstCa(alloc, pem_out.items, pair.ca_pem, null, test_now),
    );
}
