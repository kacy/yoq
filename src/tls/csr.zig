// csr — minimal X.509 Certificate Signing Request generation
//
// generates a DER-encoded PKCS#10 CSR for ACME certificate provisioning.
// uses ECDSA P-256 with SHA-256 for the signature algorithm, matching
// the JWS signing algorithm used for ACME requests.
//
// only supports a single domain (CN in subject + SAN extension).
// this is sufficient for ACME HTTP-01 single-domain certificates.
//
// references:
//   RFC 2986 (PKCS#10 CSR)
//   RFC 5280 §4.2.1.6 (Subject Alternative Name)

const std = @import("std");
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const CsrError = error{
    SigningFailed,
    EncodingFailed,
    AllocFailed,
    DomainTooLong,
};

/// generate an ECDSA P-256 keypair and a DER-encoded CSR for the given domain.
/// returns the CSR bytes and the keypair (caller needs the private key for
/// the certificate later).
///
/// caller owns the returned CSR bytes.
pub fn generateCsr(
    io: std.Io,
    allocator: std.mem.Allocator,
    domain: []const u8,
) CsrError!struct { csr_der: []u8, key_pair: EcdsaP256.KeyPair } {
    if (domain.len > 253) return CsrError.DomainTooLong;

    const kp = EcdsaP256.KeyPair.generate(io);
    const csr_der = try buildCsr(allocator, domain, kp);

    return .{
        .csr_der = csr_der,
        .key_pair = kp,
    };
}

// -- CSR building --

/// build the full DER-encoded CSR.
fn buildCsr(
    allocator: std.mem.Allocator,
    domain: []const u8,
    key_pair: EcdsaP256.KeyPair,
) CsrError![]u8 {
    // step 1: build CertificationRequestInfo (the to-be-signed portion)
    var info: DerBuf = .{};
    buildCertRequestInfo(&info, domain, key_pair.public_key) catch
        return CsrError.EncodingFailed;

    // step 2: sign the info
    const sig = key_pair.sign(info.slice(), null) catch
        return CsrError.SigningFailed;

    // step 3: assemble the full CSR
    var inner: DerBuf = .{};
    inner.appendSlice(info.slice()) catch return CsrError.EncodingFailed;

    // signatureAlgorithm: ecdsa-with-SHA256 (OID 1.2.840.10045.4.3.2)
    inner.appendSlice(&[_]u8{
        0x30, 0x0A, // SEQUENCE, length 10
        0x06, 0x08, // OID, length 8
        0x2A, 0x86,
        0x48, 0xCE,
        0x3D, 0x04,
        0x03, 0x02,
    }) catch return CsrError.EncodingFailed;

    // signature: BIT STRING wrapping DER-encoded ECDSA signature
    var der_sig_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = sig.toDer(&der_sig_buf);

    var bitstring: DerBuf = .{};
    bitstring.appendByte(0x00) catch return CsrError.EncodingFailed;
    bitstring.appendSlice(der_sig) catch return CsrError.EncodingFailed;
    inner.appendTagged(0x03, bitstring.slice()) catch return CsrError.EncodingFailed;

    // wrap in outer SEQUENCE
    var csr: DerBuf = .{};
    csr.appendTagged(0x30, inner.slice()) catch return CsrError.EncodingFailed;

    return allocator.dupe(u8, csr.slice()) catch return CsrError.AllocFailed;
}

/// build the CertificationRequestInfo portion.
fn buildCertRequestInfo(
    out: *DerBuf,
    domain: []const u8,
    public_key: EcdsaP256.PublicKey,
) !void {
    var content: DerBuf = .{};

    // version: INTEGER 0
    try content.appendSlice(&[_]u8{ 0x02, 0x01, 0x00 });

    // subject: SEQUENCE { SET { SEQUENCE { OID(CN), UTF8String(domain) } } }
    try appendSubject(&content, domain);

    // subjectPKInfo
    try appendSubjectPublicKeyInfo(&content, public_key);

    // attributes [0]: extensionRequest with SAN
    try appendAttributes(&content, domain);

    // wrap content in SEQUENCE
    try out.appendTagged(0x30, content.slice());
}

/// append subject (CommonName only).
fn appendSubject(out: *DerBuf, domain: []const u8) !void {
    // AttributeTypeAndValue: SEQUENCE { OID(CN), UTF8String(domain) }
    var atv: DerBuf = .{};
    try atv.appendSlice(&[_]u8{ 0x06, 0x03, 0x55, 0x04, 0x03 }); // OID: commonName
    try atv.appendTagged(0x0C, domain); // UTF8String

    // wrap in SEQUENCE
    var atv_seq: DerBuf = .{};
    try atv_seq.appendTagged(0x30, atv.slice());

    // wrap in SET
    var rdn: DerBuf = .{};
    try rdn.appendTagged(0x31, atv_seq.slice());

    // subject is a SEQUENCE of RDNs
    try out.appendTagged(0x30, rdn.slice());
}

/// append SubjectPublicKeyInfo for EC P-256.
fn appendSubjectPublicKeyInfo(out: *DerBuf, public_key: EcdsaP256.PublicKey) !void {
    var inner: DerBuf = .{};

    // algorithm: SEQUENCE { OID(ecPublicKey), OID(prime256v1) }
    try inner.appendSlice(&[_]u8{
        0x30, 0x13, // SEQUENCE, length 19
        0x06, 0x07, // OID, length 7
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, // ecPublicKey (1.2.840.10045.2.1)
        0x06, 0x08, // OID, length 8
        0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, // prime256v1 (1.2.840.10045.3.1.7)
    });

    // public key as BIT STRING wrapping uncompressed SEC1 point
    const pub_bytes = public_key.toUncompressedSec1();
    var bitstring: DerBuf = .{};
    try bitstring.appendByte(0x00); // unused bits = 0
    try bitstring.appendSlice(&pub_bytes);
    try inner.appendTagged(0x03, bitstring.slice());

    try out.appendTagged(0x30, inner.slice());
}

/// append attributes [0] with extensionRequest containing SAN.
fn appendAttributes(out: *DerBuf, domain: []const u8) !void {
    // SAN extension value: SEQUENCE { dNSName }
    var san_val: DerBuf = .{};
    try san_val.appendTagged(0x82, domain); // dNSName: context [2] implicit

    var san_seq: DerBuf = .{};
    try san_seq.appendTagged(0x30, san_val.slice());

    // wrap in OCTET STRING
    var san_oct: DerBuf = .{};
    try san_oct.appendTagged(0x04, san_seq.slice());

    // extension: SEQUENCE { OID(subjectAltName), OCTET STRING }
    var ext: DerBuf = .{};
    try ext.appendSlice(&[_]u8{ 0x06, 0x03, 0x55, 0x1D, 0x11 }); // OID: subjectAltName (2.5.29.17)
    try ext.appendSlice(san_oct.slice());

    var ext_seq: DerBuf = .{};
    try ext_seq.appendTagged(0x30, ext.slice());

    // extensions: SEQUENCE { extension }
    var exts: DerBuf = .{};
    try exts.appendTagged(0x30, ext_seq.slice());

    // extensionRequest: SEQUENCE { OID, SET { extensions } }
    var extreq: DerBuf = .{};
    try extreq.appendSlice(&[_]u8{
        0x06, 0x09, // OID, length 9
        0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E, // extensionRequest (1.2.840.113549.1.9.14)
    });
    var exts_set: DerBuf = .{};
    try exts_set.appendTagged(0x31, exts.slice());
    try extreq.appendSlice(exts_set.slice());

    var extreq_seq: DerBuf = .{};
    try extreq_seq.appendTagged(0x30, extreq.slice());

    // attributes: [0] IMPLICIT
    try out.appendTagged(0xA0, extreq_seq.slice());
}

// -- DER buffer helper --
//
// simple fixed-size buffer for building DER structures without allocation.
// 2KB is enough for a single-domain CSR.

pub const DerBuf = struct {
    data: [2048]u8 = undefined,
    len: usize = 0,

    fn slice(self: *const DerBuf) []const u8 {
        return self.data[0..self.len];
    }

    fn appendByte(self: *DerBuf, b: u8) !void {
        if (self.len >= self.data.len) return error.BufferTooSmall;
        self.data[self.len] = b;
        self.len += 1;
    }

    fn appendSlice(self: *DerBuf, s: []const u8) !void {
        if (self.len + s.len > self.data.len) return error.BufferTooSmall;
        @memcpy(self.data[self.len .. self.len + s.len], s);
        self.len += s.len;
    }

    /// write a TLV (tag-length-value) for the given data.
    fn appendTagged(self: *DerBuf, tag: u8, content: []const u8) !void {
        try self.appendByte(tag);
        try self.appendLength(content.len);
        try self.appendSlice(content);
    }

    fn appendLength(self: *DerBuf, length: usize) !void {
        if (length < 128) {
            try self.appendByte(@intCast(length));
        } else if (length < 256) {
            try self.appendByte(0x81);
            try self.appendByte(@intCast(length));
        } else {
            try self.appendByte(0x82);
            try self.appendByte(@intCast(length >> 8));
            try self.appendByte(@intCast(length & 0xFF));
        }
    }
};

/// wrap a raw EC P-256 private key (32 bytes) in PEM format.
///
/// builds an RFC 5915 ECPrivateKey DER structure and base64-encodes
/// it with PEM headers. caller owns the returned memory.
///
/// securely zeroes all intermediate buffers containing key material.
pub fn derKeyToPem(allocator: std.mem.Allocator, raw_key: []const u8) CsrError![]u8 {
    if (raw_key.len != 32) return CsrError.EncodingFailed;

    // derive public key from the private key for the DER structure
    const kp = EcdsaP256.KeyPair.fromSecretKey(
        EcdsaP256.SecretKey.fromBytes(raw_key[0..32].*) catch return CsrError.SigningFailed,
    ) catch return CsrError.SigningFailed;
    const pub_uncompressed = kp.public_key.toUncompressedSec1(); // 65 bytes

    // build the ECPrivateKey DER structure using DerBuf
    var content: DerBuf = .{};
    defer std.crypto.secureZero(u8, &content.data);

    // version: INTEGER 1
    content.appendSlice(&[_]u8{ 0x02, 0x01, 0x01 }) catch return CsrError.EncodingFailed;

    // privateKey: OCTET STRING (32 bytes)
    content.appendTagged(0x04, raw_key) catch return CsrError.EncodingFailed;

    // parameters [0] EXPLICIT: OID prime256v1
    content.appendTagged(0xA0, &[_]u8{
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    }) catch return CsrError.EncodingFailed;

    // publicKey [1] EXPLICIT: BIT STRING wrapping uncompressed point
    var bitstring: DerBuf = .{};
    bitstring.appendByte(0x00) catch return CsrError.EncodingFailed; // unused bits
    bitstring.appendSlice(&pub_uncompressed) catch return CsrError.EncodingFailed;

    var pubkey_wrapped: DerBuf = .{};
    pubkey_wrapped.appendTagged(0x03, bitstring.slice()) catch return CsrError.EncodingFailed;
    content.appendTagged(0xA1, pubkey_wrapped.slice()) catch return CsrError.EncodingFailed;

    // wrap in outer SEQUENCE
    var der: DerBuf = .{};
    defer std.crypto.secureZero(u8, &der.data);
    der.appendTagged(0x30, content.slice()) catch return CsrError.EncodingFailed;

    const der_bytes = der.slice();

    // PEM-encode: base64 with line wrapping at 64 chars
    const encoder = std.base64.standard.Encoder;
    const b64_len = encoder.calcSize(der_bytes.len);
    const b64 = allocator.alloc(u8, b64_len) catch return CsrError.AllocFailed;
    defer {
        std.crypto.secureZero(u8, b64);
        allocator.free(b64);
    }
    _ = encoder.encode(b64, der_bytes);

    // PEM layout: header + base64 lines (64 chars + newline each) + footer
    const header = "-----BEGIN EC PRIVATE KEY-----\n";
    const footer = "-----END EC PRIVATE KEY-----\n";
    const num_lines = (b64_len + 63) / 64;
    const pem_len = header.len + b64_len + num_lines + footer.len;

    const pem = allocator.alloc(u8, pem_len) catch return CsrError.AllocFailed;
    var pos: usize = 0;

    @memcpy(pem[pos .. pos + header.len], header);
    pos += header.len;

    // write base64 with line breaks every 64 chars
    var b64_pos: usize = 0;
    while (b64_pos < b64_len) {
        const line_end = @min(b64_pos + 64, b64_len);
        const line_len = line_end - b64_pos;
        @memcpy(pem[pos .. pos + line_len], b64[b64_pos..line_end]);
        pos += line_len;
        pem[pos] = '\n';
        pos += 1;
        b64_pos = line_end;
    }

    @memcpy(pem[pos .. pos + footer.len], footer);
    pos += footer.len;

    return pem;
}

// -- tests --

test "generateCsr produces valid DER" {
    const alloc = std.testing.allocator;

    const result = try generateCsr(std.testing.io, alloc, "example.com");
    defer alloc.free(result.csr_der);

    // CSR must start with SEQUENCE tag (0x30)
    try std.testing.expectEqual(@as(u8, 0x30), result.csr_der[0]);

    // should be non-trivially long (at least 200 bytes for a minimal CSR)
    try std.testing.expect(result.csr_der.len > 200);
}

test "generateCsr contains domain" {
    const alloc = std.testing.allocator;

    const domain = "test.example.org";
    const result = try generateCsr(std.testing.io, alloc, domain);
    defer alloc.free(result.csr_der);

    // the domain should appear in the DER (in CN and SAN)
    try std.testing.expect(std.mem.indexOf(u8, result.csr_der, domain) != null);
}

test "generateCsr different domains produce different CSRs" {
    const alloc = std.testing.allocator;

    const r1 = try generateCsr(std.testing.io, alloc, "foo.com");
    defer alloc.free(r1.csr_der);
    const r2 = try generateCsr(std.testing.io, alloc, "bar.com");
    defer alloc.free(r2.csr_der);

    try std.testing.expect(!std.mem.eql(u8, r1.csr_der, r2.csr_der));
}

test "generateCsr rejects domain too long" {
    const alloc = std.testing.allocator;
    const long_domain = "a" ** 254;
    try std.testing.expectError(CsrError.DomainTooLong, generateCsr(std.testing.io, alloc, long_domain));
}

test "CSR contains ecdsa-with-SHA256 OID" {
    const alloc = std.testing.allocator;

    const result = try generateCsr(std.testing.io, alloc, "example.com");
    defer alloc.free(result.csr_der);

    const ecdsa_sha256_oid = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02 };
    try std.testing.expect(std.mem.indexOf(u8, result.csr_der, &ecdsa_sha256_oid) != null);
}

test "CSR contains ecPublicKey OID" {
    const alloc = std.testing.allocator;

    const result = try generateCsr(std.testing.io, alloc, "example.com");
    defer alloc.free(result.csr_der);

    const ec_pub_oid = [_]u8{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
    try std.testing.expect(std.mem.indexOf(u8, result.csr_der, &ec_pub_oid) != null);
}

test "CSR contains subjectAltName OID" {
    const alloc = std.testing.allocator;

    const result = try generateCsr(std.testing.io, alloc, "example.com");
    defer alloc.free(result.csr_der);

    const san_oid = [_]u8{ 0x55, 0x1D, 0x11 }; // 2.5.29.17
    try std.testing.expect(std.mem.indexOf(u8, result.csr_der, &san_oid) != null);
}

test "DerBuf appendTagged" {
    var buf: DerBuf = .{};

    try buf.appendTagged(0x30, &[_]u8{ 0x01, 0x02 });

    try std.testing.expectEqual(@as(u8, 0x30), buf.data[0]);
    try std.testing.expectEqual(@as(u8, 2), buf.data[1]);
    try std.testing.expectEqual(@as(u8, 0x01), buf.data[2]);
    try std.testing.expectEqual(@as(u8, 0x02), buf.data[3]);
    try std.testing.expectEqual(@as(usize, 4), buf.len);
}

test "DerBuf appendLength long form" {
    var buf: DerBuf = .{};

    try buf.appendLength(200);

    try std.testing.expectEqual(@as(u8, 0x81), buf.data[0]);
    try std.testing.expectEqual(@as(u8, 200), buf.data[1]);
    try std.testing.expectEqual(@as(usize, 2), buf.len);
}

test "derKeyToPem produces valid PEM" {
    const alloc = std.testing.allocator;

    // generate a keypair to get a valid 32-byte secret key
    const kp = EcdsaP256.KeyPair.generate(std.testing.io);
    const key_bytes = kp.secret_key.toBytes();

    const pem = try derKeyToPem(alloc, &key_bytes);
    defer alloc.free(pem);

    // must have correct PEM headers
    try std.testing.expect(std.mem.startsWith(u8, pem, "-----BEGIN EC PRIVATE KEY-----\n"));
    try std.testing.expect(std.mem.endsWith(u8, pem, "-----END EC PRIVATE KEY-----\n"));
}

test "derKeyToPem rejects wrong key length" {
    const alloc = std.testing.allocator;

    const short_key = [_]u8{0} ** 16;
    try std.testing.expectError(CsrError.EncodingFailed, derKeyToPem(alloc, &short_key));
}
