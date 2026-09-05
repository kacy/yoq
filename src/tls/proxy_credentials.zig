const std = @import("std");
const secrets = @import("../state/secrets.zig");
const mtls_store = @import("../state/store/certificates_mtls.zig");
const identity = @import("peer_identity.zig");
const verify = @import("x509_verify.zig");
const csr = @import("csr.zig");

pub const Key = [secrets.key_length]u8;

/// Own a fresh database snapshot for one dial. Rotation never changes buffers
/// used by an in-flight handshake, and private material is cleared on release.
pub const Credentials = struct {
    cert_pem: []u8,
    key_pem: []u8,

    pub fn deinit(self: Credentials, alloc: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.key_pem);
        alloc.free(self.key_pem);
        alloc.free(self.cert_pem);
    }
};

pub fn load(alloc: std.mem.Allocator, key: Key, ca_pem: []const u8, now: i64) !Credentials {
    const rec = (try mtls_store.getProxy(alloc)) orelse return error.ProxyCredentialsMissing;
    defer rec.deinit(alloc);
    _ = try verify.verifyLeafAgainstCa(alloc, rec.cert_pem, ca_pem, identity.proxy_identity, now);
    if (rec.key_nonce.len != secrets.nonce_length or rec.key_tag.len != secrets.tag_length) return error.InvalidEncryptedKey;
    const raw_key = try secrets.decrypt(alloc, rec.encrypted_key, rec.key_nonce[0..secrets.nonce_length].*, rec.key_tag[0..secrets.tag_length].*, key);
    defer {
        std.crypto.secureZero(u8, raw_key);
        alloc.free(raw_key);
    }
    if (raw_key.len != 32) return error.InvalidSecretKey;
    const pem = try csr.derKeyToPem(alloc, raw_key);
    errdefer {
        std.crypto.secureZero(u8, pem);
        alloc.free(pem);
    }
    return .{ .cert_pem = try alloc.dupe(u8, rec.cert_pem), .key_pem = pem };
}
