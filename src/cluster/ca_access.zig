// ca_access — load the cluster's mTLS CA cert + private key on demand.
//
// the CA cert is in raft state (cluster_ca table, see PR #432) and the
// private key is encrypted there with sha256(join_token). every node in the
// cluster has the join token, so any node can decrypt and sign with the CA
// after a leader has bootstrapped it (ca_bootstrap.zig). this module exists
// because issuing leaf certs is a per-call operation, separate from the
// one-time bootstrap. callers are expected to secureZero the secret-key
// bytes via the returned helper.

const std = @import("std");
const store = @import("../state/store.zig");
const secrets = @import("../state/secrets.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Error = error{
    NotBootstrapped,
    InvalidEncryptedKey,
    DecryptFailed,
    InvalidSecretKey,
    StoreReadFailed,
    OutOfMemory,
};

pub const Loaded = struct {
    cert_pem: []u8,
    key_pair: EcdsaP256.KeyPair,

    /// release the cert pem and zero the in-memory secret key. callers
    /// usually `defer loaded.deinit(alloc)` right after loading.
    pub fn deinit(self: *Loaded, alloc: std.mem.Allocator) void {
        alloc.free(self.cert_pem);
        var raw = self.key_pair.secret_key.toBytes();
        std.crypto.secureZero(u8, &raw);
    }
};

/// fetch the cluster CA cert + decrypt its private key. returns
/// `error.NotBootstrapped` when no leader has seeded the row yet.
pub fn load(alloc: std.mem.Allocator, join_token: []const u8) Error!Loaded {
    const rec_opt = store.getClusterCa(alloc) catch return Error.StoreReadFailed;
    const rec = rec_opt orelse return Error.NotBootstrapped;
    defer rec.deinit(alloc);

    if (rec.key_nonce.len != secrets.nonce_length or rec.key_tag.len != secrets.tag_length) {
        return Error.InvalidEncryptedKey;
    }

    var nonce: [secrets.nonce_length]u8 = undefined;
    var tag: [secrets.tag_length]u8 = undefined;
    @memcpy(&nonce, rec.key_nonce);
    @memcpy(&tag, rec.key_tag);

    const derived_key = deriveKey(join_token);
    const raw_key = secrets.decrypt(alloc, rec.encrypted_key, nonce, tag, derived_key) catch return Error.DecryptFailed;
    defer {
        std.crypto.secureZero(u8, raw_key);
        alloc.free(raw_key);
    }

    if (raw_key.len != 32) return Error.InvalidSecretKey;

    const sk = EcdsaP256.SecretKey.fromBytes(raw_key[0..32].*) catch return Error.InvalidSecretKey;
    const kp = EcdsaP256.KeyPair.fromSecretKey(sk) catch return Error.InvalidSecretKey;

    const cert_pem = alloc.dupe(u8, rec.cert_pem) catch return Error.OutOfMemory;
    return .{ .cert_pem = cert_pem, .key_pair = kp };
}

fn deriveKey(join_token: []const u8) [secrets.key_length]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(join_token, &digest, .{});
    return digest;
}

test "load decrypts a CA written by the bootstrap path" {
    const alloc = std.testing.allocator;
    const x509_gen = @import("../tls/x509_gen.zig");
    const sqlite = @import("sqlite");
    const schema = @import("../state/schema.zig");

    // round-trip via an in-memory DB so we don't depend on a leased state DB.
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    // generate a CA, encrypt its key, write the row directly.
    const join_token = "test-join-token-abc123";
    const derived = deriveKey(join_token);

    var minted = try x509_gen.generateCa(std.testing.io, alloc, "yoq-cluster-ca", 1_700_000_000, 1_700_000_000 + 86_400);
    defer alloc.free(minted.cert_pem);
    var raw_key = minted.key_pair.secret_key.toBytes();
    defer std.crypto.secureZero(u8, &raw_key);
    var enc = try secrets.encrypt(alloc, &raw_key, derived);
    defer alloc.free(enc.ciphertext);

    const sql = try store.buildClusterCaInsertSql(
        alloc,
        minted.cert_pem,
        enc.ciphertext,
        &enc.nonce,
        &enc.tag,
        1_700_000_000,
        1_700_000_000 + 86_400,
    );
    defer alloc.free(sql);
    try db.execDynamic(sql, .{}, .{});

    // load via this module — but route through the in-db helper, since
    // load() leases the shared state DB.
    const rec_opt = try store.getClusterCaInDb(&db, alloc);
    const rec = rec_opt.?;
    defer rec.deinit(alloc);

    var nonce: [secrets.nonce_length]u8 = undefined;
    var tag: [secrets.tag_length]u8 = undefined;
    @memcpy(&nonce, rec.key_nonce);
    @memcpy(&tag, rec.key_tag);
    const decrypted = try secrets.decrypt(alloc, rec.encrypted_key, nonce, tag, derived);
    defer {
        std.crypto.secureZero(u8, decrypted);
        alloc.free(decrypted);
    }
    try std.testing.expectEqual(@as(usize, 32), decrypted.len);

    const sk = try EcdsaP256.SecretKey.fromBytes(decrypted[0..32].*);
    const reloaded = try EcdsaP256.KeyPair.fromSecretKey(sk);
    try std.testing.expectEqualSlices(u8, &minted.key_pair.public_key.toUncompressedSec1(), &reloaded.public_key.toUncompressedSec1());
}
