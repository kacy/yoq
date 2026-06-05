const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const schema = @import("../schema.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

/// the cluster's mTLS CA, distributed via raft. exactly one row (id=1) holds
/// the cert and the private key encrypted with a join-token-derived key.
pub const ClusterCaRecord = struct {
    cert_pem: []const u8,
    encrypted_key: []const u8,
    key_nonce: []const u8,
    key_tag: []const u8,
    created_at: i64,
    not_after: i64,

    pub fn deinit(self: ClusterCaRecord, alloc: Allocator) void {
        alloc.free(self.cert_pem);
        alloc.free(self.encrypted_key);
        alloc.free(self.key_nonce);
        alloc.free(self.key_tag);
    }
};

const ClusterCaRow = struct {
    cert_pem: sqlite.Blob,
    encrypted_key: sqlite.Blob,
    key_nonce: sqlite.Blob,
    key_tag: sqlite.Blob,
    created_at: i64,
    not_after: i64,
};

fn rowToRecord(row: ClusterCaRow) ClusterCaRecord {
    return .{
        .cert_pem = row.cert_pem.data,
        .encrypted_key = row.encrypted_key.data,
        .key_nonce = row.key_nonce.data,
        .key_tag = row.key_tag.data,
        .created_at = row.created_at,
        .not_after = row.not_after,
    };
}

/// read the cluster CA row, or null if it has not been bootstrapped yet.
/// caller owns the returned record.
pub fn getClusterCa(alloc: Allocator) StoreError!?ClusterCaRecord {
    var lease = try common.leaseDb();
    defer lease.deinit();
    return getClusterCaInDb(lease.db, alloc);
}

pub fn getClusterCaInDb(db: *sqlite.Db, alloc: Allocator) StoreError!?ClusterCaRecord {
    var stmt = db.prepare(
        "SELECT cert_pem, encrypted_key, key_nonce, key_tag, created_at, not_after FROM cluster_ca WHERE id = 1;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(ClusterCaRow, .{}) catch return StoreError.ReadFailed;
    if (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        return rowToRecord(row);
    }
    return null;
}

/// is there a cluster CA row yet? cheap existence check that needs no alloc.
pub fn clusterCaExistsInDb(db: *sqlite.Db) bool {
    var stmt = db.prepare("SELECT 1 FROM cluster_ca WHERE id = 1 LIMIT 1;") catch return false;
    defer stmt.deinit();
    var iter = stmt.iterator(struct { present: i64 }, .{}) catch return false;
    const row = iter.next(.{}) catch return false;
    return row != null;
}

/// build the raft-replicated INSERT SQL that seeds the cluster CA row.
/// blobs are inlined as sqlite x'..' hex literals because raft.propose() takes
/// a raw SQL string (no prepared-statement bindings).
pub fn buildInsertSql(
    alloc: Allocator,
    cert_pem: []const u8,
    encrypted_key: []const u8,
    key_nonce: []const u8,
    key_tag: []const u8,
    created_at: i64,
    not_after: i64,
) StoreError![]u8 {
    const cert_hex = try allocHex(alloc, cert_pem);
    defer alloc.free(cert_hex);
    const key_hex = try allocHex(alloc, encrypted_key);
    defer alloc.free(key_hex);
    const nonce_hex = try allocHex(alloc, key_nonce);
    defer alloc.free(nonce_hex);
    const tag_hex = try allocHex(alloc, key_tag);
    defer alloc.free(tag_hex);

    return std.fmt.allocPrint(
        alloc,
        "INSERT INTO cluster_ca (id, cert_pem, encrypted_key, key_nonce, key_tag, created_at, not_after) VALUES (1, x'{s}', x'{s}', x'{s}', x'{s}', {d}, {d});",
        .{ cert_hex, key_hex, nonce_hex, tag_hex, created_at, not_after },
    ) catch return StoreError.WriteFailed;
}

fn allocHex(alloc: Allocator, bytes: []const u8) StoreError![]u8 {
    const hex_chars = "0123456789abcdef";
    const out = alloc.alloc(u8, bytes.len * 2) catch return StoreError.WriteFailed;
    for (bytes, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
    return out;
}

test "cluster CA round-trip through INSERT SQL + read" {
    const alloc = std.testing.allocator;
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try std.testing.expect(!clusterCaExistsInDb(&db));
    try std.testing.expect((try getClusterCaInDb(&db, alloc)) == null);

    const cert_pem = "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n";
    const encrypted_key = "encrypted-key-bytes";
    const nonce = "nonce-24-bytes-xxxxxxxxx";
    const tag = "tag-16-bytes-yyy";

    const sql = try buildInsertSql(alloc, cert_pem, encrypted_key, nonce, tag, 100, 1000);
    defer alloc.free(sql);
    try db.execDynamic(sql, .{}, .{});

    try std.testing.expect(clusterCaExistsInDb(&db));
    const rec = (try getClusterCaInDb(&db, alloc)).?;
    defer rec.deinit(alloc);
    try std.testing.expectEqualStrings(cert_pem, rec.cert_pem);
    try std.testing.expectEqualStrings(encrypted_key, rec.encrypted_key);
    try std.testing.expectEqualStrings(nonce, rec.key_nonce);
    try std.testing.expectEqualStrings(tag, rec.key_tag);
    try std.testing.expectEqual(@as(i64, 100), rec.created_at);
    try std.testing.expectEqual(@as(i64, 1000), rec.not_after);
}
