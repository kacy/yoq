// raft-replicated reads + writes for per-service mTLS leaf certs.
//
// the `certificates` table is shared with ACME (source="acme") and manual
// installs (source="manual"). this module only touches rows we own —
// source="mtls", keyed by "service:<name>" in the `domain` column — and
// writes through raft (via node.propose) so every node ends up with the
// same row. local-only writes via CertStore.install would diverge across
// followers.

const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const schema = @import("../schema.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

pub const source_label = "mtls";
pub const key_prefix = "service:";

pub const Record = struct {
    domain: []const u8,
    cert_pem: []const u8,
    encrypted_key: []const u8,
    key_nonce: []const u8,
    key_tag: []const u8,
    not_after: i64,
    created_at: i64,
    updated_at: i64,

    pub fn deinit(self: Record, alloc: Allocator) void {
        alloc.free(self.domain);
        alloc.free(self.cert_pem);
        alloc.free(self.encrypted_key);
        alloc.free(self.key_nonce);
        alloc.free(self.key_tag);
    }
};

const Row = struct {
    domain: sqlite.Text,
    cert_pem: sqlite.Blob,
    encrypted_key: sqlite.Blob,
    key_nonce: sqlite.Blob,
    key_tag: sqlite.Blob,
    not_after: i64,
    created_at: i64,
    updated_at: i64,
};

fn rowToRecord(row: Row) Record {
    return .{
        .domain = row.domain.data,
        .cert_pem = row.cert_pem.data,
        .encrypted_key = row.encrypted_key.data,
        .key_nonce = row.key_nonce.data,
        .key_tag = row.key_tag.data,
        .not_after = row.not_after,
        .created_at = row.created_at,
        .updated_at = row.updated_at,
    };
}

/// format the table key for a service. callers don't need to know the
/// prefix layout — they pass the service name.
pub fn buildKey(alloc: Allocator, service_name: []const u8) StoreError![]u8 {
    return std.fmt.allocPrint(alloc, "{s}{s}", .{ key_prefix, service_name }) catch return StoreError.WriteFailed;
}

/// read the mtls cert row for a service, or null when one hasn't been
/// issued yet. caller owns the returned record.
pub fn get(alloc: Allocator, service_name: []const u8) StoreError!?Record {
    var lease = try common.leaseDb();
    defer lease.deinit();
    return getInDb(lease.db, alloc, service_name);
}

pub fn getInDb(db: *sqlite.Db, alloc: Allocator, service_name: []const u8) StoreError!?Record {
    const key = try buildKey(alloc, service_name);
    defer alloc.free(key);

    var stmt = db.prepare(
        "SELECT domain, cert_pem, encrypted_key, key_nonce, key_tag, not_after, created_at, updated_at FROM certificates WHERE domain = ? AND source = ?;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(Row, .{ key, source_label }) catch return StoreError.ReadFailed;
    if (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        return rowToRecord(row);
    }
    return null;
}

/// build the raft-replicated upsert. blobs go in as sqlite x'..' hex
/// literals; raft.propose() takes raw SQL with no bindings. `domain` is
/// quoted because service names are ascii and the schema PK matches on
/// the exact string we wrote.
pub fn buildUpsertSql(
    alloc: Allocator,
    service_name: []const u8,
    cert_pem: []const u8,
    encrypted_key: []const u8,
    key_nonce: []const u8,
    key_tag: []const u8,
    not_after: i64,
    issued_at: i64,
) StoreError![]u8 {
    if (!isSafeServiceName(service_name)) return StoreError.WriteFailed;

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
        "INSERT OR REPLACE INTO certificates (domain, cert_pem, encrypted_key, key_nonce, key_tag, not_after, source, created_at, updated_at) VALUES ('{s}{s}', x'{s}', x'{s}', x'{s}', x'{s}', {d}, '{s}', {d}, {d});",
        .{ key_prefix, service_name, cert_hex, key_hex, nonce_hex, tag_hex, not_after, source_label, issued_at, issued_at },
    ) catch return StoreError.WriteFailed;
}

/// service names should be a small ascii subset: letters, digits, `-`, `_`.
/// rejecting anything else keeps single-quote injection out of the raft
/// SQL we hand-format. matches the existing service-name validators
/// elsewhere in the codebase.
fn isSafeServiceName(name: []const u8) bool {
    if (name.len == 0 or name.len > 128) return false;
    for (name) |c| {
        const ok = (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '-' or c == '_';
        if (!ok) return false;
    }
    return true;
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

test "mtls cert round-trip through upsert SQL + read" {
    const alloc = std.testing.allocator;
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try std.testing.expect((try getInDb(&db, alloc, "billing")) == null);

    const cert_pem = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n";
    const encrypted_key = "encrypted-leaf-key";
    const nonce = "nonce-24-bytes-xxxxxxxxx";
    const tag = "tag-16-bytes-yyy";

    const sql = try buildUpsertSql(alloc, "billing", cert_pem, encrypted_key, nonce, tag, 5000, 4000);
    defer alloc.free(sql);
    try db.execDynamic(sql, .{}, .{});

    const rec = (try getInDb(&db, alloc, "billing")).?;
    defer rec.deinit(alloc);
    try std.testing.expectEqualStrings("service:billing", rec.domain);
    try std.testing.expectEqualStrings(cert_pem, rec.cert_pem);
    try std.testing.expectEqualStrings(encrypted_key, rec.encrypted_key);
    try std.testing.expectEqualStrings(nonce, rec.key_nonce);
    try std.testing.expectEqualStrings(tag, rec.key_tag);
    try std.testing.expectEqual(@as(i64, 5000), rec.not_after);
    try std.testing.expectEqual(@as(i64, 4000), rec.created_at);
    try std.testing.expectEqual(@as(i64, 4000), rec.updated_at);
}

test "upsert replaces an existing row in place" {
    const alloc = std.testing.allocator;
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const first = try buildUpsertSql(alloc, "billing", "old", "k", "n", "t", 100, 50);
    defer alloc.free(first);
    try db.execDynamic(first, .{}, .{});

    const second = try buildUpsertSql(alloc, "billing", "new", "k2", "n2", "t2", 200, 150);
    defer alloc.free(second);
    try db.execDynamic(second, .{}, .{});

    const rec = (try getInDb(&db, alloc, "billing")).?;
    defer rec.deinit(alloc);
    try std.testing.expectEqualStrings("new", rec.cert_pem);
    try std.testing.expectEqual(@as(i64, 200), rec.not_after);
    try std.testing.expectEqual(@as(i64, 150), rec.updated_at);
}

test "unsafe service names are rejected" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(StoreError.WriteFailed, buildUpsertSql(alloc, "bad name", "c", "k", "n", "t", 1, 1));
    try std.testing.expectError(StoreError.WriteFailed, buildUpsertSql(alloc, "evil'); DROP TABLE", "c", "k", "n", "t", 1, 1));
    try std.testing.expectError(StoreError.WriteFailed, buildUpsertSql(alloc, "", "c", "k", "n", "t", 1, 1));
}
