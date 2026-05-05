const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const schema = @import("../schema.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

pub const ImageRecord = struct {
    id: []const u8,
    repository: []const u8,
    tag: []const u8,
    manifest_digest: []const u8,
    config_digest: []const u8,
    total_size: i64,
    created_at: i64,

    pub fn deinit(self: ImageRecord, alloc: Allocator) void {
        alloc.free(self.id);
        alloc.free(self.repository);
        alloc.free(self.tag);
        alloc.free(self.manifest_digest);
        alloc.free(self.config_digest);
    }
};

const image_columns =
    "id, repository, tag, manifest_digest, config_digest, total_size, created_at";

const ImageRow = struct {
    id: sqlite.Text,
    repository: sqlite.Text,
    tag: sqlite.Text,
    manifest_digest: sqlite.Text,
    config_digest: sqlite.Text,
    total_size: i64,
    created_at: i64,
};

fn rowToRecord(row: ImageRow) ImageRecord {
    return .{
        .id = row.id.data,
        .repository = row.repository.data,
        .tag = row.tag.data,
        .manifest_digest = row.manifest_digest.data,
        .config_digest = row.config_digest.data,
        .total_size = row.total_size,
        .created_at = row.created_at,
    };
}

pub fn saveImage(record: ImageRecord) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    lease.db.exec(
        "INSERT OR REPLACE INTO images (" ++ image_columns ++ ")" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{
            record.id,
            record.repository,
            record.tag,
            record.manifest_digest,
            record.config_digest,
            record.total_size,
            record.created_at,
        },
    ) catch return StoreError.WriteFailed;
}

fn loadOne(alloc: Allocator, comptime query: []const u8, args: anytype) StoreError!ImageRecord {
    var lease = try common.leaseDb();
    defer lease.deinit();

    const row = (lease.db.oneAlloc(ImageRow, alloc, query, .{}, args) catch return StoreError.ReadFailed) orelse
        return StoreError.NotFound;
    return rowToRecord(row);
}

pub fn loadImage(alloc: Allocator, id: []const u8) StoreError!ImageRecord {
    return loadOne(alloc, "SELECT " ++ image_columns ++ " FROM images WHERE id = ?;", .{id});
}

pub fn findImage(alloc: Allocator, repository: []const u8, tag: []const u8) StoreError!ImageRecord {
    return loadOne(
        alloc,
        "SELECT " ++ image_columns ++ " FROM images WHERE repository = ? AND tag = ?;",
        .{ repository, tag },
    );
}

pub fn listImages(alloc: Allocator) StoreError!std.ArrayList(ImageRecord) {
    var lease = try common.leaseDb();
    defer lease.deinit();

    var images: std.ArrayList(ImageRecord) = .empty;
    var stmt = lease.db.prepare(
        "SELECT " ++ image_columns ++ " FROM images ORDER BY created_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(ImageRow, .{}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        images.append(alloc, rowToRecord(row)) catch return StoreError.ReadFailed;
    }
    return images;
}

pub fn removeImage(id: []const u8) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    const exists = lease.db.one(
        struct { exists: i32 },
        "SELECT 1 AS exists FROM images WHERE id = ?;",
        .{},
        .{id},
    ) catch return StoreError.ReadFailed;
    if (exists == null) return StoreError.NotFound;
    lease.db.exec("DELETE FROM images WHERE id = ?;", .{}, .{id}) catch return StoreError.WriteFailed;
}

test "image record round-trip via sqlite" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO images (" ++ image_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "sha256:abc", "library/nginx", "latest", "sha256:abc", "sha256:def", @as(i64, 2048), @as(i64, 1700000000) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(ImageRow, alloc, "SELECT " ++ image_columns ++ " FROM images WHERE id = ?;", .{}, .{"sha256:abc"}) catch unreachable).?;
    defer {
        alloc.free(row.id.data);
        alloc.free(row.repository.data);
        alloc.free(row.tag.data);
        alloc.free(row.manifest_digest.data);
        alloc.free(row.config_digest.data);
    }

    try std.testing.expectEqualStrings("sha256:abc", row.id.data);
    try std.testing.expectEqualStrings("library/nginx", row.repository.data);
    try std.testing.expectEqualStrings("latest", row.tag.data);
    try std.testing.expectEqual(@as(i64, 2048), row.total_size);
}
