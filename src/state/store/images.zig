const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const schema = @import("../schema.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

pub const ImageRecord = struct {
    id: []const u8,
    registry: ?[]const u8 = null,
    repository: []const u8,
    tag: []const u8,
    manifest_digest: []const u8,
    config_digest: []const u8,
    total_size: i64,
    created_at: i64,

    pub fn deinit(self: ImageRecord, alloc: Allocator) void {
        alloc.free(self.id);
        if (self.registry) |registry| alloc.free(registry);
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
    registry: sqlite.Text,
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
        .registry = row.registry.data,
        .repository = row.repository.data,
        .tag = row.tag.data,
        .manifest_digest = row.manifest_digest.data,
        .config_digest = row.config_digest.data,
        .total_size = row.total_size,
        .created_at = row.created_at,
    };
}

const reference_columns =
    "i.id, COALESCE(r.registry, '') AS registry, COALESCE(r.repository, i.repository) AS repository," ++
    " COALESCE(r.tag, i.tag) AS tag, i.manifest_digest, i.config_digest, i.total_size, i.created_at";
const reference_join = " FROM images i LEFT JOIN image_references r ON r.image_id = i.id";

const CanonicalReference = struct {
    host_buf: [512]u8 = undefined,
    repository_buf: [4096]u8 = undefined,
    host_len: usize,
    repository_len: usize,

    fn init(host: []const u8, repository: []const u8) StoreError!CanonicalReference {
        if (host.len > 512) return error.WriteFailed;
        var result = CanonicalReference{ .host_len = host.len, .repository_len = 0 };
        _ = std.ascii.lowerString(result.host_buf[0..host.len], host);
        const lower = result.host_buf[0..host.len];
        const hub = std.mem.eql(u8, lower, "docker.io") or std.mem.eql(u8, lower, "index.docker.io") or
            std.mem.eql(u8, lower, "registry-1.docker.io");
        if (hub) {
            const canonical = "registry-1.docker.io";
            @memcpy(result.host_buf[0..canonical.len], canonical);
            result.host_len = canonical.len;
        }
        const canonical_repo = if (hub and std.mem.indexOfScalar(u8, repository, '/') == null)
            std.fmt.bufPrint(&result.repository_buf, "library/{s}", .{repository}) catch return error.WriteFailed
        else
            std.fmt.bufPrint(&result.repository_buf, "{s}", .{repository}) catch return error.WriteFailed;
        result.repository_len = canonical_repo.len;
        return result;
    }

    fn hostSlice(self: *const CanonicalReference) []const u8 {
        return self.host_buf[0..self.host_len];
    }
    fn repositorySlice(self: *const CanonicalReference) []const u8 {
        return self.repository_buf[0..self.repository_len];
    }
};

pub fn saveImage(record: ImageRecord) StoreError!void {
    const ref = try CanonicalReference.init(record.registry orelse "registry-1.docker.io", record.repository);
    var lease = try common.leaseDb();
    defer lease.deinit();
    try saveImageInDb(lease.db, record, &ref);
}

/// Publish all references from an archive together after content validation.
pub fn saveImages(records: []const ImageRecord) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();
    lease.db.exec("SAVEPOINT image_import;", .{}, .{}) catch return error.WriteFailed;
    errdefer {
        lease.db.exec("ROLLBACK TO image_import;", .{}, .{}) catch {};
        lease.db.exec("RELEASE image_import;", .{}, .{}) catch {};
    }
    for (records) |record| {
        const ref = try CanonicalReference.init(record.registry orelse "registry-1.docker.io", record.repository);
        try saveImageInDb(lease.db, record, &ref);
    }
    lease.db.exec("RELEASE image_import;", .{}, .{}) catch return error.WriteFailed;
}

fn saveImageInDb(db: *sqlite.Db, record: ImageRecord, ref: *const CanonicalReference) StoreError!void {
    db.exec("SAVEPOINT image_save;", .{}, .{}) catch return error.WriteFailed;
    errdefer {
        db.exec("ROLLBACK TO image_save;", .{}, .{}) catch {};
        db.exec("RELEASE image_save;", .{}, .{}) catch {};
    }

    // discard the old content record only when this tag was its final reference.
    // the savepoint keeps both tag movement and content replacement atomic.
    db.exec(
        "DELETE FROM images WHERE id IN (SELECT image_id FROM image_references WHERE registry = ? AND repository = ? AND tag = ?)" ++
            " AND id != ? AND NOT EXISTS (SELECT 1 FROM image_references r WHERE r.image_id = images.id" ++
            " AND NOT (r.registry = ? AND r.repository = ? AND r.tag = ?));",
        .{},
        .{ ref.hostSlice(), ref.repositorySlice(), record.tag, record.id, ref.hostSlice(), ref.repositorySlice(), record.tag },
    ) catch return error.WriteFailed;
    db.exec(
        "INSERT INTO images (" ++ image_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?)" ++
            " ON CONFLICT(id) DO UPDATE SET manifest_digest = excluded.manifest_digest," ++
            " config_digest = excluded.config_digest, total_size = excluded.total_size;",
        .{},
        .{ record.id, ref.repositorySlice(), record.tag, record.manifest_digest, record.config_digest, record.total_size, record.created_at },
    ) catch return error.WriteFailed;
    db.exec(
        "INSERT INTO image_references (registry, repository, tag, image_id) VALUES (?, ?, ?, ?)" ++
            " ON CONFLICT(registry, repository, tag) DO UPDATE SET image_id = excluded.image_id;",
        .{},
        .{ ref.hostSlice(), ref.repositorySlice(), record.tag, record.id },
    ) catch return error.WriteFailed;
    db.exec("RELEASE image_save;", .{}, .{}) catch return error.WriteFailed;
}

fn loadOne(alloc: Allocator, comptime query: []const u8, args: anytype) StoreError!ImageRecord {
    var lease = try common.leaseDb();
    defer lease.deinit();

    const row = (lease.db.oneAlloc(ImageRow, alloc, query, .{}, args) catch return StoreError.ReadFailed) orelse
        return StoreError.NotFound;
    return rowToRecord(row);
}

pub fn loadImage(alloc: Allocator, id: []const u8) StoreError!ImageRecord {
    return loadOne(alloc, "SELECT " ++ reference_columns ++ reference_join ++ " WHERE i.id = ? LIMIT 1;", .{id});
}

pub fn findImage(alloc: Allocator, host: []const u8, repository: []const u8, tag: []const u8) StoreError!ImageRecord {
    const ref = try CanonicalReference.init(host, repository);
    return loadOne(alloc, "SELECT " ++ reference_columns ++ reference_join ++
        " WHERE r.registry = ? AND r.repository = ? AND r.tag = ?;", .{ ref.hostSlice(), ref.repositorySlice(), tag });
}

pub fn listImages(alloc: Allocator) StoreError!std.ArrayList(ImageRecord) {
    var lease = try common.leaseDb();
    defer lease.deinit();

    var images: std.ArrayList(ImageRecord) = .empty;
    errdefer {
        for (images.items) |image| image.deinit(alloc);
        images.deinit(alloc);
    }
    var stmt = lease.db.prepare(
        "SELECT " ++ reference_columns ++ reference_join ++ " ORDER BY i.created_at DESC, r.registry, r.repository, r.tag;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(ImageRow, .{}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        const record = rowToRecord(row);
        images.append(alloc, record) catch {
            record.deinit(alloc);
            return StoreError.ReadFailed;
        };
    }
    return images;
}

pub fn removeImage(id: []const u8) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    const exists = lease.db.one(
        struct { present: i32 },
        "SELECT 1 AS present FROM images WHERE id = ?;",
        .{},
        .{id},
    ) catch return StoreError.ReadFailed;
    if (exists == null) return StoreError.NotFound;
    lease.db.exec("SAVEPOINT image_remove;", .{}, .{}) catch return error.WriteFailed;
    errdefer {
        lease.db.exec("ROLLBACK TO image_remove;", .{}, .{}) catch {};
        lease.db.exec("RELEASE image_remove;", .{}, .{}) catch {};
    }
    lease.db.exec("DELETE FROM image_references WHERE image_id = ?;", .{}, .{id}) catch return error.WriteFailed;
    lease.db.exec("DELETE FROM images WHERE id = ?;", .{}, .{id}) catch return error.WriteFailed;
    lease.db.exec("RELEASE image_remove;", .{}, .{}) catch return error.WriteFailed;
}

pub fn removeImageReference(host: []const u8, repository: []const u8, tag: []const u8) StoreError!void {
    const ref = try CanonicalReference.init(host, repository);
    var lease = try common.leaseDb();
    defer lease.deinit();
    const db = lease.db;
    db.exec("SAVEPOINT image_untag;", .{}, .{}) catch return error.WriteFailed;
    errdefer {
        db.exec("ROLLBACK TO image_untag;", .{}, .{}) catch {};
        db.exec("RELEASE image_untag;", .{}, .{}) catch {};
    }
    const exists = db.one(struct { present: i32 }, "SELECT 1 AS present FROM image_references WHERE registry = ? AND repository = ? AND tag = ?;", .{}, .{ ref.hostSlice(), ref.repositorySlice(), tag }) catch return error.ReadFailed;
    if (exists == null) return error.NotFound;
    db.exec("DELETE FROM images WHERE id IN (SELECT image_id FROM image_references WHERE registry = ? AND repository = ? AND tag = ?)" ++
        " AND NOT EXISTS (SELECT 1 FROM image_references r WHERE r.image_id = images.id" ++
        " AND NOT (r.registry = ? AND r.repository = ? AND r.tag = ?));", .{}, .{ ref.hostSlice(), ref.repositorySlice(), tag, ref.hostSlice(), ref.repositorySlice(), tag }) catch return error.WriteFailed;
    db.exec("DELETE FROM image_references WHERE registry = ? AND repository = ? AND tag = ?;", .{}, .{ ref.hostSlice(), ref.repositorySlice(), tag }) catch return error.WriteFailed;
    db.exec("RELEASE image_untag;", .{}, .{}) catch return error.WriteFailed;
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
    const row = (db.oneAlloc(ImageRow, alloc, "SELECT " ++ reference_columns ++ reference_join ++ " WHERE i.id = ?;", .{}, .{"sha256:abc"}) catch unreachable).?;
    defer {
        alloc.free(row.id.data);
        alloc.free(row.registry.data);
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

fn referenceTestRecord(host: []const u8, tag: []const u8, id: []const u8) ImageRecord {
    return .{ .id = id, .registry = host, .repository = "team/app", .tag = tag, .manifest_digest = id, .config_digest = "sha256:config", .total_size = 10, .created_at = 1 };
}

fn expectReference(host: []const u8, repository: []const u8, tag: []const u8, id: []const u8) !void {
    const image = try findImage(std.testing.allocator, host, repository, tag);
    defer image.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(id, image.id);
}

test "image reliability references retain registry ports aliases and moving tags" {
    try common.initTestDb();
    defer common.deinitTestDb();
    try saveImage(referenceTestRecord("first.example:5000", "stable", "first"));
    try saveImage(referenceTestRecord("first.example:5001", "stable", "second"));
    try saveImage(referenceTestRecord("second.example", "stable", "third"));
    try saveImage(referenceTestRecord("first.example:5000", "release", "first"));
    try expectReference("FIRST.EXAMPLE:5000", "team/app", "stable", "first");
    try expectReference("first.example:5001", "team/app", "stable", "second");
    try expectReference("second.example", "team/app", "stable", "third");
    try std.testing.expectError(error.NotFound, findImage(std.testing.allocator, "missing.example", "team/app", "stable"));

    try saveImage(referenceTestRecord("first.example:5000", "stable", "new"));
    try expectReference("first.example:5000", "team/app", "stable", "new");
    try expectReference("first.example:5000", "team/app", "release", "first");
    {
        var images = try listImages(std.testing.allocator);
        defer {
            for (images.items) |image| image.deinit(std.testing.allocator);
            images.deinit(std.testing.allocator);
        }
        try std.testing.expectEqual(@as(usize, 4), images.items.len);
    }
    try std.testing.expectError(error.NotFound, removeImageReference("first.example:5000", "stable-wrong-repo", "stable"));
    try removeImageReference("first.example:5000", "team/app", "release");
    try std.testing.expectError(error.NotFound, loadImage(std.testing.allocator, "first"));
    try expectReference("first.example:5000", "team/app", "stable", "new");
    try removeImage("new");
    try std.testing.expectError(error.NotFound, findImage(std.testing.allocator, "first.example:5000", "team/app", "stable"));
}

test "image reliability docker hub aliases resolve to one canonical reference" {
    try common.initTestDb();
    defer common.deinitTestDb();
    var record = referenceTestRecord("docker.io", "latest", "hub");
    record.repository = "alpine";
    try saveImage(record);
    try expectReference("registry-1.docker.io", "library/alpine", "latest", "hub");
    try expectReference("index.docker.io", "alpine", "latest", "hub");
    try std.testing.expectError(error.NotFound, findImage(std.testing.allocator, "other.example", "alpine", "latest"));
}

test "image reliability failed tag update rolls back its previous content" {
    try common.initTestDb();
    defer common.deinitTestDb();
    try saveImage(referenceTestRecord("registry.example", "stable", "old"));
    {
        var lease = try common.leaseDb();
        defer lease.deinit();
        try lease.db.exec("CREATE TRIGGER fail_reference_update BEFORE UPDATE ON image_references BEGIN INSERT INTO missing_reference_table VALUES (1); END;", .{}, .{});
    }
    try std.testing.expectError(error.WriteFailed, saveImage(referenceTestRecord("registry.example", "stable", "new")));
    try expectReference("registry.example", "team/app", "stable", "old");
    try std.testing.expectError(error.NotFound, loadImage(std.testing.allocator, "new"));
    var lease = try common.leaseDb();
    defer lease.deinit();
    try std.testing.expect(sqlite.c.sqlite3_get_autocommit(lease.db.db) != 0);
}

test "image reliability legacy records keep content without guessing registry origin" {
    try common.initTestDb();
    defer common.deinitTestDb();
    {
        var lease = try common.leaseDb();
        defer lease.deinit();
        try lease.db.exec("INSERT INTO images (" ++ image_columns ++ ") VALUES ('legacy', 'team/app', 'stable', 'legacy', 'config', 1, 1);", .{}, .{});
        try schema.init(lease.db);
    }
    const legacy = try loadImage(std.testing.allocator, "legacy");
    defer legacy.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("", legacy.registry.?);
    try std.testing.expectError(error.NotFound, findImage(std.testing.allocator, "registry-1.docker.io", "team/app", "stable"));
    try std.testing.expectError(error.NotFound, findImage(std.testing.allocator, "other.example", "team/app", "stable"));
    try saveImage(referenceTestRecord("registry.example", "stable", "legacy"));
    try expectReference("registry.example", "team/app", "stable", "legacy");
}

test "image archive reference publication rolls back the entire batch on failure" {
    try common.initTestDb();
    defer common.deinitTestDb();
    {
        var lease = try common.leaseDb();
        defer lease.deinit();
        try lease.db.exec("CREATE TRIGGER reject_archive_tag BEFORE INSERT ON image_references WHEN NEW.tag = 'reject' BEGIN SELECT RAISE(ABORT, 'fixture'); END;", .{}, .{});
    }
    const first: ImageRecord = .{ .id = "archive-first", .repository = "archive-batch", .tag = "first", .manifest_digest = "archive-first", .config_digest = "config", .total_size = 0, .created_at = 1 };
    var second = first;
    second.id = "archive-second";
    second.manifest_digest = "archive-second";
    second.tag = "reject";
    try std.testing.expectError(error.WriteFailed, saveImages(&.{ first, second }));
    try std.testing.expectError(error.NotFound, findImage(std.testing.allocator, "docker.io", "archive-batch", "first"));
    try std.testing.expectError(error.NotFound, loadImage(std.testing.allocator, "archive-first"));
}
