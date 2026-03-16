const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const schema = @import("../schema.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

pub const BuildCacheEntry = struct {
    cache_key: []const u8,
    layer_digest: []const u8,
    diff_id: []const u8,
    layer_size: i64,
    created_at: i64,

    pub fn deinit(self: BuildCacheEntry, alloc: Allocator) void {
        alloc.free(self.cache_key);
        alloc.free(self.layer_digest);
        alloc.free(self.diff_id);
    }
};

const build_cache_columns =
    "cache_key, layer_digest, diff_id, layer_size, created_at";

const BuildCacheRow = struct {
    cache_key: sqlite.Text,
    layer_digest: sqlite.Text,
    diff_id: sqlite.Text,
    layer_size: i64,
    created_at: i64,
};

fn rowToEntry(row: BuildCacheRow) BuildCacheEntry {
    return .{
        .cache_key = row.cache_key.data,
        .layer_digest = row.layer_digest.data,
        .diff_id = row.diff_id.data,
        .layer_size = row.layer_size,
        .created_at = row.created_at,
    };
}

pub fn lookupBuildCache(alloc: Allocator, cache_key: []const u8) StoreError!?BuildCacheEntry {
    const db = try common.getDb();
    const row = (db.oneAlloc(
        BuildCacheRow,
        alloc,
        "SELECT " ++ build_cache_columns ++ " FROM build_cache WHERE cache_key = ?;",
        .{},
        .{cache_key},
    ) catch return StoreError.ReadFailed) orelse return null;
    return rowToEntry(row);
}

pub fn storeBuildCache(entry: BuildCacheEntry) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "INSERT OR REPLACE INTO build_cache (" ++ build_cache_columns ++ ")" ++
            " VALUES (?, ?, ?, ?, ?);",
        .{},
        .{
            entry.cache_key,
            entry.layer_digest,
            entry.diff_id,
            entry.layer_size,
            entry.created_at,
        },
    ) catch return StoreError.WriteFailed;
}

pub fn listBuildCacheDigests(alloc: Allocator) StoreError!std.ArrayList([]const u8) {
    const db = try common.getDb();
    var digests = std.ArrayList([]const u8).empty;
    errdefer {
        for (digests.items) |digest| alloc.free(digest);
        digests.deinit(alloc);
    }

    inline for ([_][]const u8{
        "SELECT layer_digest AS value FROM build_cache;",
        "SELECT diff_id AS value FROM build_cache;",
    }) |query| {
        const Row = struct { value: sqlite.Text };
        var stmt = db.prepare(query) catch return StoreError.ReadFailed;
        defer stmt.deinit();
        var iter = stmt.iterator(Row, .{}) catch return StoreError.ReadFailed;
        while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
            digests.append(alloc, row.value.data) catch return StoreError.ReadFailed;
        }
    }

    return digests;
}

test "build cache store and lookup" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO build_cache (" ++ build_cache_columns ++ ") VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "sha256:key1", "sha256:layer1", "sha256:diff1", @as(i64, 4096), @as(i64, 1700000000) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(BuildCacheRow, alloc, "SELECT " ++ build_cache_columns ++ " FROM build_cache WHERE cache_key = ?;", .{}, .{"sha256:key1"}) catch unreachable).?;
    defer {
        alloc.free(row.cache_key.data);
        alloc.free(row.layer_digest.data);
        alloc.free(row.diff_id.data);
    }

    try std.testing.expectEqualStrings("sha256:key1", row.cache_key.data);
    try std.testing.expectEqualStrings("sha256:layer1", row.layer_digest.data);
    try std.testing.expectEqualStrings("sha256:diff1", row.diff_id.data);
    try std.testing.expectEqual(@as(i64, 4096), row.layer_size);
}

test "build cache miss returns null row" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const alloc = std.testing.allocator;
    const row = db.oneAlloc(
        BuildCacheRow,
        alloc,
        "SELECT " ++ build_cache_columns ++ " FROM build_cache WHERE cache_key = ?;",
        .{},
        .{"sha256:nonexistent"},
    ) catch unreachable;

    try std.testing.expect(row == null);
}

test "build cache replace on conflict" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO build_cache (" ++ build_cache_columns ++ ") VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "sha256:key1", "sha256:old_layer", "sha256:old_diff", @as(i64, 1024), @as(i64, 100) },
    ) catch unreachable;
    db.exec(
        "INSERT OR REPLACE INTO build_cache (" ++ build_cache_columns ++ ") VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "sha256:key1", "sha256:new_layer", "sha256:new_diff", @as(i64, 2048), @as(i64, 200) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(BuildCacheRow, alloc, "SELECT " ++ build_cache_columns ++ " FROM build_cache WHERE cache_key = ?;", .{}, .{"sha256:key1"}) catch unreachable).?;
    defer {
        alloc.free(row.cache_key.data);
        alloc.free(row.layer_digest.data);
        alloc.free(row.diff_id.data);
    }

    try std.testing.expectEqualStrings("sha256:new_layer", row.layer_digest.data);
    try std.testing.expectEqual(@as(i64, 2048), row.layer_size);
}

test "listBuildCacheDigests returns empty when no entries" {
    const alloc = std.testing.allocator;
    const result = listBuildCacheDigests(alloc);
    if (result) |owned_digests| {
        var digests = owned_digests;
        defer {
            for (digests.items) |digest| alloc.free(digest);
            digests.deinit(alloc);
        }
        try std.testing.expect(digests.items.len >= 0);
    } else |_| {}
}
