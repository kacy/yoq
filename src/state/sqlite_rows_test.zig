const std = @import("std");
const sqlite = @import("sqlite");

const Color = enum {
    blue,
    unknown,

    pub const BaseType = []const u8;
    pub const default = Color.unknown;
};

const OwnedRow = struct {
    text: sqlite.Text,
    blob: ?sqlite.Blob,
    optional: ?[]const u8,
    absent: ?sqlite.Text,
    sentinel: [:0]u8,
    indirect: *[]const u8,
    number: *i64,
    color: Color,
    fixed: [3]u8,

    fn deinit(self: OwnedRow, allocator: std.mem.Allocator) void {
        allocator.free(self.text.data);
        allocator.free(self.blob.?.data);
        allocator.free(self.optional.?);
        allocator.free(self.sentinel);
        allocator.free(self.indirect.*);
        allocator.destroy(self.indirect);
        allocator.destroy(self.number);
    }
};

fn readOwnedRow(allocator: std.mem.Allocator, db: *sqlite.Db) !void {
    var stmt = try db.prepare("SELECT 'text', x'626c6f62', 'optional', NULL, 'sentinel', 'indirect', 42, 'blue', 'abc'");
    defer stmt.deinit();
    const row = (try stmt.oneAlloc(OwnedRow, allocator, .{}, .{})).?;
    defer row.deinit(allocator);

    try std.testing.expectEqualStrings("text", row.text.data);
    try std.testing.expectEqualStrings("blob", row.blob.?.data);
    try std.testing.expectEqualStrings("optional", row.optional.?);
    try std.testing.expectEqual(null, row.absent);
    try std.testing.expectEqualStrings("sentinel", row.sentinel);
    try std.testing.expectEqual(@as(u8, 0), row.sentinel[row.sentinel.len]);
    try std.testing.expectEqualStrings("indirect", row.indirect.*);
    try std.testing.expectEqual(@as(i64, 42), row.number.*);
    try std.testing.expectEqual(Color.blue, row.color);
    try std.testing.expectEqualStrings("abc", &row.fixed);
}

test "sqlite rows release earlier fields when an allocation fails" {
    var db = try sqlite.Db.init(.{ .mode = .Memory });
    defer db.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, readOwnedRow, .{&db});
}

const ListRow = struct {
    name: []const u8,
    data: ?sqlite.Blob,

    fn deinit(self: ListRow, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.data) |data| allocator.free(data.data);
    }
};

const list_query =
    \\WITH RECURSIVE numbers(n) AS (
    \\  SELECT 1 UNION ALL SELECT n + 1 FROM numbers WHERE n < 20
    \\)
    \\SELECT 'row', CASE WHEN n % 2 = 0 THEN x'64617461' ELSE NULL END FROM numbers
;

fn readRows(allocator: std.mem.Allocator, db: *sqlite.Db, comptime dynamic: bool) !void {
    var stmt = if (dynamic) try db.prepareDynamic(list_query) else try db.prepare(list_query);
    defer stmt.deinit();
    const rows = try stmt.all(ListRow, allocator, .{}, .{});
    defer {
        for (rows) |row| row.deinit(allocator);
        allocator.free(rows);
    }

    try std.testing.expectEqual(@as(usize, 20), rows.len);
    for (rows, 0..) |row, i| {
        try std.testing.expectEqualStrings("row", row.name);
        if (i % 2 == 1) {
            try std.testing.expectEqualStrings("data", row.data.?.data);
        } else {
            try std.testing.expectEqual(null, row.data);
        }
    }
}

fn readStaticRows(allocator: std.mem.Allocator, db: *sqlite.Db) !void {
    try readRows(allocator, db, false);
}

fn readDynamicRows(allocator: std.mem.Allocator, db: *sqlite.Db) !void {
    try readRows(allocator, db, true);
}

test "sqlite rows release collected rows on allocation failure" {
    var db = try sqlite.Db.init(.{ .mode = .Memory });
    defer db.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, readStaticRows, .{&db});
}

test "sqlite rows release collected dynamic rows on allocation failure" {
    var db = try sqlite.Db.init(.{ .mode = .Memory });
    defer db.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, readDynamicRows, .{&db});
}

const BorrowedValue = struct {
    data: []const u8,

    pub const BaseType = i64;

    pub fn readField(_: std.mem.Allocator, _: i64) !BorrowedValue {
        return .{ .data = "borrowed" };
    }
};

test "sqlite rows leave custom conversion ownership unchanged on a later decode error" {
    var db = try sqlite.Db.init(.{ .mode = .Memory });
    defer db.deinit();
    var stmt = try db.prepare("SELECT 'owned', 1, 'too long'");
    defer stmt.deinit();
    const Row = struct { text: []const u8, custom: *BorrowedValue, fixed: [1]u8 };

    try std.testing.expectError(error.ArraySizeMismatch, stmt.oneAlloc(Row, std.testing.allocator, .{}, .{}));
}

const RejectedValue = struct {
    pub const BaseType = i64;

    pub fn readField(_: std.mem.Allocator, _: i64) !RejectedValue {
        return error.InvalidValue;
    }
};

test "sqlite rows release fields when a custom conversion fails" {
    var db = try sqlite.Db.init(.{ .mode = .Memory });
    defer db.deinit();
    var stmt = try db.prepare("SELECT 'owned', 1");
    defer stmt.deinit();
    const Row = struct { text: []const u8, custom: RejectedValue };

    try std.testing.expectError(error.InvalidValue, stmt.oneAlloc(Row, std.testing.allocator, .{}, .{}));
}

test "sqlite rows release collected rows when a later row cannot be decoded" {
    var db = try sqlite.Db.init(.{ .mode = .Memory });
    defer db.deinit();
    const query = "SELECT 'owned', 'a' UNION ALL SELECT 'another', 'too long'";
    const Row = struct { text: []const u8, fixed: [1]u8 };

    var stmt = try db.prepare(query);
    defer stmt.deinit();
    try std.testing.expectError(error.ArraySizeMismatch, stmt.all(Row, std.testing.allocator, .{}, .{}));

    var dynamic_stmt = try db.prepareDynamic(query);
    defer dynamic_stmt.deinit();
    try std.testing.expectError(error.ArraySizeMismatch, dynamic_stmt.all(Row, std.testing.allocator, .{}, .{}));
}
