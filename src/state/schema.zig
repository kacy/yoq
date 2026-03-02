// schema — database schema and initialization
//
// creates the tables yoq needs on first run. all schema changes
// go through this file so there's one place to look for the
// database structure.

const std = @import("std");
const db_mod = @import("db.zig");

pub const SchemaError = error{
    InitFailed,
    PathTooLong,
    HomeDirNotFound,
};

const containers_table =
    \\CREATE TABLE IF NOT EXISTS containers (
    \\    id TEXT PRIMARY KEY,
    \\    rootfs TEXT NOT NULL,
    \\    command TEXT NOT NULL,
    \\    hostname TEXT NOT NULL DEFAULT 'container',
    \\    status TEXT NOT NULL DEFAULT 'created',
    \\    pid INTEGER,
    \\    exit_code INTEGER,
    \\    created_at INTEGER NOT NULL
    \\);
;

/// initialize the database schema. safe to call multiple times
/// (uses CREATE TABLE IF NOT EXISTS).
pub fn init(db: *db_mod.Db) SchemaError!void {
    db.exec(@ptrCast(containers_table)) catch return SchemaError.InitFailed;
}

/// build the default database path: ~/.local/share/yoq/yoq.db
/// creates parent directories if needed.
pub fn defaultDbPath(buf: *[512]u8) SchemaError![:0]const u8 {
    const home = std.posix.getenv("HOME") orelse return SchemaError.HomeDirNotFound;
    const dir_path = std.fmt.bufPrint(buf, "{s}/.local/share/yoq", .{home}) catch
        return SchemaError.PathTooLong;

    // ensure the directory exists
    std.fs.cwd().makePath(dir_path) catch {};

    const path = std.fmt.bufPrintZ(buf, "{s}/.local/share/yoq/yoq.db", .{home}) catch
        return SchemaError.PathTooLong;
    return path;
}

// -- tests --

test "init creates containers table" {
    var db = try db_mod.Db.open(":memory:");
    defer db.close();

    try init(&db);

    // verify table exists by inserting a row
    var stmt = try db.prepare(
        "INSERT INTO containers (id, rootfs, command, created_at) VALUES (?1, ?2, ?3, ?4);",
    );
    defer stmt.finalize();
    try stmt.bindText(1, "test123");
    try stmt.bindText(2, "/tmp/rootfs");
    try stmt.bindText(3, "/bin/sh");
    try stmt.bindInt(4, 1234567890);
    const result = try stmt.step();
    try std.testing.expectEqual(db_mod.StepResult.done, result);
}

test "init is idempotent" {
    var db = try db_mod.Db.open(":memory:");
    defer db.close();

    // calling init twice should not fail
    try init(&db);
    try init(&db);
}

test "default columns" {
    var db = try db_mod.Db.open(":memory:");
    defer db.close();

    try init(&db);

    // insert with minimal fields, check defaults
    db.exec(@ptrCast(
        "INSERT INTO containers (id, rootfs, command, created_at) " ++
            "VALUES ('abc', '/rootfs', '/bin/sh', 100);"
    )) catch unreachable;

    var query = try db.prepare("SELECT hostname, status, pid, exit_code FROM containers WHERE id = 'abc';");
    defer query.finalize();
    _ = try query.step();

    try std.testing.expectEqualStrings("container", query.columnText(0).?);
    try std.testing.expectEqualStrings("created", query.columnText(1).?);
    try std.testing.expect(query.columnOptionalInt(2) == null);
    try std.testing.expect(query.columnOptionalInt(3) == null);
}
