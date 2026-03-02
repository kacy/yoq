// store — persistent container state
//
// stores container metadata in a SQLite database so we can list
// containers, check their status, and recover after restarts.
// database lives at ~/.local/share/yoq/yoq.db.
//
// all container state goes through this module — no other code
// touches the database directly.

const std = @import("std");
const db_mod = @import("db.zig");
const schema = @import("schema.zig");

pub const StoreError = error{
    WriteFailed,
    ReadFailed,
    NotFound,
    InvalidData,
    DbOpenFailed,
};

/// persisted container record
pub const ContainerRecord = struct {
    id: []const u8,
    rootfs: []const u8,
    command: []const u8,
    hostname: []const u8,
    status: []const u8,
    pid: ?i32,
    exit_code: ?u8,
    created_at: i64,
};

/// open the store database, creating it and the schema if needed.
/// caller must call db.close() when done.
fn openDb() StoreError!db_mod.Db {
    var path_buf: [512]u8 = undefined;
    const path = schema.defaultDbPath(&path_buf) catch return StoreError.DbOpenFailed;
    var db = db_mod.Db.open(path) catch return StoreError.DbOpenFailed;
    schema.init(&db) catch {
        db.close();
        return StoreError.DbOpenFailed;
    };
    return db;
}

/// save (insert or replace) a container record
pub fn save(record: ContainerRecord) StoreError!void {
    var db = try openDb();
    defer db.close();

    var stmt = db.prepare(
        "INSERT OR REPLACE INTO containers (id, rootfs, command, hostname, status, pid, exit_code, created_at)" ++
            " VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);",
    ) catch return StoreError.WriteFailed;
    defer stmt.finalize();

    stmt.bindText(1, record.id) catch return StoreError.WriteFailed;
    stmt.bindText(2, record.rootfs) catch return StoreError.WriteFailed;
    stmt.bindText(3, record.command) catch return StoreError.WriteFailed;
    stmt.bindText(4, record.hostname) catch return StoreError.WriteFailed;
    stmt.bindText(5, record.status) catch return StoreError.WriteFailed;

    if (record.pid) |p| {
        stmt.bindInt(6, @intCast(p)) catch return StoreError.WriteFailed;
    } else {
        stmt.bindNull(6) catch return StoreError.WriteFailed;
    }

    if (record.exit_code) |code| {
        stmt.bindInt(7, @intCast(code)) catch return StoreError.WriteFailed;
    } else {
        stmt.bindNull(7) catch return StoreError.WriteFailed;
    }

    stmt.bindInt(8, record.created_at) catch return StoreError.WriteFailed;

    _ = stmt.step() catch return StoreError.WriteFailed;
}

/// load a single container record by id.
/// caller owns the returned strings (allocated with alloc).
pub fn load(alloc: std.mem.Allocator, id: []const u8) StoreError!ContainerRecord {
    var db = try openDb();
    defer db.close();

    var stmt = db.prepare(
        "SELECT id, rootfs, command, hostname, status, pid, exit_code, created_at" ++
            " FROM containers WHERE id = ?1;",
    ) catch return StoreError.ReadFailed;
    defer stmt.finalize();

    stmt.bindText(1, id) catch return StoreError.ReadFailed;

    const result = stmt.step() catch return StoreError.ReadFailed;
    if (result == .done) return StoreError.NotFound;

    return readRow(alloc, &stmt);
}

/// delete a container record
pub fn remove(id: []const u8) StoreError!void {
    var db = try openDb();
    defer db.close();

    var stmt = db.prepare("DELETE FROM containers WHERE id = ?1;") catch
        return StoreError.WriteFailed;
    defer stmt.finalize();

    stmt.bindText(1, id) catch return StoreError.WriteFailed;
    _ = stmt.step() catch return StoreError.WriteFailed;
}

/// list all container IDs, newest first
pub fn listIds(alloc: std.mem.Allocator) StoreError!std.ArrayList([]const u8) {
    var db = try openDb();
    defer db.close();

    var stmt = db.prepare("SELECT id FROM containers ORDER BY created_at DESC;") catch
        return StoreError.ReadFailed;
    defer stmt.finalize();

    var ids: std.ArrayList([]const u8) = .empty;

    while (true) {
        const result = stmt.step() catch return StoreError.ReadFailed;
        if (result == .done) break;

        const id_text = stmt.columnText(0) orelse continue;
        const id = alloc.dupe(u8, id_text) catch return StoreError.ReadFailed;
        ids.append(alloc, id) catch return StoreError.ReadFailed;
    }

    return ids;
}

/// update specific fields on a container. only non-null values are written.
pub fn update(
    id: []const u8,
    status: ?[]const u8,
    pid: ?i32,
    exit_code: ?u8,
) StoreError!void {
    var db = try openDb();
    defer db.close();

    // build SET clause based on what's provided.
    // we always have at least one field to update (otherwise why call this?)
    var set_parts: [3][]const u8 = undefined;
    var count: usize = 0;

    if (status != null) {
        set_parts[count] = "status = ?";
        count += 1;
    }
    if (pid != null) {
        set_parts[count] = "pid = ?";
        count += 1;
    }
    if (exit_code != null) {
        set_parts[count] = "exit_code = ?";
        count += 1;
    }

    if (count == 0) return;

    // build the full SQL. parameterized where clause for the id.
    var sql_buf: [256]u8 = undefined;
    var offset: usize = 0;

    const prefix = "UPDATE containers SET ";
    @memcpy(sql_buf[offset .. offset + prefix.len], prefix);
    offset += prefix.len;

    for (set_parts[0..count], 0..) |part, i| {
        @memcpy(sql_buf[offset .. offset + part.len], part);
        offset += part.len;
        if (i < count - 1) {
            @memcpy(sql_buf[offset .. offset + 2], ", ");
            offset += 2;
        }
    }

    const suffix = " WHERE id = ?;";
    @memcpy(sql_buf[offset .. offset + suffix.len], suffix);
    offset += suffix.len;
    sql_buf[offset] = 0;

    var stmt = db.prepare(sql_buf[0..offset :0]) catch return StoreError.WriteFailed;
    defer stmt.finalize();

    // bind the SET values in order
    var bind_idx: c_int = 1;
    if (status) |s| {
        stmt.bindText(bind_idx, s) catch return StoreError.WriteFailed;
        bind_idx += 1;
    }
    if (pid) |p| {
        stmt.bindInt(bind_idx, @intCast(p)) catch return StoreError.WriteFailed;
        bind_idx += 1;
    }
    if (exit_code) |code| {
        stmt.bindInt(bind_idx, @intCast(code)) catch return StoreError.WriteFailed;
        bind_idx += 1;
    }

    // bind the WHERE id = ?
    stmt.bindText(bind_idx, id) catch return StoreError.WriteFailed;

    _ = stmt.step() catch return StoreError.WriteFailed;
}

/// extract a ContainerRecord from the current row of a statement.
/// allocates strings with alloc (caller owns them).
fn readRow(alloc: std.mem.Allocator, stmt: *db_mod.Statement) StoreError!ContainerRecord {
    const id = alloc.dupe(u8, stmt.columnText(0) orelse return StoreError.InvalidData) catch
        return StoreError.ReadFailed;
    const rootfs = alloc.dupe(u8, stmt.columnText(1) orelse return StoreError.InvalidData) catch
        return StoreError.ReadFailed;
    const command = alloc.dupe(u8, stmt.columnText(2) orelse return StoreError.InvalidData) catch
        return StoreError.ReadFailed;
    const hostname = alloc.dupe(u8, stmt.columnText(3) orelse "") catch
        return StoreError.ReadFailed;
    const status_text = alloc.dupe(u8, stmt.columnText(4) orelse "created") catch
        return StoreError.ReadFailed;

    const pid_val = stmt.columnOptionalInt(5);
    const exit_val = stmt.columnOptionalInt(6);

    return ContainerRecord{
        .id = id,
        .rootfs = rootfs,
        .command = command,
        .hostname = hostname,
        .status = status_text,
        .pid = if (pid_val) |p| @intCast(p) else null,
        .exit_code = if (exit_val) |e| @intCast(e) else null,
        .created_at = stmt.columnInt(7),
    };
}

// -- tests --
//
// these tests use in-memory databases to avoid touching the filesystem.
// we test through the db/schema layers directly rather than through
// the public functions (which open the real database path).

test "container record defaults" {
    const record = ContainerRecord{
        .id = "abc123",
        .rootfs = "/tmp/rootfs",
        .command = "/bin/sh",
        .hostname = "test",
        .status = "created",
        .pid = null,
        .exit_code = null,
        .created_at = 1234567890,
    };

    try std.testing.expectEqualStrings("abc123", record.id);
    try std.testing.expect(record.pid == null);
    try std.testing.expect(record.exit_code == null);
}

test "save and load round-trip via sqlite" {
    var db = try db_mod.Db.open(":memory:");
    defer db.close();
    try schema.init(&db);

    // insert
    var insert = try db.prepare(
        "INSERT INTO containers (id, rootfs, command, hostname, status, pid, exit_code, created_at)" ++
            " VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8);",
    );
    defer insert.finalize();

    try insert.bindText(1, "abc123");
    try insert.bindText(2, "/tmp/rootfs");
    try insert.bindText(3, "/bin/sh");
    try insert.bindText(4, "myhost");
    try insert.bindText(5, "running");
    try insert.bindInt(6, 42);
    try insert.bindNull(7);
    try insert.bindInt(8, 1234567890);
    _ = try insert.step();

    // read back
    var query = try db.prepare(
        "SELECT id, rootfs, command, hostname, status, pid, exit_code, created_at" ++
            " FROM containers WHERE id = 'abc123';",
    );
    defer query.finalize();
    _ = try query.step();

    try std.testing.expectEqualStrings("abc123", query.columnText(0).?);
    try std.testing.expectEqualStrings("/tmp/rootfs", query.columnText(1).?);
    try std.testing.expectEqualStrings("/bin/sh", query.columnText(2).?);
    try std.testing.expectEqualStrings("myhost", query.columnText(3).?);
    try std.testing.expectEqualStrings("running", query.columnText(4).?);
    try std.testing.expectEqual(@as(i64, 42), query.columnInt(5));
    try std.testing.expect(query.columnOptionalInt(6) == null);
    try std.testing.expectEqual(@as(i64, 1234567890), query.columnInt(7));
}

test "list ids returns newest first" {
    var db = try db_mod.Db.open(":memory:");
    defer db.close();
    try schema.init(&db);

    // insert two containers with different timestamps
    db.exec(@ptrCast(
        "INSERT INTO containers (id, rootfs, command, created_at) VALUES ('older', '/r', '/sh', 100);"
    )) catch unreachable;
    db.exec(@ptrCast(
        "INSERT INTO containers (id, rootfs, command, created_at) VALUES ('newer', '/r', '/sh', 200);"
    )) catch unreachable;

    var query = try db.prepare("SELECT id FROM containers ORDER BY created_at DESC;");
    defer query.finalize();

    _ = try query.step();
    try std.testing.expectEqualStrings("newer", query.columnText(0).?);
    _ = try query.step();
    try std.testing.expectEqualStrings("older", query.columnText(0).?);
}

test "delete removes record" {
    var db = try db_mod.Db.open(":memory:");
    defer db.close();
    try schema.init(&db);

    db.exec(@ptrCast(
        "INSERT INTO containers (id, rootfs, command, created_at) VALUES ('del1', '/r', '/sh', 100);"
    )) catch unreachable;

    db.exec(@ptrCast("DELETE FROM containers WHERE id = 'del1';")) catch unreachable;

    var query = try db.prepare("SELECT COUNT(*) FROM containers;");
    defer query.finalize();
    _ = try query.step();
    try std.testing.expectEqual(@as(i64, 0), query.columnInt(0));
}

test "update status" {
    var db = try db_mod.Db.open(":memory:");
    defer db.close();
    try schema.init(&db);

    db.exec(@ptrCast(
        "INSERT INTO containers (id, rootfs, command, status, created_at) VALUES ('upd1', '/r', '/sh', 'created', 100);"
    )) catch unreachable;

    db.exec(@ptrCast(
        "UPDATE containers SET status = 'running', pid = 1234 WHERE id = 'upd1';"
    )) catch unreachable;

    var query = try db.prepare("SELECT status, pid FROM containers WHERE id = 'upd1';");
    defer query.finalize();
    _ = try query.step();
    try std.testing.expectEqualStrings("running", query.columnText(0).?);
    try std.testing.expectEqual(@as(i64, 1234), query.columnInt(1));
}
