// db — thin sqlite3 wrapper
//
// only file that touches @cImport. provides a small API for
// opening databases, executing statements, and running
// parameterized queries. all error handling maps sqlite error
// codes to a single DbError type.

const std = @import("std");
const c = @cImport(@cInclude("sqlite3.h"));

// SQLITE_TRANSIENT (-1 cast to a destructor fn pointer) can't be
// represented in zig due to alignment requirements. we use SQLITE_STATIC
// (null) instead, which means sqlite won't copy the data. this is safe
// because our API always binds data that outlives the step() call.

pub const DbError = error{
    OpenFailed,
    ExecFailed,
    PrepareFailed,
    BindFailed,
    StepFailed,
    ColumnError,
};

pub const StepResult = enum {
    row,
    done,
};

pub const Db = struct {
    handle: *c.sqlite3,

    /// open a database file. creates it if it doesn't exist.
    /// enables WAL mode for better concurrent read performance.
    pub fn open(path: [*:0]const u8) DbError!Db {
        var handle: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open(path, &handle);
        if (rc != c.SQLITE_OK or handle == null) {
            if (handle) |h| _ = c.sqlite3_close(h);
            return DbError.OpenFailed;
        }

        var db = Db{ .handle = handle.? };

        // enable WAL mode — better concurrency, less fsync pressure
        db.exec("PRAGMA journal_mode=WAL;") catch {};
        // busy timeout so we don't immediately fail on contention
        _ = c.sqlite3_busy_timeout(db.handle, 5000);

        return db;
    }

    /// close the database handle
    pub fn close(self: *Db) void {
        _ = c.sqlite3_close(self.handle);
    }

    /// execute a simple SQL statement (no parameters, no results).
    /// useful for DDL, pragmas, and simple writes.
    pub fn exec(self: *Db, sql: [*:0]const u8) DbError!void {
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.handle, sql, null, null, &err_msg);
        if (err_msg) |msg| c.sqlite3_free(msg);
        if (rc != c.SQLITE_OK) return DbError.ExecFailed;
    }

    /// prepare a parameterized statement for execution.
    /// caller must call finalize() when done.
    pub fn prepare(self: *Db, sql: [*:0]const u8) DbError!Statement {
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(self.handle, sql, -1, &stmt, null);
        if (rc != c.SQLITE_OK or stmt == null) return DbError.PrepareFailed;
        return Statement{ .stmt = stmt.? };
    }
};

pub const Statement = struct {
    stmt: *c.sqlite3_stmt,

    /// bind a text value to a parameter (1-indexed)
    pub fn bindText(self: *Statement, col: c_int, value: []const u8) DbError!void {
        const rc = c.sqlite3_bind_text(
            self.stmt,
            col,
            value.ptr,
            @intCast(value.len),
            null, // SQLITE_STATIC — data outlives step()
        );
        if (rc != c.SQLITE_OK) return DbError.BindFailed;
    }

    /// bind an integer value to a parameter (1-indexed)
    pub fn bindInt(self: *Statement, col: c_int, value: i64) DbError!void {
        const rc = c.sqlite3_bind_int64(self.stmt, col, value);
        if (rc != c.SQLITE_OK) return DbError.BindFailed;
    }

    /// bind null to a parameter (1-indexed)
    pub fn bindNull(self: *Statement, col: c_int) DbError!void {
        const rc = c.sqlite3_bind_null(self.stmt, col);
        if (rc != c.SQLITE_OK) return DbError.BindFailed;
    }

    /// advance to the next row. returns .row if data is available,
    /// .done if the statement is complete.
    pub fn step(self: *Statement) DbError!StepResult {
        const rc = c.sqlite3_step(self.stmt);
        return switch (rc) {
            c.SQLITE_ROW => .row,
            c.SQLITE_DONE => .done,
            else => DbError.StepFailed,
        };
    }

    /// read a text column from the current row (0-indexed).
    /// returns null if the column is NULL.
    /// the returned slice is valid until the next step() or finalize().
    pub fn columnText(self: *Statement, col: c_int) ?[]const u8 {
        const ptr = c.sqlite3_column_text(self.stmt, col);
        if (ptr == null) return null;
        const len = c.sqlite3_column_bytes(self.stmt, col);
        if (len <= 0) return "";
        return ptr[0..@intCast(len)];
    }

    /// read an integer column from the current row (0-indexed)
    pub fn columnInt(self: *Statement, col: c_int) i64 {
        return c.sqlite3_column_int64(self.stmt, col);
    }

    /// read an integer column that might be NULL (0-indexed)
    pub fn columnOptionalInt(self: *Statement, col: c_int) ?i64 {
        if (c.sqlite3_column_type(self.stmt, col) == c.SQLITE_NULL) return null;
        return c.sqlite3_column_int64(self.stmt, col);
    }

    /// reset the statement so it can be re-executed with new bindings
    pub fn reset(self: *Statement) void {
        _ = c.sqlite3_reset(self.stmt);
        _ = c.sqlite3_clear_bindings(self.stmt);
    }

    /// release the compiled statement. must be called when done.
    pub fn finalize(self: *Statement) void {
        _ = c.sqlite3_finalize(self.stmt);
    }
};

// -- tests --

test "open and close in-memory db" {
    var db = try Db.open(":memory:");
    defer db.close();
}

test "exec create table" {
    var db = try Db.open(":memory:");
    defer db.close();

    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT);");
}

test "prepare, bind, step" {
    var db = try Db.open(":memory:");
    defer db.close();

    try db.exec("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT);");

    // insert a row
    var insert = try db.prepare("INSERT INTO test (id, name) VALUES (?1, ?2);");
    defer insert.finalize();
    try insert.bindInt(1, 42);
    try insert.bindText(2, "hello");
    const insert_result = try insert.step();
    try std.testing.expectEqual(StepResult.done, insert_result);

    // query it back
    var query = try db.prepare("SELECT id, name FROM test WHERE id = ?1;");
    defer query.finalize();
    try query.bindInt(1, 42);
    const query_result = try query.step();
    try std.testing.expectEqual(StepResult.row, query_result);

    const id = query.columnInt(0);
    try std.testing.expectEqual(@as(i64, 42), id);

    const name = query.columnText(1);
    try std.testing.expectEqualStrings("hello", name.?);
}

test "column null handling" {
    var db = try Db.open(":memory:");
    defer db.close();

    try db.exec("CREATE TABLE test (id INTEGER, val INTEGER);");

    var insert = try db.prepare("INSERT INTO test (id, val) VALUES (?1, ?2);");
    defer insert.finalize();
    try insert.bindInt(1, 1);
    try insert.bindNull(2);
    _ = try insert.step();

    var query = try db.prepare("SELECT val FROM test WHERE id = 1;");
    defer query.finalize();
    _ = try query.step();

    const val = query.columnOptionalInt(0);
    try std.testing.expect(val == null);
}

test "statement reset and reuse" {
    var db = try Db.open(":memory:");
    defer db.close();

    try db.exec("CREATE TABLE test (id INTEGER, name TEXT);");

    var insert = try db.prepare("INSERT INTO test (id, name) VALUES (?1, ?2);");
    defer insert.finalize();

    // first insert
    try insert.bindInt(1, 1);
    try insert.bindText(2, "one");
    _ = try insert.step();
    insert.reset();

    // second insert with same statement
    try insert.bindInt(1, 2);
    try insert.bindText(2, "two");
    _ = try insert.step();

    // verify both rows exist
    var query = try db.prepare("SELECT COUNT(*) FROM test;");
    defer query.finalize();
    _ = try query.step();
    try std.testing.expectEqual(@as(i64, 2), query.columnInt(0));
}

test "exec error on bad sql" {
    var db = try Db.open(":memory:");
    defer db.close();

    const result = db.exec("NOT VALID SQL;");
    try std.testing.expectError(DbError.ExecFailed, result);
}
