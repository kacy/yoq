// backup — SQLite online backup and restore for yoq state
//
// uses the SQLite Online Backup API (sqlite3_backup_init/step/finish)
// to create consistent snapshots of the yoq database while the server
// may still be running. restores validate the schema version before
// replacing the active database.
//
// only metadata is backed up — volume data (which can be very large)
// is NOT included.

const std = @import("std");
const platform = @import("platform");
const sqlite = @import("sqlite");
const schema = @import("schema.zig");
const paths = @import("../lib/paths.zig");

const c = sqlite.c;

pub const BackupError = error{
    DbOpenFailed,
    BackupFailed,
    RestoreFailed,
    PathError,
    ServerRunning,
    SchemaValidationFailed,
};

/// create a backup of the yoq database to the given output path.
/// safe to call while the server is running — uses SQLite online backup.
pub fn backup(output_path: [:0]const u8) BackupError!void {
    // open the source database
    var src_path_buf: [paths.max_path]u8 = undefined;
    const src_path = schema.defaultDbPath(&src_path_buf) catch return BackupError.PathError;

    var src_db: ?*c.sqlite3 = null;
    if (c.sqlite3_open(src_path.ptr, &src_db) != c.SQLITE_OK or src_db == null) {
        if (src_db) |db| _ = c.sqlite3_close(db);
        return BackupError.DbOpenFailed;
    }
    defer _ = c.sqlite3_close(src_db);

    // open the destination database
    var dest_db: ?*c.sqlite3 = null;
    if (c.sqlite3_open(output_path.ptr, &dest_db) != c.SQLITE_OK or dest_db == null) {
        if (dest_db) |db| _ = c.sqlite3_close(db);
        return BackupError.BackupFailed;
    }
    defer _ = c.sqlite3_close(dest_db);

    // perform the backup
    const bk = c.sqlite3_backup_init(dest_db, "main", src_db, "main");
    if (bk == null) return BackupError.BackupFailed;

    const step_rc = c.sqlite3_backup_step(bk, -1);
    const finish_rc = c.sqlite3_backup_finish(bk);

    if (step_rc != c.SQLITE_DONE) return BackupError.BackupFailed;
    if (finish_rc != c.SQLITE_OK) return BackupError.BackupFailed;
}

/// restore a database backup to the yoq data directory.
/// validates that the backup contains a valid schema before replacing.
/// warns if the server appears to be running (lockfile check).
pub fn restore(input_path: [:0]const u8) BackupError!void {
    var dest_path_buf: [paths.max_path]u8 = undefined;
    const dest_path = schema.defaultDbPath(&dest_path_buf) catch return BackupError.PathError;

    var src_db: ?*c.sqlite3 = null;
    if (c.sqlite3_open_v2(input_path.ptr, &src_db, c.SQLITE_OPEN_READONLY, null) != c.SQLITE_OK or src_db == null) {
        if (src_db) |db| _ = c.sqlite3_close(db);
        return BackupError.RestoreFailed;
    }
    defer _ = c.sqlite3_close(src_db);
    try validateBackupSchema(src_db.?);

    var dest_db: ?*c.sqlite3 = null;
    if (c.sqlite3_open_v2(dest_path.ptr, &dest_db, c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE, null) != c.SQLITE_OK or dest_db == null) {
        if (dest_db) |db| _ = c.sqlite3_close(db);
        return BackupError.RestoreFailed;
    }
    defer _ = c.sqlite3_close(dest_db);
    try beginExclusiveRestore(dest_db.?);
    var transaction_open = true;
    defer {
        if (transaction_open) _ = c.sqlite3_exec(dest_db, "ROLLBACK;", null, null, null);
    }

    const bk = c.sqlite3_backup_init(dest_db, "main", src_db, "main");
    if (bk == null) return BackupError.RestoreFailed;

    const step_rc = c.sqlite3_backup_step(bk, -1);
    const finish_rc = c.sqlite3_backup_finish(bk);

    if (step_rc != c.SQLITE_DONE) return BackupError.RestoreFailed;
    if (finish_rc != c.SQLITE_OK) return BackupError.RestoreFailed;
    if (c.sqlite3_exec(dest_db, "COMMIT;", null, null, null) != c.SQLITE_OK) {
        return BackupError.RestoreFailed;
    }
    transaction_open = false;
}

fn beginExclusiveRestore(db: *c.sqlite3) BackupError!void {
    _ = c.sqlite3_busy_timeout(db, 0);
    if (c.sqlite3_exec(db, "PRAGMA locking_mode=EXCLUSIVE;", null, null, null) != c.SQLITE_OK) {
        return BackupError.RestoreFailed;
    }
    const rc = c.sqlite3_exec(db, "BEGIN IMMEDIATE;", null, null, null);
    if (rc == c.SQLITE_BUSY or rc == c.SQLITE_LOCKED) return BackupError.ServerRunning;
    if (rc != c.SQLITE_OK) return BackupError.RestoreFailed;
}

fn validateBackupSchema(db: *c.sqlite3) BackupError!void {
    const required_tables_sql =
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN (" ++
        "'containers','images','ip_allocations','build_cache','service_names','services','service_endpoints'," ++
        "'agents','assignments','deployments','secrets','network_policies'," ++
        "'wireguard_peers','volumes','certificates','s3_multipart_uploads'," ++
        "'s3_upload_parts','training_jobs','training_checkpoints'" ++
        ");";
    const required_table_count = 19;

    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, required_tables_sql, @intCast(required_tables_sql.len), &stmt, null) != c.SQLITE_OK) {
        return BackupError.SchemaValidationFailed;
    }
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return BackupError.SchemaValidationFailed;
    if (c.sqlite3_column_int(stmt, 0) != required_table_count) return BackupError.SchemaValidationFailed;

    var integrity_stmt: ?*c.sqlite3_stmt = null;
    const integrity_sql = "PRAGMA integrity_check;";
    if (c.sqlite3_prepare_v2(db, integrity_sql, @intCast(integrity_sql.len), &integrity_stmt, null) != c.SQLITE_OK) {
        return BackupError.SchemaValidationFailed;
    }
    defer _ = c.sqlite3_finalize(integrity_stmt);
    if (c.sqlite3_step(integrity_stmt) != c.SQLITE_ROW) return BackupError.SchemaValidationFailed;
    const result = c.sqlite3_column_text(integrity_stmt, 0) orelse return BackupError.SchemaValidationFailed;
    const text = std.mem.span(@as([*:0]const u8, @ptrCast(result)));
    if (!std.mem.eql(u8, text, "ok")) return BackupError.SchemaValidationFailed;
}

// -- tests --

test "backup error types compile" {
    // verify the module compiles and function signatures are correct
    try std.testing.expect(@TypeOf(backup) == fn ([:0]const u8) BackupError!void);
    try std.testing.expect(@TypeOf(restore) == fn ([:0]const u8) BackupError!void);
}

test "validateBackupSchema rejects incomplete database" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const path = try platform.Dir.from(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(path);

    var path_buf: [paths.max_path]u8 = undefined;
    const db_path = try std.fmt.bufPrintZ(&path_buf, "{s}/bad.db", .{path});

    var db: ?*c.sqlite3 = null;
    try std.testing.expectEqual(@as(c_int, c.SQLITE_OK), c.sqlite3_open(db_path.ptr, &db));
    defer _ = c.sqlite3_close(db);
    _ = c.sqlite3_exec(db, "CREATE TABLE containers (id TEXT);", null, null, null);

    try std.testing.expectError(BackupError.SchemaValidationFailed, validateBackupSchema(db.?));
}
