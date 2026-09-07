// Replicated command format: an unmodified SQL batch. Admission and
// replay share this guard and statement iterator; Raft remains byte-oriented.
// Keep the legacy format until a negotiated protocol upgrade can replace it.
const sqlite = @import("sqlite");
const types = @import("../raft_types.zig");
const sql_guard = @import("sql_guard.zig");
const db_runtime = @import("db_runtime.zig");
const log = @import("../../lib/log.zig");

/// Structural validation is independent of local database contents. SQL
/// syntax, schema and constraint errors are detected during atomic apply.
pub fn validate(sql: []const u8) error{InvalidCommand}!void {
    if (!sql_guard.isAllowedStatement(sql)) return error.InvalidCommand;
}

/// Validate the complete command before opening a transaction. Use the same
/// iterator to execute it, keeping mutations and the replay position in one
/// transaction. Neither a later statement failure nor a failed commit may
/// leave a partial batch or advance the in-memory position.
pub fn apply(db: *sqlite.Db, entry: types.LogEntry) !void {
    try validate(entry.data);
    try db_runtime.execStatement(db, "BEGIN IMMEDIATE;", .{});
    errdefer {
        // SQLite may already have rolled back on a storage/constraint error.
        if (sqlite.c.sqlite3_get_autocommit(db.db) == 0) {
            db_runtime.execStatement(db, "ROLLBACK;", .{}) catch |err| {
                log.err("state machine: failed to roll back entry {d}: {}", .{ entry.index, err });
            };
        }
    }

    var statements = sql_guard.StatementIterator{ .sql = entry.data };
    while (statements.next()) |sql| {
        db_runtime.execStatement(db, sql, .{}) catch |err| {
            if (err != error.SQLiteConstraint) return err;
            // A client conflict has a deterministic result. Roll back the whole
            // command and record rejection, so later committed entries can run.
            try db_runtime.execStatement(db, "ROLLBACK;", .{});
            try db_runtime.execStatement(db, "BEGIN IMMEDIATE;", .{});
            try db_runtime.initMeta(db);
            try db_runtime.execStatement(db, "INSERT INTO rejected_commands (log_index, term) VALUES (?, ?);", .{ @as(i64, @intCast(entry.index)), @as(i64, @intCast(entry.term)) });
            break;
        };
    }
    try db_runtime.setLastApplied(db, entry.index);
    try db_runtime.execStatement(db, "COMMIT;", .{});
}

/// Rejections are snapshot state, just like the applied position. A caller
/// can still observe its outcome after compaction removes the original log.
pub fn wasRejected(db: *sqlite.Db, index: types.LogIndex, term: types.Term) !bool {
    const Row = struct { count: i64 };
    const row = (try db.one(Row, "SELECT COUNT(*) AS count FROM rejected_commands WHERE log_index = ? AND term = ?;", .{}, .{ @as(i64, @intCast(index)), @as(i64, @intCast(term)) })).?;
    return row.count != 0;
}
