// replicated commands remain unmodified SQL batches. admission and replay
// use the same canonical schema and guard; raft still stores the original
// bytes until a negotiated protocol upgrade can replace this format.
const validation = @import("validation.zig");
pub const Validator = validation.Validator;

const sqlite = @import("sqlite");
const types = @import("../raft_types.zig");
const sql_guard = @import("sql_guard.zig");
const db_runtime = @import("db_runtime.zig");
const log = @import("../../lib/log.zig");

/// standalone validation for callers without a state machine. nodes reuse
/// their validator to avoid rebuilding the canonical schema per proposal.
pub fn validate(sql: []const u8) validation.Error!void {
    var validator = Validator.init() catch return error.ValidationUnavailable;
    defer validator.deinit();
    try validator.validate(sql);
}

/// validate the complete command before opening a transaction. mutations and
/// the replay position commit together. a later statement failure or a failed
/// commit must not leave a partial batch or advance the in-memory position.
pub fn apply(db: *sqlite.Db, validator: *Validator, entry: types.LogEntry) !void {
    const invalid = invalid: {
        validator.validate(entry.data) catch |err| switch (err) {
            error.InvalidCommand => break :invalid true,
            else => return err,
        };
        break :invalid false;
    };
    try db_runtime.execStatement(db, "BEGIN IMMEDIATE;", .{});
    errdefer {
        // sqlite may already have rolled back on a storage or constraint error.
        if (sqlite.c.sqlite3_get_autocommit(db.db) == 0) {
            db_runtime.execStatement(db, "ROLLBACK;", .{}) catch |err| {
                log.err("state machine: failed to roll back entry {d}: {}", .{ entry.index, err });
            };
        }
    }

    if (invalid) {
        // an old leader may have committed an invalid command. classify it
        // against the same empty schema on every upgraded replica, then
        // persist rejection and the apply position in one transaction.
        try reject(db, entry);
        try db_runtime.setLastApplied(db, entry.index);
        try db_runtime.execStatement(db, "COMMIT;", .{});
        return;
    }

    var statements = sql_guard.StatementIterator{ .sql = entry.data };
    while (statements.next()) |sql| {
        db_runtime.execStatement(db, sql, .{}) catch |err| {
            if (err != error.SQLiteConstraint) return err;
            // a constraint conflict rejects the whole command. roll back its
            // writes before recording rejection so later entries can run.
            if (sqlite.c.sqlite3_get_autocommit(db.db) == 0)
                try db_runtime.execStatement(db, "ROLLBACK;", .{});
            try db_runtime.execStatement(db, "BEGIN IMMEDIATE;", .{});
            try reject(db, entry);
            break;
        };
    }
    try db_runtime.setLastApplied(db, entry.index);
    try db_runtime.execStatement(db, "COMMIT;", .{});
}

fn reject(db: *sqlite.Db, entry: types.LogEntry) !void {
    try db_runtime.initMeta(db);
    try db_runtime.execStatement(db, "INSERT INTO rejected_commands (log_index, term) VALUES (?, ?);", .{ @as(i64, @intCast(entry.index)), @as(i64, @intCast(entry.term)) });
}

/// rejections are snapshot state, just like the applied position. callers can
/// read the outcome after compaction removes the original log entry.
pub fn wasRejected(db: *sqlite.Db, index: types.LogIndex, term: types.Term) !bool {
    const Row = struct { count: i64 };
    const row = (try db.one(Row, "SELECT COUNT(*) AS count FROM rejected_commands WHERE log_index = ? AND term = ?;", .{}, .{ @as(i64, @intCast(index)), @as(i64, @intCast(term)) })).?;
    return row.count != 0;
}
