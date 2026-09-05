const std = @import("std");
const sqlite = @import("sqlite");
const types = @import("../raft_types.zig");

pub const Term = types.Term;
pub const LogIndex = types.LogIndex;
pub const NodeId = types.NodeId;
pub const LogEntry = types.LogEntry;
pub const SnapshotMeta = types.SnapshotMeta;

pub const LogError = error{
    DbOpenFailed,
    WriteFailed,
    ReadFailed,
    CorruptedLog,
};

pub inline fn safeU64(val: i64) LogError!u64 {
    return std.math.cast(u64, val) orelse LogError.CorruptedLog;
}

/// Reset failed statements before finalizing; the caller reports the original
/// storage error, without a second cleanup error from the SQLite wrapper.
pub fn execStatement(db: *sqlite.Db, sql: []const u8, values: anytype) !void {
    var stmt = try db.prepareDynamic(sql);
    defer stmt.deinit();
    stmt.exec(.{}, values) catch |err| {
        _ = sqlite.c.sqlite3_reset(stmt.stmt);
        return err;
    };
}
