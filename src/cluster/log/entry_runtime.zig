const std = @import("std");
const sqlite = @import("sqlite");

const common = @import("common.zig");

const LogIndex = common.LogIndex;
const LogEntry = common.LogEntry;
const LogError = common.LogError;

pub fn append(db: *sqlite.Db, entry: LogEntry) LogError!void {
    db.exec(
        "INSERT INTO raft_log (log_index, term, data) VALUES (?, ?, ?);",
        .{},
        .{
            @as(i64, @intCast(entry.index)),
            @as(i64, @intCast(entry.term)),
            sqlite.Text{ .data = entry.data },
        },
    ) catch return LogError.WriteFailed;
}

pub fn getEntry(db: *sqlite.Db, alloc: std.mem.Allocator, index: LogIndex) LogError!?LogEntry {
    const Row = struct { log_index: i64, term: i64, data: sqlite.Text };
    const row = (db.oneAlloc(
        Row,
        alloc,
        "SELECT log_index, term, data FROM raft_log WHERE log_index = ?;",
        .{},
        .{@as(i64, @intCast(index))},
    ) catch return LogError.ReadFailed) orelse return null;
    return LogEntry{
        .index = common.safeU64(row.log_index) catch return LogError.ReadFailed,
        .term = common.safeU64(row.term) catch return LogError.ReadFailed,
        .data = row.data.data,
    };
}

pub fn truncateFrom(db: *sqlite.Db, index: LogIndex) LogError!void {
    db.exec(
        "DELETE FROM raft_log WHERE log_index >= ?;",
        .{},
        .{@as(i64, @intCast(index))},
    ) catch return LogError.WriteFailed;
}

pub fn getEntries(db: *sqlite.Db, alloc: std.mem.Allocator, from: LogIndex, to: LogIndex) LogError![]LogEntry {
    var entries: std.ArrayList(LogEntry) = .empty;

    const Row = struct { log_index: i64, term: i64, data: sqlite.Text };
    var stmt = db.prepare(
        "SELECT log_index, term, data FROM raft_log WHERE log_index >= ? AND log_index <= ? ORDER BY log_index;",
    ) catch return LogError.ReadFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(Row, .{
        @as(i64, @intCast(from)),
        @as(i64, @intCast(to)),
    }) catch return LogError.ReadFailed;

    while (iter.nextAlloc(alloc, .{}) catch return LogError.ReadFailed) |row| {
        entries.append(alloc, LogEntry{
            .index = common.safeU64(row.log_index) catch return LogError.ReadFailed,
            .term = common.safeU64(row.term) catch return LogError.ReadFailed,
            .data = row.data.data,
        }) catch return LogError.ReadFailed;
    }

    return entries.toOwnedSlice(alloc) catch return LogError.ReadFailed;
}
