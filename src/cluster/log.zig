// log — SQLite-backed persistent raft log
//
// stores raft persistent state: current term, voted_for, and the
// replicated log entries. uses SQLite for crash recovery — if the
// process dies, we can resume from the last persisted state.
//
// the raft paper requires that current_term, voted_for, and log
// entries survive restarts. this module handles all three.

const std = @import("std");
const sqlite = @import("sqlite");
const types = @import("raft_types.zig");

const Term = types.Term;
const LogIndex = types.LogIndex;
const NodeId = types.NodeId;
const LogEntry = types.LogEntry;

pub const LogError = error{
    DbOpenFailed,
    WriteFailed,
    ReadFailed,
};

pub const Log = struct {
    db: sqlite.Db,

    pub fn init(path: [:0]const u8) LogError!Log {
        var db = sqlite.Db.init(.{
            .mode = .{ .File = path },
            .open_flags = .{ .write = true, .create = true },
        }) catch return LogError.DbOpenFailed;

        initSchema(&db) catch {
            db.deinit();
            return LogError.DbOpenFailed;
        };

        return .{ .db = db };
    }

    /// open an in-memory database (for testing)
    pub fn initMemory() LogError!Log {
        var db = sqlite.Db.init(.{
            .mode = .Memory,
            .open_flags = .{ .write = true },
        }) catch return LogError.DbOpenFailed;

        initSchema(&db) catch {
            db.deinit();
            return LogError.DbOpenFailed;
        };

        return .{ .db = db };
    }

    pub fn deinit(self: *Log) void {
        self.db.deinit();
    }

    // -- persistent state (survives restarts) --

    pub fn getCurrentTerm(self: *Log) Term {
        const Row = struct { current_term: i64 };
        const row = (self.db.one(
            Row,
            "SELECT current_term FROM raft_state WHERE id = 1;",
            .{},
            .{},
        ) catch return 0) orelse return 0;
        return @intCast(row.current_term);
    }

    pub fn setCurrentTerm(self: *Log, term: Term) void {
        self.db.exec(
            "UPDATE raft_state SET current_term = ? WHERE id = 1;",
            .{},
            .{@as(i64, @intCast(term))},
        ) catch {};
    }

    pub fn getVotedFor(self: *Log) ?NodeId {
        const Row = struct { voted_for: ?i64 };
        const row = (self.db.one(
            Row,
            "SELECT voted_for FROM raft_state WHERE id = 1;",
            .{},
            .{},
        ) catch return null) orelse return null;
        return if (row.voted_for) |v| @intCast(v) else null;
    }

    pub fn setVotedFor(self: *Log, id: ?NodeId) void {
        const val: ?i64 = if (id) |v| @intCast(v) else null;
        self.db.exec(
            "UPDATE raft_state SET voted_for = ? WHERE id = 1;",
            .{},
            .{val},
        ) catch {};
    }

    // -- log operations --

    pub fn append(self: *Log, entry: LogEntry) LogError!void {
        self.db.exec(
            "INSERT INTO raft_log (log_index, term, data) VALUES (?, ?, ?);",
            .{},
            .{
                @as(i64, @intCast(entry.index)),
                @as(i64, @intCast(entry.term)),
                sqlite.Text{ .data = entry.data },
            },
        ) catch return LogError.WriteFailed;
    }

    pub fn getEntry(self: *Log, alloc: std.mem.Allocator, index: LogIndex) LogError!?LogEntry {
        const Row = struct { log_index: i64, term: i64, data: sqlite.Text };
        const row = (self.db.oneAlloc(
            Row,
            alloc,
            "SELECT log_index, term, data FROM raft_log WHERE log_index = ?;",
            .{},
            .{@as(i64, @intCast(index))},
        ) catch return LogError.ReadFailed) orelse return null;
        return LogEntry{
            .index = @intCast(row.log_index),
            .term = @intCast(row.term),
            .data = row.data.data,
        };
    }

    pub fn lastIndex(self: *Log) LogIndex {
        const Row = struct { max_index: ?i64 };
        const row = (self.db.one(
            Row,
            "SELECT MAX(log_index) AS max_index FROM raft_log;",
            .{},
            .{},
        ) catch return 0) orelse return 0;
        return if (row.max_index) |m| @intCast(m) else 0;
    }

    pub fn lastTerm(self: *Log) Term {
        const last = self.lastIndex();
        if (last == 0) return 0;
        const Row = struct { term: i64 };
        const row = (self.db.one(
            Row,
            "SELECT term FROM raft_log WHERE log_index = ?;",
            .{},
            .{@as(i64, @intCast(last))},
        ) catch return 0) orelse return 0;
        return @intCast(row.term);
    }

    /// get the term for a specific log index (needed for consistency checks)
    pub fn termAt(self: *Log, index: LogIndex) Term {
        if (index == 0) return 0;
        const Row = struct { term: i64 };
        const row = (self.db.one(
            Row,
            "SELECT term FROM raft_log WHERE log_index = ?;",
            .{},
            .{@as(i64, @intCast(index))},
        ) catch return 0) orelse return 0;
        return @intCast(row.term);
    }

    /// remove all entries from index onwards (inclusive).
    /// used when a leader's log conflicts with ours.
    pub fn truncateFrom(self: *Log, index: LogIndex) void {
        self.db.exec(
            "DELETE FROM raft_log WHERE log_index >= ?;",
            .{},
            .{@as(i64, @intCast(index))},
        ) catch {};
    }

    /// get entries in range [from, to] inclusive.
    /// caller owns the returned slice and entry data.
    pub fn getEntries(self: *Log, alloc: std.mem.Allocator, from: LogIndex, to: LogIndex) LogError![]LogEntry {
        var entries: std.ArrayList(LogEntry) = .{};

        const Row = struct { log_index: i64, term: i64, data: sqlite.Text };
        var stmt = self.db.prepare(
            "SELECT log_index, term, data FROM raft_log WHERE log_index >= ? AND log_index <= ? ORDER BY log_index;",
        ) catch return LogError.ReadFailed;
        defer stmt.deinit();

        var iter = stmt.iterator(Row, .{
            @as(i64, @intCast(from)),
            @as(i64, @intCast(to)),
        }) catch return LogError.ReadFailed;

        while (iter.nextAlloc(alloc, .{}) catch return LogError.ReadFailed) |row| {
            entries.append(alloc, LogEntry{
                .index = @intCast(row.log_index),
                .term = @intCast(row.term),
                .data = row.data.data,
            }) catch return LogError.ReadFailed;
        }

        return entries.toOwnedSlice(alloc) catch return LogError.ReadFailed;
    }
};

// -- schema --

fn initSchema(db: *sqlite.Db) !void {
    db.exec(
        \\CREATE TABLE IF NOT EXISTS raft_state (
        \\    id INTEGER PRIMARY KEY CHECK (id = 1),
        \\    current_term INTEGER NOT NULL DEFAULT 0,
        \\    voted_for INTEGER
        \\);
    , .{}, .{}) catch return error.InitFailed;

    // ensure the single state row exists
    db.exec(
        "INSERT OR IGNORE INTO raft_state (id, current_term) VALUES (1, 0);",
        .{},
        .{},
    ) catch return error.InitFailed;

    db.exec(
        \\CREATE TABLE IF NOT EXISTS raft_log (
        \\    log_index INTEGER PRIMARY KEY,
        \\    term INTEGER NOT NULL,
        \\    data BLOB NOT NULL
        \\);
    , .{}, .{}) catch return error.InitFailed;
}

// -- tests --

test "term persistence" {
    var log = try Log.initMemory();
    defer log.deinit();

    try std.testing.expectEqual(@as(Term, 0), log.getCurrentTerm());

    log.setCurrentTerm(5);
    try std.testing.expectEqual(@as(Term, 5), log.getCurrentTerm());

    log.setCurrentTerm(10);
    try std.testing.expectEqual(@as(Term, 10), log.getCurrentTerm());
}

test "voted_for persistence" {
    var log = try Log.initMemory();
    defer log.deinit();

    try std.testing.expect(log.getVotedFor() == null);

    log.setVotedFor(42);
    try std.testing.expectEqual(@as(?NodeId, 42), log.getVotedFor());

    log.setVotedFor(null);
    try std.testing.expect(log.getVotedFor() == null);
}

test "log append and get" {
    var log = try Log.initMemory();
    defer log.deinit();
    const alloc = std.testing.allocator;

    try log.append(.{ .index = 1, .term = 1, .data = "cmd1" });
    try log.append(.{ .index = 2, .term = 1, .data = "cmd2" });
    try log.append(.{ .index = 3, .term = 2, .data = "cmd3" });

    const entry = (try log.getEntry(alloc, 2)).?;
    defer alloc.free(entry.data);
    try std.testing.expectEqual(@as(LogIndex, 2), entry.index);
    try std.testing.expectEqual(@as(Term, 1), entry.term);
    try std.testing.expectEqualStrings("cmd2", entry.data);

    // nonexistent entry
    try std.testing.expect((try log.getEntry(alloc, 99)) == null);
}

test "lastIndex and lastTerm" {
    var log = try Log.initMemory();
    defer log.deinit();

    try std.testing.expectEqual(@as(LogIndex, 0), log.lastIndex());
    try std.testing.expectEqual(@as(Term, 0), log.lastTerm());

    try log.append(.{ .index = 1, .term = 3, .data = "a" });
    try std.testing.expectEqual(@as(LogIndex, 1), log.lastIndex());
    try std.testing.expectEqual(@as(Term, 3), log.lastTerm());

    try log.append(.{ .index = 2, .term = 5, .data = "b" });
    try std.testing.expectEqual(@as(LogIndex, 2), log.lastIndex());
    try std.testing.expectEqual(@as(Term, 5), log.lastTerm());
}

test "truncateFrom" {
    var log = try Log.initMemory();
    defer log.deinit();
    const alloc = std.testing.allocator;

    try log.append(.{ .index = 1, .term = 1, .data = "a" });
    try log.append(.{ .index = 2, .term = 1, .data = "b" });
    try log.append(.{ .index = 3, .term = 2, .data = "c" });

    log.truncateFrom(2);

    try std.testing.expectEqual(@as(LogIndex, 1), log.lastIndex());
    try std.testing.expect((try log.getEntry(alloc, 2)) == null);
    try std.testing.expect((try log.getEntry(alloc, 3)) == null);

    // entry 1 should still exist
    const entry = (try log.getEntry(alloc, 1)).?;
    defer alloc.free(entry.data);
    try std.testing.expectEqualStrings("a", entry.data);
}

test "getEntries range" {
    var log = try Log.initMemory();
    defer log.deinit();
    const alloc = std.testing.allocator;

    try log.append(.{ .index = 1, .term = 1, .data = "a" });
    try log.append(.{ .index = 2, .term = 1, .data = "b" });
    try log.append(.{ .index = 3, .term = 2, .data = "c" });
    try log.append(.{ .index = 4, .term = 2, .data = "d" });

    const entries = try log.getEntries(alloc, 2, 3);
    defer {
        for (entries) |e| alloc.free(e.data);
        alloc.free(entries);
    }

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqual(@as(LogIndex, 2), entries[0].index);
    try std.testing.expectEqual(@as(LogIndex, 3), entries[1].index);
}

test "termAt" {
    var log = try Log.initMemory();
    defer log.deinit();

    try std.testing.expectEqual(@as(Term, 0), log.termAt(0));
    try std.testing.expectEqual(@as(Term, 0), log.termAt(1));

    try log.append(.{ .index = 1, .term = 3, .data = "x" });
    try log.append(.{ .index = 2, .term = 5, .data = "y" });

    try std.testing.expectEqual(@as(Term, 3), log.termAt(1));
    try std.testing.expectEqual(@as(Term, 5), log.termAt(2));
}
