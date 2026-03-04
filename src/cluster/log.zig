// log — SQLite-backed persistent raft log
//
// stores raft persistent state: current term, voted_for, and the
// replicated log entries. uses SQLite for crash recovery — if the
// process dies, we can resume from the last persisted state.
//
// the raft paper requires that current_term, voted_for, and log
// entries survive restarts. this module handles all three.
//
// snapshot awareness: after a snapshot is taken and log entries are
// truncated, the log may be empty. queries like lastIndex() and
// lastTerm() fall back to the snapshot metadata in that case, so
// the rest of the raft algorithm doesn't need special cases.

const std = @import("std");
const sqlite = @import("sqlite");
const types = @import("raft_types.zig");

const Term = types.Term;
const LogIndex = types.LogIndex;
const NodeId = types.NodeId;
const LogEntry = types.LogEntry;
const SnapshotMeta = types.SnapshotMeta;

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

    // -- snapshot metadata --
    //
    // after a snapshot is taken, we record what index/term it covers.
    // this lets snapshot-aware queries (lastIndex, lastTerm, termAt)
    // return correct values even when the log has been truncated.

    pub fn getSnapshotMeta(self: *Log) ?SnapshotMeta {
        const Row = struct {
            last_included_index: i64,
            last_included_term: i64,
            data_len: i64,
        };
        const row = (self.db.one(
            Row,
            "SELECT last_included_index, last_included_term, data_len FROM snapshot_meta WHERE id = 1;",
            .{},
            .{},
        ) catch return null) orelse return null;

        // no snapshot yet — the row exists but with all zeros
        if (row.last_included_index == 0) return null;

        return SnapshotMeta{
            .last_included_index = @intCast(row.last_included_index),
            .last_included_term = @intCast(row.last_included_term),
            .data_len = @intCast(row.data_len),
        };
    }

    pub fn setSnapshotMeta(self: *Log, meta: SnapshotMeta) void {
        self.db.exec(
            "UPDATE snapshot_meta SET last_included_index = ?, last_included_term = ?, data_len = ? WHERE id = 1;",
            .{},
            .{
                @as(i64, @intCast(meta.last_included_index)),
                @as(i64, @intCast(meta.last_included_term)),
                @as(i64, @intCast(meta.data_len)),
            },
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

    /// returns the highest log index. if the log is empty but a snapshot
    /// exists, returns the snapshot's last_included_index.
    pub fn lastIndex(self: *Log) LogIndex {
        const Row = struct { max_index: ?i64 };
        const row = (self.db.one(
            Row,
            "SELECT MAX(log_index) AS max_index FROM raft_log;",
            .{},
            .{},
        ) catch return self.snapshotLastIndex()) orelse return self.snapshotLastIndex();

        if (row.max_index) |m| {
            return @intCast(m);
        }

        // log is empty — fall back to snapshot
        return self.snapshotLastIndex();
    }

    /// returns the term of the last log entry. if the log is empty but a
    /// snapshot exists, returns the snapshot's last_included_term.
    pub fn lastTerm(self: *Log) Term {
        const last = self.lastLogIndex();
        if (last > 0) {
            const Row = struct { term: i64 };
            const row = (self.db.one(
                Row,
                "SELECT term FROM raft_log WHERE log_index = ?;",
                .{},
                .{@as(i64, @intCast(last))},
            ) catch return 0) orelse return 0;
            return @intCast(row.term);
        }

        // log is empty — fall back to snapshot
        if (self.getSnapshotMeta()) |meta| {
            return meta.last_included_term;
        }
        return 0;
    }

    /// get the term for a specific log index (needed for consistency checks).
    /// if the index matches the snapshot's last_included_index, returns the
    /// snapshot's term — this covers the case where the entry was truncated
    /// after snapshotting.
    pub fn termAt(self: *Log, index: LogIndex) Term {
        if (index == 0) return 0;

        // first try the log itself
        const Row = struct { term: i64 };
        const row = self.db.one(
            Row,
            "SELECT term FROM raft_log WHERE log_index = ?;",
            .{},
            .{@as(i64, @intCast(index))},
        ) catch return 0;

        if (row) |r| {
            return @intCast(r.term);
        }

        // not in log — check if the snapshot covers this index
        if (self.getSnapshotMeta()) |meta| {
            if (index == meta.last_included_index) {
                return meta.last_included_term;
            }
        }

        return 0;
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

    /// remove all entries up to and including the given index.
    /// used after a snapshot is taken to reclaim space — we no longer
    /// need entries that are covered by the snapshot.
    pub fn truncateUpTo(self: *Log, index: LogIndex) void {
        self.db.exec(
            "DELETE FROM raft_log WHERE log_index <= ?;",
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

    // -- internal helpers --

    /// the highest index actually present in the log table (ignoring snapshots).
    /// used internally to distinguish "log has entries" from "only snapshot".
    fn lastLogIndex(self: *Log) LogIndex {
        const Row = struct { max_index: ?i64 };
        const row = (self.db.one(
            Row,
            "SELECT MAX(log_index) AS max_index FROM raft_log;",
            .{},
            .{},
        ) catch return 0) orelse return 0;
        return if (row.max_index) |m| @intCast(m) else 0;
    }

    /// snapshot fallback for lastIndex
    fn snapshotLastIndex(self: *Log) LogIndex {
        if (self.getSnapshotMeta()) |meta| {
            return meta.last_included_index;
        }
        return 0;
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

    // snapshot metadata — single row, like raft_state.
    // records the last log entry included in the most recent snapshot.
    db.exec(
        \\CREATE TABLE IF NOT EXISTS snapshot_meta (
        \\    id INTEGER PRIMARY KEY CHECK (id = 1),
        \\    last_included_index INTEGER NOT NULL DEFAULT 0,
        \\    last_included_term INTEGER NOT NULL DEFAULT 0,
        \\    data_len INTEGER NOT NULL DEFAULT 0
        \\);
    , .{}, .{}) catch return error.InitFailed;

    db.exec(
        "INSERT OR IGNORE INTO snapshot_meta (id) VALUES (1);",
        .{},
        .{},
    ) catch return error.InitFailed;
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

test "truncateFrom then append replaces entries" {
    var log = try Log.initMemory();
    defer log.deinit();
    const alloc = std.testing.allocator;

    try log.append(.{ .index = 1, .term = 1, .data = "a" });
    try log.append(.{ .index = 2, .term = 1, .data = "b" });
    try log.append(.{ .index = 3, .term = 1, .data = "c" });

    // leader conflict: truncate from index 2 and write new entries
    log.truncateFrom(2);
    try log.append(.{ .index = 2, .term = 2, .data = "new_b" });

    try std.testing.expectEqual(@as(LogIndex, 2), log.lastIndex());
    try std.testing.expectEqual(@as(Term, 2), log.termAt(2));

    const entry = (try log.getEntry(alloc, 2)).?;
    defer alloc.free(entry.data);
    try std.testing.expectEqualStrings("new_b", entry.data);

    // old entry 3 should be gone
    try std.testing.expect((try log.getEntry(alloc, 3)) == null);
}

test "getEntries with from greater than to returns empty" {
    var log = try Log.initMemory();
    defer log.deinit();
    const alloc = std.testing.allocator;

    try log.append(.{ .index = 1, .term = 1, .data = "a" });
    try log.append(.{ .index = 2, .term = 1, .data = "b" });

    const entries = try log.getEntries(alloc, 5, 3);
    defer alloc.free(entries);
    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "termAt beyond last entry returns zero" {
    var log = try Log.initMemory();
    defer log.deinit();

    try log.append(.{ .index = 1, .term = 3, .data = "x" });
    try log.append(.{ .index = 2, .term = 5, .data = "y" });

    try std.testing.expectEqual(@as(Term, 0), log.termAt(99));
}

// -- snapshot-aware tests --

test "snapshot meta persistence" {
    var log = try Log.initMemory();
    defer log.deinit();

    // no snapshot initially
    try std.testing.expect(log.getSnapshotMeta() == null);

    log.setSnapshotMeta(.{
        .last_included_index = 100,
        .last_included_term = 5,
        .data_len = 4096,
    });

    const meta = log.getSnapshotMeta().?;
    try std.testing.expectEqual(@as(LogIndex, 100), meta.last_included_index);
    try std.testing.expectEqual(@as(Term, 5), meta.last_included_term);
    try std.testing.expectEqual(@as(u64, 4096), meta.data_len);
}

test "lastIndex falls back to snapshot when log is empty" {
    var log = try Log.initMemory();
    defer log.deinit();

    try std.testing.expectEqual(@as(LogIndex, 0), log.lastIndex());

    // set snapshot metadata without any log entries
    log.setSnapshotMeta(.{
        .last_included_index = 50,
        .last_included_term = 3,
        .data_len = 1024,
    });

    try std.testing.expectEqual(@as(LogIndex, 50), log.lastIndex());
}

test "lastTerm falls back to snapshot when log is empty" {
    var log = try Log.initMemory();
    defer log.deinit();

    log.setSnapshotMeta(.{
        .last_included_index = 50,
        .last_included_term = 3,
        .data_len = 1024,
    });

    try std.testing.expectEqual(@as(Term, 3), log.lastTerm());
}

test "lastIndex prefers log entries over snapshot" {
    var log = try Log.initMemory();
    defer log.deinit();

    log.setSnapshotMeta(.{
        .last_included_index = 50,
        .last_included_term = 3,
        .data_len = 1024,
    });

    // add an entry beyond the snapshot
    try log.append(.{ .index = 51, .term = 3, .data = "after snapshot" });

    try std.testing.expectEqual(@as(LogIndex, 51), log.lastIndex());
}

test "lastTerm prefers log entries over snapshot" {
    var log = try Log.initMemory();
    defer log.deinit();

    log.setSnapshotMeta(.{
        .last_included_index = 50,
        .last_included_term = 3,
        .data_len = 1024,
    });

    try log.append(.{ .index = 51, .term = 4, .data = "new term" });

    try std.testing.expectEqual(@as(Term, 4), log.lastTerm());
}

test "termAt returns snapshot term for snapshot boundary index" {
    var log = try Log.initMemory();
    defer log.deinit();

    log.setSnapshotMeta(.{
        .last_included_index = 50,
        .last_included_term = 3,
        .data_len = 1024,
    });

    // index 50 was truncated but snapshot covers it
    try std.testing.expectEqual(@as(Term, 3), log.termAt(50));

    // index 49 is not in log or at snapshot boundary
    try std.testing.expectEqual(@as(Term, 0), log.termAt(49));
}

test "truncateUpTo removes entries up to index" {
    var log = try Log.initMemory();
    defer log.deinit();
    const alloc = std.testing.allocator;

    try log.append(.{ .index = 1, .term = 1, .data = "a" });
    try log.append(.{ .index = 2, .term = 1, .data = "b" });
    try log.append(.{ .index = 3, .term = 2, .data = "c" });
    try log.append(.{ .index = 4, .term = 2, .data = "d" });

    log.truncateUpTo(2);

    // entries 1 and 2 should be gone
    try std.testing.expect((try log.getEntry(alloc, 1)) == null);
    try std.testing.expect((try log.getEntry(alloc, 2)) == null);

    // entries 3 and 4 should remain
    const entry3 = (try log.getEntry(alloc, 3)).?;
    defer alloc.free(entry3.data);
    try std.testing.expectEqualStrings("c", entry3.data);

    const entry4 = (try log.getEntry(alloc, 4)).?;
    defer alloc.free(entry4.data);
    try std.testing.expectEqualStrings("d", entry4.data);
}

test "truncateUpTo with snapshot preserves lastIndex" {
    var log = try Log.initMemory();
    defer log.deinit();

    try log.append(.{ .index = 1, .term = 1, .data = "a" });
    try log.append(.{ .index = 2, .term = 1, .data = "b" });
    try log.append(.{ .index = 3, .term = 2, .data = "c" });

    // snapshot at index 2, then truncate
    log.setSnapshotMeta(.{
        .last_included_index = 2,
        .last_included_term = 1,
        .data_len = 512,
    });
    log.truncateUpTo(2);

    // lastIndex should still be 3 (from the log)
    try std.testing.expectEqual(@as(LogIndex, 3), log.lastIndex());

    // termAt(2) should return snapshot term
    try std.testing.expectEqual(@as(Term, 1), log.termAt(2));
}

test "truncateUpTo all entries with snapshot" {
    var log = try Log.initMemory();
    defer log.deinit();

    try log.append(.{ .index = 1, .term = 1, .data = "a" });
    try log.append(.{ .index = 2, .term = 1, .data = "b" });

    log.setSnapshotMeta(.{
        .last_included_index = 2,
        .last_included_term = 1,
        .data_len = 512,
    });
    log.truncateUpTo(2);

    // log is empty but snapshot provides the answer
    try std.testing.expectEqual(@as(LogIndex, 2), log.lastIndex());
    try std.testing.expectEqual(@as(Term, 1), log.lastTerm());
}
