// log — SQLite-backed persistent raft log
//
// the public log API stays here while storage, snapshot, and schema
// details live in `cluster/log/` support modules.

const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("log/common.zig");
const entry_runtime = @import("log/entry_runtime.zig");
const logger = @import("../lib/log.zig");
const snapshot_support = @import("log/snapshot_support.zig");
const state_runtime = @import("log/state_runtime.zig");

const Term = common.Term;
const LogIndex = common.LogIndex;
const NodeId = common.NodeId;
const LogEntry = common.LogEntry;
const SnapshotMeta = common.SnapshotMeta;

pub const LogError = common.LogError;

pub const Log = struct {
    db: sqlite.Db,

    pub fn init(path: [:0]const u8) LogError!Log {
        return .{ .db = try state_runtime.init(path) };
    }

    /// open an in-memory database (for testing)
    pub fn initMemory() LogError!Log {
        return .{ .db = try state_runtime.initMemory() };
    }

    pub fn deinit(self: *Log) void {
        self.db.deinit();
    }

    // -- persistent state (survives restarts) --

    pub fn getCurrentTerm(self: *Log) Term {
        return state_runtime.getCurrentTerm(&self.db);
    }

    pub fn setCurrentTerm(self: *Log, term: Term) bool {
        state_runtime.setCurrentTerm(&self.db, term) catch |e| {
            logger.warn("raft_log: failed to set current_term to {d}: {}", .{ term, e });
            return false;
        };
        return true;
    }

    pub fn getVotedFor(self: *Log) ?NodeId {
        return state_runtime.getVotedFor(&self.db);
    }

    pub fn setVotedFor(self: *Log, id: ?NodeId) bool {
        state_runtime.setVotedFor(&self.db, id) catch |e| {
            logger.warn("raft_log: failed to set voted_for to {?d}: {}", .{ id, e });
            return false;
        };
        return true;
    }

    // -- snapshot metadata --
    //
    // after a snapshot is taken, we record what index/term it covers.
    // this lets snapshot-aware queries (lastIndex, lastTerm, termAt)
    // return correct values even when the log has been truncated.

    pub fn getSnapshotMeta(self: *Log) ?SnapshotMeta {
        return snapshot_support.getSnapshotMeta(&self.db);
    }

    pub fn setSnapshotMeta(self: *Log, meta: SnapshotMeta) bool {
        snapshot_support.setSnapshotMeta(&self.db, meta) catch |e| {
            logger.warn("raft_log: failed to set snapshot metadata: {}", .{e});
            return false;
        };
        return true;
    }

    // -- log operations --

    pub fn append(self: *Log, entry: LogEntry) LogError!void {
        return entry_runtime.append(&self.db, entry);
    }

    pub fn getEntry(self: *Log, alloc: std.mem.Allocator, index: LogIndex) LogError!?LogEntry {
        return entry_runtime.getEntry(&self.db, alloc, index);
    }

    /// returns the highest log index. if the log is empty but a snapshot
    /// exists, returns the snapshot's last_included_index.
    pub fn lastIndex(self: *Log) LogIndex {
        return snapshot_support.lastIndex(&self.db);
    }

    /// returns the term of the last log entry. if the log is empty but a
    /// snapshot exists, returns the snapshot's last_included_term.
    pub fn lastTerm(self: *Log) Term {
        return snapshot_support.lastTerm(&self.db);
    }

    /// get the term for a specific log index (needed for consistency checks).
    /// if the index matches the snapshot's last_included_index, returns the
    /// snapshot's term — this covers the case where the entry was truncated
    /// after snapshotting.
    pub fn termAt(self: *Log, index: LogIndex) Term {
        return snapshot_support.termAt(&self.db, index);
    }

    /// remove all entries from index onwards (inclusive).
    /// used when a leader's log conflicts with ours.
    pub fn truncateFrom(self: *Log, index: LogIndex) bool {
        entry_runtime.truncateFrom(&self.db, index) catch |e| {
            logger.warn("raft_log: failed to truncate from index {d}: {}", .{ index, e });
            return false;
        };
        return true;
    }

    /// remove all entries up to and including the given index.
    /// used after a snapshot is taken to reclaim space — we no longer
    /// need entries that are covered by the snapshot.
    pub fn truncateUpTo(self: *Log, index: LogIndex) bool {
        snapshot_support.truncateUpTo(&self.db, index) catch |e| {
            logger.warn("raft_log: failed to truncate up to index {d}: {}", .{ index, e });
            return false;
        };
        return true;
    }

    /// get entries in range [from, to] inclusive.
    /// caller owns the returned slice and entry data.
    pub fn getEntries(self: *Log, alloc: std.mem.Allocator, from: LogIndex, to: LogIndex) LogError![]LogEntry {
        return entry_runtime.getEntries(&self.db, alloc, from, to);
    }
};

// -- tests --

test "term persistence" {
    var log = try Log.initMemory();
    defer log.deinit();

    try std.testing.expectEqual(@as(Term, 0), log.getCurrentTerm());

    _ = log.setCurrentTerm(5);
    try std.testing.expectEqual(@as(Term, 5), log.getCurrentTerm());

    _ = log.setCurrentTerm(10);
    try std.testing.expectEqual(@as(Term, 10), log.getCurrentTerm());
}

test "voted_for persistence" {
    var log = try Log.initMemory();
    defer log.deinit();

    try std.testing.expect(log.getVotedFor() == null);

    _ = log.setVotedFor(42);
    try std.testing.expectEqual(@as(?NodeId, 42), log.getVotedFor());

    _ = log.setVotedFor(null);
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

    _ = log.truncateFrom(2);

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
    _ = log.truncateFrom(2);
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

    _ = log.setSnapshotMeta(.{
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
    _ = log.setSnapshotMeta(.{
        .last_included_index = 50,
        .last_included_term = 3,
        .data_len = 1024,
    });

    try std.testing.expectEqual(@as(LogIndex, 50), log.lastIndex());
}

test "lastTerm falls back to snapshot when log is empty" {
    var log = try Log.initMemory();
    defer log.deinit();

    _ = log.setSnapshotMeta(.{
        .last_included_index = 50,
        .last_included_term = 3,
        .data_len = 1024,
    });

    try std.testing.expectEqual(@as(Term, 3), log.lastTerm());
}

test "lastIndex prefers log entries over snapshot" {
    var log = try Log.initMemory();
    defer log.deinit();

    _ = log.setSnapshotMeta(.{
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

    _ = log.setSnapshotMeta(.{
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

    _ = log.setSnapshotMeta(.{
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

    _ = log.truncateUpTo(2);

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
    _ = log.setSnapshotMeta(.{
        .last_included_index = 2,
        .last_included_term = 1,
        .data_len = 512,
    });
    _ = log.truncateUpTo(2);

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

    _ = log.setSnapshotMeta(.{
        .last_included_index = 2,
        .last_included_term = 1,
        .data_len = 512,
    });
    _ = log.truncateUpTo(2);

    // log is empty but snapshot provides the answer
    try std.testing.expectEqual(@as(LogIndex, 2), log.lastIndex());
    try std.testing.expectEqual(@as(Term, 1), log.lastTerm());
}
