const sqlite = @import("sqlite");

const common = @import("common.zig");

const Term = common.Term;
const LogIndex = common.LogIndex;
const SnapshotMeta = common.SnapshotMeta;
const LogError = common.LogError;

pub fn getSnapshotMeta(db: *sqlite.Db) ?SnapshotMeta {
    const Row = struct {
        last_included_index: i64,
        last_included_term: i64,
        data_len: i64,
    };
    const row = (db.one(
        Row,
        "SELECT last_included_index, last_included_term, data_len FROM snapshot_meta WHERE id = 1;",
        .{},
        .{},
    ) catch return null) orelse return null;

    if (row.last_included_index == 0) return null;
    if (row.last_included_term <= 0) return null;

    return SnapshotMeta{
        .last_included_index = common.safeU64(row.last_included_index) catch return null,
        .last_included_term = common.safeU64(row.last_included_term) catch return null,
        .data_len = common.safeU64(row.data_len) catch return null,
    };
}

pub fn setSnapshotMeta(db: *sqlite.Db, meta: SnapshotMeta) LogError!void {
    db.exec(
        "UPDATE snapshot_meta SET last_included_index = ?, last_included_term = ?, data_len = ? WHERE id = 1;",
        .{},
        .{
            @as(i64, @intCast(meta.last_included_index)),
            @as(i64, @intCast(meta.last_included_term)),
            @as(i64, @intCast(meta.data_len)),
        },
    ) catch return LogError.WriteFailed;
}

pub fn lastIndex(db: *sqlite.Db) LogIndex {
    const Row = struct { max_index: ?i64 };
    const row = (db.one(
        Row,
        "SELECT MAX(log_index) AS max_index FROM raft_log;",
        .{},
        .{},
    ) catch return snapshotLastIndex(db)) orelse return snapshotLastIndex(db);

    if (row.max_index) |m| {
        return common.safeU64(m) catch snapshotLastIndex(db);
    }
    return snapshotLastIndex(db);
}

pub fn lastTerm(db: *sqlite.Db) Term {
    const last = lastLogIndex(db);
    if (last > 0) {
        const Row = struct { term: i64 };
        const row = (db.one(
            Row,
            "SELECT term FROM raft_log WHERE log_index = ?;",
            .{},
            .{@as(i64, @intCast(last))},
        ) catch return 0) orelse return 0;
        return common.safeU64(row.term) catch 0;
    }

    if (getSnapshotMeta(db)) |meta| {
        return meta.last_included_term;
    }
    return 0;
}

pub fn termAt(db: *sqlite.Db, index: LogIndex) Term {
    if (index == 0) return 0;

    const Row = struct { term: i64 };
    const row = db.one(
        Row,
        "SELECT term FROM raft_log WHERE log_index = ?;",
        .{},
        .{@as(i64, @intCast(index))},
    ) catch return 0;

    if (row) |r| {
        return common.safeU64(r.term) catch 0;
    }

    if (getSnapshotMeta(db)) |meta| {
        if (index == meta.last_included_index) {
            return meta.last_included_term;
        }
    }

    return 0;
}

pub fn truncateUpTo(db: *sqlite.Db, index: LogIndex) LogError!void {
    db.exec(
        "DELETE FROM raft_log WHERE log_index <= ?;",
        .{},
        .{@as(i64, @intCast(index))},
    ) catch return LogError.WriteFailed;
}

fn lastLogIndex(db: *sqlite.Db) LogIndex {
    const Row = struct { max_index: ?i64 };
    const row = (db.one(
        Row,
        "SELECT MAX(log_index) AS max_index FROM raft_log;",
        .{},
        .{},
    ) catch return 0) orelse return 0;
    return if (row.max_index) |m| common.safeU64(m) catch 0 else 0;
}

fn snapshotLastIndex(db: *sqlite.Db) LogIndex {
    if (getSnapshotMeta(db)) |meta| {
        return meta.last_included_index;
    }
    return 0;
}
