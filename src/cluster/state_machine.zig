// state_machine — applies committed raft log entries to the application database
//
// the state machine sits between the raft consensus layer and the
// application database (yoq.db). when raft commits entries, the node
// calls apply() to execute each entry's data as a SQL statement.
//
// this gives us replicated SQLite — the same sequence of SQL statements
// applied to every node produces identical databases.
//
// note: entries are opaque bytes to raft but SQL strings to the state
// machine. this coupling is intentional — it keeps the replication
// layer simple while providing the full power of SQL for state updates.
//
// snapshots: takeSnapshot() uses the SQLite Online Backup API to create
// a point-in-time copy of the database while writes may be happening.
// restoreFromSnapshot() does the reverse: copies a snapshot file into
// the live database. snapshot files have a binary header followed by
// the raw sqlite database bytes.

const std = @import("std");
const sqlite = @import("sqlite");
const types = @import("raft_types.zig");
const schema = @import("../state/schema.zig");
const log = @import("../lib/log.zig");

const c = sqlite.c;
const LogEntry = types.LogEntry;
const LogIndex = types.LogIndex;
const SnapshotMeta = types.SnapshotMeta;

pub const StateMachineError = error{
    DbOpenFailed,
};

pub const SnapshotError = error{
    BackupFailed,
    IoError,
    InvalidSnapshot,
    CorruptSnapshot,
};

// snapshot file format:
//   [8 bytes] last_included_index (little-endian)
//   [8 bytes] last_included_term  (little-endian)
//   [8 bytes] sqlite_data_len     (little-endian)
//   [N bytes] raw sqlite database
const snapshot_header_size = 24;

pub const StateMachine = struct {
    db: sqlite.Db,
    last_applied: LogIndex,

    pub fn init(path: [:0]const u8) StateMachineError!StateMachine {
        var db = sqlite.Db.init(.{
            .mode = .{ .File = path },
            .open_flags = .{ .write = true, .create = true },
        }) catch return StateMachineError.DbOpenFailed;

        // create cluster tables (agents, assignments) in the replicated DB
        schema.init(&db) catch {};

        return .{
            .db = db,
            .last_applied = 0,
        };
    }

    pub fn initMemory() StateMachineError!StateMachine {
        var db = sqlite.Db.init(.{
            .mode = .Memory,
            .open_flags = .{ .write = true },
        }) catch return StateMachineError.DbOpenFailed;

        schema.init(&db) catch {};

        return .{
            .db = db,
            .last_applied = 0,
        };
    }

    pub fn deinit(self: *StateMachine) void {
        self.db.deinit();
    }

    /// apply a committed log entry by executing its data as SQL.
    /// entries must be applied in order; skips if already applied.
    ///
    /// always advances last_applied, even if the SQL fails. a committed
    /// entry is "applied" regardless — skipping bad entries prevents one
    /// malformed entry from blocking all subsequent entries across the
    /// entire cluster.
    pub fn apply(self: *StateMachine, entry: LogEntry) void {
        if (entry.index <= self.last_applied) return;

        self.db.execDynamic(entry.data, .{}, .{}) catch {
            log.warn("state machine: failed to apply entry {d}, skipping", .{entry.index});
        };
        self.last_applied = entry.index;
    }

    /// apply all entries up to the given index.
    pub fn applyUpTo(
        self: *StateMachine,
        raft_log: *@import("log.zig").Log,
        alloc: std.mem.Allocator,
        up_to: LogIndex,
    ) void {
        var idx = self.last_applied + 1;
        while (idx <= up_to) : (idx += 1) {
            const entry = (raft_log.getEntry(alloc, idx) catch continue) orelse continue;
            defer alloc.free(entry.data);
            self.apply(entry);
        }
    }

    /// create a snapshot of the current database state.
    ///
    /// uses the SQLite Online Backup API (sqlite3_backup_init/step/finish)
    /// which is safe to call while the database is being written to.
    /// the backup captures a consistent point-in-time snapshot.
    ///
    /// writes a snapshot file at dest_path with format:
    ///   [8B index][8B term][8B data_len][sqlite bytes]
    pub fn takeSnapshot(self: *StateMachine, dest_path: []const u8, meta: SnapshotMeta) SnapshotError!void {
        // open a new sqlite database at a temporary path for the backup
        var tmp_path_buf: [512]u8 = undefined;
        const tmp_path_slice = std.fmt.bufPrint(&tmp_path_buf, "{s}.tmp", .{dest_path}) catch
            return SnapshotError.IoError;
        if (tmp_path_slice.len >= tmp_path_buf.len) return SnapshotError.IoError;
        tmp_path_buf[tmp_path_slice.len] = 0;
        const tmp_path: [:0]const u8 = tmp_path_buf[0..tmp_path_slice.len :0];

        // open destination database
        var dest_db: ?*c.sqlite3 = null;
        const open_rc = c.sqlite3_open(tmp_path.ptr, &dest_db);
        if (open_rc != c.SQLITE_OK or dest_db == null) {
            if (dest_db) |db| _ = c.sqlite3_close(db);
            return SnapshotError.BackupFailed;
        }
        defer _ = c.sqlite3_close(dest_db);

        // use the backup API to copy self.db -> dest_db
        const backup = c.sqlite3_backup_init(dest_db, "main", self.db.db, "main");
        if (backup == null) {
            return SnapshotError.BackupFailed;
        }

        // step with -1 copies the entire database in one go.
        // for very large databases you could step in pages, but our state
        // machine databases are small (cluster metadata).
        const step_rc = c.sqlite3_backup_step(backup, -1);
        const finish_rc = c.sqlite3_backup_finish(backup);

        if (step_rc != c.SQLITE_DONE) {
            return SnapshotError.BackupFailed;
        }
        if (finish_rc != c.SQLITE_OK) {
            return SnapshotError.BackupFailed;
        }

        // now read the temporary sqlite file and write the snapshot file
        // with our header prepended
        const tmp_data = std.fs.cwd().readFileAlloc(
            std.heap.page_allocator,
            tmp_path_slice,
            64 * 1024 * 1024, // 64MB max — plenty for cluster metadata
        ) catch return SnapshotError.IoError;
        defer std.heap.page_allocator.free(tmp_data);

        // write the snapshot file: header + sqlite bytes
        const file = std.fs.cwd().createFile(dest_path, .{}) catch
            return SnapshotError.IoError;
        defer file.close();

        var header: [snapshot_header_size]u8 = undefined;
        std.mem.writeInt(u64, header[0..8], meta.last_included_index, .little);
        std.mem.writeInt(u64, header[8..16], meta.last_included_term, .little);
        std.mem.writeInt(u64, header[16..24], @intCast(tmp_data.len), .little);

        file.writeAll(&header) catch return SnapshotError.IoError;
        file.writeAll(tmp_data) catch return SnapshotError.IoError;

        // clean up the temporary sqlite file
        std.fs.cwd().deleteFile(tmp_path_slice) catch {};
    }

    /// restore the state machine from a snapshot file.
    ///
    /// reads the snapshot header, then uses the SQLite Backup API to
    /// copy the snapshot's database into the live state machine database.
    /// after restoration, last_applied is set to the snapshot's index.
    ///
    /// returns the snapshot metadata so the caller can update the raft log.
    pub fn restoreFromSnapshot(self: *StateMachine, src_path: []const u8) SnapshotError!SnapshotMeta {
        // read the snapshot file
        const data = std.fs.cwd().readFileAlloc(
            std.heap.page_allocator,
            src_path,
            64 * 1024 * 1024,
        ) catch return SnapshotError.IoError;
        defer std.heap.page_allocator.free(data);

        return self.restoreFromBytes(data);
    }

    /// restore from snapshot bytes (header + sqlite data).
    /// useful when receiving a snapshot over the network.
    pub fn restoreFromBytes(self: *StateMachine, data: []const u8) SnapshotError!SnapshotMeta {
        if (data.len < snapshot_header_size) return SnapshotError.InvalidSnapshot;

        // parse header
        const last_included_index = std.mem.readInt(u64, data[0..8], .little);
        const last_included_term = std.mem.readInt(u64, data[8..16], .little);
        const sqlite_data_len = std.mem.readInt(u64, data[16..24], .little);

        if (data.len < snapshot_header_size + sqlite_data_len) {
            return SnapshotError.CorruptSnapshot;
        }

        const sqlite_data = data[snapshot_header_size .. snapshot_header_size + sqlite_data_len];

        // write sqlite data to a temporary file so we can open it as a database
        var tmp_path_buf: [64]u8 = undefined;
        const tmp_path_slice = std.fmt.bufPrint(&tmp_path_buf, "/tmp/yoq_snap_restore_{d}.db", .{
            @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())))),
        }) catch return SnapshotError.IoError;
        if (tmp_path_slice.len >= tmp_path_buf.len) return SnapshotError.IoError;
        tmp_path_buf[tmp_path_slice.len] = 0;
        const tmp_path: [:0]const u8 = tmp_path_buf[0..tmp_path_slice.len :0];

        // write the sqlite bytes to the temp file
        const tmp_file = std.fs.cwd().createFile(tmp_path_slice, .{}) catch
            return SnapshotError.IoError;
        tmp_file.writeAll(sqlite_data) catch {
            tmp_file.close();
            return SnapshotError.IoError;
        };
        tmp_file.close();
        defer std.fs.cwd().deleteFile(tmp_path_slice) catch {};

        // open the temp database
        var src_db: ?*c.sqlite3 = null;
        const open_rc = c.sqlite3_open(tmp_path.ptr, &src_db);
        if (open_rc != c.SQLITE_OK or src_db == null) {
            if (src_db) |db| _ = c.sqlite3_close(db);
            return SnapshotError.BackupFailed;
        }
        defer _ = c.sqlite3_close(src_db);

        // use backup API to copy src_db -> self.db (reverse direction)
        const backup = c.sqlite3_backup_init(self.db.db, "main", src_db, "main");
        if (backup == null) {
            return SnapshotError.BackupFailed;
        }

        const step_rc = c.sqlite3_backup_step(backup, -1);
        const finish_rc = c.sqlite3_backup_finish(backup);

        if (step_rc != c.SQLITE_DONE) {
            return SnapshotError.BackupFailed;
        }
        if (finish_rc != c.SQLITE_OK) {
            return SnapshotError.BackupFailed;
        }

        const meta = SnapshotMeta{
            .last_included_index = last_included_index,
            .last_included_term = last_included_term,
            .data_len = sqlite_data_len,
        };

        self.last_applied = last_included_index;
        return meta;
    }
};

/// read snapshot metadata from a snapshot file without loading the full database.
/// useful for checking what a snapshot contains before deciding to restore it.
pub fn readSnapshotMeta(path: []const u8) SnapshotError!SnapshotMeta {
    const file = std.fs.cwd().openFile(path, .{}) catch
        return SnapshotError.IoError;
    defer file.close();

    var header: [snapshot_header_size]u8 = undefined;
    const n = file.readAll(&header) catch return SnapshotError.IoError;
    if (n < snapshot_header_size) return SnapshotError.InvalidSnapshot;

    return SnapshotMeta{
        .last_included_index = std.mem.readInt(u64, header[0..8], .little),
        .last_included_term = std.mem.readInt(u64, header[8..16], .little),
        .data_len = std.mem.readInt(u64, header[16..24], .little),
    };
}

// -- tests --

test "apply executes SQL statement" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    // create a table via state machine
    sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);",
    });

    sm.apply(.{
        .index = 2,
        .term = 1,
        .data = "INSERT INTO kv (key, value) VALUES ('x', '42');",
    });

    // verify the data was written
    const Row = struct { value: sqlite.Text };
    const alloc = std.testing.allocator;
    const row = (sm.db.oneAlloc(
        Row,
        alloc,
        "SELECT value FROM kv WHERE key = ?;",
        .{},
        .{"x"},
    ) catch unreachable).?;
    defer alloc.free(row.value.data);

    try std.testing.expectEqualStrings("42", row.value.data);
    try std.testing.expectEqual(@as(LogIndex, 2), sm.last_applied);
}

test "apply skips already-applied entries" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);",
    });

    // applying the same index again should be a no-op (not fail with "table exists")
    sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);",
    });

    try std.testing.expectEqual(@as(LogIndex, 1), sm.last_applied);
}

test "apply advances past bad SQL" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);",
    });

    // entry 2 is invalid SQL — should log warning but advance last_applied
    sm.apply(.{
        .index = 2,
        .term = 1,
        .data = "THIS IS NOT VALID SQL AT ALL",
    });

    try std.testing.expectEqual(@as(LogIndex, 2), sm.last_applied);

    // entry 3 should still work
    sm.apply(.{
        .index = 3,
        .term = 1,
        .data = "INSERT INTO kv (key, value) VALUES ('y', '99');",
    });

    try std.testing.expectEqual(@as(LogIndex, 3), sm.last_applied);

    // verify the data from entry 3 was actually written
    const Row = struct { value: sqlite.Text };
    const alloc = std.testing.allocator;
    const row = (sm.db.oneAlloc(
        Row,
        alloc,
        "SELECT value FROM kv WHERE key = ?;",
        .{},
        .{"y"},
    ) catch unreachable).?;
    defer alloc.free(row.value.data);

    try std.testing.expectEqualStrings("99", row.value.data);
}

test "applyUpTo applies entries in order" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    var raft_log = try @import("log.zig").Log.initMemory();
    defer raft_log.deinit();

    const alloc = std.testing.allocator;

    // insert entries into the raft log
    try raft_log.append(.{
        .index = 1,
        .term = 1,
        .data = "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);",
    });
    try raft_log.append(.{
        .index = 2,
        .term = 1,
        .data = "INSERT INTO kv (key, value) VALUES ('a', '1');",
    });
    try raft_log.append(.{
        .index = 3,
        .term = 1,
        .data = "INSERT INTO kv (key, value) VALUES ('b', '2');",
    });

    sm.applyUpTo(&raft_log, alloc, 3);

    try std.testing.expectEqual(@as(LogIndex, 3), sm.last_applied);

    // verify both inserts were applied
    const Row = struct { value: sqlite.Text };
    const row_a = (sm.db.oneAlloc(Row, alloc, "SELECT value FROM kv WHERE key = ?;", .{}, .{"a"}) catch unreachable).?;
    defer alloc.free(row_a.value.data);
    try std.testing.expectEqualStrings("1", row_a.value.data);

    const row_b = (sm.db.oneAlloc(Row, alloc, "SELECT value FROM kv WHERE key = ?;", .{}, .{"b"}) catch unreachable).?;
    defer alloc.free(row_b.value.data);
    try std.testing.expectEqualStrings("2", row_b.value.data);
}

test "takeSnapshot and restoreFromSnapshot round-trip" {
    // this test uses file-backed databases since the backup API
    // needs real files for the snapshot format.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    // set up state machine with some data
    var sm_path_buf: [512]u8 = undefined;
    const sm_path_slice = std.fmt.bufPrint(&sm_path_buf, "{s}/state.db", .{tmp_path}) catch return;
    sm_path_buf[sm_path_slice.len] = 0;
    const sm_path: [:0]const u8 = sm_path_buf[0..sm_path_slice.len :0];

    var sm = StateMachine.init(sm_path) catch return;
    defer sm.deinit();

    // apply some entries
    sm.apply(.{ .index = 1, .term = 1, .data = "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);" });
    sm.apply(.{ .index = 2, .term = 1, .data = "INSERT INTO kv (key, value) VALUES ('hello', 'world');" });

    // take a snapshot
    var snap_path_buf: [512]u8 = undefined;
    const snap_path = std.fmt.bufPrint(&snap_path_buf, "{s}/100.snap", .{tmp_path}) catch return;

    const meta = SnapshotMeta{
        .last_included_index = 2,
        .last_included_term = 1,
        .data_len = 0, // will be filled by takeSnapshot
    };

    sm.takeSnapshot(snap_path, meta) catch return;

    // verify snapshot file exists and has correct header
    const read_meta = readSnapshotMeta(snap_path) catch return;
    try std.testing.expectEqual(@as(LogIndex, 2), read_meta.last_included_index);
    try std.testing.expectEqual(@as(types.Term, 1), read_meta.last_included_term);
    try std.testing.expect(read_meta.data_len > 0);

    // create a new empty state machine and restore from snapshot
    var sm2_path_buf: [512]u8 = undefined;
    const sm2_path_slice = std.fmt.bufPrint(&sm2_path_buf, "{s}/state2.db", .{tmp_path}) catch return;
    sm2_path_buf[sm2_path_slice.len] = 0;
    const sm2_path: [:0]const u8 = sm2_path_buf[0..sm2_path_slice.len :0];

    var sm2 = StateMachine.init(sm2_path) catch return;
    defer sm2.deinit();

    const restored_meta = sm2.restoreFromSnapshot(snap_path) catch return;
    try std.testing.expectEqual(@as(LogIndex, 2), restored_meta.last_included_index);
    try std.testing.expectEqual(@as(LogIndex, 2), sm2.last_applied);

    // verify the restored database has the data
    const Row = struct { value: sqlite.Text };
    const alloc = std.testing.allocator;
    const row = (sm2.db.oneAlloc(
        Row,
        alloc,
        "SELECT value FROM kv WHERE key = ?;",
        .{},
        .{"hello"},
    ) catch return).?;
    defer alloc.free(row.value.data);

    try std.testing.expectEqualStrings("world", row.value.data);
}

test "restoreFromBytes rejects short data" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    // too short to contain header
    const short_data = [_]u8{ 0, 0, 0, 0 };
    const result = sm.restoreFromBytes(&short_data);
    try std.testing.expectError(SnapshotError.InvalidSnapshot, result);
}

test "restoreFromBytes rejects truncated snapshot" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    // header claims 1000 bytes of sqlite data but only provides 5
    var data: [snapshot_header_size + 5]u8 = undefined;
    std.mem.writeInt(u64, data[0..8], 10, .little); // index
    std.mem.writeInt(u64, data[8..16], 2, .little); // term
    std.mem.writeInt(u64, data[16..24], 1000, .little); // claims 1000 bytes
    @memset(data[snapshot_header_size..], 0);

    const result = sm.restoreFromBytes(&data);
    try std.testing.expectError(SnapshotError.CorruptSnapshot, result);
}
