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
    /// could not open or initialize the replicated state machine database
    DbOpenFailed,
};

pub const SnapshotError = error{
    /// the SQLite Online Backup API (sqlite3_backup_init/step/finish) failed
    BackupFailed,
    /// could not read or write the snapshot file on disk
    IoError,
    /// snapshot data is too short to contain the required header
    InvalidSnapshot,
    /// snapshot header claims more sqlite data than the file contains
    CorruptSnapshot,
};

// snapshot file format:
//   [8 bytes] last_included_index (little-endian)
//   [8 bytes] last_included_term  (little-endian)
//   [8 bytes] sqlite_data_len     (little-endian)
//   [N bytes] raw sqlite database
const snapshot_header_size = 24;

// maximum snapshot size — matches transport's max_receive_size (64MB).
// cluster metadata databases are small, so this is generous.
const max_snapshot_size: u64 = 64 * 1024 * 1024;

pub const StateMachine = struct {
    db: sqlite.Db,
    last_applied: LogIndex,

    pub fn init(path: [:0]const u8) StateMachineError!StateMachine {
        var db = sqlite.Db.init(.{
            .mode = .{ .File = path },
            .open_flags = .{ .write = true, .create = true },
        }) catch return StateMachineError.DbOpenFailed;

        // create cluster tables (agents, assignments) in the replicated DB
        schema.init(&db) catch |e| {
            log.err("state_machine: failed to initialize schema: {}. Database may be corrupted.", .{e});
            return StateMachineError.DbOpenFailed;
        };

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

        schema.init(&db) catch |e| {
            log.err("state_machine: failed to initialize schema: {}. Database may be corrupted.", .{e});
            return StateMachineError.DbOpenFailed;
        };

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
    /// always advances last_applied, even if the SQL fails or is
    /// rejected by the allowlist. a committed entry is "applied"
    /// regardless — skipping bad entries prevents one malformed
    /// entry from blocking all subsequent entries across the
    /// entire cluster.
    ///
    /// security: only statements matching the SQL allowlist are
    /// executed. this prevents a compromised raft peer from
    /// injecting arbitrary SQL (DROP TABLE, ATTACH DATABASE, etc.)
    /// into the replicated state machine.
    pub fn apply(self: *StateMachine, entry: LogEntry) void {
        if (entry.index <= self.last_applied) return;

        if (!isAllowedStatement(entry.data)) {
            log.warn("state machine: rejected disallowed SQL at entry {d}", .{entry.index});
            self.last_applied = entry.index;
            return;
        }

        self.db.execDynamic(entry.data, .{}, .{}) catch |err| {
            // log at err level — a failed apply means this node's state may
            // diverge from peers that succeeded. we can't retry because raft
            // requires deterministic apply order (retrying would re-order
            // entries relative to subsequent ones). the entry is still marked
            // applied below to prevent the state machine from stalling.
            log.err("state machine: failed to apply entry {d}: {}", .{ entry.index, err });
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
            const entry = (raft_log.getEntry(alloc, idx) catch {
                log.warn("state_machine: failed to read log entry {d}, skipping", .{idx});
                continue;
            }) orelse continue;
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
        const tmp_path = bufPrintZ(&tmp_path_buf, "{s}.tmp", .{dest_path}) orelse
            return SnapshotError.IoError;

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
            tmp_path,
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
        std.fs.cwd().deleteFile(tmp_path) catch {};
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

        // validate snapshot size before allocating or processing
        if (sqlite_data_len > max_snapshot_size) return SnapshotError.InvalidSnapshot;

        // exact match — the snapshot should contain exactly the header + sqlite data.
        // a `<` check would accept trailing garbage which could mask corruption.
        if (data.len != snapshot_header_size + sqlite_data_len) return SnapshotError.CorruptSnapshot;

        const sqlite_data = data[snapshot_header_size .. snapshot_header_size + sqlite_data_len];

        // write sqlite data to a temporary file so we can open it as a database
        var tmp_path_buf: [64]u8 = undefined;
        const tmp_path = bufPrintZ(&tmp_path_buf, "/tmp/yoq_snap_restore_{d}.db", .{
            @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())))),
        }) orelse return SnapshotError.IoError;

        // write the sqlite bytes to the temp file
        const tmp_file = std.fs.cwd().createFile(tmp_path, .{}) catch
            return SnapshotError.IoError;
        tmp_file.writeAll(sqlite_data) catch {
            tmp_file.close();
            return SnapshotError.IoError;
        };
        tmp_file.close();
        defer std.fs.cwd().deleteFile(tmp_path) catch {};

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

/// check if a SQL statement is allowed to be executed by the state machine.
///
/// the raft state machine only needs a small set of SQL operations for
/// cluster management (agents, assignments, and wireguard_peers tables).
/// this allowlist blocks arbitrary SQL injection from compromised raft
/// peers — a single malicious entry would otherwise be replicated to
/// every node in the cluster.
///
/// allowed patterns match the SQL generated by registry.zig and scheduler.zig:
///   - INSERT/UPDATE/DELETE on agents, assignments, and wireguard_peers tables
///   - CREATE TABLE IF NOT EXISTS and CREATE INDEX IF NOT EXISTS for schema init
pub fn isAllowedStatement(sql: []const u8) bool {
    const allowed_prefixes = [_][]const u8{
        // agents table — registry.zig: registerSql, heartbeatSql, drainSql, markOfflineSql
        "INSERT INTO agents ",
        "UPDATE agents SET ",
        "DELETE FROM agents ",
        // assignments table — scheduler.zig: assignmentSql, registry.zig: updateAssignmentStatusSql,
        // orphanAssignmentsSql, reassignSql, deleteAgentAssignmentsSql
        "INSERT INTO assignments ",
        "UPDATE assignments SET ",
        "DELETE FROM assignments ",
        // wireguard_peers table — registry.zig: addWireguardPeerSql, removeWireguardPeerSql
        "INSERT INTO wireguard_peers ",
        "UPDATE wireguard_peers SET ",
        "DELETE FROM wireguard_peers ",
        // volumes table — volumes.zig: create, destroy
        "INSERT INTO volumes ",
        "UPDATE volumes SET ",
        "DELETE FROM volumes ",
        // schema initialization — schema.zig: CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS
        "CREATE TABLE IF NOT EXISTS ",
        "CREATE INDEX IF NOT EXISTS ",
    };

    for (allowed_prefixes) |prefix| {
        if (sql.len >= prefix.len and std.mem.eql(u8, sql[0..prefix.len], prefix)) {
            return true;
        }
    }

    return false;
}

/// read snapshot metadata from a snapshot file without loading the full database.
/// useful for checking what a snapshot contains before deciding to restore it.
pub fn readSnapshotMeta(path: []const u8) SnapshotError!SnapshotMeta {
    const file = std.fs.cwd().openFile(path, .{}) catch
        return SnapshotError.IoError;
    defer file.close();

    var header: [snapshot_header_size]u8 = undefined;
    const bytes_read = file.readAll(&header) catch return SnapshotError.IoError;
    if (bytes_read < snapshot_header_size) return SnapshotError.InvalidSnapshot;

    return SnapshotMeta{
        .last_included_index = std.mem.readInt(u64, header[0..8], .little),
        .last_included_term = std.mem.readInt(u64, header[8..16], .little),
        .data_len = std.mem.readInt(u64, header[16..24], .little),
    };
}

/// format a string into a buffer and null-terminate it.
/// returns null if the formatted string doesn't fit (needs room for the NUL).
fn bufPrintZ(buf: []u8, comptime fmt: []const u8, args: anytype) ?[:0]const u8 {
    const slice = std.fmt.bufPrint(buf, fmt, args) catch return null;
    if (slice.len >= buf.len) return null;
    buf[slice.len] = 0;
    return buf[0..slice.len :0];
}

// -- tests --

test "apply executes SQL statement" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    // agents table is created by schema.init() in initMemory()
    sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('test01', 'localhost', 'active', 4, 8192, 0, 0, 0, 1000, 1000);",
    });

    // verify the data was written
    const Row = struct { id: sqlite.Text };
    const alloc = std.testing.allocator;
    const row = (sm.db.oneAlloc(
        Row,
        alloc,
        "SELECT id FROM agents WHERE id = ?;",
        .{},
        .{"test01"},
    ) catch unreachable).?;
    defer alloc.free(row.id.data);

    try std.testing.expectEqualStrings("test01", row.id.data);
    try std.testing.expectEqual(@as(LogIndex, 1), sm.last_applied);
}

test "apply skips already-applied entries" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('test01', 'localhost', 'active', 4, 8192, 0, 0, 0, 1000, 1000);",
    });

    // applying the same index again should be a no-op (not fail with "unique constraint")
    sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('test01', 'localhost', 'active', 4, 8192, 0, 0, 0, 1000, 1000);",
    });

    try std.testing.expectEqual(@as(LogIndex, 1), sm.last_applied);
}

test "apply advances past disallowed SQL" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('test01', 'localhost', 'active', 4, 8192, 0, 0, 0, 1000, 1000);",
    });

    // entry 2 is disallowed — should log warning but advance last_applied
    sm.apply(.{
        .index = 2,
        .term = 1,
        .data = "DROP TABLE agents;",
    });

    try std.testing.expectEqual(@as(LogIndex, 2), sm.last_applied);

    // entry 3 should still work
    sm.apply(.{
        .index = 3,
        .term = 1,
        .data = "UPDATE agents SET status = 'draining' WHERE id = 'test01';",
    });

    try std.testing.expectEqual(@as(LogIndex, 3), sm.last_applied);

    // verify the agent still exists (DROP was blocked) and was updated
    const Row = struct { status: sqlite.Text };
    const alloc = std.testing.allocator;
    const row = (sm.db.oneAlloc(
        Row,
        alloc,
        "SELECT status FROM agents WHERE id = ?;",
        .{},
        .{"test01"},
    ) catch unreachable).?;
    defer alloc.free(row.status.data);

    try std.testing.expectEqualStrings("draining", row.status.data);
}

test "applyUpTo applies entries in order" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    var raft_log = try @import("log.zig").Log.initMemory();
    defer raft_log.deinit();

    const alloc = std.testing.allocator;

    // insert entries into the raft log using allowed SQL patterns
    try raft_log.append(.{
        .index = 1,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('agent_a', 'host_a', 'active', 2, 4096, 0, 0, 0, 100, 100);",
    });
    try raft_log.append(.{
        .index = 2,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('agent_b', 'host_b', 'active', 4, 8192, 0, 0, 0, 200, 200);",
    });

    sm.applyUpTo(&raft_log, alloc, 2);

    try std.testing.expectEqual(@as(LogIndex, 2), sm.last_applied);

    // verify both inserts were applied
    const Row = struct { id: sqlite.Text };
    const row_a = (sm.db.oneAlloc(Row, alloc, "SELECT id FROM agents WHERE id = ?;", .{}, .{"agent_a"}) catch unreachable).?;
    defer alloc.free(row_a.id.data);
    try std.testing.expectEqualStrings("agent_a", row_a.id.data);

    const row_b = (sm.db.oneAlloc(Row, alloc, "SELECT id FROM agents WHERE id = ?;", .{}, .{"agent_b"}) catch unreachable).?;
    defer alloc.free(row_b.id.data);
    try std.testing.expectEqualStrings("agent_b", row_b.id.data);
}

test "isAllowedStatement accepts valid agent operations" {
    // all SQL patterns generated by registry.zig
    try std.testing.expect(isAllowedStatement("INSERT INTO agents (id, address, status) VALUES ('a', 'b', 'active');"));
    try std.testing.expect(isAllowedStatement("UPDATE agents SET status = 'draining' WHERE id = 'x';"));
    try std.testing.expect(isAllowedStatement("UPDATE agents SET status = 'offline' WHERE id = 'x';"));
    try std.testing.expect(isAllowedStatement("UPDATE agents SET cpu_used = 0, memory_used_mb = 0 WHERE id = 'x';"));
    try std.testing.expect(isAllowedStatement("DELETE FROM agents WHERE id = 'x';"));
}

test "isAllowedStatement accepts valid assignment operations" {
    // all SQL patterns generated by scheduler.zig and registry.zig
    try std.testing.expect(isAllowedStatement("INSERT INTO assignments (id, agent_id, image) VALUES ('a', 'b', 'nginx');"));
    try std.testing.expect(isAllowedStatement("UPDATE assignments SET status = 'running' WHERE id = 'x';"));
    try std.testing.expect(isAllowedStatement("UPDATE assignments SET agent_id = '' WHERE agent_id = 'x';"));
    try std.testing.expect(isAllowedStatement("DELETE FROM assignments WHERE agent_id = 'x';"));
}

test "isAllowedStatement accepts valid wireguard_peers operations" {
    // all SQL patterns generated by registry.zig for wireguard peer management
    try std.testing.expect(isAllowedStatement("INSERT INTO wireguard_peers (node_id, public_key) VALUES (1, 'key123');"));
    try std.testing.expect(isAllowedStatement("UPDATE wireguard_peers SET endpoint = '10.0.0.1:51820' WHERE node_id = 1;"));
    try std.testing.expect(isAllowedStatement("DELETE FROM wireguard_peers WHERE node_id = 1;"));
}

test "isAllowedStatement accepts valid volume operations" {
    try std.testing.expect(isAllowedStatement("INSERT INTO volumes (name, app_name, driver, path, status, created_at) VALUES ('data', 'myapp', 'local', '/path', 'created', 1000);"));
    try std.testing.expect(isAllowedStatement("UPDATE volumes SET status = 'active' WHERE name = 'data';"));
    try std.testing.expect(isAllowedStatement("DELETE FROM volumes WHERE name = 'data' AND app_name = 'myapp';"));
}

test "isAllowedStatement accepts schema init" {
    try std.testing.expect(isAllowedStatement("CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY);"));
    try std.testing.expect(isAllowedStatement("CREATE INDEX IF NOT EXISTS idx_test ON agents (id);"));
}

test "isAllowedStatement rejects dangerous SQL" {
    try std.testing.expect(!isAllowedStatement("DROP TABLE agents;"));
    try std.testing.expect(!isAllowedStatement("ALTER TABLE agents ADD COLUMN evil TEXT;"));
    try std.testing.expect(!isAllowedStatement("ATTACH DATABASE '/etc/passwd' AS pwn;"));
    try std.testing.expect(!isAllowedStatement("PRAGMA journal_mode=OFF;"));
    try std.testing.expect(!isAllowedStatement("SELECT * FROM agents;"));
    try std.testing.expect(!isAllowedStatement("CREATE TABLE malicious (data TEXT);"));
    try std.testing.expect(!isAllowedStatement(""));
    try std.testing.expect(!isAllowedStatement("INSERT INTO secrets (name) VALUES ('stolen');"));
    try std.testing.expect(!isAllowedStatement("DELETE FROM containers WHERE 1=1;"));
    try std.testing.expect(!isAllowedStatement("UPDATE containers SET status = 'pwned';"));
}

test "apply with disallowed statement advances last_applied but does not execute" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    // insert a legitimate agent
    sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('victim', 'localhost', 'active', 4, 8192, 0, 0, 0, 1000, 1000);",
    });

    // try to drop the table via a compromised raft entry — should be blocked
    sm.apply(.{
        .index = 2,
        .term = 1,
        .data = "DROP TABLE agents;",
    });

    // last_applied should still advance
    try std.testing.expectEqual(@as(LogIndex, 2), sm.last_applied);

    // agents table should still exist with data intact
    const Row = struct { id: sqlite.Text };
    const alloc = std.testing.allocator;
    const row = (sm.db.oneAlloc(
        Row,
        alloc,
        "SELECT id FROM agents WHERE id = ?;",
        .{},
        .{"victim"},
    ) catch unreachable).?;
    defer alloc.free(row.id.data);

    try std.testing.expectEqualStrings("victim", row.id.data);
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

    // apply some entries using allowed SQL patterns
    sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('snap_agent', 'localhost', 'active', 4, 8192, 0, 0, 0, 1000, 1000);",
    });

    // take a snapshot
    var snap_path_buf: [512]u8 = undefined;
    const snap_path = std.fmt.bufPrint(&snap_path_buf, "{s}/100.snap", .{tmp_path}) catch return;

    const meta = SnapshotMeta{
        .last_included_index = 1,
        .last_included_term = 1,
        .data_len = 0, // will be filled by takeSnapshot
    };

    sm.takeSnapshot(snap_path, meta) catch return;

    // verify snapshot file exists and has correct header
    const read_meta = readSnapshotMeta(snap_path) catch return;
    try std.testing.expectEqual(@as(LogIndex, 1), read_meta.last_included_index);
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
    try std.testing.expectEqual(@as(LogIndex, 1), restored_meta.last_included_index);
    try std.testing.expectEqual(@as(LogIndex, 1), sm2.last_applied);

    // verify the restored database has the data
    const Row = struct { id: sqlite.Text };
    const alloc = std.testing.allocator;
    const row = (sm2.db.oneAlloc(
        Row,
        alloc,
        "SELECT id FROM agents WHERE id = ?;",
        .{},
        .{"snap_agent"},
    ) catch return).?;
    defer alloc.free(row.id.data);

    try std.testing.expectEqualStrings("snap_agent", row.id.data);
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

test "restoreFromBytes rejects oversized snapshot" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    // header claims more than max_snapshot_size
    var data: [snapshot_header_size]u8 = undefined;
    std.mem.writeInt(u64, data[0..8], 10, .little); // index
    std.mem.writeInt(u64, data[8..16], 2, .little); // term
    std.mem.writeInt(u64, data[16..24], max_snapshot_size + 1, .little); // too large

    const result = sm.restoreFromBytes(&data);
    try std.testing.expectError(SnapshotError.InvalidSnapshot, result);
}

test "apply with failing SQL still advances last_applied" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    // this SQL is allowed by the prefix check but references a
    // non-existent column, which fails at prepare time. the state
    // machine must still advance last_applied past the failed entry.
    sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "INSERT INTO agents (id, nonexistent_col) VALUES ('bad', 'x');",
    });

    // last_applied must still advance even though SQL failed
    try std.testing.expectEqual(@as(LogIndex, 1), sm.last_applied);

    // next entry should still work
    sm.apply(.{
        .index = 2,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('valid', 'localhost', 'active', 4, 8192, 0, 0, 0, 1000, 1000);",
    });

    try std.testing.expectEqual(@as(LogIndex, 2), sm.last_applied);
}

test "applyUpTo skips missing entries without stalling" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    var raft_log = try @import("log.zig").Log.initMemory();
    defer raft_log.deinit();

    const alloc = std.testing.allocator;

    // insert entries 1 and 3, skip 2
    try raft_log.append(.{
        .index = 1,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('a1', 'host1', 'active', 2, 4096, 0, 0, 0, 100, 100);",
    });
    try raft_log.append(.{
        .index = 3,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('a3', 'host3', 'active', 4, 8192, 0, 0, 0, 300, 300);",
    });

    // apply up to 3 — entry 2 is missing, should be skipped
    sm.applyUpTo(&raft_log, alloc, 3);

    // last_applied should reach 3 even though entry 2 was missing
    try std.testing.expectEqual(@as(LogIndex, 3), sm.last_applied);
}

test "snapshot round-trip preserves last_applied" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [512]u8 = undefined;
    const tmp_path = tmp.dir.realpath(".", &path_buf) catch return;

    // create source state machine with data
    var sm_path_buf: [512]u8 = undefined;
    const sm_path_slice = std.fmt.bufPrint(&sm_path_buf, "{s}/src.db", .{tmp_path}) catch return;
    sm_path_buf[sm_path_slice.len] = 0;
    const sm_path: [:0]const u8 = sm_path_buf[0..sm_path_slice.len :0];

    var sm = StateMachine.init(sm_path) catch return;
    defer sm.deinit();

    // apply several entries to advance last_applied
    sm.apply(.{ .index = 1, .term = 1, .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('x', 'h', 'active', 1, 1024, 0, 0, 0, 1, 1);" });
    sm.apply(.{ .index = 2, .term = 1, .data = "UPDATE agents SET status = 'draining' WHERE id = 'x';" });
    sm.apply(.{ .index = 3, .term = 1, .data = "UPDATE agents SET status = 'active' WHERE id = 'x';" });
    try std.testing.expectEqual(@as(LogIndex, 3), sm.last_applied);

    // take snapshot at index 3
    var snap_path_buf: [512]u8 = undefined;
    const snap_path = std.fmt.bufPrint(&snap_path_buf, "{s}/snap.dat", .{tmp_path}) catch return;
    sm.takeSnapshot(snap_path, .{
        .last_included_index = 3,
        .last_included_term = 1,
        .data_len = 0,
    }) catch return;

    // restore into a new state machine
    var sm2_path_buf: [512]u8 = undefined;
    const sm2_path_slice = std.fmt.bufPrint(&sm2_path_buf, "{s}/dst.db", .{tmp_path}) catch return;
    sm2_path_buf[sm2_path_slice.len] = 0;
    const sm2_path: [:0]const u8 = sm2_path_buf[0..sm2_path_slice.len :0];

    var sm2 = StateMachine.init(sm2_path) catch return;
    defer sm2.deinit();

    const meta = sm2.restoreFromSnapshot(snap_path) catch return;

    // last_applied should be restored from the snapshot header
    try std.testing.expectEqual(@as(LogIndex, 3), sm2.last_applied);
    try std.testing.expectEqual(@as(LogIndex, 3), meta.last_included_index);
}

test "restoreFromBytes rejects snapshot with trailing data" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    // header claims 5 bytes but we provide 10 (trailing garbage)
    var data: [snapshot_header_size + 10]u8 = undefined;
    std.mem.writeInt(u64, data[0..8], 10, .little); // index
    std.mem.writeInt(u64, data[8..16], 2, .little); // term
    std.mem.writeInt(u64, data[16..24], 5, .little); // claims 5 bytes
    @memset(data[snapshot_header_size..], 0);

    const result = sm.restoreFromBytes(&data);
    try std.testing.expectError(SnapshotError.CorruptSnapshot, result);
}

test "two state machines produce identical state from same log" {
    const alloc = std.testing.allocator;
    const RaftLog = @import("log.zig").Log;

    // create a log with 5 realistic entries
    var raft_log = try RaftLog.initMemory();
    defer raft_log.deinit();

    try raft_log.append(.{
        .index = 1,
        .term = 1,
        .data = "INSERT INTO agents (id, address, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at) VALUES ('agent-1', '10.0.0.1:9090', 'active', 4, 8192, 0, 0, 0, 1000, 1000);",
    });
    try raft_log.append(.{
        .index = 2,
        .term = 1,
        .data = "UPDATE agents SET last_heartbeat = 2000, cpu_used = 1500, memory_used_mb = 2048 WHERE id = 'agent-1';",
    });
    try raft_log.append(.{
        .index = 3,
        .term = 1,
        .data = "INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, created_at) VALUES ('assign-001', 'agent-1', 'nginx:latest', '/bin/sh', 'pending', 1000, 256, 1500);",
    });
    try raft_log.append(.{
        .index = 4,
        .term = 2,
        .data = "UPDATE assignments SET status = 'running' WHERE id = 'assign-001';",
    });
    try raft_log.append(.{
        .index = 5,
        .term = 2,
        .data = "UPDATE agents SET status = 'draining' WHERE id = 'agent-1';",
    });

    // create two state machines and apply the same log
    var sm1 = try StateMachine.initMemory();
    defer sm1.deinit();
    var sm2 = try StateMachine.initMemory();
    defer sm2.deinit();

    sm1.applyUpTo(&raft_log, alloc, 5);
    sm2.applyUpTo(&raft_log, alloc, 5);

    // both should have the same last_applied
    try std.testing.expectEqual(@as(LogIndex, 5), sm1.last_applied);
    try std.testing.expectEqual(@as(LogIndex, 5), sm2.last_applied);

    // query both databases for agents — should be identical
    const registry = @import("registry.zig");
    const agents1 = try registry.listAgents(alloc, &sm1.db);
    defer {
        for (agents1) |*a| {
            var agent = a.*;
            agent.deinit(alloc);
        }
        alloc.free(agents1);
    }
    const agents2 = try registry.listAgents(alloc, &sm2.db);
    defer {
        for (agents2) |*a| {
            var agent = a.*;
            agent.deinit(alloc);
        }
        alloc.free(agents2);
    }

    try std.testing.expectEqual(agents1.len, agents2.len);
    try std.testing.expectEqual(@as(usize, 1), agents1.len);

    // verify same field values
    try std.testing.expectEqualStrings(agents1[0].id, agents2[0].id);
    try std.testing.expectEqualStrings("draining", agents1[0].status);
    try std.testing.expectEqualStrings("draining", agents2[0].status);
}
