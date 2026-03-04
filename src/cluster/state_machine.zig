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

const std = @import("std");
const sqlite = @import("sqlite");
const types = @import("raft_types.zig");
const schema = @import("../state/schema.zig");
const log = @import("../lib/log.zig");

const LogEntry = types.LogEntry;
const LogIndex = types.LogIndex;

pub const StateMachineError = error{
    DbOpenFailed,
};

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
};

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
