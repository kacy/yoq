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

const LogEntry = types.LogEntry;
const LogIndex = types.LogIndex;

pub const StateMachineError = error{
    DbOpenFailed,
    ApplyFailed,
};

pub const StateMachine = struct {
    db: sqlite.Db,
    last_applied: LogIndex,

    pub fn init(path: [:0]const u8) StateMachineError!StateMachine {
        const db = sqlite.Db.init(.{
            .mode = .{ .File = path },
            .open_flags = .{ .write = true, .create = true },
        }) catch return StateMachineError.DbOpenFailed;

        return .{
            .db = db,
            .last_applied = 0,
        };
    }

    pub fn initMemory() StateMachineError!StateMachine {
        const db = sqlite.Db.init(.{
            .mode = .Memory,
            .open_flags = .{ .write = true },
        }) catch return StateMachineError.DbOpenFailed;

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
    pub fn apply(self: *StateMachine, entry: LogEntry) StateMachineError!void {
        if (entry.index <= self.last_applied) return;

        self.db.exec(entry.data, .{}, .{}) catch return StateMachineError.ApplyFailed;
        self.last_applied = entry.index;
    }

    /// apply all entries up to the given index.
    pub fn applyUpTo(
        self: *StateMachine,
        log: *@import("log.zig").Log,
        alloc: std.mem.Allocator,
        up_to: LogIndex,
    ) void {
        var idx = self.last_applied + 1;
        while (idx <= up_to) : (idx += 1) {
            const entry = (log.getEntry(alloc, idx) catch continue) orelse continue;
            defer alloc.free(entry.data);
            self.apply(entry) catch {};
        }
    }
};

// -- tests --

test "apply executes SQL statement" {
    var sm = try StateMachine.initMemory();
    defer sm.deinit();

    // create a table via state machine
    try sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);",
    });

    try sm.apply(.{
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

    try sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);",
    });

    // applying the same index again should be a no-op (not fail with "table exists")
    try sm.apply(.{
        .index = 1,
        .term = 1,
        .data = "CREATE TABLE kv (key TEXT PRIMARY KEY, value TEXT);",
    });

    try std.testing.expectEqual(@as(LogIndex, 1), sm.last_applied);
}
