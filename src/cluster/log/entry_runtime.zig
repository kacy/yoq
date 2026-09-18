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
    errdefer alloc.free(row.data.data);

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
    errdefer {
        for (entries.items) |entry| alloc.free(entry.data);
        entries.deinit(alloc);
    }

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
        // the row owns its data until the entry is added to the list.
        errdefer alloc.free(row.data.data);
        entries.append(alloc, LogEntry{
            .index = common.safeU64(row.log_index) catch return LogError.ReadFailed,
            .term = common.safeU64(row.term) catch return LogError.ReadFailed,
            .data = row.data.data,
        }) catch return LogError.ReadFailed;
    }

    return entries.toOwnedSlice(alloc) catch return LogError.ReadFailed;
}

test "log reads release row data when a persisted term is invalid" {
    var db = try @import("state_runtime.zig").initMemory();
    defer db.deinit();
    const alloc = std.testing.allocator;

    try append(&db, .{ .index = 1, .term = 2, .data = "valid prefix" });
    try db.exec("INSERT INTO raft_log (log_index, term, data) VALUES (2, -1, 'invalid term');", .{}, .{});

    try std.testing.expectError(error.ReadFailed, getEntry(&db, alloc, 2));
    // the range read must also release entries collected before the bad row.
    try std.testing.expectError(error.ReadFailed, getEntries(&db, alloc, 1, 2));

    try db.exec("UPDATE raft_log SET term = 3 WHERE log_index = 2;", .{}, .{});
    const entries = try getEntries(&db, alloc, 1, 2);
    defer {
        for (entries) |entry| alloc.free(entry.data);
        alloc.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqual(@as(u64, 3), entries[1].term);
    try std.testing.expectEqualStrings("invalid term", entries[1].data);
}

test "log range reads release all allocations at each allocation failure" {
    var db = try @import("state_runtime.zig").initMemory();
    defer db.deinit();
    for (1..4) |index| {
        try append(&db, .{ .index = index, .term = 2, .data = "entry data" });
    }

    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
            .fail_index = fail_index,
            // force the final slice conversion to allocate instead of shrinking.
            .resize_fail_index = 0,
        });
        const alloc = failing.allocator();
        const entries = getEntries(&db, alloc, 1, 3) catch |err| {
            try std.testing.expectEqual(error.ReadFailed, err);
            try std.testing.expect(failing.has_induced_failure);
            try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
            continue;
        };
        defer {
            for (entries) |entry| alloc.free(entry.data);
            alloc.free(entries);
        }
        try std.testing.expect(!failing.has_induced_failure);
        try std.testing.expectEqual(@as(usize, 3), entries.len);
        for (entries, 1..) |entry, index| {
            try std.testing.expectEqual(index, entry.index);
            try std.testing.expectEqualStrings("entry data", entry.data);
        }
        return;
    }
}
