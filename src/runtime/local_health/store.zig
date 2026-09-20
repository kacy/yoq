const std = @import("std");
const sqlite = @import("sqlite");
const db_store = @import("../../state/store/common.zig");
const state = @import("state.zig");
const diagnostics = @import("output.zig");

pub const Record = struct {
    generation: i64,
    pid: i32,
    status: state.Status,
    failing_streak: u32,
    last_exit: ?u8,
    checked_at: ?i64,
    output: ?[]const u8 = null,
    output_truncated: bool = false,

    pub fn deinit(self: Record, alloc: std.mem.Allocator) void {
        if (self.output) |bytes| alloc.free(bytes);
    }
};

fn ensureTable(db: anytype) !void {
    try db.exec("CREATE TABLE IF NOT EXISTS local_container_health (container_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, pid INTEGER NOT NULL, status TEXT NOT NULL, failing_streak INTEGER NOT NULL DEFAULT 0, last_exit INTEGER, checked_at INTEGER);", .{}, .{});
    // a separate table also works with existing health records. both rows are
    // written in one transaction, and deletion does not rely on foreign keys.
    try db.exec("CREATE TABLE IF NOT EXISTS local_container_health_output (container_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, pid INTEGER NOT NULL, output TEXT NOT NULL CHECK(length(CAST(output AS BLOB)) <= 4096), truncated INTEGER NOT NULL);", .{}, .{});
    try db.exec("CREATE TRIGGER IF NOT EXISTS delete_local_health_output AFTER DELETE ON local_container_health BEGIN DELETE FROM local_container_health_output WHERE container_id = OLD.container_id; END;", .{}, .{});
}

pub fn current(id: []const u8, pid: i32, generation: i64) !bool {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    const row = try lease.db.one(struct { active: i64 }, "SELECT COUNT(*) AS active FROM containers c JOIN local_containers l ON l.container_id = c.id WHERE c.id = ? AND c.pid = ? AND l.generation = ? AND l.desired_running = 1;", .{}, .{ id, pid, generation });
    return row != null and row.?.active == 1;
}

pub fn write(id: []const u8, pid: i32, generation: i64, value: state.State, exit_code: ?u8) !void {
    return writeRecord(id, pid, generation, value, exit_code, null);
}

pub fn writeResult(id: []const u8, pid: i32, generation: i64, value: state.State, exit_code: u8, output: *const diagnostics.Output) !void {
    if (output.len > diagnostics.max_bytes or !std.unicode.utf8ValidateSlice(output.text())) return error.InvalidHealthOutput;
    return writeRecord(id, pid, generation, value, exit_code, output);
}

fn writeRecord(id: []const u8, pid: i32, generation: i64, value: state.State, exit_code: ?u8, output: ?*const diagnostics.Output) !void {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    try ensureTable(lease.db);
    try lease.db.exec("SAVEPOINT health_result;", .{}, .{});
    errdefer lease.db.exec("ROLLBACK TO health_result; RELEASE health_result;", .{}, .{}) catch {};
    const exit: ?i64 = if (exit_code) |code| code else null;
    const checked: ?i64 = if (exit_code != null) std.Io.Clock.real.now(std.Options.debug_io).toSeconds() else null;
    try lease.db.exec(
        "INSERT INTO local_container_health (container_id, generation, pid, status, failing_streak, last_exit, checked_at)" ++
            " SELECT c.id, ?, ?, ?, ?, ?, ? FROM containers c JOIN local_containers l ON l.container_id = c.id" ++
            " WHERE c.id = ? AND c.pid = ? AND l.generation = ? AND l.desired_running = 1" ++
            " ON CONFLICT(container_id) DO UPDATE SET generation=excluded.generation, pid=excluded.pid, status=excluded.status," ++
            " failing_streak=excluded.failing_streak, last_exit=excluded.last_exit, checked_at=excluded.checked_at;",
        .{},
        .{ generation, pid, @tagName(value.status), value.failures, exit, checked, id, pid, generation },
    );
    // a stale result changes neither row. the write transaction keeps a new
    // generation from appearing between the state update and its diagnostics.
    if (lease.db.rowsAffected() != 0) {
        if (output) |result| {
            var statement = try lease.db.prepareDynamic(
                "INSERT INTO local_container_health_output (container_id, generation, pid, output, truncated) VALUES (?, ?, ?, ?, ?)" ++
                    " ON CONFLICT(container_id) DO UPDATE SET generation=excluded.generation, pid=excluded.pid, output=excluded.output, truncated=excluded.truncated;",
            );
            defer statement.deinit();
            statement.exec(.{}, .{ id, generation, pid, result.text(), @intFromBool(result.truncated) }) catch |err| {
                // finalize otherwise reports the same step error a second time.
                // retain the write error so the result transaction rolls back.
                _ = sqlite.c.sqlite3_reset(statement.stmt);
                return err;
            };
        } else {
            try lease.db.exec("DELETE FROM local_container_health_output WHERE container_id = ?;", .{}, .{id});
        }
    }
    try lease.db.exec("RELEASE health_result;", .{}, .{});
}

pub fn markUnavailable(id: []const u8, pid: i32, generation: i64) !void {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    try ensureTable(lease.db);
    try lease.db.exec(
        "UPDATE local_container_health SET status = 'unknown' WHERE container_id = ? AND pid = ? AND generation = ?" ++
            " AND EXISTS (SELECT 1 FROM containers c JOIN local_containers l ON l.container_id = c.id" ++
            " WHERE c.id = ? AND c.pid = ? AND l.generation = ? AND l.desired_running = 1);",
        .{},
        .{ id, pid, generation, id, pid, generation },
    );
}

// the returned record owns its diagnostic bytes; callers release it with deinit.
pub fn read(alloc: std.mem.Allocator, id: []const u8) !?Record {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    try ensureTable(lease.db);
    const Row = struct {
        generation: i64,
        pid: i64,
        status: sqlite.Text,
        failing_streak: i64,
        last_exit: ?i64,
        checked_at: ?i64,
        output: ?sqlite.Text,
        truncated: ?i64,
    };
    const row = try lease.db.oneAlloc(Row, alloc, "SELECT h.generation, h.pid, h.status, h.failing_streak, h.last_exit, h.checked_at, o.output, o.truncated" ++
        " FROM local_container_health h LEFT JOIN local_container_health_output o" ++
        " ON o.container_id = h.container_id AND o.generation = h.generation AND o.pid = h.pid WHERE h.container_id = ?;", .{}, .{id}) orelse return null;
    defer alloc.free(row.status.data);
    errdefer if (row.output) |output| alloc.free(output.data);
    return .{
        .generation = row.generation,
        .pid = std.math.cast(i32, row.pid) orelse return error.InvalidHealthState,
        .status = std.meta.stringToEnum(state.Status, row.status.data) orelse return error.InvalidHealthState,
        .failing_streak = std.math.cast(u32, row.failing_streak) orelse return error.InvalidHealthState,
        .last_exit = if (row.last_exit) |code| std.math.cast(u8, code) orelse return error.InvalidHealthState else null,
        .checked_at = row.checked_at,
        .output = if (row.output) |output| output.data else null,
        .output_truncated = (row.truncated orelse 0) != 0,
    };
}

pub fn clearCurrent(id: []const u8, pid: i32, generation: i64) !void {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    try ensureTable(lease.db);
    try lease.db.exec("DELETE FROM local_container_health WHERE container_id = ? AND EXISTS (SELECT 1 FROM containers c JOIN local_containers l ON l.container_id = c.id WHERE c.id = ? AND c.pid = ? AND l.generation = ? AND l.desired_running = 1);", .{}, .{ id, id, pid, generation });
}

pub fn remove(id: []const u8) !void {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    try ensureTable(lease.db);
    try lease.db.exec("DELETE FROM local_container_health WHERE container_id = ?;", .{}, .{id});
}

test "local health results cannot overwrite newer generations or attempts" {
    const containers = @import("../../state/store.zig");
    const control = @import("../local_control.zig");
    try containers.initTestDb();
    defer containers.deinitTestDb();
    const id = "deadbeef1122";
    try containers.save(.{ .id = id, .rootfs = "/fixture", .command = "true", .hostname = "health", .status = "running", .pid = 123, .exit_code = null, .created_at = 0 });
    try control.register(id, null);
    const old = try control.request(id, true);
    try write(id, 123, old, .{ .started_ns = 0, .status = .healthy }, 0);
    const generation = try control.request(id, true);
    try containers.updateStatus(id, "running", 456, null);
    try write(id, 456, generation, .{ .started_ns = 0, .status = .starting }, null);
    try write(id, 123, old, .{ .started_ns = 0, .status = .unhealthy }, 1);
    try write(id, 123, generation, .{ .started_ns = 0, .status = .unhealthy }, 1);
    try clearCurrent(id, 123, old);
    const record = (try read(std.testing.allocator, id)).?;
    try std.testing.expectEqual(generation, record.generation);
    try std.testing.expectEqual(@as(i32, 456), record.pid);
    try std.testing.expectEqual(state.Status.starting, record.status);
    try clearCurrent(id, 456, generation);
    try std.testing.expect((try read(std.testing.allocator, id)) == null);
}

test "monitor failures preserve the last probe and cannot change a newer run" {
    const containers = @import("../../state/store.zig");
    const control = @import("../local_control.zig");
    try containers.initTestDb();
    defer containers.deinitTestDb();
    const id = "deadbeef2233";
    try containers.save(.{ .id = id, .rootfs = "/fixture", .command = "true", .hostname = "health", .status = "running", .pid = 123, .exit_code = null, .created_at = 0 });
    try control.register(id, null);
    const generation = try control.request(id, true);
    try write(id, 123, generation, .{ .started_ns = 0, .status = .healthy, .failures = 1 }, 1);
    const before = (try read(std.testing.allocator, id)).?;
    try markUnavailable(id, 123, generation);
    const unknown = (try read(std.testing.allocator, id)).?;
    try std.testing.expectEqual(state.Status.unknown, unknown.status);
    try std.testing.expectEqual(before.failing_streak, unknown.failing_streak);
    try std.testing.expectEqual(before.last_exit, unknown.last_exit);
    try std.testing.expectEqual(before.checked_at, unknown.checked_at);

    try write(id, 123, generation, .{ .started_ns = 0, .status = .healthy }, 0);
    try std.testing.expectEqual(state.Status.healthy, (try read(std.testing.allocator, id)).?.status);
    const next = try control.request(id, true);
    try containers.updateStatus(id, "running", 456, null);
    try write(id, 456, next, .{ .started_ns = 0 }, null);
    try markUnavailable(id, 123, generation);
    try markUnavailable(id, 123, next);
    try std.testing.expectEqual(state.Status.starting, (try read(std.testing.allocator, id)).?.status);
}

test "health diagnostics follow the current attempt and clear on restart or disable" {
    const containers = @import("../../state/store.zig");
    const control = @import("../local_control.zig");
    const alloc = std.testing.allocator;
    try containers.initTestDb();
    defer containers.deinitTestDb();
    const id = "deadbeef3344";
    try containers.save(.{ .id = id, .rootfs = "/fixture", .command = "true", .hostname = "health", .status = "running", .pid = 123, .exit_code = null, .created_at = 0 });
    try control.register(id, null);
    const previous = try control.request(id, true);
    var output: diagnostics.Output = .{ .len = 4, .truncated = true };
    @memcpy(output.bytes[0..4], "test");
    try writeResult(id, 123, previous, .{ .started_ns = 0, .status = .unhealthy }, 124, &output);
    try markUnavailable(id, 123, previous);
    const timed_out = (try read(alloc, id)).?;
    defer timed_out.deinit(alloc);
    try std.testing.expectEqualStrings("test", timed_out.output.?);
    try std.testing.expect(timed_out.output_truncated);
    try std.testing.expectEqual(@as(?u8, 124), timed_out.last_exit);

    const generation = try control.request(id, true);
    try containers.updateStatus(id, "running", 456, null);
    try write(id, 456, generation, .{ .started_ns = 0 }, null);
    const restarted = (try read(alloc, id)).?;
    defer restarted.deinit(alloc);
    try std.testing.expect(restarted.output == null and !restarted.output_truncated);
    try writeResult(id, 456, generation, .{ .started_ns = 0, .status = .healthy }, 0, &output);
    @memcpy(output.bytes[0..4], "old!");
    try writeResult(id, 123, previous, .{ .started_ns = 0, .status = .unhealthy }, 1, &output);
    try writeResult(id, 123, generation, .{ .started_ns = 0, .status = .unhealthy }, 1, &output);
    try clearCurrent(id, 123, previous);
    const current_result = (try read(alloc, id)).?;
    defer current_result.deinit(alloc);
    try std.testing.expectEqualStrings("test", current_result.output.?);
    try std.testing.expectEqual(state.Status.healthy, current_result.status);
    try clearCurrent(id, 456, generation);
    try std.testing.expect((try read(alloc, id)) == null);
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    const leftovers = (try lease.db.one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM local_container_health_output;", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 0), leftovers.count);
}

test "health state rolls back when its diagnostic write fails" {
    const containers = @import("../../state/store.zig");
    const control = @import("../local_control.zig");
    const alloc = std.testing.allocator;
    try containers.initTestDb();
    defer containers.deinitTestDb();
    const id = "deadbeef4455";
    try containers.save(.{ .id = id, .rootfs = "/fixture", .command = "true", .hostname = "health", .status = "running", .pid = 123, .exit_code = null, .created_at = 0 });
    try control.register(id, null);
    const generation = try control.request(id, true);
    var output: diagnostics.Output = .{ .len = 2 };
    @memcpy(output.bytes[0..2], "ok");
    try writeResult(id, 123, generation, .{ .started_ns = 0, .status = .healthy }, 0, &output);
    {
        var lease = try db_store.leaseDb();
        defer lease.deinit();
        try lease.db.exec("CREATE TEMP TRIGGER fail_health_output BEFORE UPDATE ON local_container_health_output BEGIN SELECT RAISE(ABORT, 'test failure'); END;", .{}, .{});
    }
    @memcpy(output.bytes[0..2], "no");
    if (writeResult(id, 123, generation, .{ .started_ns = 0, .status = .unhealthy, .failures = 3 }, 1, &output)) |_| return error.ExpectedWriteFailure else |_| {}
    const unchanged = (try read(alloc, id)).?;
    defer unchanged.deinit(alloc);
    try std.testing.expectEqual(state.Status.healthy, unchanged.status);
    try std.testing.expectEqual(@as(?u8, 0), unchanged.last_exit);
    try std.testing.expectEqualStrings("ok", unchanged.output.?);
}

test "health diagnostics read existing databases without output columns" {
    const containers = @import("../../state/store.zig");
    try containers.initTestDb();
    defer containers.deinitTestDb();
    {
        var lease = try db_store.leaseDb();
        defer lease.deinit();
        try lease.db.exec("CREATE TABLE local_container_health (container_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, pid INTEGER NOT NULL, status TEXT NOT NULL, failing_streak INTEGER NOT NULL DEFAULT 0, last_exit INTEGER, checked_at INTEGER);", .{}, .{});
        try lease.db.exec("INSERT INTO local_container_health VALUES ('deadbeef5566', 1, 123, 'healthy', 0, 0, 100);", .{}, .{});
    }
    const record = (try read(std.testing.allocator, "deadbeef5566")).?;
    defer record.deinit(std.testing.allocator);
    try std.testing.expectEqual(state.Status.healthy, record.status);
    try std.testing.expectEqual(@as(?i64, 100), record.checked_at);
    try std.testing.expect(record.output == null and !record.output_truncated);
}
