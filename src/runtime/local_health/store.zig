const std = @import("std");
const sqlite = @import("sqlite");
const db_store = @import("../../state/store/common.zig");
const state = @import("state.zig");

pub const Record = struct {
    generation: i64,
    pid: i32,
    status: state.Status,
    failing_streak: u32,
    last_exit: ?u8,
    checked_at: ?i64,
};

fn ensureTable(db: anytype) !void {
    try db.exec("CREATE TABLE IF NOT EXISTS local_container_health (container_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, pid INTEGER NOT NULL, status TEXT NOT NULL, failing_streak INTEGER NOT NULL DEFAULT 0, last_exit INTEGER, checked_at INTEGER);", .{}, .{});
}

pub fn current(id: []const u8, pid: i32, generation: i64) !bool {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    const row = try lease.db.one(struct { active: i64 }, "SELECT COUNT(*) AS active FROM containers c JOIN local_containers l ON l.container_id = c.id WHERE c.id = ? AND c.pid = ? AND l.generation = ? AND l.desired_running = 1;", .{}, .{ id, pid, generation });
    return row != null and row.?.active == 1;
}

pub fn write(id: []const u8, pid: i32, generation: i64, value: state.State, exit_code: ?u8) !void {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    try ensureTable(lease.db);
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
}

pub fn read(alloc: std.mem.Allocator, id: []const u8) !?Record {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    try ensureTable(lease.db);
    const row = try lease.db.oneAlloc(struct { generation: i64, pid: i64, status: sqlite.Text, failing_streak: i64, last_exit: ?i64, checked_at: ?i64 }, alloc, "SELECT generation, pid, status, failing_streak, last_exit, checked_at FROM local_container_health WHERE container_id = ?;", .{}, .{id}) orelse return null;
    defer alloc.free(row.status.data);
    return .{ .generation = row.generation, .pid = std.math.cast(i32, row.pid) orelse return error.InvalidHealthState, .status = std.meta.stringToEnum(state.Status, row.status.data) orelse return error.InvalidHealthState, .failing_streak = std.math.cast(u32, row.failing_streak) orelse return error.InvalidHealthState, .last_exit = if (row.last_exit) |code| std.math.cast(u8, code) orelse return error.InvalidHealthState else null, .checked_at = row.checked_at };
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
