// standalone containers keep their requested state across process exits.
// command locks serialize callers, transition locks order stop against startup,
// and owner locks keep one supervisor responsible for cleanup. lock files stay
// in place: unlinking one would let callers lock different inodes for the same id.
const std = @import("std");
const linux = std.os.linux;
const linux_platform = @import("linux_platform");
const sqlite = @import("sqlite");
const paths = @import("../lib/paths.zig");
const db_store = @import("../state/store/common.zig");
const container = @import("container.zig");

pub const LockKind = enum { command, transition, owner };
pub const Lock = struct {
    fd: std.posix.fd_t,

    pub fn deinit(self: Lock) void {
        _ = linux.flock(self.fd, 8);
        linux_platform.posix.close(self.fd);
    }
};

pub fn lock(id: []const u8, kind: LockKind, wait: bool) !Lock {
    if (!container.isValidContainerId(id)) return error.InvalidId;
    try paths.ensureDataDirStrict("container_locks");
    var buf: [paths.max_path]u8 = undefined;
    const path = try paths.dataPathFmt(&buf, "container_locks/{s}.{s}", .{ id, @tagName(kind) });
    if (path.len == buf.len) return error.PathTooLong;
    buf[path.len] = 0;
    const rc = linux.open(buf[0..path.len :0], .{ .ACCMODE = .RDWR, .CREAT = true, .CLOEXEC = true }, 0o600);
    if (linux.errno(rc) != .SUCCESS) return error.LockFailed;
    const fd: std.posix.fd_t = @intCast(rc);
    errdefer linux_platform.posix.close(fd);
    while (true) {
        switch (linux.errno(linux.flock(fd, 2 | @as(i32, if (wait) 0 else 4)))) {
            .SUCCESS => return .{ .fd = fd },
            .INTR => continue,
            .AGAIN => return error.Busy,
            else => return error.LockFailed,
        }
    }
}

pub fn register(id: []const u8, name: ?[]const u8) !void {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    if (name) |value| {
        const legacy = try lease.db.one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM containers WHERE hostname = ? AND id NOT IN (SELECT container_id FROM local_containers WHERE name IS NOT NULL);", .{}, .{value});
        if (legacy != null and legacy.?.count > 0) return error.NameInUse;
    }
    const inserted = try lease.db.one(struct { inserted: i64 }, "INSERT INTO local_containers (container_id, name) VALUES (?, ?) ON CONFLICT DO NOTHING RETURNING 1 AS inserted;", .{}, .{ id, name });
    if (inserted == null) return error.NameInUse;
}

// old standalone records acquire lifecycle state lazily. leave legacy names
// unreserved so an upgrade can report duplicates without choosing an owner.
pub fn ensureRegistered(id: []const u8) !void {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    try lease.db.exec("INSERT OR IGNORE INTO local_containers (container_id) VALUES (?);", .{}, .{id});
}

pub fn request(id: []const u8, running: bool) !i64 {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    const row = try lease.db.one(struct { generation: i64 }, "UPDATE local_containers SET desired_running = ?, generation = generation + 1, restart_count = CASE WHEN ? = 1 THEN 0 ELSE restart_count END WHERE container_id = ? RETURNING generation;", .{}, .{ @intFromBool(running), @intFromBool(running), id }) orelse return error.NotFound;
    return row.generation;
}

pub fn countRestart(id: []const u8, generation: i64) !void {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    try lease.db.exec("UPDATE local_containers SET restart_count = restart_count + 1 WHERE container_id = ? AND generation = ? AND desired_running = 1;", .{}, .{ id, generation });
}

pub fn restartCount(id: []const u8) !i64 {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    const row = try lease.db.one(struct { count: i64 }, "SELECT restart_count AS count FROM local_containers WHERE container_id = ?;", .{}, .{id});
    return if (row) |value| value.count else 0;
}

pub fn shouldRun(id: []const u8, generation: i64) !bool {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    const row = try lease.db.one(struct { desired_running: i64, generation: i64 }, "SELECT desired_running, generation FROM local_containers WHERE container_id = ?;", .{}, .{id}) orelse return false;
    return row.desired_running != 0 and row.generation == generation;
}

pub fn wantsRunning(id: []const u8) !bool {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    const row = try lease.db.one(struct { desired_running: i64 }, "SELECT desired_running FROM local_containers WHERE container_id = ?;", .{}, .{id}) orelse return false;
    return row.desired_running != 0;
}

pub fn finish(id: []const u8, generation: i64) !void {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    try lease.db.exec("UPDATE local_containers SET desired_running = 0 WHERE container_id = ? AND generation = ?;", .{}, .{ id, generation });
}

pub fn remove(id: []const u8) !void {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    try lease.db.exec("DELETE FROM local_containers WHERE container_id = ?;", .{}, .{id});
}

pub fn findName(alloc: std.mem.Allocator, name: []const u8) !?[]const u8 {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    const row = try lease.db.oneAlloc(struct { container_id: sqlite.Text }, alloc, "SELECT container_id FROM local_containers WHERE name = ?;", .{}, .{name}) orelse return null;
    return row.container_id.data;
}

pub fn nameForId(alloc: std.mem.Allocator, id: []const u8) !?[]const u8 {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    const row = try lease.db.oneAlloc(struct { name: sqlite.Text }, alloc, "SELECT name FROM local_containers WHERE container_id = ? AND name IS NOT NULL;", .{}, .{id}) orelse return null;
    return row.name.data;
}

pub fn rename(id: []const u8, name: []const u8) !void {
    if (name.len == 0 or name.len > 128) return error.InvalidName;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.') return error.InvalidName;
    try ensureRegistered(id);
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    // The unique index arbitrates concurrent renames. Legacy hostnames also
    // reserve their names until those containers are renamed or removed.
    const row = try lease.db.one(struct { updated: i64 }, "UPDATE OR IGNORE local_containers SET name = ? WHERE container_id = ? AND NOT EXISTS (SELECT 1 FROM containers WHERE hostname = ? AND id != ? AND id NOT IN (SELECT container_id FROM local_containers WHERE name IS NOT NULL)) RETURNING 1 AS updated;", .{}, .{ name, id, name, id });
    if (row == null) return error.NameInUse;
}

test "rename resolves legacy duplicate names without changing hostname" {
    const store = @import("../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    for ([_][]const u8{ "0123456789ab", "abcdef012345" }) |id| {
        try store.save(.{ .id = id, .rootfs = "", .command = "sh", .hostname = "old", .status = "stopped", .pid = null, .exit_code = 0, .created_at = 0 });
    }
    try std.testing.expectError(error.NameInUse, rename("0123456789ab", "old"));
    try rename("0123456789ab", "first");
    try rename("abcdef012345", "old");
    try std.testing.expectError(error.NameInUse, rename("abcdef012345", "first"));
    const record = try store.load(std.testing.allocator, "0123456789ab");
    defer record.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("old", record.hostname);
}

test "local lifecycle generations reject delayed supervisors and stale completion" {
    const store = @import("../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    try register("0123456789ab", "web");
    const first = try request("0123456789ab", true);
    try std.testing.expect(try shouldRun("0123456789ab", first));
    _ = try request("0123456789ab", false);
    try std.testing.expect(!try shouldRun("0123456789ab", first));
    const second = try request("0123456789ab", true);
    try finish("0123456789ab", first);
    try std.testing.expect(try shouldRun("0123456789ab", second));
    try finish("0123456789ab", second);
    try std.testing.expect(!try wantsRunning("0123456789ab"));
}

test "local container names remain reserved until removal" {
    const store = @import("../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    try register("0123456789ab", "web");
    if (register("abcdef012345", "web")) |_| return error.ExpectedNameConflict else |_| {}
    const id = (try findName(std.testing.allocator, "web")).?;
    defer std.testing.allocator.free(id);
    try std.testing.expectEqualStrings("0123456789ab", id);
    try remove("0123456789ab");
    try register("abcdef012345", "web");
}

test "local container owner lock has one holder" {
    const first = try lock("aabbccddeeff", .owner, false);
    defer first.deinit();
    try std.testing.expectError(error.Busy, lock("aabbccddeeff", .owner, false));
}

// metadata is removed together, so a failed database write cannot release the
// name while leaving a container that still owns storage.
pub fn removeRecord(id: []const u8) !void {
    var lease = try db_store.leaseDb();
    defer lease.deinit();
    try lease.db.exec("SAVEPOINT remove_local_container;", .{}, .{});
    errdefer lease.db.exec("ROLLBACK TO remove_local_container; RELEASE remove_local_container;", .{}, .{}) catch {};
    try lease.db.exec("DELETE FROM containers WHERE id = ?;", .{}, .{id});
    try lease.db.exec("DELETE FROM local_containers WHERE container_id = ?;", .{}, .{id});
    try lease.db.exec("RELEASE remove_local_container;", .{}, .{});
}

test "legacy container names stay reserved after lazy lifecycle registration" {
    const store = @import("../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    try store.save(.{ .id = "111111111111", .rootfs = "/fixture", .command = "sh", .hostname = "legacy", .status = "stopped", .pid = null, .exit_code = 0, .created_at = 1 });
    try ensureRegistered("111111111111");
    try std.testing.expectError(error.NameInUse, register("222222222222", "legacy"));
    try removeRecord("111111111111");
    try register("222222222222", "legacy");
}
