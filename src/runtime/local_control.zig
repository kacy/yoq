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
    try lease.db.exec("INSERT INTO local_containers (container_id, name) VALUES (?, ?);", .{}, .{ id, name });
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
    const row = try lease.db.one(struct { generation: i64 }, "UPDATE local_containers SET desired_running = ?, generation = generation + 1 WHERE container_id = ? RETURNING generation;", .{}, .{ @intFromBool(running), id }) orelse return error.NotFound;
    return row.generation;
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
