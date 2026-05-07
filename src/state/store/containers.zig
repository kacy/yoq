const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const schema = @import("../schema.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

pub const ContainerRecord = struct {
    id: []const u8,
    rootfs: []const u8,
    command: []const u8,
    hostname: []const u8,
    status: []const u8,
    pid: ?i32,
    exit_code: ?u8,
    ip_address: ?[]const u8 = null,
    veth_host: ?[]const u8 = null,
    app_name: ?[]const u8 = null,
    created_at: i64,

    pub fn deinit(self: ContainerRecord, alloc: Allocator) void {
        alloc.free(self.id);
        alloc.free(self.rootfs);
        alloc.free(self.command);
        alloc.free(self.hostname);
        alloc.free(self.status);
        if (self.ip_address) |ip| alloc.free(ip);
        if (self.veth_host) |veth| alloc.free(veth);
        if (self.app_name) |app| alloc.free(app);
    }
};

const container_columns =
    "id, rootfs, command, hostname, status, pid, exit_code, ip_address, veth_host, app_name, created_at";

const ContainerRow = struct {
    id: sqlite.Text,
    rootfs: sqlite.Text,
    command: sqlite.Text,
    hostname: sqlite.Text,
    status: sqlite.Text,
    pid: ?i64,
    exit_code: ?i64,
    ip_address: ?sqlite.Text,
    veth_host: ?sqlite.Text,
    app_name: ?sqlite.Text,
    created_at: i64,
};

const IdRow = struct {
    id: sqlite.Text,
};

fn rowToRecord(row: ContainerRow) ContainerRecord {
    return .{
        .id = row.id.data,
        .rootfs = row.rootfs.data,
        .command = row.command.data,
        .hostname = row.hostname.data,
        .status = row.status.data,
        .pid = if (row.pid) |pid| @intCast(pid) else null,
        .exit_code = if (row.exit_code) |exit_code|
            if (exit_code >= 0 and exit_code <= 255) @as(?u8, @intCast(exit_code)) else null
        else
            null,
        .ip_address = if (row.ip_address) |ip| ip.data else null,
        .veth_host = if (row.veth_host) |veth| veth.data else null,
        .app_name = if (row.app_name) |app| app.data else null,
        .created_at = row.created_at,
    };
}

pub fn save(record: ContainerRecord) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return saveInDb(lease.db, record);
}

fn saveInDb(db: *sqlite.Db, record: ContainerRecord) StoreError!void {
    const pid: ?i64 = if (record.pid) |value| @intCast(value) else null;
    const exit_code: ?i64 = if (record.exit_code) |value| @intCast(value) else null;

    db.exec(
        "INSERT OR REPLACE INTO containers (" ++ container_columns ++ ")" ++
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{
            record.id,
            record.rootfs,
            record.command,
            record.hostname,
            record.status,
            pid,
            exit_code,
            record.ip_address,
            record.veth_host,
            record.app_name,
            record.created_at,
        },
    ) catch return StoreError.WriteFailed;
}

pub fn load(alloc: Allocator, id: []const u8) StoreError!ContainerRecord {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return loadInDb(lease.db, alloc, id);
}

fn loadInDb(db: *sqlite.Db, alloc: Allocator, id: []const u8) StoreError!ContainerRecord {
    const row = (db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT " ++ container_columns ++ " FROM containers WHERE id = ?;",
        .{},
        .{id},
    ) catch return StoreError.ReadFailed) orelse return StoreError.NotFound;
    return rowToRecord(row);
}

pub fn findByHostname(alloc: Allocator, hostname: []const u8) StoreError!?ContainerRecord {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return findByHostnameInDb(lease.db, alloc, hostname);
}

fn findByHostnameInDb(db: *sqlite.Db, alloc: Allocator, hostname: []const u8) StoreError!?ContainerRecord {
    const row = (db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT " ++ container_columns ++ " FROM containers WHERE hostname = ? ORDER BY created_at DESC LIMIT 1;",
        .{},
        .{hostname},
    ) catch return StoreError.ReadFailed) orelse return null;
    return rowToRecord(row);
}

pub fn remove(id: []const u8) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    lease.db.exec("DELETE FROM containers WHERE id = ?;", .{}, .{id}) catch return StoreError.WriteFailed;
}

fn listIdQuery(alloc: Allocator, comptime query: []const u8, args: anytype) StoreError!std.ArrayList([]const u8) {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return listIdQueryInDb(lease.db, alloc, query, args);
}

fn listIdQueryInDb(db: *sqlite.Db, alloc: Allocator, comptime query: []const u8, args: anytype) StoreError!std.ArrayList([]const u8) {
    var ids: std.ArrayList([]const u8) = .empty;
    var stmt = db.prepare(query) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(IdRow, args) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        ids.append(alloc, row.id.data) catch return StoreError.ReadFailed;
    }
    return ids;
}

pub fn listIds(alloc: Allocator) StoreError!std.ArrayList([]const u8) {
    return listIdQuery(alloc, "SELECT id FROM containers ORDER BY created_at DESC;", .{});
}

pub fn updateStatus(id: []const u8, status: []const u8, pid: ?i32, exit_code: ?u8) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return updateStatusInDb(lease.db, id, status, pid, exit_code);
}

fn updateStatusInDb(db: *sqlite.Db, id: []const u8, status: []const u8, pid: ?i32, exit_code: ?u8) StoreError!void {
    const pid_val: ?i64 = if (pid) |value| @intCast(value) else null;
    const exit_val: ?i64 = if (exit_code) |value| @intCast(value) else null;
    db.exec(
        "UPDATE containers SET status = ?, pid = ?, exit_code = ? WHERE id = ?;",
        .{},
        .{ status, pid_val, exit_val, id },
    ) catch return StoreError.WriteFailed;
}

pub fn updateNetwork(id: []const u8, ip_address: ?[]const u8, veth_host: ?[]const u8) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();

    lease.db.exec(
        "UPDATE containers SET ip_address = ?, veth_host = ? WHERE id = ?;",
        .{},
        .{ ip_address, veth_host, id },
    ) catch return StoreError.WriteFailed;
}

pub fn listAppContainerIds(alloc: Allocator, app_name: []const u8) StoreError!std.ArrayList([]const u8) {
    return listIdQuery(
        alloc,
        "SELECT id FROM containers WHERE app_name = ? ORDER BY created_at DESC;",
        .{app_name},
    );
}

pub fn findAppContainer(alloc: Allocator, app_name: []const u8, hostname: []const u8) StoreError!?ContainerRecord {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return findAppContainerInDb(lease.db, alloc, app_name, hostname);
}

fn findAppContainerInDb(db: *sqlite.Db, alloc: Allocator, app_name: []const u8, hostname: []const u8) StoreError!?ContainerRecord {
    const row = (db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT " ++ container_columns ++ " FROM containers WHERE app_name = ? AND hostname = ? ORDER BY created_at DESC LIMIT 1;",
        .{},
        .{ app_name, hostname },
    ) catch return StoreError.ReadFailed) orelse return null;
    return rowToRecord(row);
}

pub fn listAll(alloc: Allocator) StoreError!std.ArrayList(ContainerRecord) {
    var lease = try common.leaseDb();
    defer lease.deinit();

    return listAllInDb(lease.db, alloc);
}

fn listAllInDb(db: *sqlite.Db, alloc: Allocator) StoreError!std.ArrayList(ContainerRecord) {
    var records: std.ArrayList(ContainerRecord) = .empty;
    var stmt = db.prepare(
        "SELECT " ++ container_columns ++ " FROM containers WHERE status != 'stopped' ORDER BY hostname, created_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(ContainerRow, .{}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        records.append(alloc, rowToRecord(row)) catch return StoreError.ReadFailed;
    }
    return records;
}

test "container record defaults" {
    const record = ContainerRecord{
        .id = "abc123",
        .rootfs = "/tmp/rootfs",
        .command = "/bin/sh",
        .hostname = "test",
        .status = "created",
        .pid = null,
        .exit_code = null,
        .created_at = 1234567890,
    };

    try std.testing.expectEqualStrings("abc123", record.id);
    try std.testing.expect(record.pid == null);
    try std.testing.expect(record.exit_code == null);
}

test "save and load round-trip via sqlite" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO containers (id, rootfs, command, hostname, status, pid, exit_code, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "abc123", "/tmp/rootfs", "/bin/sh", "myhost", "running", @as(i64, 42), @as(?i64, null), @as(i64, 1234567890) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT " ++ container_columns ++ " FROM containers WHERE id = ?;",
        .{},
        .{"abc123"},
    ) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("abc123", record.id);
    try std.testing.expectEqualStrings("/tmp/rootfs", record.rootfs);
    try std.testing.expectEqualStrings("/bin/sh", record.command);
    try std.testing.expectEqualStrings("myhost", record.hostname);
    try std.testing.expectEqualStrings("running", record.status);
    try std.testing.expectEqual(@as(?i32, 42), record.pid);
    try std.testing.expect(record.exit_code == null);
    try std.testing.expect(record.app_name == null);
    try std.testing.expectEqual(@as(i64, 1234567890), record.created_at);
}

test "list ids returns newest first" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec("INSERT INTO containers (id, rootfs, command, created_at) VALUES (?, ?, ?, ?);", .{}, .{ "older", "/r", "/sh", @as(i64, 100) }) catch unreachable;
    db.exec("INSERT INTO containers (id, rootfs, command, created_at) VALUES (?, ?, ?, ?);", .{}, .{ "newer", "/r", "/sh", @as(i64, 200) }) catch unreachable;

    const alloc = std.testing.allocator;
    const first = (db.oneAlloc(IdRow, alloc, "SELECT id FROM containers ORDER BY created_at DESC;", .{}, .{}) catch unreachable).?;
    defer alloc.free(first.id.data);

    try std.testing.expectEqualStrings("newer", first.id.data);
}

test "delete removes record" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec("INSERT INTO containers (id, rootfs, command, created_at) VALUES (?, ?, ?, ?);", .{}, .{ "del1", "/r", "/sh", @as(i64, 100) }) catch unreachable;
    db.exec("DELETE FROM containers WHERE id = ?;", .{}, .{"del1"}) catch unreachable;

    const CountRow = struct { count: i64 };
    const result = (db.one(CountRow, "SELECT COUNT(*) AS count FROM containers;", .{}, .{}) catch unreachable).?;
    try std.testing.expectEqual(@as(i64, 0), result.count);
}

test "update status" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO containers (id, rootfs, command, status, created_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "upd1", "/r", "/sh", "created", @as(i64, 100) },
    ) catch unreachable;
    db.exec("UPDATE containers SET status = ?, pid = ? WHERE id = ?;", .{}, .{ "running", @as(i64, 1234), "upd1" }) catch unreachable;

    const alloc = std.testing.allocator;
    const Row = struct { status: sqlite.Text, pid: ?i64 };
    const row = (db.oneAlloc(Row, alloc, "SELECT status, pid FROM containers WHERE id = ?;", .{}, .{"upd1"}) catch unreachable).?;
    defer alloc.free(row.status.data);

    try std.testing.expectEqualStrings("running", row.status.data);
    try std.testing.expectEqual(@as(?i64, 1234), row.pid);
}

test "app_name stored and retrieved" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO containers (id, rootfs, command, hostname, status, app_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "app1", "/r", "/sh", "web", "running", "myapp", @as(i64, 100) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(ContainerRow, alloc, "SELECT " ++ container_columns ++ " FROM containers WHERE id = ?;", .{}, .{"app1"}) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("myapp", record.app_name.?);
    try std.testing.expectEqualStrings("web", record.hostname);
}

test "app_name null by default" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec("INSERT INTO containers (id, rootfs, command, created_at) VALUES (?, ?, ?, ?);", .{}, .{ "noapp", "/r", "/sh", @as(i64, 100) }) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(ContainerRow, alloc, "SELECT " ++ container_columns ++ " FROM containers WHERE id = ?;", .{}, .{"noapp"}) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expect(record.app_name == null);
}

test "list app container ids" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec("INSERT INTO containers (id, rootfs, command, hostname, app_name, created_at) VALUES (?, ?, ?, ?, ?, ?);", .{}, .{ "a1", "/r", "/sh", "web", "myapp", @as(i64, 100) }) catch unreachable;
    db.exec("INSERT INTO containers (id, rootfs, command, hostname, app_name, created_at) VALUES (?, ?, ?, ?, ?, ?);", .{}, .{ "a2", "/r", "/sh", "db", "myapp", @as(i64, 200) }) catch unreachable;
    db.exec("INSERT INTO containers (id, rootfs, command, hostname, app_name, created_at) VALUES (?, ?, ?, ?, ?, ?);", .{}, .{ "b1", "/r", "/sh", "api", "other", @as(i64, 150) }) catch unreachable;

    const alloc = std.testing.allocator;
    var stmt = db.prepare("SELECT id FROM containers WHERE app_name = ? ORDER BY created_at DESC;") catch unreachable;
    defer stmt.deinit();

    var ids: std.ArrayList([]const u8) = .empty;
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    var iter = stmt.iterator(IdRow, .{"myapp"}) catch unreachable;
    while (iter.nextAlloc(alloc, .{}) catch unreachable) |row| {
        ids.append(alloc, row.id.data) catch unreachable;
    }

    try std.testing.expectEqual(@as(usize, 2), ids.items.len);
    try std.testing.expectEqualStrings("a2", ids.items[0]);
    try std.testing.expectEqualStrings("a1", ids.items[1]);
}

test "find app container by hostname" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO containers (id, rootfs, command, hostname, status, app_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "f1", "/r", "/sh", "web", "running", "myapp", @as(i64, 100) },
    ) catch unreachable;
    db.exec(
        "INSERT INTO containers (id, rootfs, command, hostname, status, app_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "f2", "/r", "/sh", "db", "running", "myapp", @as(i64, 200) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT " ++ container_columns ++ " FROM containers WHERE app_name = ? AND hostname = ? ORDER BY created_at DESC LIMIT 1;",
        .{},
        .{ "myapp", "db" },
    ) catch unreachable).?;
    const record = rowToRecord(row);
    defer record.deinit(alloc);

    try std.testing.expectEqualStrings("f2", record.id);
    try std.testing.expectEqualStrings("db", record.hostname);
    try std.testing.expectEqualStrings("myapp", record.app_name.?);

    const missing = db.oneAlloc(
        ContainerRow,
        alloc,
        "SELECT " ++ container_columns ++ " FROM containers WHERE app_name = ? AND hostname = ? ORDER BY created_at DESC LIMIT 1;",
        .{},
        .{ "myapp", "cache" },
    ) catch unreachable;
    try std.testing.expect(missing == null);
}
