// a replacement advances the service generation before stopping old children.
// supervisor tokens prevent an old process from restarting its retired group;
// instance generations keep concurrent replacements from killing newer children.
const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("../../state/store/common.zig");
const Allocator = std.mem.Allocator;

fn ensureSchema(db: *sqlite.Db) !void {
    try db.exec("CREATE TABLE IF NOT EXISTS local_service_owners (app TEXT NOT NULL, service TEXT NOT NULL, token TEXT NOT NULL, generation INTEGER NOT NULL, PRIMARY KEY(app, service));", .{}, .{});
    try db.exec("CREATE UNIQUE INDEX IF NOT EXISTS local_service_active_name ON local_service_owners(service) WHERE token != '';", .{}, .{});
    try db.exec("CREATE TABLE IF NOT EXISTS local_service_instances (container TEXT PRIMARY KEY, app TEXT NOT NULL, service TEXT NOT NULL, generation INTEGER NOT NULL);", .{}, .{});
}

pub fn claim(app: []const u8, service: []const u8, token: []const u8) !void {
    var db = try common.leaseDb();
    defer db.deinit();
    try ensureSchema(db.db);
    try assertAvailableInDb(db.db, app, service);
    try db.db.exec("INSERT INTO local_service_owners (app, service, token, generation) VALUES (?, ?, ?, 1) ON CONFLICT(app, service) DO UPDATE SET generation = CASE WHEN token = excluded.token THEN generation ELSE generation + 1 END, token = excluded.token;", .{}, .{ app, service, token });
}

pub fn assertAvailable(app: []const u8, service: []const u8) !void {
    var db = try common.leaseDb();
    defer db.deinit();
    try ensureSchema(db.db);
    try assertAvailableInDb(db.db, app, service);
}

fn assertAvailableInDb(db: *sqlite.Db, app: []const u8, service: []const u8) !void {
    const Row = struct { count: i64 };
    const owners = try db.one(Row, "SELECT COUNT(*) AS count FROM local_service_owners WHERE service = ? AND app != ? AND token != '';", .{}, .{ service, app });
    if (owners.?.count > 0) return error.ServiceNameInUse;
    const containers = try db.one(Row, "SELECT COUNT(*) AS count FROM containers WHERE hostname = ? AND coalesce(app_name, '') != ? AND status IN ('created', 'running');", .{}, .{ service, app });
    if (containers.?.count > 0) return error.ServiceNameInUse;
}

pub fn isOwner(app: []const u8, service: []const u8, token: []const u8) !bool {
    var db = try common.leaseDb();
    defer db.deinit();
    try ensureSchema(db.db);
    return (try db.db.one(struct { generation: i64 }, "SELECT generation FROM local_service_owners WHERE app = ? AND service = ? AND token = ?;", .{}, .{ app, service, token })) != null;
}

pub fn release(app: []const u8, service: []const u8, token: []const u8) !void {
    var db = try common.leaseDb();
    defer db.deinit();
    try ensureSchema(db.db);
    // retain the generation counter so a later owner is newer than every child
    // left behind by a failed cleanup or an interrupted supervisor.
    try db.db.exec("UPDATE local_service_owners SET token = '' WHERE app = ? AND service = ? AND token = ?;", .{}, .{ app, service, token });
}

pub fn registerInstance(app: []const u8, service: []const u8, token: []const u8, container: []const u8) !void {
    var db = try common.leaseDb();
    defer db.deinit();
    try ensureSchema(db.db);
    try db.db.exec("INSERT INTO local_service_instances (container, app, service, generation) SELECT ?, app, service, generation FROM local_service_owners WHERE app = ? AND service = ? AND token = ?;", .{}, .{ container, app, service, token });
    if (db.db.rowsAffected() != 1) return error.SupervisorSuperseded;
}

pub fn removeInstance(container: []const u8) !void {
    var db = try common.leaseDb();
    defer db.deinit();
    try ensureSchema(db.db);
    try db.db.exec("DELETE FROM local_service_instances WHERE container = ?;", .{}, .{container});
}

pub fn instanceExists(container: []const u8) !bool {
    var db = try common.leaseDb();
    defer db.deinit();
    try ensureSchema(db.db);
    return (try db.db.one(struct { generation: i64 }, "SELECT generation FROM local_service_instances WHERE container = ?;", .{}, .{container})) != null;
}

pub fn priorInstances(alloc: Allocator, app: []const u8, service: []const u8, token: []const u8) !std.ArrayList([]const u8) {
    var db = try common.leaseDb();
    defer db.deinit();
    try ensureSchema(db.db);
    var result: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (result.items) |id| alloc.free(id);
        result.deinit(alloc);
    }
    var query = try db.db.prepare("SELECT i.container AS id FROM local_service_instances i JOIN local_service_owners o ON o.app = i.app AND o.service = i.service WHERE o.app = ? AND o.service = ? AND o.token = ? AND i.generation < o.generation UNION SELECT c.id FROM containers c LEFT JOIN local_service_instances i ON i.container = c.id JOIN local_service_owners o ON o.app = c.app_name AND o.service = c.hostname WHERE o.app = ? AND o.service = ? AND o.token = ? AND i.container IS NULL;");
    defer query.deinit();
    var rows = try query.iterator(struct { id: sqlite.Text }, .{ app, service, token, app, service, token });
    while (try rows.nextAlloc(alloc, .{})) |row| {
        result.append(alloc, row.id.data) catch |err| {
            alloc.free(row.id.data);
            return err;
        };
    }
    return result;
}

test "replacement generations reject stale restarts and preserve the current owner" {
    const store = @import("../../state/store.zig");
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();
    try claim("app", "web", "old");
    try registerInstance("app", "web", "old", "old-instance");
    try store.save(.{ .id = "old-instance", .rootfs = "", .command = "serve", .hostname = "web", .status = "running", .pid = null, .exit_code = null, .app_name = "app", .created_at = 1 });
    try claim("app", "web", "new");
    try registerInstance("app", "web", "new", "new-instance");
    try store.save(.{ .id = "new-instance", .rootfs = "", .command = "serve", .hostname = "web", .status = "running", .pid = null, .exit_code = null, .app_name = "app", .created_at = 2 });

    const StaleSupervisor = struct {
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            verify() catch |err| {
                self.failure = err;
            };
        }

        fn verify() !void {
            try std.testing.expect(!try isOwner("app", "web", "old"));
            try std.testing.expectError(error.SupervisorSuperseded, registerInstance("app", "web", "old", "resurrected!"));
            try release("app", "web", "old");
        }
    };
    var old_supervisor: StaleSupervisor = .{};
    const stale = try std.Thread.spawn(.{}, StaleSupervisor.run, .{&old_supervisor});
    stale.join();
    if (old_supervisor.failure) |err| return err;
    try std.testing.expect(try isOwner("app", "web", "new"));
    var previous = try priorInstances(alloc, "app", "web", "new");
    defer {
        for (previous.items) |id| alloc.free(id);
        previous.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 1), previous.items.len);
    try std.testing.expectEqualStrings("old-instance", previous.items[0]);
    var retired = try priorInstances(alloc, "app", "web", "old");
    defer retired.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 0), retired.items.len);
    try release("app", "web", "new");
    try claim("app", "web", "third");
    var leftovers = try priorInstances(alloc, "app", "web", "third");
    defer {
        for (leftovers.items) |id| alloc.free(id);
        leftovers.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 2), leftovers.items.len);
}

test "global service names reject a different active app" {
    const store = @import("../../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    try claim("first", "web", "first-owner");
    try std.testing.expectError(error.ServiceNameInUse, assertAvailable("second", "web"));
    try std.testing.expectError(error.ServiceNameInUse, claim("second", "web", "second-owner"));
    try claim("first", "web", "replacement");
    try release("first", "web", "first-owner");
    try std.testing.expectError(error.ServiceNameInUse, claim("second", "web", "second-owner"));
    try release("first", "web", "replacement");
    try claim("second", "web", "second-owner");
    try std.testing.expect(try isOwner("second", "web", "second-owner"));
}
