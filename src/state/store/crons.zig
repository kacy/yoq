const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

pub const CronScheduleRecord = struct {
    app_name: []const u8,
    name: []const u8,
    every: i64,
    spec_json: []const u8,
    created_at: i64,
    updated_at: i64,

    pub fn deinit(self: CronScheduleRecord, alloc: Allocator) void {
        alloc.free(self.app_name);
        alloc.free(self.name);
        alloc.free(self.spec_json);
    }
};

const cron_columns =
    "app_name, name, every, spec_json, created_at, updated_at";

const CronScheduleRow = struct {
    app_name: sqlite.Text,
    name: sqlite.Text,
    every: i64,
    spec_json: sqlite.Text,
    created_at: i64,
    updated_at: i64,
};

fn rowToRecord(row: CronScheduleRow) CronScheduleRecord {
    return .{
        .app_name = row.app_name.data,
        .name = row.name.data,
        .every = row.every,
        .spec_json = row.spec_json.data,
        .created_at = row.created_at,
        .updated_at = row.updated_at,
    };
}

pub fn replaceCronSchedulesForApp(
    alloc: Allocator,
    app_name: []const u8,
    schedules: []const @import("../../manifest/app_snapshot.zig").CronScheduleSpec,
    now: i64,
) StoreError!void {
    const Context = struct {
        alloc: Allocator,
        app_name: []const u8,
        schedules: []const @import("../../manifest/app_snapshot.zig").CronScheduleSpec,
        now: i64,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!void {
            return replaceCronSchedulesForAppInDb(db, ctx.alloc, ctx.app_name, ctx.schedules, ctx.now);
        }
    };

    var ctx = Context{ .alloc = alloc, .app_name = app_name, .schedules = schedules, .now = now };
    return common.withDb(void, &ctx, Context.run);
}

pub fn replaceCronSchedulesForAppInDb(
    db: *sqlite.Db,
    alloc: Allocator,
    app_name: []const u8,
    schedules: []const @import("../../manifest/app_snapshot.zig").CronScheduleSpec,
    now: i64,
) StoreError!void {
    db.exec("DELETE FROM cron_schedules WHERE app_name = ?;", .{}, .{app_name}) catch return StoreError.WriteFailed;

    for (schedules) |schedule| {
        db.exec(
            "INSERT INTO cron_schedules (" ++ cron_columns ++ ") VALUES (?, ?, ?, ?, ?, ?);",
            .{},
            .{
                app_name,
                schedule.name,
                @as(i64, @intCast(schedule.every)),
                schedule.spec_json,
                now,
                now,
            },
        ) catch return StoreError.WriteFailed;
    }

    _ = alloc;
}

pub fn listCronSchedulesByApp(alloc: Allocator, app_name: []const u8) StoreError!std.ArrayList(CronScheduleRecord) {
    const Context = struct {
        alloc: Allocator,
        app_name: []const u8,

        fn run(ctx: *@This(), db: *sqlite.Db) StoreError!std.ArrayList(CronScheduleRecord) {
            return listCronSchedulesByAppInDb(db, ctx.alloc, ctx.app_name);
        }
    };

    var ctx = Context{ .alloc = alloc, .app_name = app_name };
    return common.withDb(std.ArrayList(CronScheduleRecord), &ctx, Context.run);
}

pub fn listCronSchedulesByAppInDb(
    db: *sqlite.Db,
    alloc: Allocator,
    app_name: []const u8,
) StoreError!std.ArrayList(CronScheduleRecord) {
    var records: std.ArrayList(CronScheduleRecord) = .empty;
    var stmt = db.prepare(
        "SELECT " ++ cron_columns ++ " FROM cron_schedules WHERE app_name = ? ORDER BY name ASC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(CronScheduleRow, .{app_name}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        records.append(alloc, rowToRecord(row)) catch return StoreError.ReadFailed;
    }
    return records;
}

test "replaceCronSchedulesForAppInDb swaps active schedules for app" {
    const alloc = std.testing.allocator;
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try @import("../schema.zig").init(&db);

    const app_snapshot = @import("../../manifest/app_snapshot.zig");
    const first = [_]app_snapshot.CronScheduleSpec{
        .{ .name = "cleanup", .every = 60, .spec_json = "{\"name\":\"cleanup\",\"every\":60}" },
    };
    const second = [_]app_snapshot.CronScheduleSpec{
        .{ .name = "backup", .every = 3600, .spec_json = "{\"name\":\"backup\",\"every\":3600}" },
    };

    try replaceCronSchedulesForAppInDb(&db, alloc, "demo-app", &first, 100);
    try replaceCronSchedulesForAppInDb(&db, alloc, "demo-app", &second, 200);

    var records = try listCronSchedulesByAppInDb(&db, alloc, "demo-app");
    defer {
        for (records.items) |record| record.deinit(alloc);
        records.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), records.items.len);
    try std.testing.expectEqualStrings("backup", records.items[0].name);
    try std.testing.expectEqual(@as(i64, 3600), records.items[0].every);
    try std.testing.expectEqual(@as(i64, 200), records.items[0].updated_at);
}
