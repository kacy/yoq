// local rank ownership survives controller exits and manifest changes.
// container names are display values, not evidence that a job owns a process.
const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("../../state/store/common.zig");
const Allocator = std.mem.Allocator;

pub fn register(app: []const u8, job: []const u8, job_id: []const u8, container_id: []const u8, rank: u32) !void {
    var lease = try common.leaseDb();
    defer lease.deinit();
    try lease.db.exec("INSERT INTO local_training_ranks (container_id, app_name, job_name, job_id, rank) SELECT id, ?, ?, ?, ? FROM containers WHERE id = ? AND app_name = ?;", .{}, .{ app, job, job_id, rank, container_id, app });
    if (lease.db.rowsAffected() != 1) return error.ContainerMissing;
}

/// a null job id selects prior runs and requires the caller's controller lock.
pub fn listOwned(alloc: Allocator, app: []const u8, job: []const u8, job_id: ?[]const u8) !std.ArrayList([]const u8) {
    var lease = try common.leaseDb();
    defer lease.deinit();
    var ids: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }
    var query = try lease.db.prepare("SELECT r.container_id FROM local_training_ranks r JOIN containers c ON c.id = r.container_id AND c.app_name = r.app_name WHERE r.app_name = ? AND r.job_name = ? AND (? IS NULL OR r.job_id = ?) ORDER BY r.container_id;");
    defer query.deinit();
    var rows = try query.iterator(struct { container_id: sqlite.Text }, .{ app, job, job_id, job_id });
    while (try rows.nextAlloc(alloc, .{})) |row| {
        ids.append(alloc, row.container_id.data) catch |err| {
            alloc.free(row.container_id.data);
            return err;
        };
    }
    return ids;
}

fn expectOwned(app: []const u8, job: []const u8, job_id: ?[]const u8, expected: []const []const u8) !void {
    var ids = try listOwned(std.testing.allocator, app, job, job_id);
    defer {
        for (ids.items) |id| std.testing.allocator.free(id);
        ids.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(expected.len, ids.items.len);
    for (expected, ids.items) |want, got| try std.testing.expectEqualStrings(want, got);
}

test "training rank ownership excludes ordinary services and other runs" {
    const store = @import("../../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    // identical names remain ambiguous across releases, even when one record
    // predates the current controller and another belongs to another app.
    for ([_][]const u8{ "ordinary-old", "ordinary-current", "rank-old", "rank-new", "rank-stale", "other-app", "other-job" }) |id| {
        try store.save(.{ .id = id, .rootfs = "/", .command = "true", .hostname = "train-rank-0", .status = "created", .pid = null, .exit_code = null, .app_name = if (std.mem.eql(u8, id, "other-app")) "other" else "demo", .created_at = 0 });
    }
    try register("demo", "train", "old-run", "rank-old", 0);
    try register("demo", "train", "old-run", "rank-stale", 17);
    try register("demo", "train", "new-run", "rank-new", 0);
    try register("other", "train", "old-run", "other-app", 0);
    try register("demo", "another-job", "old-run", "other-job", 0);
    try expectOwned("demo", "train", "old-run", &.{ "rank-old", "rank-stale" });
    try expectOwned("demo", "train", "new-run", &.{"rank-new"});
    try expectOwned("demo", "train", null, &.{ "rank-new", "rank-old", "rank-stale" });
    try std.testing.expectError(error.ContainerMissing, register("wrong-app", "train", "old-run", "ordinary-old", 0));
}

test "training rank ownership is removed atomically with its container" {
    const store = @import("../../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    try store.save(.{ .id = "rank", .rootfs = "/", .command = "true", .hostname = "train-rank-0", .status = "created", .pid = null, .exit_code = null, .app_name = "demo", .created_at = 0 });
    try register("demo", "train", "run", "rank", 0);
    try store.remove("rank");
    // reusing an id must not inherit the deleted container's ownership.
    try store.save(.{ .id = "rank", .rootfs = "/", .command = "true", .hostname = "train-rank-0", .status = "created", .pid = null, .exit_code = null, .app_name = "demo", .created_at = 1 });
    try expectOwned("demo", "train", null, &.{});
    try std.testing.expectError(error.ContainerMissing, register("demo", "train", "run", "missing", 0));
    var lease = try common.leaseDb();
    defer lease.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try lease.db.one(i64, "SELECT COUNT(*) FROM local_training_ranks;", .{}, .{})).?);
}
