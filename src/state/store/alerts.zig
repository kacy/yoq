const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");

pub const Status = struct {
    app: []const u8,
    service: []const u8,
    metric: []const u8,
    state: []const u8,
    active: bool,
    threshold: f64,
    value: ?f64,
    sampled_at: i64,
    sample_error: ?[]const u8,
    delivery: []const u8,
    delivery_error: ?[]const u8,
    delivered_at: ?i64,
    http_status: ?u16,
};

pub fn save(alloc: std.mem.Allocator, status: Status) !void {
    return saveForOwner(alloc, status, null);
}

pub fn saveForOwner(alloc: std.mem.Allocator, status: Status, token: ?[]const u8) !void {
    const json = try std.json.Stringify.valueAlloc(alloc, status, .{});
    defer alloc.free(json);
    var lease = try common.leaseDb();
    defer lease.deinit();
    if (token) |owner| {
        // the ownership test and update share one statement. a late result from
        // an old supervisor cannot overwrite the replacement's status.
        try lease.db.exec(
            "INSERT INTO alert_status (app, service, metric, status_json) SELECT ?, ?, ?, ? " ++
                "WHERE EXISTS (SELECT 1 FROM local_service_owners WHERE app = ? AND service = ? AND token = ?) " ++
                "ON CONFLICT(app, service, metric) DO UPDATE SET status_json = excluded.status_json;",
            .{},
            .{ status.app, status.service, status.metric, json, status.app, status.service, owner },
        );
        return;
    }
    try lease.db.exec(
        "INSERT INTO alert_status (app, service, metric, status_json) VALUES (?, ?, ?, ?) " ++
            "ON CONFLICT(app, service, metric) DO UPDATE SET status_json = excluded.status_json;",
        .{},
        .{ status.app, status.service, status.metric, json },
    );
}

pub fn clearService(app: []const u8, service: []const u8) !void {
    return clearForOwner(app, service, null);
}

pub fn clearForOwner(app: []const u8, service: []const u8, token: ?[]const u8) !void {
    var lease = try common.leaseDb();
    defer lease.deinit();
    if (token) |owner| {
        try lease.db.exec("DELETE FROM alert_status WHERE app = ? AND service = ? AND EXISTS (SELECT 1 FROM local_service_owners WHERE app = ? AND service = ? AND token = ?);", .{}, .{ app, service, app, service, owner });
    } else try lease.db.exec("DELETE FROM alert_status WHERE app = ? AND service = ?;", .{}, .{ app, service });
}

// rows remain after a supervisor exits. sampled_at lets callers identify stale
// samples without presenting an old firing alert as a current measurement.
pub fn listJson(alloc: std.mem.Allocator, app: ?[]const u8) ![]u8 {
    var lease = try common.leaseDb();
    defer lease.deinit();
    var statement = try lease.db.prepare("SELECT status_json FROM alert_status WHERE (? IS NULL OR app = ?) ORDER BY app, service, metric;");
    defer statement.deinit();
    var rows = try statement.iterator(struct { status_json: sqlite.Text }, .{ app, app });
    var output = std.Io.Writer.Allocating.init(alloc);
    defer output.deinit();
    try output.writer.writeByte('[');
    var first = true;
    while (try rows.nextAlloc(alloc, .{})) |row| {
        defer alloc.free(row.status_json.data);
        if (!first) try output.writer.writeByte(',');
        first = false;
        try output.writer.writeAll(row.status_json.data);
    }
    try output.writer.writeByte(']');
    return output.toOwnedSlice();
}

test "alert status persists observations and delivery errors without exposing webhook urls" {
    const store = @import("../store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    var status: Status = .{ .app = "example", .service = "api", .metric = "cpu_percent", .state = "firing", .active = true, .threshold = 80, .value = 91, .sampled_at = 100, .sample_error = null, .delivery = "failed", .delivery_error = "UnexpectedStatus", .delivered_at = null, .http_status = 503 };
    try save(alloc, status);
    status.value = null;
    status.state = "unknown";
    status.sample_error = "no running containers";
    try save(alloc, status);
    const json = try listJson(alloc, "example");
    defer alloc.free(json);
    const parsed = try std.json.parseFromSlice([]Status, alloc, json, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.len);
    try std.testing.expect(parsed.value[0].active);
    try std.testing.expectEqualStrings("UnexpectedStatus", parsed.value[0].delivery_error.?);
    const absent = try listJson(alloc, "other");
    defer alloc.free(absent);
    try std.testing.expectEqualStrings("[]", absent);
}
