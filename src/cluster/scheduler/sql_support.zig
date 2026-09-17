const std = @import("std");
const linux_platform = @import("linux_platform");
const sql_escape = @import("../../lib/sql.zig");
const gpu_scheduler = @import("../../gpu/scheduler.zig");
const common = @import("common.zig");

pub const PlacementRequest = common.PlacementRequest;

pub fn assignmentSql(
    buf: []u8,
    id: []const u8,
    agent_id: []const u8,
    request: PlacementRequest,
    now: i64,
) ![]const u8 {
    return assignmentSqlGang(buf, id, agent_id, request, now, null);
}

pub fn assignmentSqlGang(
    buf: []u8,
    id: []const u8,
    agent_id: []const u8,
    request: PlacementRequest,
    now: i64,
    gang: ?gpu_scheduler.GangPlacement,
) ![]const u8 {
    var img_esc_buf: [512]u8 = undefined;
    const img_esc = try sql_escape.escapeSqlString(&img_esc_buf, request.image);
    var cmd_esc_buf: [@import("../assignment_spec.zig").max_encoded_bytes * 2]u8 = undefined;
    const cmd_esc = try sql_escape.escapeSqlString(&cmd_esc_buf, request.command);
    var metadata_values_buf: [768]u8 = undefined;
    const metadata = try assignmentMetadata(&metadata_values_buf, request);

    if (gang) |placement| {
        var master_esc_buf: [256]u8 = undefined;
        const master_esc = try sql_escape.escapeSqlString(&master_esc_buf, placement.master_addr);
        return std.fmt.bufPrint(buf,
            \\INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, gang_rank, gang_world_size, gang_master_addr, gang_master_port, created_at{s})
            \\ VALUES ('{s}', '{s}', '{s}', '{s}', 'pending', {d}, {d}, {d}, {d}, '{s}', {d}, {d}{s});
        , .{ metadata.columns, id, agent_id, img_esc, cmd_esc, request.cpu_limit, request.memory_limit_mb, placement.rank, placement.world_size, master_esc, placement.master_port, now, metadata.values });
    }

    return std.fmt.bufPrint(buf,
        \\INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, created_at{s})
        \\ VALUES ('{s}', '{s}', '{s}', '{s}', 'pending', {d}, {d}, {d}{s});
    , .{ metadata.columns, id, agent_id, img_esc, cmd_esc, request.cpu_limit, request.memory_limit_mb, now, metadata.values });
}

const AssignmentMetadata = struct {
    columns: []const u8 = "",
    values: []const u8 = "",
};

// include metadata only when all three workload identifiers are present.
// the returned values slice borrows buf. column names follow the same field order.
fn assignmentMetadata(buf: []u8, request: PlacementRequest) !AssignmentMetadata {
    const app_name = request.app_name orelse return .{};
    const workload_kind = request.workload_kind orelse return .{};
    const workload_name = request.workload_name orelse return .{};

    var app_buf: [256]u8 = undefined;
    var kind_buf: [64]u8 = undefined;
    var name_buf: [256]u8 = undefined;
    const escaped_app = try sql_escape.escapeSqlString(&app_buf, app_name);
    const escaped_kind = try sql_escape.escapeSqlString(&kind_buf, workload_kind);
    const escaped_name = try sql_escape.escapeSqlString(&name_buf, workload_name);

    if (request.health_check_json) |health_check_json| {
        var health_buf: [1024]u8 = undefined;
        const escaped_health = try sql_escape.escapeSqlString(&health_buf, health_check_json);
        return .{
            .columns = ", app_name, workload_kind, workload_name, health_check_json",
            .values = try std.fmt.bufPrint(buf, ", '{s}', '{s}', '{s}', '{s}'", .{
                escaped_app, escaped_kind, escaped_name, escaped_health,
            }),
        };
    }

    return .{
        .columns = ", app_name, workload_kind, workload_name",
        .values = try std.fmt.bufPrint(buf, ", '{s}', '{s}', '{s}'", .{
            escaped_app, escaped_kind, escaped_name,
        }),
    };
}

pub fn generateAssignmentId(buf: *[12]u8) void {
    var random_bytes: [6]u8 = undefined;
    linux_platform.randomBytes(&random_bytes);
    const hex = "0123456789abcdef";
    for (random_bytes, 0..) |byte, i| {
        buf[i * 2] = hex[byte >> 4];
        buf[i * 2 + 1] = hex[byte & 0x0f];
    }
}

test "assignmentSql includes service health check metadata when present" {
    var buf: [2048]u8 = undefined;
    const sql = try assignmentSql(
        &buf,
        "assign123456",
        "agent123456",
        .{
            .image = "nginx:latest",
            .command = "nginx -g daemon off",
            .health_check_json = "{\"kind\":\"http\",\"path\":\"/ready\",\"port\":8080}",
            .cpu_limit = 1000,
            .memory_limit_mb = 256,
            .app_name = "demo-app",
            .workload_kind = "service",
            .workload_name = "web",
        },
        100,
    );

    try std.testing.expect(std.mem.indexOf(u8, sql, "health_check_json") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "\"kind\":\"http\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sql, "\"path\":\"/ready\"") != null);
}

test "assignmentSql escapes workload metadata without a health check" {
    var buf: [2048]u8 = undefined;
    const sql = try assignmentSql(&buf, "assignment", "agent", .{
        .image = "nginx",
        .command = "",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
        .app_name = "team's app",
        .workload_kind = "worker's kind",
        .workload_name = "worker's name",
    }, 100);

    try std.testing.expectEqualStrings(
        \\INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, created_at, app_name, workload_kind, workload_name)
        \\ VALUES ('assignment', 'agent', 'nginx', '', 'pending', 1000, 256, 100, 'team''s app', 'worker''s kind', 'worker''s name');
    , sql);
}

test "assignmentSql omits metadata when any workload identifier is missing" {
    const request = PlacementRequest{
        .image = "nginx",
        .command = "",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
        .app_name = "demo",
        .workload_kind = "service",
        .workload_name = "web",
        .health_check_json = "{}",
    };

    var incomplete_requests = [_]PlacementRequest{request} ** 3;
    incomplete_requests[0].app_name = null;
    incomplete_requests[1].workload_kind = null;
    incomplete_requests[2].workload_name = null;

    for (incomplete_requests) |incomplete| {
        var buf: [2048]u8 = undefined;
        const sql = try assignmentSql(&buf, "assignment", "agent", incomplete, 100);
        try std.testing.expectEqualStrings(
            \\INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, created_at)
            \\ VALUES ('assignment', 'agent', 'nginx', '', 'pending', 1000, 256, 100);
        , sql);
    }
}

test "assignmentSqlGang preserves metadata order and escapes health checks" {
    var buf: [2048]u8 = undefined;
    const sql = try assignmentSqlGang(&buf, "assignment", "agent", .{
        .image = "training",
        .command = "",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
        .app_name = "demo",
        .workload_kind = "training",
        .workload_name = "trainer",
        .health_check_json = "{\"path\":\"/worker's-health\"}",
    }, 100, .{
        .agent_id = "agent",
        .rank = 1,
        .gpu_start = 2,
        .gpu_count = 2,
        .world_size = 4,
        .master_addr = "master's-host",
        .master_port = 29500,
    });

    try std.testing.expectEqualStrings(
        \\INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, gang_rank, gang_world_size, gang_master_addr, gang_master_port, created_at, app_name, workload_kind, workload_name, health_check_json)
        \\ VALUES ('assignment', 'agent', 'training', '', 'pending', 1000, 256, 1, 4, 'master''s-host', 29500, 100, 'demo', 'training', 'trainer', '{"path":"/worker''s-health"}');
    , sql);
}

test "assignmentSql rejects metadata that exceeds its value buffer" {
    var buf: [2048]u8 = undefined;
    // the escaped health check fits its own buffer, but not the metadata buffer.
    const health_check = "x" ** 768;
    try std.testing.expectError(error.NoSpaceLeft, assignmentSql(&buf, "assignment", "agent", .{
        .image = "nginx",
        .command = "",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
        .app_name = "demo",
        .workload_kind = "service",
        .workload_name = "web",
        .health_check_json = health_check,
    }, 100));
}
