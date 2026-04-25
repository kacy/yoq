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
    var cmd_esc_buf: [512]u8 = undefined;
    const cmd_esc = try sql_escape.escapeSqlString(&cmd_esc_buf, request.command);
    var app_esc_buf: [256]u8 = undefined;
    var kind_esc_buf: [64]u8 = undefined;
    var name_esc_buf: [256]u8 = undefined;
    var health_esc_buf: [1024]u8 = undefined;
    var metadata_vals_buf: [768]u8 = undefined;

    const metadata_cols = if (request.app_name != null and request.workload_kind != null and request.workload_name != null)
        if (request.health_check_json != null)
            ", app_name, workload_kind, workload_name, health_check_json"
        else
            ", app_name, workload_kind, workload_name"
    else
        "";
    const metadata_vals = if (request.app_name != null and request.workload_kind != null and request.workload_name != null)
        if (request.health_check_json) |health_check_json|
            try std.fmt.bufPrint(
                &metadata_vals_buf,
                ", '{s}', '{s}', '{s}', '{s}'",
                .{
                    try sql_escape.escapeSqlString(&app_esc_buf, request.app_name.?),
                    try sql_escape.escapeSqlString(&kind_esc_buf, request.workload_kind.?),
                    try sql_escape.escapeSqlString(&name_esc_buf, request.workload_name.?),
                    try sql_escape.escapeSqlString(&health_esc_buf, health_check_json),
                },
            )
        else
            try std.fmt.bufPrint(
                &metadata_vals_buf,
                ", '{s}', '{s}', '{s}'",
                .{
                    try sql_escape.escapeSqlString(&app_esc_buf, request.app_name.?),
                    try sql_escape.escapeSqlString(&kind_esc_buf, request.workload_kind.?),
                    try sql_escape.escapeSqlString(&name_esc_buf, request.workload_name.?),
                },
            )
    else
        "";

    if (gang) |placement| {
        var master_esc_buf: [256]u8 = undefined;
        const master_esc = try sql_escape.escapeSqlString(&master_esc_buf, placement.master_addr);
        return std.fmt.bufPrint(buf,
            \\INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, gang_rank, gang_world_size, gang_master_addr, gang_master_port, created_at{s})
            \\ VALUES ('{s}', '{s}', '{s}', '{s}', 'pending', {d}, {d}, {d}, {d}, '{s}', {d}, {d}{s});
        , .{ metadata_cols, id, agent_id, img_esc, cmd_esc, request.cpu_limit, request.memory_limit_mb, placement.rank, placement.world_size, master_esc, placement.master_port, now, metadata_vals });
    }

    return std.fmt.bufPrint(buf,
        \\INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, created_at{s})
        \\ VALUES ('{s}', '{s}', '{s}', '{s}', 'pending', {d}, {d}, {d}{s});
    , .{ metadata_cols, id, agent_id, img_esc, cmd_esc, request.cpu_limit, request.memory_limit_mb, now, metadata_vals });
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
