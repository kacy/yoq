const std = @import("std");
const agent_types = @import("../agent_types.zig");
const sql_escape = @import("../../lib/sql.zig");

pub const AgentResources = agent_types.AgentResources;

pub const RegisterOpts = struct {
    agent_api_port: ?u16 = null,
    node_id: ?u16 = null,
    wg_public_key: ?[]const u8 = null,
    overlay_ip: ?[]const u8 = null,
    role: ?[]const u8 = null,
    region: ?[]const u8 = null,
    labels: ?[]const u8 = null,
};

pub fn registerSql(
    buf: []u8,
    id: []const u8,
    address: []const u8,
    resources: AgentResources,
    now: i64,
) ![]const u8 {
    return registerSqlFull(buf, id, address, resources, now, .{});
}

pub fn registerSqlFull(
    buf: []u8,
    id: []const u8,
    address: []const u8,
    resources: AgentResources,
    now: i64,
    opts: RegisterOpts,
) ![]const u8 {
    const node_id = opts.node_id;
    const agent_api_port = opts.agent_api_port;
    const wg_public_key = opts.wg_public_key;
    const overlay_ip = opts.overlay_ip;
    const role = opts.role;
    const region = opts.region;
    const labels = opts.labels;

    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);
    var addr_esc_buf: [512]u8 = undefined;
    const addr_esc = try sql_escape.escapeSqlString(&addr_esc_buf, address);

    var role_esc_buf: [32]u8 = undefined;
    const role_esc = try sql_escape.escapeSqlString(&role_esc_buf, role orelse "both");
    var region_esc_buf: [128]u8 = undefined;
    const region_val = region orelse "";
    var labels_esc_buf: [512]u8 = undefined;
    const labels_esc = try sql_escape.escapeSqlString(&labels_esc_buf, labels orelse "");

    var model_esc_buf: [128]u8 = undefined;
    const model_esc = if (resources.gpu_model) |model|
        try sql_escape.escapeSqlString(&model_esc_buf, model)
    else
        "";
    const vram_mb: u64 = resources.gpu_vram_mb;

    var gpu_cols_buf: [128]u8 = undefined;
    var gpu_vals_buf: [256]u8 = undefined;
    const gpu_cols = if (resources.gpu_model != null)
        try std.fmt.bufPrint(&gpu_cols_buf, ", gpu_count, gpu_used, gpu_model, gpu_vram_mb", .{})
    else
        try std.fmt.bufPrint(&gpu_cols_buf, ", gpu_count, gpu_used", .{});
    const gpu_vals = if (resources.gpu_model != null)
        try std.fmt.bufPrint(&gpu_vals_buf, ", {d}, {d}, '{s}', {d}", .{ resources.gpu_count, resources.gpu_used, model_esc, vram_mb })
    else
        try std.fmt.bufPrint(&gpu_vals_buf, ", {d}, {d}", .{ resources.gpu_count, resources.gpu_used });

    if (node_id) |nid| {
        var key_esc_buf: [128]u8 = undefined;
        const key_esc = try sql_escape.escapeSqlString(&key_esc_buf, wg_public_key orelse "");
        var ip_esc_buf: [64]u8 = undefined;
        const ip_esc = try sql_escape.escapeSqlString(&ip_esc_buf, overlay_ip orelse "");

        if (region_val.len > 0) {
            const reg_esc = try sql_escape.escapeSqlString(&region_esc_buf, region_val);
            return std.fmt.bufPrint(
                buf,
                "INSERT INTO agents (id, address, agent_api_port, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, node_id, wg_public_key, overlay_ip, role, region, labels{s})" ++
                    " VALUES ('{s}', '{s}', {any}, 'active', {d}, {d}, 0, 0, 0, {d}, {d}, {d}, '{s}', '{s}', '{s}', '{s}', '{s}'{s});",
                .{ gpu_cols, id_esc, addr_esc, agent_api_port, resources.cpu_cores, resources.memory_mb, now, now, nid, key_esc, ip_esc, role_esc, reg_esc, labels_esc, gpu_vals },
            );
        }
        return std.fmt.bufPrint(
            buf,
            "INSERT INTO agents (id, address, agent_api_port, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, node_id, wg_public_key, overlay_ip, role, labels{s})" ++
                " VALUES ('{s}', '{s}', {any}, 'active', {d}, {d}, 0, 0, 0, {d}, {d}, {d}, '{s}', '{s}', '{s}', '{s}'{s});",
            .{ gpu_cols, id_esc, addr_esc, agent_api_port, resources.cpu_cores, resources.memory_mb, now, now, nid, key_esc, ip_esc, role_esc, labels_esc, gpu_vals },
        );
    }

    if (region_val.len > 0) {
        const reg_esc = try sql_escape.escapeSqlString(&region_esc_buf, region_val);
        return std.fmt.bufPrint(
            buf,
            "INSERT INTO agents (id, address, agent_api_port, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role, region, labels{s})" ++
                " VALUES ('{s}', '{s}', {any}, 'active', {d}, {d}, 0, 0, 0, {d}, {d}, '{s}', '{s}', '{s}'{s});",
            .{ gpu_cols, id_esc, addr_esc, agent_api_port, resources.cpu_cores, resources.memory_mb, now, now, role_esc, reg_esc, labels_esc, gpu_vals },
        );
    }

    return std.fmt.bufPrint(
        buf,
        "INSERT INTO agents (id, address, agent_api_port, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role, labels{s})" ++
            " VALUES ('{s}', '{s}', {any}, 'active', {d}, {d}, 0, 0, 0, {d}, {d}, '{s}', '{s}'{s});",
        .{ gpu_cols, id_esc, addr_esc, agent_api_port, resources.cpu_cores, resources.memory_mb, now, now, role_esc, labels_esc, gpu_vals },
    );
}

pub fn heartbeatSql(
    buf: []u8,
    id: []const u8,
    resources: AgentResources,
    now: i64,
) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);

    const health_raw = resources.gpu_health.slice();
    var health_esc_buf: [256]u8 = undefined;
    const health_esc = if (health_raw.len > 0)
        try sql_escape.escapeSqlString(&health_esc_buf, health_raw)
    else
        "healthy";

    return std.fmt.bufPrint(buf,
        \\UPDATE agents SET cpu_used = {d}, memory_used_mb = {d}, containers = {d}, gpu_used = {d}, gpu_health = '{s}', last_heartbeat = {d},
        \\ status = CASE WHEN status = 'offline' THEN 'active' ELSE status END
        \\ WHERE id = '{s}';
    , .{ resources.cpu_used, resources.memory_used_mb, resources.containers, resources.gpu_used, health_esc, now, id_esc });
}

pub fn drainSql(buf: []u8, id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);
    return std.fmt.bufPrint(buf, "UPDATE agents SET status = 'draining' WHERE id = '{s}';", .{id_esc});
}

pub fn updateAssignmentStatusSql(buf: []u8, assignment_id: []const u8, new_status: []const u8, reason: ?[]const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, assignment_id);
    var status_esc_buf: [64]u8 = undefined;
    const status_esc = try sql_escape.escapeSqlString(&status_esc_buf, new_status);
    var reason_esc_buf: [128]u8 = undefined;
    if (reason) |status_reason| {
        const reason_esc = try sql_escape.escapeSqlString(&reason_esc_buf, status_reason);
        return std.fmt.bufPrint(buf, "UPDATE assignments SET status = '{s}', status_reason = '{s}' WHERE id = '{s}';", .{ status_esc, reason_esc, id_esc });
    }
    return std.fmt.bufPrint(buf, "UPDATE assignments SET status = '{s}', status_reason = NULL WHERE id = '{s}';", .{ status_esc, id_esc });
}

pub fn markOfflineSql(buf: []u8, id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);
    return std.fmt.bufPrint(buf, "UPDATE agents SET status = 'offline' WHERE id = '{s}';", .{id_esc});
}

pub fn markActiveSql(buf: []u8, id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);
    return std.fmt.bufPrint(buf, "UPDATE agents SET status = 'active' WHERE id = '{s}' AND status = 'offline';", .{id_esc});
}

pub fn updateLabelsSql(buf: []u8, id: []const u8, labels: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);
    var labels_esc_buf: [512]u8 = undefined;
    const labels_esc = try sql_escape.escapeSqlString(&labels_esc_buf, labels);
    return std.fmt.bufPrint(buf, "UPDATE agents SET labels = '{s}' WHERE id = '{s}';", .{ labels_esc, id_esc });
}

pub fn removeSql(buf: []u8, id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);
    return std.fmt.bufPrint(buf, "DELETE FROM agents WHERE id = '{s}';", .{id_esc});
}

pub fn orphanAssignmentsSql(buf: []u8, agent_id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, agent_id);
    return std.fmt.bufPrint(
        buf,
        "UPDATE assignments SET agent_id = '', status = 'pending' WHERE agent_id = '{s}' AND status IN ('pending', 'running');",
        .{id_esc},
    );
}

pub fn reassignSql(buf: []u8, assignment_id: []const u8, new_agent_id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, assignment_id);
    var agent_esc_buf: [64]u8 = undefined;
    const agent_esc = try sql_escape.escapeSqlString(&agent_esc_buf, new_agent_id);
    return std.fmt.bufPrint(
        buf,
        "UPDATE assignments SET agent_id = '{s}' WHERE id = '{s}' AND agent_id = '';",
        .{ agent_esc, id_esc },
    );
}

pub fn deleteAgentAssignmentsSql(buf: []u8, agent_id: []const u8) ![]const u8 {
    var id_esc_buf: [64]u8 = undefined;
    const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, agent_id);
    return std.fmt.bufPrint(buf, "DELETE FROM assignments WHERE agent_id = '{s}';", .{id_esc});
}

pub fn deleteAssignmentsForWorkloadSql(
    buf: []u8,
    app_name: []const u8,
    workload_kind: []const u8,
    workload_name: []const u8,
) ![]const u8 {
    var app_esc_buf: [256]u8 = undefined;
    const app_esc = try sql_escape.escapeSqlString(&app_esc_buf, app_name);
    var kind_esc_buf: [64]u8 = undefined;
    const kind_esc = try sql_escape.escapeSqlString(&kind_esc_buf, workload_kind);
    var name_esc_buf: [256]u8 = undefined;
    const name_esc = try sql_escape.escapeSqlString(&name_esc_buf, workload_name);
    return std.fmt.bufPrint(
        buf,
        "DELETE FROM assignments WHERE app_name = '{s}' AND workload_kind = '{s}' AND workload_name = '{s}';",
        .{ app_esc, kind_esc, name_esc },
    );
}

pub fn deleteOtherAssignmentsForWorkloadSql(
    buf: []u8,
    app_name: []const u8,
    workload_kind: []const u8,
    workload_name: []const u8,
    keep_ids: []const []const u8,
) ![]const u8 {
    var stream: std.Io.Writer = .fixed(buf);
    const writer = &stream;

    var app_esc_buf: [256]u8 = undefined;
    const app_esc = try sql_escape.escapeSqlString(&app_esc_buf, app_name);
    var kind_esc_buf: [64]u8 = undefined;
    const kind_esc = try sql_escape.escapeSqlString(&kind_esc_buf, workload_kind);
    var name_esc_buf: [256]u8 = undefined;
    const name_esc = try sql_escape.escapeSqlString(&name_esc_buf, workload_name);

    try writer.print(
        "DELETE FROM assignments WHERE app_name = '{s}' AND workload_kind = '{s}' AND workload_name = '{s}'",
        .{ app_esc, kind_esc, name_esc },
    );
    if (keep_ids.len > 0) {
        try writer.writeAll(" AND id NOT IN (");
        for (keep_ids, 0..) |id, i| {
            if (i > 0) try writer.writeAll(", ");
            var id_esc_buf: [64]u8 = undefined;
            const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);
            try writer.print("'{s}'", .{id_esc});
        }
        try writer.writeByte(')');
    }
    try writer.writeByte(';');
    return stream.buffered();
}

pub fn deleteAssignmentsByIdsSql(
    buf: []u8,
    assignment_ids: []const []const u8,
) ![]const u8 {
    var stream: std.Io.Writer = .fixed(buf);
    const writer = &stream;

    try writer.writeAll("DELETE FROM assignments");
    if (assignment_ids.len > 0) {
        try writer.writeAll(" WHERE id IN (");
        for (assignment_ids, 0..) |id, i| {
            if (i > 0) try writer.writeAll(", ");
            var id_esc_buf: [64]u8 = undefined;
            const id_esc = try sql_escape.escapeSqlString(&id_esc_buf, id);
            try writer.print("'{s}'", .{id_esc});
        }
        try writer.writeByte(')');
    } else {
        try writer.writeAll(" WHERE 1 = 0");
    }
    try writer.writeByte(';');
    return stream.buffered();
}

pub fn wireguardPeerSql(
    buf: []u8,
    node_id: u16,
    agent_id: []const u8,
    public_key: []const u8,
    endpoint: []const u8,
    overlay_ip: []const u8,
    container_subnet: []const u8,
) ![]const u8 {
    var agent_esc_buf: [64]u8 = undefined;
    const agent_esc = try sql_escape.escapeSqlString(&agent_esc_buf, agent_id);
    var key_esc_buf: [128]u8 = undefined;
    const key_esc = try sql_escape.escapeSqlString(&key_esc_buf, public_key);
    var ep_esc_buf: [128]u8 = undefined;
    const ep_esc = try sql_escape.escapeSqlString(&ep_esc_buf, endpoint);
    var ip_esc_buf: [64]u8 = undefined;
    const ip_esc = try sql_escape.escapeSqlString(&ip_esc_buf, overlay_ip);
    var subnet_esc_buf: [64]u8 = undefined;
    const subnet_esc = try sql_escape.escapeSqlString(&subnet_esc_buf, container_subnet);

    return std.fmt.bufPrint(buf,
        \\INSERT INTO wireguard_peers (node_id, agent_id, public_key, endpoint, overlay_ip, container_subnet)
        \\ VALUES ({d}, '{s}', '{s}', '{s}', '{s}', '{s}');
    , .{ node_id, agent_esc, key_esc, ep_esc, ip_esc, subnet_esc });
}

pub fn removeWireguardPeerSql(buf: []u8, node_id: u16) ![]const u8 {
    return std.fmt.bufPrint(buf, "DELETE FROM wireguard_peers WHERE node_id = {d};", .{node_id});
}
