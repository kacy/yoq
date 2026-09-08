const std = @import("std");
const sql = @import("sql_command.zig");
const store = @import("../state/store.zig");

pub fn insert(alloc: std.mem.Allocator, record: store.DeploymentRecord) ![]u8 {
    return sql.render(alloc, "INSERT INTO deployments (id, app_name, service_name, trigger, source_release_id, resumed_from_release_id, manifest_hash, config_snapshot, completed_targets, failed_targets, status, message, rollout_control_state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", .{ record.id, record.app_name, record.service_name, record.trigger, record.source_release_id, record.resumed_from_release_id, record.manifest_hash, record.config_snapshot, record.completed_targets, record.failed_targets, record.status, record.message, record.rollout_control_state orelse "active", record.created_at });
}

pub const Progress = struct {
    status: []const u8,
    message: ?[]const u8,
    completed_targets: usize,
    failed_targets: usize,
    failure_details_json: ?[]const u8,
    rollout_targets_json: ?[]const u8,
    rollout_checkpoint_json: ?[]const u8,
};

pub fn progress(alloc: std.mem.Allocator, id: []const u8, update: Progress) ![]u8 {
    const terminal = !std.mem.eql(u8, update.status, "pending") and !std.mem.eql(u8, update.status, "in_progress");
    return sql.render(alloc, "UPDATE deployments SET status = ?, message = ?, completed_targets = ?, failed_targets = ?, failure_details_json = ?, rollout_targets_json = ?, rollout_checkpoint_json = ?, rollout_control_state = COALESCE(?, rollout_control_state) WHERE id = ?;", .{ update.status, update.message, update.completed_targets, update.failed_targets, update.failure_details_json, update.rollout_targets_json, update.rollout_checkpoint_json, @as(?[]const u8, if (terminal) "active" else null), id });
}

pub fn control(alloc: std.mem.Allocator, id: []const u8, state: []const u8) ![]u8 {
    if (!std.mem.eql(u8, state, "active") and !std.mem.eql(u8, state, "paused") and !std.mem.eql(u8, state, "cancel_requested")) return error.InvalidControl;
    return sql.render(alloc, "UPDATE deployments SET rollout_control_state = ? WHERE id = ? AND status IN ('pending', 'in_progress');", .{ state, id });
}
