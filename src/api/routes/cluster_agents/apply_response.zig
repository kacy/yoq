const std = @import("std");

const json_helpers = @import("../../../lib/json_helpers.zig");
const apply_release = @import("../../../manifest/apply_release.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");

pub fn formatLegacy(alloc: std.mem.Allocator, placed: usize, failed: usize) ![]u8 {
    return std.fmt.allocPrint(alloc, "{{\"placed\":{d},\"failed\":{d}}}", .{ placed, failed });
}

pub fn formatApp(
    alloc: std.mem.Allocator,
    report: apply_release.ApplyReport,
    summary: app_snapshot.Summary,
) ![]u8 {
    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();

    const writer = &json_buf_writer.writer;

    try writer.writeByte('{');
    try json_helpers.writeJsonStringField(writer, "app_name", report.app_name);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "trigger", report.trigger.toString());
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "release_id", report.release_id orelse "");
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "status", report.status.toString());
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "rollout_state", report.rolloutState());
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "rollout_control_state", report.rollout_control_state.toString());
    try writer.print(",\"service_count\":{d},\"worker_count\":{d},\"cron_count\":{d},\"training_job_count\":{d},\"placed\":{d},\"failed\":{d},\"completed_targets\":{d},\"failed_targets\":{d},\"remaining_targets\":{d}", .{
        summary.service_count,
        summary.worker_count,
        summary.cron_count,
        summary.training_job_count,
        report.placed,
        report.failed,
        report.completed_targets,
        report.failed_targets,
        report.remainingTargets(),
    });
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "source_release_id", report.source_release_id);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "resumed_from_release_id", report.resumed_from_release_id);

    const resolved_message = try report.resolvedMessage(alloc);
    defer if (resolved_message) |message| alloc.free(message);

    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "message", resolved_message);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "failure_details", report.failure_details_json);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "rollout_targets", report.rollout_targets_json);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "rollout_checkpoint", report.rollout_checkpoint_json);
    try writer.writeAll(",\"rollout\":{");
    try json_helpers.writeJsonStringField(writer, "state", report.rolloutState());
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "control_state", report.rollout_control_state.toString());
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "resumed_from_release_id", report.resumed_from_release_id);
    try writer.print(",\"completed_targets\":{d},\"failed_targets\":{d},\"remaining_targets\":{d}", .{
        report.completed_targets,
        report.failed_targets,
        report.remainingTargets(),
    });
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "failure_details", report.failure_details_json);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "targets", report.rollout_targets_json);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "checkpoint", report.rollout_checkpoint_json);
    try writer.writeByte('}');
    try writer.writeByte('}');

    return json_buf_writer.toOwnedSlice();
}

test "formatApp includes app release metadata" {
    const alloc = std.testing.allocator;
    const json = try formatApp(alloc, .{
        .app_name = "demo-app",
        .release_id = "abc123def456",
        .status = .completed,
        .service_count = 2,
        .placed = 2,
        .failed = 0,
        .completed_targets = 2,
        .failed_targets = 0,
        .rollout_checkpoint_json = "{\"engine\":\"cluster\",\"phase\":\"cutover\",\"batch_start\":0,\"batch_end\":2,\"total_targets\":2,\"completed_targets\":2,\"failed_targets\":0,\"remaining_targets\":0,\"control_state\":\"active\"}",
    }, .{ .service_count = 2 });
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"apply\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"abc123def456\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":\"completed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_state\":\"stable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"service_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"worker_count\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"placed\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"completed_targets\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed_targets\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"remaining_targets\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_release_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"apply completed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_checkpoint\":{\"engine\":\"cluster\",\"phase\":\"cutover\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout\":{\"state\":\"stable\",\"control_state\":\"active\"") != null);
}

test "formatApp includes rollback trigger metadata" {
    const alloc = std.testing.allocator;
    const json = try formatApp(alloc, .{
        .app_name = "demo-app",
        .release_id = "dep-2",
        .status = .completed,
        .service_count = 2,
        .placed = 2,
        .failed = 0,
        .completed_targets = 2,
        .failed_targets = 0,
        .message = "all placements succeeded",
        .trigger = .rollback,
        .source_release_id = "dep-1",
    }, .{ .service_count = 2 });
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"rollback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_release_id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_state\":\"stable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"rollback to dep-1 completed: all placements succeeded\"") != null);
}

test "formatApp includes partially failed status" {
    const alloc = std.testing.allocator;
    const json = try formatApp(alloc, .{
        .app_name = "demo-app",
        .release_id = "dep-3",
        .status = .partially_failed,
        .service_count = 2,
        .placed = 1,
        .failed = 1,
        .completed_targets = 1,
        .failed_targets = 1,
        .message = "one or more placements failed",
        .failure_details_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"reason\":\"placement_failed\"}]",
    }, .{ .service_count = 2 });
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"status\":\"partially_failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_state\":\"degraded\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"placed\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"one or more placements failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failure_details\":[{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"reason\":\"placement_failed\"}]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout\":{\"state\":\"degraded\",\"control_state\":\"active\"") != null);
}

test "formatApp includes rollout control state" {
    const alloc = std.testing.allocator;
    const json = try formatApp(alloc, .{
        .app_name = "demo-app",
        .release_id = "dep-7",
        .status = .in_progress,
        .service_count = 1,
        .placed = 0,
        .failed = 0,
        .completed_targets = 0,
        .failed_targets = 0,
        .rollout_control_state = .paused,
    }, .{ .service_count = 1 });
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_control_state\":\"paused\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"control_state\":\"paused\"") != null);
}

test "formatLegacy preserves compact deploy shape" {
    const alloc = std.testing.allocator;
    const json = try formatLegacy(alloc, 1, 1);
    defer alloc.free(json);

    try std.testing.expectEqualStrings("{\"placed\":1,\"failed\":1}", json);
}

test "formatApp includes non-service workload counts" {
    const alloc = std.testing.allocator;
    const json = try formatApp(alloc, .{
        .app_name = "demo-app",
        .release_id = "dep-4",
        .status = .completed,
        .service_count = 0,
        .placed = 0,
        .failed = 0,
        .completed_targets = 0,
        .failed_targets = 0,
    }, .{
        .worker_count = 1,
        .cron_count = 2,
        .training_job_count = 1,
    });
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"worker_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"cron_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"training_job_count\":1") != null);
}
