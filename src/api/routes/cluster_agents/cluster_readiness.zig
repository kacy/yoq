const std = @import("std");
const sqlite = @import("sqlite");

const apply_release = @import("../../../manifest/apply_release.zig");
const runtime_wait = @import("../../../lib/runtime_wait.zig");
const rollout_targets = @import("rollout_targets.zig");

pub const TargetReadiness = enum {
    pending,
    ready,
    missing,
    image_pull_failed,
    rootfs_assemble_failed,
    container_id_failed,
    container_record_failed,
    start_failed,
    readiness_timeout,
    readiness_failed,
    readiness_invalid,
    process_failed,
    failed,
};

fn nowAwakeNanoseconds() i128 {
    return @intCast(std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds());
}

pub fn failureReason(state: TargetReadiness) []const u8 {
    return switch (state) {
        .pending => "readiness_timeout",
        .missing => "assignment_missing",
        .image_pull_failed => "image_pull_failed",
        .rootfs_assemble_failed => "rootfs_assemble_failed",
        .container_id_failed => "container_id_failed",
        .container_record_failed => "container_record_failed",
        .start_failed => "start_failed",
        .readiness_timeout => "readiness_timeout",
        .readiness_failed => "readiness_failed",
        .readiness_invalid => "readiness_invalid",
        .process_failed => "process_failed",
        .failed => "assignment_failed",
        .ready => unreachable,
    };
}

pub fn resolveTargetReadinessStates(
    alloc: std.mem.Allocator,
    db: *sqlite.Db,
    targets: []const rollout_targets.ScheduledTarget,
    timeout_secs: u32,
    progress: ?apply_release.ProgressRecorder,
) ![]TargetReadiness {
    var states = try alloc.alloc(TargetReadiness, targets.len);
    errdefer alloc.free(states);
    @memset(states, .pending);

    const deadline_ns: i128 = nowAwakeNanoseconds() + (@as(i128, timeout_secs) * std.time.ns_per_s);
    var remaining = targets.len;

    while (remaining > 0) {
        if (progress) |recorder| {
            if (recorder.waitWhilePaused() catch false) return states;
        }
        for (targets, 0..) |target, i| {
            if (states[i] != .pending) continue;

            const state = try queryTargetReadiness(alloc, db, target.assignment_ids);
            if (state == .pending) continue;

            states[i] = state;
            remaining -= 1;
        }

        if (remaining == 0) return states;
        if (nowAwakeNanoseconds() >= deadline_ns) break;
        try runtime_wait.sleepOrError(std.Io.Duration.fromMilliseconds(100), "cluster rollout readiness wait");
    }

    return states;
}

pub fn queryTargetReadiness(alloc: std.mem.Allocator, db: *sqlite.Db, assignment_ids: []const []const u8) !TargetReadiness {
    if (assignment_ids.len == 0) return .missing;

    var all_running = true;
    for (assignment_ids) |assignment_id| {
        const row = try loadAssignmentState(alloc, db, assignment_id) orelse {
            return .missing;
        };
        defer {
            alloc.free(row.status);
            if (row.status_reason) |status_reason| alloc.free(status_reason);
        }

        if (std.mem.eql(u8, row.status, "running")) continue;
        if (std.mem.eql(u8, row.status, "failed") or std.mem.eql(u8, row.status, "stopped")) {
            if (row.status_reason) |status_reason| {
                if (std.mem.eql(u8, status_reason, "readiness_timeout")) return .readiness_timeout;
                if (std.mem.eql(u8, status_reason, "readiness_failed")) return .readiness_failed;
                if (std.mem.eql(u8, status_reason, "readiness_invalid")) return .readiness_invalid;
                if (std.mem.eql(u8, status_reason, "process_failed")) return .process_failed;
                if (std.mem.eql(u8, status_reason, "image_pull_failed")) return .image_pull_failed;
                if (std.mem.eql(u8, status_reason, "rootfs_assemble_failed")) return .rootfs_assemble_failed;
                if (std.mem.eql(u8, status_reason, "container_id_failed")) return .container_id_failed;
                if (std.mem.eql(u8, status_reason, "container_record_failed")) return .container_record_failed;
                if (std.mem.eql(u8, status_reason, "start_failed")) return .start_failed;
            }
            return .failed;
        }
        all_running = false;
    }

    return if (all_running) .ready else .pending;
}

fn loadAssignmentState(alloc: std.mem.Allocator, db: *sqlite.Db, assignment_id: []const u8) !?struct {
    status: []const u8,
    status_reason: ?[]const u8,
} {
    const Row = struct {
        status: sqlite.Text,
        status_reason: ?sqlite.Text,
    };
    const row = (db.oneAlloc(
        Row,
        alloc,
        "SELECT status, status_reason FROM assignments WHERE id = ?;",
        .{},
        .{assignment_id},
    ) catch return error.QueryFailed) orelse return null;
    return .{
        .status = row.status.data,
        .status_reason = if (row.status_reason) |status_reason| status_reason.data else null,
    };
}
