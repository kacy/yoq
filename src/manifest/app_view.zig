const std = @import("std");
const sqlite = @import("sqlite");
const json_helpers = @import("../lib/json_helpers.zig");
const apply_release = @import("apply_release.zig");
const app_snapshot = @import("app_snapshot.zig");
const store = @import("../state/store.zig");

pub const AppFilters = struct {
    status: ?[]const u8 = null,
    failed_only: bool = false,
    in_progress_only: bool = false,
};

pub const ReleaseView = struct {
    id: []const u8,
    app: ?[]const u8 = null,
    service: []const u8,
    trigger: []const u8,
    status: []const u8,
    rollout_state: []const u8 = "unknown",
    rollout_control_state: []const u8 = "active",
    manifest_hash: []const u8,
    created_at: i64,
    service_count: usize = 0,
    worker_count: usize = 0,
    cron_count: usize = 0,
    training_job_count: usize = 0,
    completed_targets: usize = 0,
    failed_targets: usize = 0,
    remaining_targets: usize = 0,
    source_release_id: ?[]const u8 = null,
    resumed_from_release_id: ?[]const u8 = null,
    superseded_by_release_id: ?[]const u8 = null,
    message: ?[]const u8 = null,
    failure_details_json: ?[]const u8 = null,
    rollout_targets_json: ?[]const u8 = null,
    rollout_checkpoint_json: ?[]const u8 = null,
    is_current: bool = false,
    is_previous_successful: bool = false,

    pub fn clone(self: ReleaseView, alloc: std.mem.Allocator) !ReleaseView {
        var out = ReleaseView{
            .id = try alloc.dupe(u8, self.id),
            .app = null,
            .service = "",
            .trigger = "",
            .status = "",
            .rollout_state = "",
            .rollout_control_state = "",
            .manifest_hash = "",
            .created_at = self.created_at,
            .service_count = self.service_count,
            .worker_count = self.worker_count,
            .cron_count = self.cron_count,
            .training_job_count = self.training_job_count,
            .completed_targets = self.completed_targets,
            .failed_targets = self.failed_targets,
            .remaining_targets = self.remaining_targets,
            .is_current = self.is_current,
            .is_previous_successful = self.is_previous_successful,
        };
        errdefer out.deinit(alloc);

        out.app = try cloneOptional(alloc, self.app);
        out.service = try alloc.dupe(u8, self.service);
        out.trigger = try alloc.dupe(u8, self.trigger);
        out.status = try alloc.dupe(u8, self.status);
        out.rollout_state = try alloc.dupe(u8, self.rollout_state);
        out.rollout_control_state = try alloc.dupe(u8, self.rollout_control_state);
        out.manifest_hash = try alloc.dupe(u8, self.manifest_hash);
        out.source_release_id = try cloneOptional(alloc, self.source_release_id);
        out.resumed_from_release_id = try cloneOptional(alloc, self.resumed_from_release_id);
        out.superseded_by_release_id = try cloneOptional(alloc, self.superseded_by_release_id);
        out.message = try cloneOptional(alloc, self.message);
        out.failure_details_json = try cloneOptional(alloc, self.failure_details_json);
        out.rollout_targets_json = try cloneOptional(alloc, self.rollout_targets_json);
        out.rollout_checkpoint_json = try cloneOptional(alloc, self.rollout_checkpoint_json);
        return out;
    }

    pub fn deinit(self: ReleaseView, alloc: std.mem.Allocator) void {
        alloc.free(self.id);
        if (self.app) |app| alloc.free(app);
        alloc.free(self.service);
        alloc.free(self.trigger);
        alloc.free(self.status);
        alloc.free(self.rollout_state);
        alloc.free(self.rollout_control_state);
        alloc.free(self.manifest_hash);
        freeOptional(alloc, self.source_release_id);
        freeOptional(alloc, self.resumed_from_release_id);
        freeOptional(alloc, self.superseded_by_release_id);
        freeOptional(alloc, self.message);
        freeOptional(alloc, self.failure_details_json);
        freeOptional(alloc, self.rollout_targets_json);
        freeOptional(alloc, self.rollout_checkpoint_json);
    }
};

pub const AppStatusView = struct {
    current: ReleaseView,
    previous_successful: ?ReleaseView = null,
    active_training_jobs: usize = 0,
    paused_training_jobs: usize = 0,
    failed_training_jobs: usize = 0,

    pub fn clone(self: AppStatusView, alloc: std.mem.Allocator) !AppStatusView {
        var out = AppStatusView{
            .current = try self.current.clone(alloc),
            .previous_successful = null,
            .active_training_jobs = self.active_training_jobs,
            .paused_training_jobs = self.paused_training_jobs,
            .failed_training_jobs = self.failed_training_jobs,
        };
        errdefer out.deinit(alloc);

        if (self.previous_successful) |previous| {
            out.previous_successful = try previous.clone(alloc);
        }
        return out;
    }

    pub fn deinit(self: AppStatusView, alloc: std.mem.Allocator) void {
        self.current.deinit(alloc);
        if (self.previous_successful) |previous| previous.deinit(alloc);
    }

    pub fn appName(self: AppStatusView) []const u8 {
        return self.current.app orelse self.current.service;
    }
};

pub fn deinitStatusViews(alloc: std.mem.Allocator, views: *std.ArrayList(AppStatusView)) void {
    for (views.items) |view| view.deinit(alloc);
    views.deinit(alloc);
}

pub fn deinitReleaseViews(alloc: std.mem.Allocator, views: *std.ArrayList(ReleaseView)) void {
    for (views.items) |view| view.deinit(alloc);
    views.deinit(alloc);
}

pub fn releaseViewFromDeployment(
    dep: store.DeploymentRecord,
    is_current: bool,
    is_previous_successful: bool,
) ReleaseView {
    return releaseViewFromReport(
        apply_release.reportFromDeployment(dep),
        dep.app_name,
        dep.service_name,
        app_snapshot.summarize(dep.config_snapshot),
        is_current,
        is_previous_successful,
    );
}

pub fn releaseViewFromReport(
    report: apply_release.ApplyReport,
    app_name: ?[]const u8,
    service_name: []const u8,
    summary: app_snapshot.Summary,
    is_current: bool,
    is_previous_successful: bool,
) ReleaseView {
    return .{
        .id = report.release_id orelse "",
        .app = app_name orelse report.app_name,
        .service = service_name,
        .trigger = report.trigger.toString(),
        .status = report.status.toString(),
        .rollout_state = report.rolloutState(),
        .rollout_control_state = report.rollout_control_state.toString(),
        .manifest_hash = report.manifest_hash,
        .created_at = report.created_at,
        .service_count = summary.service_count,
        .worker_count = summary.worker_count,
        .cron_count = summary.cron_count,
        .training_job_count = summary.training_job_count,
        .completed_targets = report.completed_targets,
        .failed_targets = report.failed_targets,
        .remaining_targets = report.remainingTargets(),
        .source_release_id = report.source_release_id,
        .resumed_from_release_id = report.resumed_from_release_id,
        .superseded_by_release_id = report.superseded_by_release_id,
        .message = report.message,
        .failure_details_json = report.failure_details_json,
        .rollout_targets_json = report.rollout_targets_json,
        .rollout_checkpoint_json = report.rollout_checkpoint_json,
        .is_current = is_current,
        .is_previous_successful = is_previous_successful,
    };
}

pub fn statusViewFromDeployments(
    alloc: std.mem.Allocator,
    latest: store.DeploymentRecord,
    previous_successful: ?store.DeploymentRecord,
) AppStatusView {
    return statusViewFromReports(
        apply_release.reportFromDeployment(latest),
        if (previous_successful) |dep| apply_release.reportFromDeployment(dep) else null,
        latest.app_name,
        latest.service_name,
        if (previous_successful) |dep| dep.app_name else null,
        if (previous_successful) |dep| dep.service_name else null,
        app_snapshot.summarize(latest.config_snapshot),
        if (previous_successful) |dep| app_snapshot.summarize(dep.config_snapshot) else null,
        store.summarizeTrainingJobsByApp(alloc, latest.app_name orelse latest.service_name) catch .{},
    );
}

pub fn statusViewFromDeploymentsInDb(
    db: *sqlite.Db,
    alloc: std.mem.Allocator,
    latest: store.DeploymentRecord,
    previous_successful: ?store.DeploymentRecord,
) AppStatusView {
    return statusViewFromReports(
        apply_release.reportFromDeployment(latest),
        if (previous_successful) |dep| apply_release.reportFromDeployment(dep) else null,
        latest.app_name,
        latest.service_name,
        if (previous_successful) |dep| dep.app_name else null,
        if (previous_successful) |dep| dep.service_name else null,
        app_snapshot.summarize(latest.config_snapshot),
        if (previous_successful) |dep| app_snapshot.summarize(dep.config_snapshot) else null,
        store.summarizeTrainingJobsByAppInDb(db, alloc, latest.app_name orelse latest.service_name) catch .{},
    );
}

pub fn statusViewFromReports(
    report: apply_release.ApplyReport,
    previous_successful: ?apply_release.ApplyReport,
    app_name: ?[]const u8,
    service_name: []const u8,
    previous_app_name: ?[]const u8,
    previous_service_name: ?[]const u8,
    summary: app_snapshot.Summary,
    previous_summary: ?app_snapshot.Summary,
    training_summary: store.TrainingJobSummary,
) AppStatusView {
    return .{
        .current = releaseViewFromReport(report, app_name, service_name, summary, true, false),
        .previous_successful = if (previous_successful) |previous|
            releaseViewFromReport(
                previous,
                previous_app_name orelse app_name,
                previous_service_name orelse service_name,
                previous_summary orelse .{},
                false,
                true,
            )
        else
            null,
        .active_training_jobs = training_summary.active,
        .paused_training_jobs = training_summary.paused,
        .failed_training_jobs = training_summary.failed,
    };
}

pub fn releaseViewsFromDeployments(
    alloc: std.mem.Allocator,
    deployments: []const store.DeploymentRecord,
) !std.ArrayList(ReleaseView) {
    const current_release_id = if (deployments.len > 0) deployments[0].id else null;
    const previous_successful_release_id = previousSuccessfulReleaseId(deployments);

    var entries: std.ArrayList(ReleaseView) = .empty;
    errdefer deinitReleaseViews(alloc, &entries);

    for (deployments) |dep| {
        const is_current = current_release_id != null and std.mem.eql(u8, dep.id, current_release_id.?);
        const is_previous_successful = previous_successful_release_id != null and std.mem.eql(u8, dep.id, previous_successful_release_id.?);
        try entries.append(alloc, try releaseViewFromDeployment(dep, is_current, is_previous_successful).clone(alloc));
    }
    return entries;
}

pub fn previousSuccessfulReleaseId(deployments: []const store.DeploymentRecord) ?[]const u8 {
    if (deployments.len == 0) return null;
    for (deployments[1..]) |dep| {
        if (std.mem.eql(u8, dep.status, "completed")) return dep.id;
    }
    return null;
}

pub fn parseStatus(json: []const u8) AppStatusView {
    const previous_id = json_helpers.extractJsonString(json, "previous_successful_release_id");
    return .{
        .current = .{
            .id = json_helpers.extractJsonString(json, "release_id") orelse "?",
            .app = json_helpers.extractJsonString(json, "app_name"),
            .service = json_helpers.extractJsonString(json, "app_name") orelse "?",
            .trigger = json_helpers.extractJsonString(json, "trigger") orelse "apply",
            .status = json_helpers.extractJsonString(json, "status") orelse "unknown",
            .rollout_state = json_helpers.extractJsonString(json, "rollout_state") orelse "unknown",
            .rollout_control_state = json_helpers.extractJsonString(json, "rollout_control_state") orelse "active",
            .manifest_hash = json_helpers.extractJsonString(json, "manifest_hash") orelse "?",
            .created_at = json_helpers.extractJsonInt(json, "created_at") orelse 0,
            .service_count = jsonCount(json, "service_count"),
            .worker_count = jsonCount(json, "worker_count"),
            .cron_count = jsonCount(json, "cron_count"),
            .training_job_count = jsonCount(json, "training_job_count"),
            .completed_targets = jsonCount(json, "completed_targets"),
            .failed_targets = jsonCount(json, "failed_targets"),
            .remaining_targets = jsonCount(json, "remaining_targets"),
            .source_release_id = json_helpers.extractJsonString(json, "source_release_id"),
            .resumed_from_release_id = json_helpers.extractJsonString(json, "resumed_from_release_id"),
            .superseded_by_release_id = json_helpers.extractJsonString(json, "superseded_by_release_id"),
            .message = json_helpers.extractJsonString(json, "message"),
            .failure_details_json = json_helpers.extractJsonArray(json, "failure_details"),
            .rollout_targets_json = json_helpers.extractJsonArray(json, "rollout_targets"),
            .rollout_checkpoint_json = json_helpers.extractJsonObject(json, "rollout_checkpoint"),
            .is_current = true,
        },
        .previous_successful = if (previous_id) |id| .{
            .id = id,
            .app = json_helpers.extractJsonString(json, "app_name"),
            .service = json_helpers.extractJsonString(json, "app_name") orelse "?",
            .trigger = json_helpers.extractJsonString(json, "previous_successful_trigger") orelse "apply",
            .status = json_helpers.extractJsonString(json, "previous_successful_status") orelse "completed",
            .rollout_state = json_helpers.extractJsonString(json, "previous_successful_rollout_state") orelse "unknown",
            .rollout_control_state = json_helpers.extractJsonString(json, "previous_successful_rollout_control_state") orelse "active",
            .manifest_hash = json_helpers.extractJsonString(json, "previous_successful_manifest_hash") orelse "?",
            .created_at = json_helpers.extractJsonInt(json, "previous_successful_created_at") orelse 0,
            .completed_targets = jsonCount(json, "previous_successful_completed_targets"),
            .failed_targets = jsonCount(json, "previous_successful_failed_targets"),
            .remaining_targets = jsonCount(json, "previous_successful_remaining_targets"),
            .source_release_id = json_helpers.extractJsonString(json, "previous_successful_source_release_id"),
            .resumed_from_release_id = json_helpers.extractJsonString(json, "previous_successful_resumed_from_release_id"),
            .superseded_by_release_id = json_helpers.extractJsonString(json, "previous_successful_superseded_by_release_id"),
            .message = json_helpers.extractJsonString(json, "previous_successful_message"),
            .failure_details_json = json_helpers.extractJsonArray(json, "previous_successful_failure_details"),
            .rollout_targets_json = json_helpers.extractJsonArray(json, "previous_successful_rollout_targets"),
            .rollout_checkpoint_json = json_helpers.extractJsonObject(json, "previous_successful_rollout_checkpoint"),
            .is_previous_successful = true,
        } else null,
        .active_training_jobs = jsonCount(json, "active_training_jobs"),
        .paused_training_jobs = jsonCount(json, "paused_training_jobs"),
        .failed_training_jobs = jsonCount(json, "failed_training_jobs"),
    };
}

pub fn parseRelease(obj: []const u8) ReleaseView {
    return .{
        .id = json_helpers.extractJsonString(obj, "id") orelse "?",
        .app = json_helpers.extractJsonString(obj, "app"),
        .service = json_helpers.extractJsonString(obj, "service") orelse "?",
        .trigger = json_helpers.extractJsonString(obj, "trigger") orelse "apply",
        .status = json_helpers.extractJsonString(obj, "status") orelse "?",
        .rollout_state = json_helpers.extractJsonString(obj, "rollout_state") orelse "unknown",
        .rollout_control_state = json_helpers.extractJsonString(obj, "rollout_control_state") orelse "active",
        .manifest_hash = json_helpers.extractJsonString(obj, "manifest_hash") orelse "?",
        .created_at = json_helpers.extractJsonInt(obj, "created_at") orelse 0,
        .service_count = jsonCount(obj, "service_count"),
        .worker_count = jsonCount(obj, "worker_count"),
        .cron_count = jsonCount(obj, "cron_count"),
        .training_job_count = jsonCount(obj, "training_job_count"),
        .completed_targets = jsonCount(obj, "completed_targets"),
        .failed_targets = jsonCount(obj, "failed_targets"),
        .remaining_targets = jsonCount(obj, "remaining_targets"),
        .source_release_id = json_helpers.extractJsonString(obj, "source_release_id"),
        .resumed_from_release_id = json_helpers.extractJsonString(obj, "resumed_from_release_id"),
        .superseded_by_release_id = json_helpers.extractJsonString(obj, "superseded_by_release_id"),
        .message = json_helpers.extractJsonString(obj, "message"),
        .failure_details_json = json_helpers.extractJsonArray(obj, "failure_details"),
        .rollout_targets_json = json_helpers.extractJsonArray(obj, "rollout_targets"),
        .rollout_checkpoint_json = json_helpers.extractJsonObject(obj, "rollout_checkpoint"),
        .is_current = json_helpers.extractJsonBool(obj, "is_current") orelse false,
        .is_previous_successful = json_helpers.extractJsonBool(obj, "is_previous_successful") orelse false,
    };
}

pub fn renderStatus(alloc: std.mem.Allocator, view: AppStatusView) ![]u8 {
    var buf = std.Io.Writer.Allocating.init(alloc);
    errdefer buf.deinit();
    try writeStatus(&buf.writer, view);
    return buf.toOwnedSlice();
}

pub fn renderStatusList(alloc: std.mem.Allocator, views: []const AppStatusView) ![]u8 {
    var buf = std.Io.Writer.Allocating.init(alloc);
    errdefer buf.deinit();
    const writer = &buf.writer;

    try writer.writeByte('[');
    for (views, 0..) |view, i| {
        if (i > 0) try writer.writeByte(',');
        try writeStatus(writer, view);
    }
    try writer.writeByte(']');
    return buf.toOwnedSlice();
}

pub fn renderHistory(alloc: std.mem.Allocator, entries: []const ReleaseView) ![]u8 {
    var buf = std.Io.Writer.Allocating.init(alloc);
    errdefer buf.deinit();
    const writer = &buf.writer;

    try writer.writeByte('[');
    for (entries, 0..) |entry, i| {
        if (i > 0) try writer.writeByte(',');
        try writeHistoryEntry(writer, entry);
    }
    try writer.writeByte(']');
    return buf.toOwnedSlice();
}

pub fn writeStatus(writer: anytype, view: AppStatusView) !void {
    const current = view.current;
    const previous = view.previous_successful;

    try writer.writeByte('{');
    try json_helpers.writeJsonStringField(writer, "app_name", view.appName());
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "trigger", current.trigger);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "release_id", current.id);
    try writer.writeByte(',');
    try writeCommonReleaseFields(writer, current);
    try writer.print(",\"active_training_jobs\":{d},\"paused_training_jobs\":{d},\"failed_training_jobs\":{d}", .{
        view.active_training_jobs,
        view.paused_training_jobs,
        view.failed_training_jobs,
    });
    try writer.writeByte(',');
    try writeStatusTransitionFields(writer, current, previous);
    try writer.writeByte(',');
    try writeRawReleaseMetadata(writer, current);
    try writer.writeByte(',');
    try writeRolloutField(writer, "rollout", current, true);
    try writer.writeAll(",\"current_release\":");
    try writeStatusReleaseObject(writer, current);
    try writer.writeAll(",\"previous_successful_release\":");
    if (previous) |release| {
        try writeStatusReleaseObject(writer, release);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeByte(',');
    try writeWorkloads(writer, current);
    try writer.print(",\"training_runtime\":{{\"active\":{d},\"paused\":{d},\"failed\":{d}}}", .{
        view.active_training_jobs,
        view.paused_training_jobs,
        view.failed_training_jobs,
    });
    try writer.writeByte('}');
}

pub fn writeHistoryEntry(writer: anytype, entry: ReleaseView) !void {
    try writer.writeByte('{');
    try json_helpers.writeJsonStringField(writer, "id", entry.id);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "app", entry.app);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "service", entry.service);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "trigger", entry.trigger);
    try writer.writeByte(',');
    try writeCommonReleaseFields(writer, entry);
    try writer.writeByte(',');
    try writeReleaseTransitionFields(writer, entry);
    try writer.writeByte(',');
    try writeRawReleaseMetadata(writer, entry);
    try writer.writeByte(',');
    try writeRolloutField(writer, "rollout", entry, true);
    try writer.print(",\"is_current\":{},\"is_previous_successful\":{}", .{ entry.is_current, entry.is_previous_successful });
    try writer.writeAll(",\"release\":");
    try writeHistoryReleaseObject(writer, entry);
    try writer.writeByte(',');
    try writeWorkloads(writer, entry);
    try writer.writeByte('}');
}

pub fn appMatchesFilters(view: AppStatusView, filters: AppFilters) bool {
    if (filters.status) |status_filter| {
        if (!std.mem.eql(u8, view.current.status, status_filter) and !std.mem.eql(u8, view.current.rollout_state, status_filter)) return false;
    }
    if (filters.failed_only and !isFailedLikeRollout(view.current.status, view.current.rollout_state)) return false;
    if (filters.in_progress_only and !isInProgressRollout(view.current.status, view.current.rollout_state)) return false;
    return true;
}

pub fn isFailedLikeRollout(status_text: []const u8, rollout_state: []const u8) bool {
    return std.mem.eql(u8, status_text, "failed") or
        std.mem.eql(u8, status_text, "partially_failed") or
        std.mem.eql(u8, rollout_state, "blocked") or
        std.mem.eql(u8, rollout_state, "degraded");
}

pub fn isInProgressRollout(status_text: []const u8, rollout_state: []const u8) bool {
    return std.mem.eql(u8, status_text, "pending") or
        std.mem.eql(u8, status_text, "in_progress") or
        std.mem.eql(u8, rollout_state, "pending") or
        std.mem.eql(u8, rollout_state, "starting") or
        std.mem.eql(u8, rollout_state, "rolling");
}

pub fn formatMessage(buf: []u8, message: ?[]const u8, failure_details_json: ?[]const u8) []const u8 {
    if (message == null or message.?.len == 0) {
        return json_helpers.summarizeFailureDetails(buf, failure_details_json) orelse "";
    }

    const prefix = std.fmt.bufPrint(buf, "{s}", .{message.?}) catch return message.?;
    if (failure_details_json == null) return prefix;

    const sep = std.fmt.bufPrint(buf[prefix.len..], " | ", .{}) catch return prefix;
    const summary = json_helpers.summarizeFailureDetails(buf[prefix.len + sep.len ..], failure_details_json) orelse return prefix;
    return buf[0 .. prefix.len + sep.len + summary.len];
}

pub fn formatProgress(buf: []u8, release: ReleaseView) []const u8 {
    return formatProgressCounts(buf, release.completed_targets, release.failed_targets, release.remaining_targets);
}

pub fn formatProgressCounts(buf: []u8, completed: usize, failed: usize, remaining: usize) []const u8 {
    return std.fmt.bufPrint(buf, "{d}/{d}/{d}", .{ completed, failed, remaining }) catch "?";
}

pub fn formatTrainingRuntime(buf: []u8, view: AppStatusView) []const u8 {
    if (view.active_training_jobs == 0 and view.paused_training_jobs == 0 and view.failed_training_jobs == 0) return "-";
    return std.fmt.bufPrint(buf, "{d}/{d}/{d}", .{
        view.active_training_jobs,
        view.paused_training_jobs,
        view.failed_training_jobs,
    }) catch "?";
}

pub fn formatRolloutControlState(control_state: []const u8) []const u8 {
    if (std.mem.eql(u8, control_state, "active")) return "-";
    if (std.mem.eql(u8, control_state, "cancel_requested")) return "cancel";
    return control_state;
}

fn writeCommonReleaseFields(writer: anytype, release: ReleaseView) !void {
    try json_helpers.writeJsonStringField(writer, "status", release.status);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "rollout_state", release.rollout_state);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "rollout_control_state", release.rollout_control_state);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "manifest_hash", release.manifest_hash);
    try writer.print(",\"created_at\":{d}", .{release.created_at});
    try writer.print(",\"service_count\":{d},\"worker_count\":{d},\"cron_count\":{d},\"training_job_count\":{d}", .{
        release.service_count,
        release.worker_count,
        release.cron_count,
        release.training_job_count,
    });
    try writer.print(",\"completed_targets\":{d},\"failed_targets\":{d},\"remaining_targets\":{d}", .{
        release.completed_targets,
        release.failed_targets,
        release.remaining_targets,
    });
}

fn writeReleaseTransitionFields(writer: anytype, release: ReleaseView) !void {
    try json_helpers.writeNullableJsonStringField(writer, "source_release_id", release.source_release_id);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "resumed_from_release_id", release.resumed_from_release_id);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "superseded_by_release_id", release.superseded_by_release_id);
}

fn writeStatusTransitionFields(writer: anytype, current: ReleaseView, previous: ?ReleaseView) !void {
    try writeReleaseTransitionFields(writer, current);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_release_id", if (previous) |release| release.id else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_trigger", if (previous) |release| release.trigger else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_status", if (previous) |release| release.status else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_rollout_state", if (previous) |release| release.rollout_state else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_rollout_control_state", if (previous) |release| release.rollout_control_state else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_manifest_hash", if (previous) |release| release.manifest_hash else null);
    if (previous) |release| {
        try writer.print(",\"previous_successful_created_at\":{d}", .{release.created_at});
        try writer.print(",\"previous_successful_completed_targets\":{d},\"previous_successful_failed_targets\":{d},\"previous_successful_remaining_targets\":{d}", .{
            release.completed_targets,
            release.failed_targets,
            release.remaining_targets,
        });
    } else {
        try writer.writeAll(",\"previous_successful_created_at\":null");
        try writer.writeAll(",\"previous_successful_completed_targets\":0,\"previous_successful_failed_targets\":0,\"previous_successful_remaining_targets\":0");
    }
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_source_release_id", if (previous) |release| release.source_release_id else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_resumed_from_release_id", if (previous) |release| release.resumed_from_release_id else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_superseded_by_release_id", if (previous) |release| release.superseded_by_release_id else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonStringField(writer, "previous_successful_message", if (previous) |release| release.message else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "previous_successful_failure_details", if (previous) |release| release.failure_details_json else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "previous_successful_rollout_targets", if (previous) |release| release.rollout_targets_json else null);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "previous_successful_rollout_checkpoint", if (previous) |release| release.rollout_checkpoint_json else null);
}

fn writeRawReleaseMetadata(writer: anytype, release: ReleaseView) !void {
    try json_helpers.writeNullableJsonStringField(writer, "message", release.message);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "failure_details", release.failure_details_json);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "rollout_targets", release.rollout_targets_json);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "rollout_checkpoint", release.rollout_checkpoint_json);
}

fn writeStatusReleaseObject(writer: anytype, release: ReleaseView) !void {
    try writer.writeByte('{');
    try writeReleaseIdentityFields(writer, release);
    try writer.writeByte(',');
    try writeReleaseTransitionFields(writer, release);
    try writer.writeByte(',');
    try writeRawReleaseMetadata(writer, release);
    try writer.writeByte(',');
    try writeRolloutField(writer, "rollout", release, false);
    try writer.writeByte('}');
}

fn writeHistoryReleaseObject(writer: anytype, release: ReleaseView) !void {
    try writer.writeByte('{');
    try writeReleaseIdentityFields(writer, release);
    try writer.writeByte(',');
    try writeReleaseTransitionFields(writer, release);
    try writer.writeByte(',');
    try writeRawReleaseMetadata(writer, release);
    try writer.writeByte(',');
    try writeRolloutField(writer, "rollout", release, false);
    try writer.print(",\"current\":{},\"previous_successful\":{}", .{ release.is_current, release.is_previous_successful });
    try writer.writeByte('}');
}

fn writeReleaseIdentityFields(writer: anytype, release: ReleaseView) !void {
    try json_helpers.writeJsonStringField(writer, "id", release.id);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "trigger", release.trigger);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "status", release.status);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "rollout_state", release.rollout_state);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "rollout_control_state", release.rollout_control_state);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "manifest_hash", release.manifest_hash);
    try writer.print(",\"created_at\":{d},\"completed_targets\":{d},\"failed_targets\":{d},\"remaining_targets\":{d}", .{
        release.created_at,
        release.completed_targets,
        release.failed_targets,
        release.remaining_targets,
    });
}

fn writeRolloutField(writer: anytype, field_name: []const u8, release: ReleaseView, include_transition_ids: bool) !void {
    try writer.writeByte('"');
    try writer.writeAll(field_name);
    try writer.writeAll("\":{");
    try json_helpers.writeJsonStringField(writer, "state", release.rollout_state);
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "control_state", release.rollout_control_state);
    if (include_transition_ids) {
        try writer.writeByte(',');
        try json_helpers.writeNullableJsonStringField(writer, "resumed_from_release_id", release.resumed_from_release_id);
        try writer.writeByte(',');
        try json_helpers.writeNullableJsonStringField(writer, "superseded_by_release_id", release.superseded_by_release_id);
    }
    try writer.print(",\"completed_targets\":{d},\"failed_targets\":{d},\"remaining_targets\":{d}", .{
        release.completed_targets,
        release.failed_targets,
        release.remaining_targets,
    });
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "failure_details", release.failure_details_json);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "targets", release.rollout_targets_json);
    try writer.writeByte(',');
    try json_helpers.writeNullableJsonRawField(writer, "checkpoint", release.rollout_checkpoint_json);
    try writer.writeByte('}');
}

fn writeWorkloads(writer: anytype, release: ReleaseView) !void {
    try writer.print("\"workloads\":{{\"services\":{d},\"workers\":{d},\"crons\":{d},\"training_jobs\":{d}}}", .{
        release.service_count,
        release.worker_count,
        release.cron_count,
        release.training_job_count,
    });
}

fn jsonCount(json: []const u8, key: []const u8) usize {
    return @intCast(@max(0, json_helpers.extractJsonInt(json, key) orelse 0));
}

fn cloneOptional(alloc: std.mem.Allocator, value: ?[]const u8) !?[]const u8 {
    return if (value) |text| try alloc.dupe(u8, text) else null;
}

fn freeOptional(alloc: std.mem.Allocator, value: ?[]const u8) void {
    if (value) |text| alloc.free(text);
}

test "app_view status json preserves top-level and nested fields" {
    const alloc = std.testing.allocator;
    const view = AppStatusView{
        .current = .{
            .id = "dep-2",
            .app = "demo-app",
            .service = "demo-app",
            .trigger = "apply",
            .status = "completed",
            .rollout_state = "stable",
            .rollout_control_state = "active",
            .manifest_hash = "sha256:222",
            .created_at = 200,
            .service_count = 2,
            .remaining_targets = 2,
            .is_current = true,
        },
    };

    const json = try renderStatus(alloc, view);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"previous_successful_release\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"current_release\":{\"id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"workloads\":{\"services\":2,\"workers\":0,\"crons\":0,\"training_jobs\":0}") != null);
}

test "app_view history json preserves release markers" {
    const alloc = std.testing.allocator;
    const entries = [_]ReleaseView{
        .{
            .id = "dep-2",
            .app = "demo-app",
            .service = "demo-app",
            .trigger = "apply",
            .status = "failed",
            .rollout_state = "failed",
            .rollout_control_state = "active",
            .manifest_hash = "sha256:222",
            .created_at = 200,
            .message = "placement failed",
            .is_current = true,
        },
        .{
            .id = "dep-1",
            .app = "demo-app",
            .service = "demo-app",
            .trigger = "apply",
            .status = "completed",
            .rollout_state = "stable",
            .rollout_control_state = "active",
            .manifest_hash = "sha256:111",
            .created_at = 100,
            .is_previous_successful = true,
        },
    };

    const json = try renderHistory(alloc, &entries);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"placement failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"is_current\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"previous_successful\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"workloads\":{\"services\":0,\"workers\":0,\"crons\":0,\"training_jobs\":0}") != null);
}

test "app_view status parser reads rendered json" {
    const alloc = std.testing.allocator;
    const view = AppStatusView{
        .current = .{
            .id = "dep-2",
            .app = "demo-app",
            .service = "demo-app",
            .trigger = "rollback",
            .status = "partially_failed",
            .rollout_state = "blocked",
            .rollout_control_state = "paused",
            .manifest_hash = "sha256:222",
            .created_at = 200,
            .completed_targets = 1,
            .failed_targets = 1,
            .remaining_targets = 2,
            .failure_details_json = "[{\"service\":\"api\",\"reason\":\"no capacity\"}]",
        },
        .active_training_jobs = 1,
    };

    const json = try renderStatus(alloc, view);
    defer alloc.free(json);

    const parsed = parseStatus(json);
    try std.testing.expectEqualStrings("demo-app", parsed.appName());
    try std.testing.expectEqualStrings("dep-2", parsed.current.id);
    try std.testing.expectEqualStrings("blocked", parsed.current.rollout_state);
    try std.testing.expectEqual(@as(usize, 1), parsed.active_training_jobs);
    try std.testing.expect(parsed.current.failure_details_json != null);
}

test "app_view filters classify failed and in-progress rollouts" {
    const failed = AppStatusView{ .current = baseRelease("failed", "degraded") };
    const pending = AppStatusView{ .current = baseRelease("pending", "starting") };
    const stable = AppStatusView{ .current = baseRelease("completed", "stable") };

    try std.testing.expect(appMatchesFilters(failed, .{ .failed_only = true }));
    try std.testing.expect(!appMatchesFilters(stable, .{ .failed_only = true }));
    try std.testing.expect(appMatchesFilters(pending, .{ .in_progress_only = true }));
    try std.testing.expect(!appMatchesFilters(stable, .{ .in_progress_only = true }));
    try std.testing.expect(appMatchesFilters(stable, .{ .status = "stable" }));
}

test "app_view message formatting appends failure summary" {
    var buf: [128]u8 = undefined;
    const message = formatMessage(&buf, "apply failed", "[{\"workload_name\":\"api\",\"reason\":\"no capacity\"}]");
    try std.testing.expect(std.mem.indexOf(u8, message, "apply failed | ") != null);
    try std.testing.expect(std.mem.indexOf(u8, message, "api: no capacity") != null);
}

fn baseRelease(status: []const u8, rollout_state: []const u8) ReleaseView {
    return .{
        .id = "dep-1",
        .app = "demo-app",
        .service = "demo-app",
        .trigger = "apply",
        .status = status,
        .rollout_state = rollout_state,
        .rollout_control_state = "active",
        .manifest_hash = "sha256:111",
        .created_at = 100,
    };
}
