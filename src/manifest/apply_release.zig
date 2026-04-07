const std = @import("std");
const json_helpers = @import("../lib/json_helpers.zig");
const store = @import("../state/store.zig");
const update_common = @import("update/common.zig");

pub const ApplyTrigger = enum {
    apply,
    rollback,

    pub fn toString(self: ApplyTrigger) []const u8 {
        return switch (self) {
            .apply => "apply",
            .rollback => "rollback",
        };
    }
};

pub const ApplyContext = struct {
    trigger: ApplyTrigger = .apply,
    source_release_id: ?[]const u8 = null,
};

pub const ApplyOutcome = struct {
    status: update_common.DeploymentStatus,
    message: ?[]const u8 = null,
    placed: usize = 0,
    failed: usize = 0,
};

pub const ApplyResult = struct {
    release_id: ?[]const u8,
    outcome: ApplyOutcome,

    pub fn toReport(self: ApplyResult, app_name: []const u8, service_count: usize, context: ApplyContext) ApplyReport {
        return .{
            .app_name = app_name,
            .release_id = self.release_id,
            .status = self.outcome.status,
            .service_count = service_count,
            .placed = self.outcome.placed,
            .failed = self.outcome.failed,
            .message = self.outcome.message,
            .manifest_hash = "",
            .created_at = 0,
            .trigger = context.trigger,
            .source_release_id = context.source_release_id,
        };
    }
};

pub const ApplyReport = struct {
    app_name: []const u8,
    release_id: ?[]const u8,
    status: update_common.DeploymentStatus,
    service_count: usize,
    placed: usize,
    failed: usize,
    message: ?[]const u8 = null,
    manifest_hash: []const u8 = "",
    created_at: i64 = 0,
    trigger: ApplyTrigger = .apply,
    source_release_id: ?[]const u8 = null,

    pub fn deinit(self: ApplyReport, alloc: std.mem.Allocator) void {
        if (self.release_id) |id| alloc.free(id);
    }

    pub fn context(self: ApplyReport) ApplyContext {
        return .{
            .trigger = self.trigger,
            .source_release_id = self.source_release_id,
        };
    }

    pub fn resolvedMessage(self: ApplyReport, alloc: std.mem.Allocator) !?[]u8 {
        return materializeMessage(alloc, self.context(), self.status, self.message);
    }

    pub fn summaryText(self: ApplyReport, alloc: std.mem.Allocator) ![]u8 {
        const status_text = self.status.toString();
        const message = try self.resolvedMessage(alloc);
        defer if (message) |msg| alloc.free(msg);

        if (self.release_id) |id| {
            return std.fmt.allocPrint(
                alloc,
                "release {s} {s}: {s} ({d} placed, {d} failed, {d} services)",
                .{ id, status_text, message.?, self.placed, self.failed, self.service_count },
            );
        }

        return std.fmt.allocPrint(
            alloc,
            "{s}: {s} ({d} placed, {d} failed, {d} services)",
            .{ status_text, message.?, self.placed, self.failed, self.service_count },
        );
    }
};

pub fn reportFromDeployment(dep: store.DeploymentRecord) ApplyReport {
    const inferred = inferContextFromStoredMessage(dep.message);
    return .{
        .app_name = dep.app_name orelse dep.service_name,
        .release_id = dep.id,
        .status = update_common.DeploymentStatus.fromString(dep.status) orelse .failed,
        .service_count = countServices(dep.config_snapshot),
        .placed = 0,
        .failed = 0,
        .message = dep.message,
        .manifest_hash = dep.manifest_hash,
        .created_at = dep.created_at,
        .trigger = inferred.trigger,
        .source_release_id = inferred.source_release_id,
    };
}

fn inferContextFromStoredMessage(message: ?[]const u8) ApplyContext {
    const text = message orelse return .{};
    const prefix = "rollback to ";
    if (std.mem.startsWith(u8, text, prefix)) {
        const remainder = text[prefix.len..];
        const split = std.mem.indexOfScalar(u8, remainder, ' ') orelse return .{ .trigger = .rollback };
        const source_release_id = remainder[0..split];
        if (source_release_id.len > 0) {
            return .{
                .trigger = .rollback,
                .source_release_id = source_release_id,
            };
        }
        return .{ .trigger = .rollback };
    }
    if (std.mem.startsWith(u8, text, "rollback ")) {
        return .{ .trigger = .rollback };
    }
    return .{};
}

pub fn materializeMessage(
    alloc: std.mem.Allocator,
    context: ApplyContext,
    status: update_common.DeploymentStatus,
    explicit: ?[]const u8,
) !?[]u8 {
    const status_text = status.toString();

    return switch (context.trigger) {
        .apply => if (explicit) |message|
            try alloc.dupe(u8, message)
        else switch (status) {
            .completed => try alloc.dupe(u8, "apply completed"),
            .failed => try alloc.dupe(u8, "apply failed"),
            else => try alloc.dupe(u8, status_text),
        },
        .rollback => if (context.source_release_id) |source_id|
            if (explicit) |message|
                try std.fmt.allocPrint(alloc, "rollback to {s} {s}: {s}", .{ source_id, status_text, message })
            else
                try std.fmt.allocPrint(alloc, "rollback to {s} {s}", .{ source_id, status_text })
        else if (explicit) |message|
            try std.fmt.allocPrint(alloc, "rollback {s}: {s}", .{ status_text, message })
        else
            try std.fmt.allocPrint(alloc, "rollback {s}", .{status_text}),
    };
}

fn countServices(snapshot: []const u8) usize {
    const services = json_helpers.extractJsonArray(snapshot, "services") orelse return 0;
    var iter = json_helpers.extractJsonObjects(services);
    var count: usize = 0;
    while (iter.next() != null) count += 1;
    return count;
}

pub fn execute(tracker: anytype, backend: anytype) !ApplyResult {
    const release_id = try tracker.begin();

    const outcome = backend.apply() catch |err| {
        if (release_id) |id| {
            try tracker.mark(id, .failed, backend.failureMessage(err));
            tracker.freeReleaseId(id);
        }
        return err;
    };

    if (release_id) |id| {
        try tracker.mark(id, outcome.status, outcome.message);
    }

    return .{
        .release_id = release_id,
        .outcome = outcome,
    };
}

test "execute marks completed releases on backend success" {
    const alloc = std.testing.allocator;

    const Tracker = struct {
        alloc: std.mem.Allocator,
        last_status: ?update_common.DeploymentStatus = null,
        last_message: ?[]const u8 = null,

        fn begin(self: *@This()) !?[]const u8 {
            const id = try self.alloc.dupe(u8, "dep123");
            return id;
        }

        fn mark(self: *@This(), id: []const u8, status: update_common.DeploymentStatus, message: ?[]const u8) !void {
            try std.testing.expectEqualStrings("dep123", id);
            self.last_status = status;
            self.last_message = message;
        }

        fn freeReleaseId(self: *@This(), id: []const u8) void {
            self.alloc.free(id);
        }
    };

    const Backend = struct {
        fn apply(_: *@This()) !ApplyOutcome {
            return .{ .status = .completed, .placed = 2 };
        }

        fn failureMessage(_: *@This(), _: anytype) ?[]const u8 {
            return "backend failed";
        }
    };

    var tracker = Tracker{ .alloc = alloc };
    var backend = Backend{};

    const result = try execute(&tracker, &backend);
    defer alloc.free(result.release_id.?);

    try std.testing.expectEqualStrings("dep123", result.release_id.?);
    try std.testing.expectEqual(update_common.DeploymentStatus.completed, result.outcome.status);
    try std.testing.expectEqual(update_common.DeploymentStatus.completed, tracker.last_status.?);
    try std.testing.expect(tracker.last_message == null);
}

test "execute marks failed releases on backend error" {
    const alloc = std.testing.allocator;

    const BackendError = error{StartupFailed};

    const Tracker = struct {
        alloc: std.mem.Allocator,
        last_status: ?update_common.DeploymentStatus = null,
        last_message: ?[]const u8 = null,

        fn begin(self: *@This()) !?[]const u8 {
            const id = try self.alloc.dupe(u8, "dep456");
            return id;
        }

        fn mark(self: *@This(), id: []const u8, status: update_common.DeploymentStatus, message: ?[]const u8) !void {
            try std.testing.expectEqualStrings("dep456", id);
            self.last_status = status;
            self.last_message = message;
        }

        fn freeReleaseId(self: *@This(), id: []const u8) void {
            self.alloc.free(id);
        }
    };

    const Backend = struct {
        fn apply(_: *@This()) BackendError!ApplyOutcome {
            return BackendError.StartupFailed;
        }

        fn failureMessage(_: *@This(), err: BackendError) ?[]const u8 {
            return switch (err) {
                BackendError.StartupFailed => "service startup failed",
            };
        }
    };

    var tracker = Tracker{ .alloc = alloc };
    var backend = Backend{};

    try std.testing.expectError(BackendError.StartupFailed, execute(&tracker, &backend));
    try std.testing.expectEqual(update_common.DeploymentStatus.failed, tracker.last_status.?);
    try std.testing.expectEqualStrings("service startup failed", tracker.last_message.?);
}

test "ApplyResult projects to shared apply report" {
    const result = ApplyResult{
        .release_id = "dep789",
        .outcome = .{
            .status = .completed,
            .message = null,
            .placed = 3,
            .failed = 0,
        },
    };

    const report = result.toReport("demo-app", 3, .{});
    try std.testing.expectEqualStrings("demo-app", report.app_name);
    try std.testing.expectEqualStrings("dep789", report.release_id.?);
    try std.testing.expectEqual(update_common.DeploymentStatus.completed, report.status);
    try std.testing.expectEqual(@as(usize, 3), report.service_count);
    try std.testing.expectEqual(@as(usize, 3), report.placed);
    try std.testing.expectEqual(@as(usize, 0), report.failed);
    try std.testing.expect(report.message == null);
    try std.testing.expectEqual(ApplyTrigger.apply, report.trigger);
    try std.testing.expect(report.source_release_id == null);
}

test "ApplyReport summaryText includes release status and counts" {
    const alloc = std.testing.allocator;
    const report = ApplyReport{
        .app_name = "demo-app",
        .release_id = "dep789",
        .status = .completed,
        .service_count = 3,
        .placed = 3,
        .failed = 0,
        .message = "all requested services started",
    };

    const summary = try report.summaryText(alloc);
    defer alloc.free(summary);

    try std.testing.expectEqualStrings(
        "release dep789 completed: all requested services started (3 placed, 0 failed, 3 services)",
        summary,
    );
}

test "materializeMessage contextualizes rollback transitions" {
    const alloc = std.testing.allocator;
    const message = try materializeMessage(alloc, .{
        .trigger = .rollback,
        .source_release_id = "dep100",
    }, .completed, "all placements succeeded");
    defer alloc.free(message.?);

    try std.testing.expectEqualStrings(
        "rollback to dep100 completed: all placements succeeded",
        message.?,
    );
}

test "reportFromDeployment preserves release metadata and counts services" {
    const dep = store.DeploymentRecord{
        .id = "dep-22",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .manifest_hash = "sha256:xyz",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"},{\"name\":\"db\"}]}",
        .status = "completed",
        .message = "all requested services started",
        .created_at = 220,
    };

    const report = reportFromDeployment(dep);
    try std.testing.expectEqualStrings("demo-app", report.app_name);
    try std.testing.expectEqualStrings("dep-22", report.release_id.?);
    try std.testing.expectEqual(update_common.DeploymentStatus.completed, report.status);
    try std.testing.expectEqual(@as(usize, 2), report.service_count);
    try std.testing.expectEqualStrings("sha256:xyz", report.manifest_hash);
    try std.testing.expectEqual(@as(i64, 220), report.created_at);
    try std.testing.expectEqualStrings("all requested services started", report.message.?);
    try std.testing.expectEqual(ApplyTrigger.apply, report.trigger);
    try std.testing.expect(report.source_release_id == null);
}

test "reportFromDeployment infers rollback context from stored message" {
    const dep = store.DeploymentRecord{
        .id = "dep-23",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .manifest_hash = "sha256:zzz",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "completed",
        .message = "rollback to dep-11 completed: all placements succeeded",
        .created_at = 230,
    };

    const report = reportFromDeployment(dep);
    try std.testing.expectEqual(ApplyTrigger.rollback, report.trigger);
    try std.testing.expectEqualStrings("dep-11", report.source_release_id.?);
}
