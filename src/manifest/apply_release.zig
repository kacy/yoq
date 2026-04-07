const std = @import("std");
const update_common = @import("update/common.zig");

pub const ApplyOutcome = struct {
    status: update_common.DeploymentStatus,
    message: ?[]const u8 = null,
    placed: usize = 0,
    failed: usize = 0,
};

pub const ApplyResult = struct {
    release_id: ?[]const u8,
    outcome: ApplyOutcome,

    pub fn toReport(self: ApplyResult, app_name: []const u8, service_count: usize) ApplyReport {
        return .{
            .app_name = app_name,
            .release_id = self.release_id,
            .status = self.outcome.status,
            .service_count = service_count,
            .placed = self.outcome.placed,
            .failed = self.outcome.failed,
            .message = self.outcome.message,
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

    pub fn deinit(self: ApplyReport, alloc: std.mem.Allocator) void {
        if (self.release_id) |id| alloc.free(id);
    }
};

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

    const report = result.toReport("demo-app", 3);
    try std.testing.expectEqualStrings("demo-app", report.app_name);
    try std.testing.expectEqualStrings("dep789", report.release_id.?);
    try std.testing.expectEqual(update_common.DeploymentStatus.completed, report.status);
    try std.testing.expectEqual(@as(usize, 3), report.service_count);
    try std.testing.expectEqual(@as(usize, 3), report.placed);
    try std.testing.expectEqual(@as(usize, 0), report.failed);
    try std.testing.expect(report.message == null);
}
