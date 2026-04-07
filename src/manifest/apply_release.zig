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
