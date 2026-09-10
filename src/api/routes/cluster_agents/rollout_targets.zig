const std = @import("std");

const scheduler = @import("../../../cluster/scheduler.zig");
const rollout_progress = @import("../../../manifest/rollout_progress.zig");

pub const ScheduledTarget = struct {
    request: scheduler.PlacementRequest,
    assignment_ids: []const []const u8,
    placement_count: usize,

    pub fn deinit(self: *const ScheduledTarget, alloc: std.mem.Allocator) void {
        for (self.assignment_ids) |id| alloc.free(id);
        alloc.free(self.assignment_ids);
    }
};

pub const ActivatedTarget = struct {
    request: scheduler.PlacementRequest,
    assignment_ids: []const []const u8,

    pub fn deinit(self: *const ActivatedTarget, alloc: std.mem.Allocator) void {
        for (self.assignment_ids) |id| alloc.free(id);
        alloc.free(self.assignment_ids);
    }
};

pub fn workloadForRequest(request: scheduler.PlacementRequest) rollout_progress.Workload {
    return .{
        .kind = request.workload_kind orelse "service",
        .name = request.workload_name orelse request.image,
    };
}

test "rollout target builder restores terminal request state from stored json" {
    const alloc = std.testing.allocator;
    var rollout_targets = rollout_progress.Targets.init(alloc);
    defer rollout_targets.deinit();

    const request: scheduler.PlacementRequest = .{
        .image = "alpine",
        .command = "echo web",
        .cpu_limit = 1000,
        .memory_limit_mb = 256,
        .app_name = "demo-app",
        .workload_kind = "service",
        .workload_name = "web",
    };

    try rollout_targets.append(workloadForRequest(request));
    rollout_targets.restoreFromJson(
        "[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"ready\",\"reason\":null}]",
    );

    try std.testing.expectEqualStrings("ready", rollout_targets.stateFor(workloadForRequest(request)));
    try std.testing.expect(rollout_progress.isTerminalState(rollout_targets.stateFor(workloadForRequest(request))));
}
