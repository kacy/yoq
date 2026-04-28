const std = @import("std");

const scheduler = @import("../../../cluster/scheduler.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const apply_request = @import("apply_request.zig");

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

const FailureDetail = struct {
    workload_kind: []const u8,
    workload_name: []const u8,
    reason: []const u8,
};

const RolloutTarget = struct {
    workload_kind: []const u8,
    workload_name: []const u8,
    state: []const u8,
    reason: ?[]const u8 = null,
};

pub const FailureDetailBuilder = struct {
    alloc: std.mem.Allocator,
    items: std.ArrayListUnmanaged(FailureDetail) = .empty,

    pub fn init(alloc: std.mem.Allocator) FailureDetailBuilder {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *FailureDetailBuilder) void {
        self.items.deinit(self.alloc);
    }

    pub fn appendRequest(self: *FailureDetailBuilder, req: apply_request.ServiceRequest, reason: []const u8) !void {
        try self.append(req.request.workload_kind orelse "service", req.request.workload_name orelse req.request.image, reason);
    }

    pub fn appendTarget(self: *FailureDetailBuilder, target: ScheduledTarget, reason: []const u8) !void {
        try self.append(target.request.workload_kind orelse "service", target.request.workload_name orelse target.request.image, reason);
    }

    fn append(self: *FailureDetailBuilder, workload_kind: []const u8, workload_name: []const u8, reason: []const u8) !void {
        try self.items.append(self.alloc, .{
            .workload_kind = workload_kind,
            .workload_name = workload_name,
            .reason = reason,
        });
    }

    pub fn toOwnedJson(self: *FailureDetailBuilder) !?[]u8 {
        if (self.items.items.len == 0) return null;

        var json_buf_writer = std.Io.Writer.Allocating.init(self.alloc);
        defer json_buf_writer.deinit();

        const writer = &json_buf_writer.writer;

        try writer.writeByte('[');
        for (self.items.items, 0..) |detail, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('{');
            try json_helpers.writeJsonStringField(writer, "workload_kind", detail.workload_kind);
            try writer.writeByte(',');
            try json_helpers.writeJsonStringField(writer, "workload_name", detail.workload_name);
            try writer.writeByte(',');
            try json_helpers.writeJsonStringField(writer, "reason", detail.reason);
            try writer.writeByte('}');
        }
        try writer.writeByte(']');
        return try json_buf_writer.toOwnedSlice();
    }
};

pub const RolloutTargetBuilder = struct {
    alloc: std.mem.Allocator,
    items: std.ArrayListUnmanaged(RolloutTarget) = .empty,

    pub fn init(alloc: std.mem.Allocator) RolloutTargetBuilder {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *RolloutTargetBuilder) void {
        self.items.deinit(self.alloc);
    }

    pub fn appendRequests(self: *RolloutTargetBuilder, requests: []const apply_request.ServiceRequest) !void {
        for (requests) |req| {
            try self.items.append(self.alloc, .{
                .workload_kind = req.request.workload_kind orelse "service",
                .workload_name = req.request.workload_name orelse req.request.image,
                .state = "pending",
                .reason = null,
            });
        }
    }

    pub fn setRequestState(
        self: *RolloutTargetBuilder,
        request: scheduler.PlacementRequest,
        state: []const u8,
        reason: ?[]const u8,
    ) void {
        self.set(
            request.workload_kind orelse "service",
            request.workload_name orelse request.image,
            state,
            reason,
        );
    }

    pub fn setTargetState(
        self: *RolloutTargetBuilder,
        target: ScheduledTarget,
        state: []const u8,
        reason: ?[]const u8,
    ) void {
        self.set(
            target.request.workload_kind orelse "service",
            target.request.workload_name orelse target.request.image,
            state,
            reason,
        );
    }

    pub fn setActivatedState(
        self: *RolloutTargetBuilder,
        target: ActivatedTarget,
        state: []const u8,
        reason: ?[]const u8,
    ) void {
        self.set(
            target.request.workload_kind orelse "service",
            target.request.workload_name orelse target.request.image,
            state,
            reason,
        );
    }

    fn set(
        self: *RolloutTargetBuilder,
        workload_kind: []const u8,
        workload_name: []const u8,
        state: []const u8,
        reason: ?[]const u8,
    ) void {
        for (self.items.items) |*item| {
            if (std.mem.eql(u8, item.workload_kind, workload_kind) and std.mem.eql(u8, item.workload_name, workload_name)) {
                item.state = state;
                item.reason = reason;
                return;
            }
        }
    }

    fn stateFor(
        self: *const RolloutTargetBuilder,
        workload_kind: []const u8,
        workload_name: []const u8,
    ) []const u8 {
        for (self.items.items) |item| {
            if (std.mem.eql(u8, item.workload_kind, workload_kind) and std.mem.eql(u8, item.workload_name, workload_name)) {
                return item.state;
            }
        }
        return "pending";
    }

    pub fn stateForRequest(self: *const RolloutTargetBuilder, request: scheduler.PlacementRequest) []const u8 {
        return self.stateFor(
            request.workload_kind orelse "service",
            request.workload_name orelse request.image,
        );
    }

    pub fn restoreFromJson(self: *RolloutTargetBuilder, rollout_targets_json: ?[]const u8) void {
        const json = rollout_targets_json orelse return;
        var iter = json_helpers.extractJsonObjects(json);
        while (iter.next()) |obj| {
            const workload_kind = json_helpers.extractJsonString(obj, "workload_kind") orelse continue;
            const workload_name = json_helpers.extractJsonString(obj, "workload_name") orelse continue;
            const state = json_helpers.extractJsonString(obj, "state") orelse continue;
            const reason = json_helpers.extractJsonString(obj, "reason");
            self.set(workload_kind, workload_name, state, reason);
        }
    }

    pub fn toOwnedJson(self: *RolloutTargetBuilder) !?[]u8 {
        if (self.items.items.len == 0) return null;

        var json_buf_writer = std.Io.Writer.Allocating.init(self.alloc);
        defer json_buf_writer.deinit();

        const writer = &json_buf_writer.writer;

        try writer.writeByte('[');
        for (self.items.items, 0..) |target, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeByte('{');
            try json_helpers.writeJsonStringField(writer, "workload_kind", target.workload_kind);
            try writer.writeByte(',');
            try json_helpers.writeJsonStringField(writer, "workload_name", target.workload_name);
            try writer.writeByte(',');
            try json_helpers.writeJsonStringField(writer, "state", target.state);
            try writer.writeByte(',');
            try json_helpers.writeNullableJsonStringField(writer, "reason", target.reason);
            try writer.writeByte('}');
        }
        try writer.writeByte(']');
        return try json_buf_writer.toOwnedSlice();
    }
};

pub fn isTerminalState(state: []const u8) bool {
    return std.mem.eql(u8, state, "ready") or
        std.mem.eql(u8, state, "failed") or
        std.mem.eql(u8, state, "rolled_back");
}

test "rollout target builder restores terminal request state from stored json" {
    const alloc = std.testing.allocator;
    var rollout_targets = RolloutTargetBuilder.init(alloc);
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

    try rollout_targets.appendRequests(&.{.{
        .request = request,
        .rollout = .{},
    }});
    rollout_targets.restoreFromJson(
        "[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"ready\",\"reason\":null}]",
    );

    try std.testing.expectEqualStrings("ready", rollout_targets.stateForRequest(request));
    try std.testing.expect(isTerminalState(rollout_targets.stateForRequest(request)));
}
