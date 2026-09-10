const std = @import("std");
const json_helpers = @import("../lib/json_helpers.zig");

pub const Workload = struct {
    kind: []const u8 = "service",
    name: []const u8,
};

const FailureDetail = struct {
    workload_kind: []const u8,
    workload_name: []const u8,
    reason: []const u8,
};

const Target = struct {
    workload_kind: []const u8,
    workload_name: []const u8,
    state: []const u8 = "pending",
    reason: ?[]const u8 = null,
};

/// records borrow their strings; the collection owns only its item storage.
pub const FailureDetails = struct {
    alloc: std.mem.Allocator,
    items: std.ArrayList(FailureDetail) = .empty,

    pub fn init(alloc: std.mem.Allocator) FailureDetails {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *FailureDetails) void {
        self.items.deinit(self.alloc);
    }

    pub fn append(self: *FailureDetails, workload: Workload, reason: []const u8) !void {
        try self.items.append(self.alloc, .{
            .workload_kind = workload.kind,
            .workload_name = workload.name,
            .reason = reason,
        });
    }

    pub fn toOwnedJson(self: *const FailureDetails) !?[]u8 {
        if (self.items.items.len == 0) return null;
        return try std.json.Stringify.valueAlloc(self.alloc, self.items.items, .{});
    }
};

/// records borrow their strings; the collection owns only its item storage.
pub const Targets = struct {
    alloc: std.mem.Allocator,
    items: std.ArrayList(Target) = .empty,

    pub fn init(alloc: std.mem.Allocator) Targets {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *Targets) void {
        self.items.deinit(self.alloc);
    }

    pub fn append(self: *Targets, workload: Workload) !void {
        try self.items.append(self.alloc, .{
            .workload_kind = workload.kind,
            .workload_name = workload.name,
        });
    }

    pub fn set(self: *Targets, workload: Workload, state: []const u8, reason: ?[]const u8) void {
        for (self.items.items) |*item| {
            if (std.mem.eql(u8, item.workload_kind, workload.kind) and std.mem.eql(u8, item.workload_name, workload.name)) {
                item.state = state;
                item.reason = reason;
                return;
            }
        }
    }

    pub fn stateFor(self: *const Targets, workload: Workload) []const u8 {
        for (self.items.items) |item| {
            if (std.mem.eql(u8, item.workload_kind, workload.kind) and std.mem.eql(u8, item.workload_name, workload.name)) {
                return item.state;
            }
        }
        return "pending";
    }

    /// restored state and reason strings borrow from the supplied JSON buffer.
    pub fn restoreFromJson(self: *Targets, rollout_targets_json: ?[]const u8) void {
        const json = rollout_targets_json orelse return;
        var iter = json_helpers.extractJsonObjects(json);
        while (iter.next()) |obj| {
            const kind = json_helpers.extractJsonString(obj, "workload_kind") orelse continue;
            const name = json_helpers.extractJsonString(obj, "workload_name") orelse continue;
            const state = json_helpers.extractJsonString(obj, "state") orelse continue;
            const reason = json_helpers.extractJsonString(obj, "reason");
            self.set(.{ .kind = kind, .name = name }, state, reason);
        }
    }

    pub fn toOwnedJson(self: *const Targets) !?[]u8 {
        if (self.items.items.len == 0) return null;
        return try std.json.Stringify.valueAlloc(self.alloc, self.items.items, .{});
    }
};

pub fn isTerminalState(state: []const u8) bool {
    return std.mem.eql(u8, state, "ready") or
        std.mem.eql(u8, state, "failed") or
        std.mem.eql(u8, state, "rolled_back");
}

test "rollout progress JSON preserves empty values fields and escaping" {
    const alloc = std.testing.allocator;
    var failures = FailureDetails.init(alloc);
    defer failures.deinit();
    var targets = Targets.init(alloc);
    defer targets.deinit();
    try std.testing.expect((try failures.toOwnedJson()) == null);
    try std.testing.expect((try targets.toOwnedJson()) == null);

    const workload: Workload = .{ .name = "web\"\\" };
    try failures.append(workload, "line one\nline two");
    try targets.append(workload);
    const failures_json = (try failures.toOwnedJson()).?;
    defer alloc.free(failures_json);
    const targets_json = (try targets.toOwnedJson()).?;
    defer alloc.free(targets_json);
    try std.testing.expectEqualStrings(
        "[{\"workload_kind\":\"service\",\"workload_name\":\"web\\\"\\\\\",\"reason\":\"line one\\nline two\"}]",
        failures_json,
    );
    try std.testing.expectEqualStrings(
        "[{\"workload_kind\":\"service\",\"workload_name\":\"web\\\"\\\\\",\"state\":\"pending\",\"reason\":null}]",
        targets_json,
    );
}

test "rollout progress restore matches kind and name and skips incomplete records" {
    var targets = Targets.init(std.testing.allocator);
    defer targets.deinit();
    const service: Workload = .{ .name = "web" };
    const job: Workload = .{ .kind = "job", .name = "web" };
    const other: Workload = .{ .name = "worker" };
    try targets.append(service);
    try targets.append(job);
    try targets.append(other);
    targets.restoreFromJson(null);
    targets.restoreFromJson(
        \\[
        \\  {"workload_kind":"service","workload_name":"web","state":"ready","reason":null},
        \\  {"workload_kind":"job","workload_name":"web","state":"failed","reason":"start_failed"},
        \\  {"workload_kind":"service","workload_name":"unknown","state":"ready"},
        \\  {"workload_kind":"service","workload_name":"worker"},
        \\  {"workload_kind":"service","state":"ready"},
        \\  {"workload_name":"worker","state":"ready"}
        \\]
    );
    try std.testing.expectEqualStrings("ready", targets.stateFor(service));
    try std.testing.expectEqualStrings("failed", targets.stateFor(job));
    try std.testing.expectEqualStrings("pending", targets.stateFor(other));
    try std.testing.expectEqualStrings("pending", targets.stateFor(.{ .name = "unknown" }));
    try std.testing.expectEqual(@as(usize, 3), targets.items.items.len);
    try std.testing.expect(targets.items.items[0].reason == null);
    try std.testing.expectEqualStrings("start_failed", targets.items.items[1].reason.?);

    targets.set(job, "rolled_back", null);
    try std.testing.expectEqualStrings("rolled_back", targets.stateFor(job));
    try std.testing.expect(targets.items.items[1].reason == null);
    for ([_][]const u8{ "ready", "failed", "rolled_back" }) |state| {
        try std.testing.expect(isTerminalState(state));
    }
    for ([_][]const u8{ "pending", "starting", "unknown" }) |state| {
        try std.testing.expect(!isTerminalState(state));
    }
}
