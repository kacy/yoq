const std = @import("std");
const spec = @import("../../image/spec.zig");

pub const Status = enum { starting, healthy, unhealthy };

pub const Settings = struct {
    interval_ns: u64,
    timeout_ns: u64,
    start_period_ns: u64,
    start_interval_ns: u64,
    retries: u32,

    pub fn fromImage(config: spec.Healthcheck) !?Settings {
        const command = config.Test orelse return null;
        if (command.len == 0) return null;
        if (std.mem.eql(u8, command[0], "NONE")) {
            if (command.len != 1) return error.InvalidHealthcheck;
            return null;
        }
        if (std.mem.eql(u8, command[0], "CMD")) {
            if (command.len < 2 or command[1].len == 0) return error.InvalidHealthcheck;
        } else if (std.mem.eql(u8, command[0], "CMD-SHELL")) {
            if (command.len != 2 or command[1].len == 0) return error.InvalidHealthcheck;
        } else return error.InvalidHealthcheck;
        const retries = config.Retries orelse 3;
        if (retries < 0 or retries > 1_000_000) return error.InvalidHealthcheck;
        return .{
            .interval_ns = try duration(config.Interval, 30 * std.time.ns_per_s),
            .timeout_ns = try duration(config.Timeout, 30 * std.time.ns_per_s),
            .start_period_ns = try duration(config.StartPeriod, 0),
            .start_interval_ns = try duration(config.StartInterval, 5 * std.time.ns_per_s),
            .retries = @intCast(if (retries == 0) 3 else retries),
        };
    }
};

fn duration(value: ?i64, default: u64) !u64 {
    const ns = value orelse return default;
    if (ns == 0) return default;
    if (ns < std.time.ns_per_ms or ns > 24 * std.time.ns_per_hour) return error.InvalidHealthcheck;
    return @intCast(ns);
}

pub const State = struct {
    status: Status = .starting,
    failures: u32 = 0,
    started_ns: i64,

    pub fn observe(self: *State, settings: Settings, now_ns: i64, success: bool) void {
        if (success) {
            self.status = .healthy;
            self.failures = 0;
        } else if (self.status != .starting or !self.inStartPeriod(settings, now_ns)) {
            self.failures +|= 1;
            if (self.failures >= settings.retries) self.status = .unhealthy;
        }
    }

    pub fn interval(self: State, settings: Settings, now_ns: i64) u64 {
        return if (self.status == .starting and self.inStartPeriod(settings, now_ns)) settings.start_interval_ns else settings.interval_ns;
    }

    fn inStartPeriod(self: State, settings: Settings, now_ns: i64) bool {
        return @as(u64, @intCast(@max(0, now_ns - self.started_ns))) < settings.start_period_ns;
    }
};

test "local health start grace retries and recovery" {
    const settings = (try Settings.fromImage(.{ .Test = &.{ "CMD", "true" }, .Retries = 2, .StartPeriod = 10 * std.time.ns_per_s })).?;
    var state: State = .{ .started_ns = 0 };
    state.observe(settings, 1, false);
    try std.testing.expectEqual(Status.starting, state.status);
    try std.testing.expectEqual(@as(u32, 0), state.failures);
    state.observe(settings, 11 * std.time.ns_per_s, false);
    try std.testing.expectEqual(Status.starting, state.status);
    state.observe(settings, 12 * std.time.ns_per_s, false);
    try std.testing.expectEqual(Status.unhealthy, state.status);
    state.observe(settings, 13 * std.time.ns_per_s, true);
    try std.testing.expectEqual(Status.healthy, state.status);
    try std.testing.expectEqual(@as(u32, 0), state.failures);
    state = .{ .started_ns = 0 };
    state.observe(settings, 1, true);
    state.observe(settings, 2, false);
    state.observe(settings, 3, false);
    try std.testing.expectEqual(Status.unhealthy, state.status);
}

test "local health rejects invalid execution forms and unbounded timing" {
    try std.testing.expect((try Settings.fromImage(.{ .Test = &.{"NONE"} })) == null);
    try std.testing.expectError(error.InvalidHealthcheck, Settings.fromImage(.{ .Test = &.{"CMD"} }));
    try std.testing.expectError(error.InvalidHealthcheck, Settings.fromImage(.{ .Test = &.{ "CMD-SHELL", "true", "extra" } }));
    try std.testing.expectError(error.InvalidHealthcheck, Settings.fromImage(.{ .Test = &.{ "CMD", "true" }, .Timeout = -1 }));
    try std.testing.expectError(error.InvalidHealthcheck, Settings.fromImage(.{ .Test = &.{ "CMD", "true" }, .Interval = std.math.maxInt(i64) }));
}
