const std = @import("std");
const spec = @import("../spec.zig");

pub const interval_ms = 5000;
pub const cooldown_ms = 60_000;
pub const consecutive_samples = 3;

pub const Metric = enum {
    cpu_percent,
    memory_percent,
    restart_count,
    latency_p99_ms,
    error_rate_percent,

    pub fn threshold(self: Metric, config: spec.AlertSpec) ?f64 {
        return switch (self) {
            .cpu_percent => config.cpu_percent,
            .memory_percent => config.memory_percent,
            .restart_count => if (config.restart_count) |count| @floatFromInt(count) else null,
            .latency_p99_ms => config.latency_p99_ms,
            .error_rate_percent => config.error_rate_percent,
        };
    }
};

pub const Event = struct {
    revision: u64,
    state: enum { firing, resolved },
    value: f64,
};

pub const Rule = struct {
    threshold: f64,
    value: ?f64 = null,
    active: bool = false,
    breach_samples: u8 = 0,
    recovery_samples: u8 = 0,
    revision: u64 = 0,
    pending: ?Event = null,
    in_flight: bool = false,
    next_attempt_ms: u64 = 0,
    transitioned: bool = false,

    pub fn observe(self: *Rule, observed: ?f64) void {
        self.transitioned = false;
        self.value = if (observed) |value| (if (std.math.isFinite(value) and value >= 0) value else null) else null;
        const value = self.value orelse {
            // missing data cannot resolve an alert or count toward a new one.
            self.breach_samples = 0;
            self.recovery_samples = 0;
            return;
        };
        if (value > self.threshold) {
            self.recovery_samples = 0;
            self.breach_samples = @min(self.breach_samples + 1, consecutive_samples);
            if (!self.active and self.breach_samples == consecutive_samples) self.transition(true, value);
        } else {
            self.breach_samples = 0;
            self.recovery_samples = @min(self.recovery_samples + 1, consecutive_samples);
            if (self.active and self.recovery_samples == consecutive_samples) self.transition(false, value);
        }
    }

    fn transition(self: *Rule, active: bool, value: f64) void {
        self.active = active;
        self.transitioned = true;
        self.revision +|= 1;
        self.pending = .{ .revision = self.revision, .state = if (active) .firing else .resolved, .value = value };
        self.next_attempt_ms = 0;
    }

    pub fn due(self: *Rule, now_ms: u64) ?Event {
        if (self.in_flight or now_ms < self.next_attempt_ms) return null;
        if (self.pending == null and self.active) {
            const value = self.value orelse return null;
            self.revision +|= 1;
            self.pending = .{ .revision = self.revision, .state = .firing, .value = value };
        }
        return self.pending;
    }

    pub fn queued(self: *Rule) void {
        self.in_flight = true;
    }

    pub fn delivered(self: *Rule, revision: u64, success: bool, now_ms: u64) void {
        self.in_flight = false;
        const pending = self.pending orelse return;
        // a recovery observed during delivery must survive the older result.
        if (pending.revision != revision) return;
        if (success) self.pending = null;
        self.next_attempt_ms = now_ms +| cooldown_ms;
    }

    pub fn status(self: Rule) []const u8 {
        if (self.value == null) return "unknown";
        if (self.active) return "firing";
        if (self.breach_samples != 0) return "pending";
        return "ok";
    }
};

test "alerts require consecutive breaches and recovery while missing data preserves active state" {
    var rule: Rule = .{ .threshold = 90 };
    rule.observe(91);
    rule.observe(90);
    try std.testing.expect(rule.due(0) == null);
    for (0..consecutive_samples) |_| rule.observe(91);
    try std.testing.expect(rule.active);
    try std.testing.expectEqual(.firing, rule.due(0).?.state);
    rule.observe(null);
    try std.testing.expect(rule.active);
    try std.testing.expectEqualStrings("unknown", rule.status());
    rule.observe(89);
    rule.observe(std.math.nan(f64));
    rule.observe(89);
    try std.testing.expect(rule.active);
    rule.observe(89);
    rule.observe(89);
    try std.testing.expect(!rule.active);
    try std.testing.expectEqual(.resolved, rule.due(0).?.state);
}

test "alerts bound retries and reminders without losing a recovery during delivery" {
    var rule: Rule = .{ .threshold = 1 };
    for (0..consecutive_samples) |_| rule.observe(2);
    const firing = rule.due(100).?;
    rule.queued();
    try std.testing.expect(rule.due(200) == null);
    rule.delivered(firing.revision, false, 200);
    try std.testing.expect(rule.due(201) == null);
    const retried = rule.due(200 + cooldown_ms).?;
    try std.testing.expectEqual(firing.revision, retried.revision);
    rule.queued();
    for (0..consecutive_samples) |_| rule.observe(0);
    rule.delivered(retried.revision, true, 300 + cooldown_ms);
    const recovery = rule.due(301 + cooldown_ms).?;
    try std.testing.expectEqual(.resolved, recovery.state);
    rule.queued();
    rule.delivered(recovery.revision, true, 400 + cooldown_ms);
    try std.testing.expect(rule.due(500 + cooldown_ms * 2) == null);

    for (0..consecutive_samples) |_| rule.observe(2);
    const fresh = rule.due(500 + cooldown_ms * 2).?;
    rule.queued();
    rule.delivered(fresh.revision, true, 600 + cooldown_ms * 2);
    try std.testing.expect(rule.due(601 + cooldown_ms * 2) == null);
    try std.testing.expectEqual(.firing, rule.due(600 + cooldown_ms * 3).?.state);
}
