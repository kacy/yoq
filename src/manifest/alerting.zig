// alerting — built-in threshold-based alerting with webhook notifications
//
// monitors service metrics against configurable thresholds and fires
// webhook notifications when conditions are met. integrates with the
// manifest spec so operators can define alerts inline:
//
//   [service.web.alerts]
//   cpu_percent = 90
//   memory_percent = 85
//   restart_count = 5
//   webhook = "https://hooks.slack.com/..."
//
// alert evaluation is pure (no I/O) — the caller provides current
// metric values and this module returns which alerts fired.

const std = @import("std");

// -- types --

/// alert severity levels
pub const Severity = enum {
    warning,
    critical,

    pub fn toString(self: Severity) []const u8 {
        return switch (self) {
            .warning => "warning",
            .critical => "critical",
        };
    }
};

/// alert state machine: tracks transitions to avoid flapping
pub const AlertState = enum {
    ok,
    pending,
    firing,
    resolved,

    pub fn toString(self: AlertState) []const u8 {
        return switch (self) {
            .ok => "ok",
            .pending => "pending",
            .firing => "firing",
            .resolved => "resolved",
        };
    }
};

/// threshold configuration for a single metric
pub const Threshold = struct {
    metric: MetricType,
    value: f64,
    severity: Severity = .warning,
    /// number of consecutive checks before firing (debounce)
    for_count: u32 = 3,
};

pub const MetricType = enum {
    cpu_percent,
    memory_percent,
    restart_count,
    latency_p99_ms,
    error_rate_percent,

    pub fn toString(self: MetricType) []const u8 {
        return switch (self) {
            .cpu_percent => "cpu_percent",
            .memory_percent => "memory_percent",
            .restart_count => "restart_count",
            .latency_p99_ms => "latency_p99_ms",
            .error_rate_percent => "error_rate_percent",
        };
    }

    pub fn fromString(s: []const u8) ?MetricType {
        if (std.mem.eql(u8, s, "cpu_percent")) return .cpu_percent;
        if (std.mem.eql(u8, s, "memory_percent")) return .memory_percent;
        if (std.mem.eql(u8, s, "restart_count")) return .restart_count;
        if (std.mem.eql(u8, s, "latency_p99_ms")) return .latency_p99_ms;
        if (std.mem.eql(u8, s, "error_rate_percent")) return .error_rate_percent;
        return null;
    }
};

/// webhook notification target
pub const WebhookConfig = struct {
    url: []const u8,
    /// optional headers (e.g. Authorization)
    headers: []const Header = &.{},

    pub const Header = struct {
        name: []const u8,
        value: []const u8,
    };
};

/// alert rule — a threshold + notification config for a service
pub const AlertRule = struct {
    service_name: []const u8,
    threshold: Threshold,
    webhook: ?WebhookConfig = null,
};

/// current metric values for a service
pub const MetricSnapshot = struct {
    cpu_percent: f64 = 0,
    memory_percent: f64 = 0,
    restart_count: u32 = 0,
    latency_p99_ms: f64 = 0,
    error_rate_percent: f64 = 0,

    pub fn getValue(self: MetricSnapshot, metric: MetricType) f64 {
        return switch (metric) {
            .cpu_percent => self.cpu_percent,
            .memory_percent => self.memory_percent,
            .restart_count => @floatFromInt(self.restart_count),
            .latency_p99_ms => self.latency_p99_ms,
            .error_rate_percent => self.error_rate_percent,
        };
    }
};

/// a fired alert — result of evaluating a rule against a snapshot
pub const FiredAlert = struct {
    service_name: []const u8,
    metric: MetricType,
    threshold: f64,
    current_value: f64,
    severity: Severity,
    state: AlertState,
};

// -- alert tracker --

/// maximum number of tracked alert rules
const max_rules = 64;

/// tracks alert state across evaluation cycles.
/// maintains consecutive breach counts for debouncing.
pub const AlertTracker = struct {
    rules: [max_rules]AlertRule = undefined,
    rule_count: usize = 0,
    /// consecutive breach count per rule (for debounce)
    breach_counts: [max_rules]u32 = .{0} ** max_rules,
    /// current state per rule
    states: [max_rules]AlertState = .{.ok} ** max_rules,

    /// add an alert rule. returns false if the tracker is full.
    pub fn addRule(self: *AlertTracker, rule: AlertRule) bool {
        if (self.rule_count >= max_rules) return false;
        self.rules[self.rule_count] = rule;
        self.rule_count += 1;
        return true;
    }

    /// evaluate all rules against the provided metrics.
    /// returns the list of alerts that changed state.
    pub fn evaluate(
        self: *AlertTracker,
        service_name: []const u8,
        snapshot: MetricSnapshot,
        results: *[max_rules]FiredAlert,
    ) usize {
        var count: usize = 0;

        for (0..self.rule_count) |i| {
            const rule = &self.rules[i];
            if (!std.mem.eql(u8, rule.service_name, service_name)) continue;

            const current = snapshot.getValue(rule.threshold.metric);
            const exceeded = current >= rule.threshold.value;

            if (exceeded) {
                self.breach_counts[i] += 1;

                if (self.breach_counts[i] >= rule.threshold.for_count) {
                    if (self.states[i] != .firing) {
                        self.states[i] = .firing;
                        results[count] = .{
                            .service_name = rule.service_name,
                            .metric = rule.threshold.metric,
                            .threshold = rule.threshold.value,
                            .current_value = current,
                            .severity = rule.threshold.severity,
                            .state = .firing,
                        };
                        count += 1;
                    }
                } else if (self.states[i] == .ok) {
                    self.states[i] = .pending;
                }
            } else {
                self.breach_counts[i] = 0;
                if (self.states[i] == .firing) {
                    self.states[i] = .resolved;
                    results[count] = .{
                        .service_name = rule.service_name,
                        .metric = rule.threshold.metric,
                        .threshold = rule.threshold.value,
                        .current_value = current,
                        .severity = rule.threshold.severity,
                        .state = .resolved,
                    };
                    count += 1;
                } else {
                    self.states[i] = .ok;
                }
            }
        }

        return count;
    }

    /// format a webhook JSON payload for a fired alert.
    /// writes to the provided buffer.
    pub fn formatWebhookPayload(alert: FiredAlert, buf: *[1024]u8) ?[]const u8 {
        const result = std.fmt.bufPrint(buf,
            \\{{"service":"{s}","metric":"{s}","threshold":{d:.1},"current":{d:.1},"severity":"{s}","state":"{s}"}}
        , .{
            alert.service_name,
            alert.metric.toString(),
            alert.threshold,
            alert.current_value,
            alert.severity.toString(),
            alert.state.toString(),
        }) catch return null;
        return result;
    }
};

// -- manifest spec integration --

/// alert configuration parsed from the manifest.
/// one AlertSpec per service with alert thresholds defined.
pub const AlertSpec = struct {
    cpu_percent: ?f64 = null,
    memory_percent: ?f64 = null,
    restart_count: ?u32 = null,
    latency_p99_ms: ?f64 = null,
    error_rate_percent: ?f64 = null,
    webhook: ?[]const u8 = null,

    pub fn deinit(self: AlertSpec, alloc: std.mem.Allocator) void {
        if (self.webhook) |w| alloc.free(w);
    }

    /// convert to alert rules for a given service name
    pub fn toRules(self: AlertSpec, service_name: []const u8, rules: *[max_rules]AlertRule) usize {
        var count: usize = 0;
        const webhook: ?WebhookConfig = if (self.webhook) |url| .{ .url = url } else null;

        if (self.cpu_percent) |v| {
            rules[count] = .{
                .service_name = service_name,
                .threshold = .{ .metric = .cpu_percent, .value = v },
                .webhook = webhook,
            };
            count += 1;
        }
        if (self.memory_percent) |v| {
            rules[count] = .{
                .service_name = service_name,
                .threshold = .{ .metric = .memory_percent, .value = v },
                .webhook = webhook,
            };
            count += 1;
        }
        if (self.restart_count) |v| {
            rules[count] = .{
                .service_name = service_name,
                .threshold = .{ .metric = .restart_count, .value = @floatFromInt(v) },
                .webhook = webhook,
            };
            count += 1;
        }
        if (self.latency_p99_ms) |v| {
            rules[count] = .{
                .service_name = service_name,
                .threshold = .{ .metric = .latency_p99_ms, .value = v },
                .webhook = webhook,
            };
            count += 1;
        }
        if (self.error_rate_percent) |v| {
            rules[count] = .{
                .service_name = service_name,
                .threshold = .{ .metric = .error_rate_percent, .value = v },
                .webhook = webhook,
            };
            count += 1;
        }

        return count;
    }
};

// -- tests --

test "alert tracker: single rule fires after debounce" {
    var tracker = AlertTracker{};
    _ = tracker.addRule(.{
        .service_name = "web",
        .threshold = .{ .metric = .cpu_percent, .value = 80, .for_count = 3 },
    });

    var results: [max_rules]FiredAlert = undefined;
    const snapshot = MetricSnapshot{ .cpu_percent = 90 };

    // first two evaluations: pending (not yet fired)
    var count = tracker.evaluate("web", snapshot, &results);
    try std.testing.expectEqual(@as(usize, 0), count);
    try std.testing.expectEqual(AlertState.pending, tracker.states[0]);

    count = tracker.evaluate("web", snapshot, &results);
    try std.testing.expectEqual(@as(usize, 0), count);

    // third evaluation: fires
    count = tracker.evaluate("web", snapshot, &results);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(AlertState.firing, results[0].state);
    try std.testing.expect(results[0].current_value == 90);
}

test "alert tracker: rule resolves when metric drops" {
    var tracker = AlertTracker{};
    _ = tracker.addRule(.{
        .service_name = "web",
        .threshold = .{ .metric = .memory_percent, .value = 80, .for_count = 1 },
    });

    var results: [max_rules]FiredAlert = undefined;

    // fire immediately (for_count = 1)
    var count = tracker.evaluate("web", .{ .memory_percent = 90 }, &results);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(AlertState.firing, results[0].state);

    // stays firing (no duplicate notification)
    count = tracker.evaluate("web", .{ .memory_percent = 85 }, &results);
    try std.testing.expectEqual(@as(usize, 0), count);

    // resolves when below threshold
    count = tracker.evaluate("web", .{ .memory_percent = 70 }, &results);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(AlertState.resolved, results[0].state);
}

test "alert tracker: ignores unrelated services" {
    var tracker = AlertTracker{};
    _ = tracker.addRule(.{
        .service_name = "api",
        .threshold = .{ .metric = .cpu_percent, .value = 80, .for_count = 1 },
    });

    var results: [max_rules]FiredAlert = undefined;
    const count = tracker.evaluate("web", .{ .cpu_percent = 99 }, &results);
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "alert tracker: multiple rules for same service" {
    var tracker = AlertTracker{};
    _ = tracker.addRule(.{
        .service_name = "web",
        .threshold = .{ .metric = .cpu_percent, .value = 80, .for_count = 1 },
    });
    _ = tracker.addRule(.{
        .service_name = "web",
        .threshold = .{ .metric = .memory_percent, .value = 90, .for_count = 1 },
    });

    var results: [max_rules]FiredAlert = undefined;
    const count = tracker.evaluate("web", .{ .cpu_percent = 85, .memory_percent = 95 }, &results);
    try std.testing.expectEqual(@as(usize, 2), count);
}

test "metric type round-trip" {
    const types = [_]MetricType{ .cpu_percent, .memory_percent, .restart_count, .latency_p99_ms, .error_rate_percent };
    for (types) |t| {
        const s = t.toString();
        const parsed = MetricType.fromString(s);
        try std.testing.expect(parsed != null);
        try std.testing.expectEqual(t, parsed.?);
    }
    try std.testing.expect(MetricType.fromString("unknown") == null);
}

test "severity toString" {
    try std.testing.expectEqualStrings("warning", Severity.warning.toString());
    try std.testing.expectEqualStrings("critical", Severity.critical.toString());
}

test "alert state toString" {
    try std.testing.expectEqualStrings("ok", AlertState.ok.toString());
    try std.testing.expectEqualStrings("firing", AlertState.firing.toString());
    try std.testing.expectEqualStrings("resolved", AlertState.resolved.toString());
}

test "format webhook payload" {
    const alert = FiredAlert{
        .service_name = "web",
        .metric = .cpu_percent,
        .threshold = 80,
        .current_value = 92.5,
        .severity = .warning,
        .state = .firing,
    };

    var buf: [1024]u8 = undefined;
    const payload = AlertTracker.formatWebhookPayload(alert, &buf);
    try std.testing.expect(payload != null);

    const p = payload.?;
    try std.testing.expect(std.mem.indexOf(u8, p, "\"service\":\"web\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, p, "\"metric\":\"cpu_percent\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, p, "\"state\":\"firing\"") != null);
}

test "metric snapshot getValue" {
    const snap = MetricSnapshot{
        .cpu_percent = 42.5,
        .memory_percent = 60,
        .restart_count = 3,
        .latency_p99_ms = 150.5,
        .error_rate_percent = 0.5,
    };
    try std.testing.expect(snap.getValue(.cpu_percent) == 42.5);
    try std.testing.expect(snap.getValue(.memory_percent) == 60);
    try std.testing.expect(snap.getValue(.restart_count) == 3);
    try std.testing.expect(snap.getValue(.latency_p99_ms) == 150.5);
    try std.testing.expect(snap.getValue(.error_rate_percent) == 0.5);
}

test "alert spec toRules" {
    const spec = AlertSpec{
        .cpu_percent = 80,
        .memory_percent = 90,
        .webhook = "https://example.com/hook",
    };

    var rules: [max_rules]AlertRule = undefined;
    const count = spec.toRules("web", &rules);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("web", rules[0].service_name);
    try std.testing.expect(rules[0].webhook != null);
    try std.testing.expectEqualStrings("https://example.com/hook", rules[0].webhook.?.url);
}

test "alert tracker full capacity" {
    var tracker = AlertTracker{};
    for (0..max_rules) |_| {
        try std.testing.expect(tracker.addRule(.{
            .service_name = "x",
            .threshold = .{ .metric = .cpu_percent, .value = 50 },
        }));
    }
    // 65th rule should fail
    try std.testing.expect(!tracker.addRule(.{
        .service_name = "x",
        .threshold = .{ .metric = .cpu_percent, .value = 50 },
    }));
}
