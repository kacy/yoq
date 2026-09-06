const std = @import("std");

pub const Metrics = struct {
    successes: std.atomic.Value(u64) = .init(0),
    failures: std.atomic.Value(u64) = .init(0),
    retention_failures: std.atomic.Value(u64) = .init(0),
    last_success: std.atomic.Value(i64) = .init(0),

    pub fn writePrometheus(self: *const Metrics, writer: *std.Io.Writer, now: i64) !void {
        const last = self.last_success.load(.acquire);
        try writer.writeAll("# TYPE yoq_backup_successes_total counter\n# TYPE yoq_backup_failures_total counter\n# TYPE yoq_backup_retention_failures_total counter\n# TYPE yoq_backup_last_success_age_seconds gauge\n");
        try writer.print("yoq_backup_successes_total {d}\nyoq_backup_failures_total {d}\nyoq_backup_retention_failures_total {d}\nyoq_backup_last_success_age_seconds {d}\n", .{
            self.successes.load(.monotonic),                                  self.failures.load(.monotonic), self.retention_failures.load(.monotonic),
            if (last == 0) @as(i128, -1) else @max(@as(i128, now) - last, 0),
        });
    }
};

pub var global: Metrics = .{};
