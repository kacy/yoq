const std = @import("std");
const common = @import("common.zig");
const formatting = @import("formatting.zig");

pub const ServiceSnapshot = common.ServiceSnapshot;

pub fn suggestTuning(buf: []u8, snap: ServiceSnapshot) ?[]const u8 {
    if (snap.memory_limit) |limit| {
        if (limit > 0 and snap.memory_bytes > 0) {
            const usage_pct = @as(f64, @floatFromInt(snap.memory_bytes)) / @as(f64, @floatFromInt(limit)) * 100.0;
            const psi = if (snap.psi_memory) |p| p.some_avg10 else 0.0;

            if (usage_pct > 80.0 and psi > 10.0) {
                const suggested = suggestedMemoryLimit(limit);
                var usage_buf: [16]u8 = undefined;
                var limit_buf: [16]u8 = undefined;
                var suggested_buf: [16]u8 = undefined;
                const usage_str = formatting.formatBytes(&usage_buf, snap.memory_bytes);
                const limit_str = formatting.formatBytes(&limit_buf, limit);
                const suggested_str = formatting.formatBytes(&suggested_buf, suggested);

                return std.fmt.bufPrint(buf, "\xe2\x9a\xa0 memory: using {s} of {s} ({d:.0}%), pressure {d:.0}% \xe2\x80\x94 suggest increasing to {s}", .{
                    usage_str, limit_str, usage_pct, psi, suggested_str,
                }) catch null;
            } else if (usage_pct > 80.0) {
                var usage_buf: [16]u8 = undefined;
                var limit_buf: [16]u8 = undefined;
                const usage_str = formatting.formatBytes(&usage_buf, snap.memory_bytes);
                const limit_str = formatting.formatBytes(&limit_buf, limit);

                return std.fmt.bufPrint(buf, "  memory: using {s} of {s} ({d:.0}%) \xe2\x80\x94 approaching limit", .{
                    usage_str, limit_str, usage_pct,
                }) catch null;
            }
        }
    } else {
        if (snap.psi_memory) |psi| {
            if (psi.some_avg10 > 25.0) {
                return std.fmt.bufPrint(buf, "  memory: pressure {d:.0}% without limit set \xe2\x80\x94 host may be memory-constrained", .{
                    psi.some_avg10,
                }) catch null;
            }
        }
    }

    if (snap.cpu_quota_pct) |quota| {
        if (snap.psi_cpu) |psi| {
            if (psi.some_avg10 > 50.0) {
                return std.fmt.bufPrint(buf, "\xe2\x9a\xa0 cpu: significant pressure {d:.0}% \xe2\x80\x94 service is cpu-starved at {d:.0}% quota", .{
                    psi.some_avg10, quota,
                }) catch null;
            } else if (psi.some_avg10 > 25.0) {
                return std.fmt.bufPrint(buf, "\xe2\x9a\xa0 cpu: pressure {d:.0}% with {d:.0}% quota \xe2\x80\x94 consider increasing cpu allocation", .{
                    psi.some_avg10, quota,
                }) catch null;
            }
        }
    }

    return null;
}

fn suggestedMemoryLimit(current: u64) u64 {
    const doubled = current *| 2;
    const max_suggestion: u64 = 64 * 1024 * 1024 * 1024;
    return @min(doubled, max_suggestion);
}

fn testSnapshot() ServiceSnapshot {
    return .{
        .name = "web",
        .status = .running,
        .health_status = null,
        .cpu_pct = 0.0,
        .memory_bytes = 0,
        .psi_cpu = null,
        .psi_memory = null,
        .running_count = 1,
        .desired_count = 1,
        .uptime_secs = 100,
    };
}

test "suggestTuning — high memory usage with pressure" {
    var buf: [256]u8 = undefined;
    var snap = testSnapshot();
    snap.memory_limit = 512 * 1024 * 1024;
    snap.memory_bytes = 450 * 1024 * 1024;
    snap.psi_memory = .{ .some_avg10 = 32.0, .full_avg10 = 8.0 };

    const msg = suggestTuning(&buf, snap);
    try std.testing.expect(msg != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "450 MB") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "512 MB") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "1.0 GB") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "suggest increasing") != null);
}

test "suggestTuning — high memory usage without pressure" {
    var buf: [256]u8 = undefined;
    var snap = testSnapshot();
    snap.memory_limit = 512 * 1024 * 1024;
    snap.memory_bytes = 450 * 1024 * 1024;
    snap.psi_memory = .{ .some_avg10 = 2.0, .full_avg10 = 0.0 };

    const msg = suggestTuning(&buf, snap);
    try std.testing.expect(msg != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "approaching limit") != null);
}

test "suggestTuning — low pressure, no suggestion" {
    var buf: [256]u8 = undefined;
    var snap = testSnapshot();
    snap.memory_limit = 512 * 1024 * 1024;
    snap.memory_bytes = 100 * 1024 * 1024;
    snap.psi_memory = .{ .some_avg10 = 1.0, .full_avg10 = 0.0 };
    snap.psi_cpu = .{ .some_avg10 = 5.0, .full_avg10 = 0.0 };

    const msg = suggestTuning(&buf, snap);
    try std.testing.expect(msg == null);
}

test "suggestTuning — unlimited memory with high pressure" {
    var buf: [256]u8 = undefined;
    var snap = testSnapshot();
    snap.memory_limit = null;
    snap.psi_memory = .{ .some_avg10 = 40.0, .full_avg10 = 15.0 };

    const msg = suggestTuning(&buf, snap);
    try std.testing.expect(msg != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "host may be memory-constrained") != null);
}

test "suggestTuning — cpu-starved" {
    var buf: [256]u8 = undefined;
    var snap = testSnapshot();
    snap.cpu_quota_pct = 50.0;
    snap.psi_cpu = .{ .some_avg10 = 65.0, .full_avg10 = 30.0 };

    const msg = suggestTuning(&buf, snap);
    try std.testing.expect(msg != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "cpu-starved") != null);
}

test "suggestTuning — moderate cpu pressure" {
    var buf: [256]u8 = undefined;
    var snap = testSnapshot();
    snap.cpu_quota_pct = 25.0;
    snap.psi_cpu = .{ .some_avg10 = 35.0, .full_avg10 = 10.0 };

    const msg = suggestTuning(&buf, snap);
    try std.testing.expect(msg != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.?, "consider increasing cpu allocation") != null);
}

test "suggestedMemoryLimit — doubles current" {
    try std.testing.expectEqual(@as(u64, 1024 * 1024 * 1024), suggestedMemoryLimit(512 * 1024 * 1024));
}

test "suggestedMemoryLimit — capped at 64 GB" {
    const large: u64 = 48 * 1024 * 1024 * 1024;
    const suggested = suggestedMemoryLimit(large);
    try std.testing.expectEqual(@as(u64, 64 * 1024 * 1024 * 1024), suggested);
}
