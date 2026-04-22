const std = @import("std");
const common = @import("common.zig");

pub const PsiMetrics = common.PsiMetrics;
pub const IoStats = common.IoStats;
pub const CgroupMetrics = common.CgroupMetrics;

pub fn readFromDir(dir: @import("compat").Dir, filename: []const u8, buf: []u8) ?[]const u8 {
    const file = dir.openFile(filename, .{}) catch return null;
    defer file.close();
    const bytes_read = file.readAll(buf) catch return null;
    return std.mem.trimEnd(u8, buf[0..bytes_read], "\n ");
}

pub fn procsContainsPid(content: []const u8, pid: std.posix.pid_t) bool {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const current = std.fmt.parseInt(std.posix.pid_t, std.mem.trim(u8, line, " \t\r"), 10) catch continue;
        if (current == pid) return true;
    }
    return false;
}

pub fn parsePsiFromContent(content: []const u8) ?PsiMetrics {
    var metrics: PsiMetrics = .{ .some_avg10 = 0.0, .full_avg10 = 0.0 };
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "some ")) {
            metrics.some_avg10 = parsePsiAvg10(line) catch return null;
        } else if (std.mem.startsWith(u8, line, "full ")) {
            metrics.full_avg10 = parsePsiAvg10(line) catch return null;
        }
    }
    return metrics;
}

pub fn parseCpuMax(content: []const u8, metrics: *CgroupMetrics) void {
    var parts = std.mem.splitScalar(u8, content, ' ');
    const quota_str = parts.next() orelse return;
    const period_str = parts.next() orelse return;

    metrics.cpu_max_period = std.fmt.parseInt(u64, period_str, 10) catch return;

    if (!std.mem.eql(u8, quota_str, "max")) {
        metrics.cpu_max_usec = std.fmt.parseInt(u64, quota_str, 10) catch return;
    }
}

pub fn parsePsiAvg10(line: []const u8) !f64 {
    const prefix = "avg10=";
    const start = std.mem.indexOf(u8, line, prefix) orelse return error.ParseError;
    const val_start = start + prefix.len;
    const val_end = std.mem.indexOfScalarPos(u8, line, val_start, ' ') orelse line.len;
    return std.fmt.parseFloat(f64, line[val_start..val_end]) catch return error.ParseError;
}

pub fn parseIoStat(content: []const u8) IoStats {
    var stats = IoStats{};
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const after_dev = std.mem.indexOf(u8, line, " ") orelse continue;
        var pairs = std.mem.splitScalar(u8, line[after_dev + 1 ..], ' ');
        while (pairs.next()) |pair| {
            if (std.mem.startsWith(u8, pair, "rbytes=")) {
                stats.read_bytes += std.fmt.parseInt(u64, pair["rbytes=".len..], 10) catch continue;
            } else if (std.mem.startsWith(u8, pair, "wbytes=")) {
                stats.write_bytes += std.fmt.parseInt(u64, pair["wbytes=".len..], 10) catch continue;
            } else if (std.mem.startsWith(u8, pair, "rios=")) {
                stats.read_ios += std.fmt.parseInt(u64, pair["rios=".len..], 10) catch continue;
            } else if (std.mem.startsWith(u8, pair, "wios=")) {
                stats.write_ios += std.fmt.parseInt(u64, pair["wios=".len..], 10) catch continue;
            }
        }
    }
    return stats;
}

test "bufPrint integer formatting" {
    var buf: [20]u8 = undefined;
    const str = std.fmt.bufPrint(&buf, "{d}", .{@as(u64, 12345)}) catch unreachable;
    try std.testing.expectEqualStrings("12345", str);
}

test "parsePsiAvg10" {
    const val = try parsePsiAvg10("some avg10=1.50 avg60=0.00 avg300=0.00 total=0");
    try std.testing.expectApproxEqAbs(@as(f64, 1.50), val, 0.001);
}

test "parsePsiAvg10 with zero value" {
    const val = try parsePsiAvg10("some avg10=0.00 avg60=0.00 avg300=0.00 total=0");
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), val, 0.001);
}

test "parsePsiAvg10 with high pressure" {
    const val = try parsePsiAvg10("full avg10=99.99 avg60=50.00 avg300=25.00 total=9999");
    try std.testing.expectApproxEqAbs(@as(f64, 99.99), val, 0.001);
}

test "parsePsiAvg10 rejects missing avg10 field" {
    const result = parsePsiAvg10("some total=12345");
    try std.testing.expectError(error.ParseError, result);
}

test "parseCpuMax — quota and period" {
    var metrics: CgroupMetrics = .{};
    parseCpuMax("50000 100000", &metrics);
    try std.testing.expectEqual(@as(u64, 50000), metrics.cpu_max_usec.?);
    try std.testing.expectEqual(@as(u64, 100000), metrics.cpu_max_period.?);
}

test "parseCpuMax — unlimited (max period)" {
    var metrics: CgroupMetrics = .{};
    parseCpuMax("max 100000", &metrics);
    try std.testing.expect(metrics.cpu_max_usec == null);
    try std.testing.expectEqual(@as(u64, 100000), metrics.cpu_max_period.?);
}

test "parseCpuMax — empty content" {
    var metrics: CgroupMetrics = .{};
    parseCpuMax("", &metrics);
    try std.testing.expect(metrics.cpu_max_usec == null);
    try std.testing.expect(metrics.cpu_max_period == null);
}

test "procsContainsPid matches exact pid lines" {
    try std.testing.expect(procsContainsPid("123\n456\n", 123));
    try std.testing.expect(procsContainsPid("123\n456\n", 456));
    try std.testing.expect(!procsContainsPid("123\n456\n", 45));
    try std.testing.expect(!procsContainsPid("", 123));
}

test "parseIoStat — single device" {
    const content = "8:0 rbytes=1024 wbytes=2048 rios=10 wios=20 dbytes=0 dios=0\n";
    const stats = parseIoStat(content);
    try std.testing.expectEqual(@as(u64, 1024), stats.read_bytes);
    try std.testing.expectEqual(@as(u64, 2048), stats.write_bytes);
    try std.testing.expectEqual(@as(u64, 10), stats.read_ios);
    try std.testing.expectEqual(@as(u64, 20), stats.write_ios);
}

test "parseIoStat — multiple devices aggregated" {
    const content =
        "8:0 rbytes=100 wbytes=200 rios=1 wios=2 dbytes=0 dios=0\n" ++
        "8:16 rbytes=300 wbytes=400 rios=3 wios=4 dbytes=0 dios=0\n";
    const stats = parseIoStat(content);
    try std.testing.expectEqual(@as(u64, 400), stats.read_bytes);
    try std.testing.expectEqual(@as(u64, 600), stats.write_bytes);
    try std.testing.expectEqual(@as(u64, 4), stats.read_ios);
    try std.testing.expectEqual(@as(u64, 6), stats.write_ios);
}

test "parseIoStat — empty content" {
    const stats = parseIoStat("");
    try std.testing.expectEqual(@as(u64, 0), stats.read_bytes);
    try std.testing.expectEqual(@as(u64, 0), stats.write_bytes);
    try std.testing.expectEqual(@as(u64, 0), stats.read_ios);
    try std.testing.expectEqual(@as(u64, 0), stats.write_ios);
}
