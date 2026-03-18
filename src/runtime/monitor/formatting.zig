const std = @import("std");
const health = @import("../../manifest/health.zig");
const common = @import("common.zig");

pub const ServiceStatus = common.ServiceStatus;

pub fn formatUptime(buf: []u8, secs: i64) []const u8 {
    if (secs <= 0) return "-";

    const s: u64 = @intCast(secs);
    const days = s / 86400;
    const hours = (s % 86400) / 3600;
    const minutes = (s % 3600) / 60;
    const seconds = s % 60;

    if (days > 0) {
        return std.fmt.bufPrint(buf, "{d}d {d}h", .{ days, hours }) catch "-";
    } else if (hours > 0) {
        return std.fmt.bufPrint(buf, "{d}h {d}m", .{ hours, minutes }) catch "-";
    } else if (minutes > 0) {
        return std.fmt.bufPrint(buf, "{d}m {d}s", .{ minutes, seconds }) catch "-";
    } else {
        return std.fmt.bufPrint(buf, "{d}s", .{seconds}) catch "-";
    }
}

pub fn formatBytes(buf: []u8, bytes: u64) []const u8 {
    if (bytes == 0) return "-";

    const gb: f64 = @floatFromInt(bytes);
    if (bytes >= 1024 * 1024 * 1024) {
        return std.fmt.bufPrint(buf, "{d:.1} GB", .{gb / (1024.0 * 1024.0 * 1024.0)}) catch "-";
    } else if (bytes >= 1024 * 1024) {
        return std.fmt.bufPrint(buf, "{d:.0} MB", .{gb / (1024.0 * 1024.0)}) catch "-";
    } else if (bytes >= 1024) {
        return std.fmt.bufPrint(buf, "{d:.0} KB", .{gb / 1024.0}) catch "-";
    } else {
        return std.fmt.bufPrint(buf, "{d} B", .{bytes}) catch "-";
    }
}

pub fn formatHealth(status: ?health.HealthStatus) []const u8 {
    const health_status = status orelse return "\xe2\x80\x94";
    return switch (health_status) {
        .healthy => "healthy",
        .unhealthy => "unhealthy",
        .starting => "starting",
    };
}

pub fn formatStatus(status: ServiceStatus) []const u8 {
    return switch (status) {
        .running => "running",
        .stopped => "stopped",
        .mixed => "partial",
    };
}

test "formatUptime — seconds only" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("45s", formatUptime(&buf, 45));
}

test "formatUptime — minutes and seconds" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("2m 30s", formatUptime(&buf, 150));
}

test "formatUptime — hours and minutes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("2h 15m", formatUptime(&buf, 2 * 3600 + 15 * 60));
}

test "formatUptime — days and hours" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("3d 5h", formatUptime(&buf, 3 * 86400 + 5 * 3600));
}

test "formatUptime — zero" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("-", formatUptime(&buf, 0));
}

test "formatUptime — negative" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("-", formatUptime(&buf, -5));
}

test "formatBytes — zero" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("-", formatBytes(&buf, 0));
}

test "formatBytes — megabytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("84 MB", formatBytes(&buf, 84 * 1024 * 1024));
}

test "formatBytes — gigabytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("1.5 GB", formatBytes(&buf, 1536 * 1024 * 1024));
}

test "formatBytes — kilobytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("512 KB", formatBytes(&buf, 512 * 1024));
}

test "formatBytes — small bytes" {
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("100 B", formatBytes(&buf, 100));
}

test "formatHealth — no health check" {
    try std.testing.expectEqualStrings("\xe2\x80\x94", formatHealth(null));
}

test "formatHealth — healthy" {
    try std.testing.expectEqualStrings("healthy", formatHealth(.healthy));
}

test "formatHealth — unhealthy" {
    try std.testing.expectEqualStrings("unhealthy", formatHealth(.unhealthy));
}

test "formatHealth — starting" {
    try std.testing.expectEqualStrings("starting", formatHealth(.starting));
}

test "formatStatus values" {
    try std.testing.expectEqualStrings("running", formatStatus(.running));
    try std.testing.expectEqualStrings("stopped", formatStatus(.stopped));
    try std.testing.expectEqualStrings("partial", formatStatus(.mixed));
}
