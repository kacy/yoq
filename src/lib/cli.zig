// cli — shared helpers for CLI commands
//
// buffered write to stdout/stderr, argument parsing utilities,
// display formatting, and validation helpers. used by command
// modules to avoid duplicating common patterns.

const std = @import("std");
const ip = @import("../network/ip.zig");
const net_setup = @import("../network/setup.zig");

// -- output --

/// write formatted output to stdout. errors are silently ignored
/// since CLI output is best-effort.
pub fn write(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var w = std.fs.File.stdout().writer(&buf);
    const out = &w.interface;
    out.print(fmt, args) catch {};
    out.flush() catch {};
}

/// write formatted output to stderr. errors are silently ignored.
pub fn writeErr(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var w = std.fs.File.stderr().writer(&buf);
    const out = &w.interface;
    out.print(fmt, args) catch {};
    out.flush() catch {};
}

// -- argument parsing --

/// require the next CLI argument, or print usage and exit.
/// used by commands that take a single required positional argument.
pub fn requireArg(args: *std.process.ArgIterator, comptime usage: []const u8) []const u8 {
    return args.next() orelse {
        writeErr(usage, .{});
        std.process.exit(1);
    };
}

/// parsed server address with defaults for localhost:7700.
pub const ServerAddr = struct {
    ip: [4]u8 = .{ 127, 0, 0, 1 },
    port: u16 = 7700,
};

/// parse a "host:port" or "host" string into a ServerAddr.
/// exits on invalid input — suitable for CLI usage.
pub fn parseServerAddr(addr_str: []const u8) ServerAddr {
    var result: ServerAddr = .{};

    if (std.mem.indexOf(u8, addr_str, ":")) |colon| {
        result.ip = ip.parseIp(addr_str[0..colon]) orelse {
            writeErr("invalid server address: {s}\n", .{addr_str});
            std.process.exit(1);
        };
        result.port = std.fmt.parseInt(u16, addr_str[colon + 1 ..], 10) catch {
            writeErr("invalid port in server address: {s}\n", .{addr_str});
            std.process.exit(1);
        };
    } else {
        result.ip = ip.parseIp(addr_str) orelse {
            writeErr("invalid server address: {s}\n", .{addr_str});
            std.process.exit(1);
        };
    }

    return result;
}

// -- validation --

/// validate a container name as an RFC 1123 DNS label.
/// must be 1-63 chars, alphanumeric or hyphens, no leading/trailing hyphen.
pub fn isValidContainerName(name: []const u8) bool {
    if (name.len == 0 or name.len > 63) return false;
    if (name[0] == '-' or name[name.len - 1] == '-') return false;
    for (name) |c| {
        const ok = (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '-';
        if (!ok) return false;
    }
    return true;
}

/// parse a port mapping string "host_port:container_port" into a PortMap
pub fn parsePortMap(str: []const u8) ?net_setup.PortMap {
    // find the colon separator
    const colon_pos = std.mem.indexOf(u8, str, ":") orelse return null;
    if (colon_pos == 0 or colon_pos >= str.len - 1) return null;

    const host_port = std.fmt.parseInt(u16, str[0..colon_pos], 10) catch return null;
    const container_port = std.fmt.parseInt(u16, str[colon_pos + 1 ..], 10) catch return null;

    return .{ .host_port = host_port, .container_port = container_port };
}

// -- display formatting --

/// format a unix timestamp as "YYYY-MM-DD HH:MM"
pub fn formatTimestamp(buf: []u8, timestamp: i64) []const u8 {
    const epoch = std.time.epoch.EpochSeconds{ .secs = @intCast(@max(0, timestamp)) };
    const day = epoch.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();

    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}", .{
        year_day.year,
        month_day.month.numeric(),
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
    }) catch "?";
}

/// format a large count with comma separators for readability.
/// e.g. 12450 → "12,450", 1234567 → "1,234,567"
pub fn formatCount(buf: []u8, count: u64) []const u8 {
    if (count == 0) return "0";

    // format the number first without commas
    var num_buf: [24]u8 = undefined;
    const digits = std.fmt.bufPrint(&num_buf, "{d}", .{count}) catch return "-";

    // insert commas
    var i: usize = 0;
    var d: usize = 0;
    const leading = digits.len % 3;
    if (leading > 0) {
        if (i + leading > buf.len) return digits;
        @memcpy(buf[i..][0..leading], digits[d..][0..leading]);
        i += leading;
        d += leading;
    }
    while (d < digits.len) {
        if (i > 0 and i < buf.len) {
            buf[i] = ',';
            i += 1;
        }
        if (i + 3 > buf.len) return digits;
        @memcpy(buf[i..][0..3], digits[d..][0..3]);
        i += 3;
        d += 3;
    }

    return buf[0..i];
}

/// truncate a string to max_len
pub fn truncate(s: []const u8, max_len: usize) []const u8 {
    if (s.len <= max_len) return s;
    return s[0..max_len];
}

// -- tests --

test "parse port map" {
    const pm = parsePortMap("8080:80").?;
    try std.testing.expectEqual(@as(u16, 8080), pm.host_port);
    try std.testing.expectEqual(@as(u16, 80), pm.container_port);
}

test "parse port map invalid" {
    try std.testing.expect(parsePortMap("invalid") == null);
    try std.testing.expect(parsePortMap(":80") == null);
    try std.testing.expect(parsePortMap("8080:") == null);
    try std.testing.expect(parsePortMap("99999:80") == null);
}

test "valid container names" {
    try std.testing.expect(isValidContainerName("db"));
    try std.testing.expect(isValidContainerName("web-api"));
    try std.testing.expect(isValidContainerName("my-service-1"));
    try std.testing.expect(isValidContainerName("A"));
    try std.testing.expect(isValidContainerName("abc123"));
}

test "invalid container names" {
    try std.testing.expect(!isValidContainerName(""));
    try std.testing.expect(!isValidContainerName("-db"));
    try std.testing.expect(!isValidContainerName("db-"));
    try std.testing.expect(!isValidContainerName("my db"));
    try std.testing.expect(!isValidContainerName("../../etc/passwd"));
    try std.testing.expect(!isValidContainerName("a" ** 64));
    try std.testing.expect(!isValidContainerName("hello_world"));
}
