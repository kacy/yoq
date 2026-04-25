// cli — shared helpers for CLI commands
//
// buffered write to stdout/stderr, argument parsing utilities,
// display formatting, and validation helpers. used by command
// modules to avoid duplicating common patterns.

const std = @import("std");
const linux_platform = @import("linux_platform");
const ip = @import("../network/ip.zig");
const net_setup = @import("../network/setup.zig");
const paths = @import("paths.zig");
const log = @import("log.zig");

// -- output mode --

/// controls whether commands emit human-readable or machine-readable output.
/// commands that support --json check this before printing.
pub const OutputMode = enum { human, json };

/// current output mode for the CLI session. defaults to human-readable.
/// set to .json when --json is passed on the command line.
pub var output_mode: OutputMode = .human;

// -- output failure tracking --

/// tracks number of stdout write failures (for debugging)
pub var stdout_write_failures: usize = 0;
/// tracks number of stderr write failures (for debugging)
pub var stderr_write_failures: usize = 0;

// -- output --

/// write formatted output to stdout. tracks failures but doesn't panic.
pub fn write(comptime fmt: []const u8, args: anytype) void {
    const io = std.Options.debug_io;
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);

    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const out = &w.interface;
    out.print(fmt, args) catch {
        stdout_write_failures += 1;
        return;
    };
    out.flush() catch {
        stdout_write_failures += 1;
        return;
    };
}

/// write formatted output to stderr. tracks failures but doesn't panic.
pub fn writeErr(comptime fmt: []const u8, args: anytype) void {
    const io = std.Options.debug_io;
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);

    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stderr().writer(io, &buf);
    const out = &w.interface;
    out.print(fmt, args) catch {
        stderr_write_failures += 1;
        return;
    };
    out.flush() catch {
        stderr_write_failures += 1;
        return;
    };
}

// -- argument parsing --

/// require the next CLI argument, or print usage and exit.
/// used by commands that take a single required positional argument.
pub fn requireArg(args: *std.process.Args.Iterator, comptime usage: []const u8) []const u8 {
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

pub const VolumeMountSpec = struct {
    source: []const u8,
    target: []const u8,
    read_only: bool = true,
};

/// parse an env var in KEY=VALUE form.
pub fn parseEnvVar(str: []const u8) ?[]const u8 {
    const eq = std.mem.indexOfScalar(u8, str, '=') orelse return null;
    if (eq == 0) return null;
    return str;
}

/// parse a volume mount in source:target[:ro] form.
pub fn parseVolumeMount(str: []const u8) ?VolumeMountSpec {
    var parts = std.mem.splitScalar(u8, str, ':');
    const source = parts.next() orelse return null;
    const target = parts.next() orelse return null;
    const mode = parts.next();
    if (source.len == 0 or target.len == 0 or parts.next() != null) return null;

    var read_only = true;
    if (mode) |m| {
        if (std.mem.eql(u8, m, "ro")) {
            read_only = true;
        } else if (std.mem.eql(u8, m, "rw")) {
            read_only = false;
        } else {
            return null;
        }
    }

    return .{ .source = source, .target = target, .read_only = read_only };
}

/// parse human-readable memory sizes like 512k, 256m, or 1g.
pub fn parseMemorySize(str: []const u8) ?u64 {
    if (str.len == 0) return null;

    const suffix = std.ascii.toLower(str[str.len - 1]);
    const has_suffix = suffix == 'k' or suffix == 'm' or suffix == 'g';
    const number_part = if (has_suffix) str[0 .. str.len - 1] else str;
    if (number_part.len == 0) return null;

    const base = std.fmt.parseInt(u64, number_part, 10) catch return null;
    const multiplier: u64 = switch (suffix) {
        'k' => 1024,
        'm' => 1024 * 1024,
        'g' => 1024 * 1024 * 1024,
        else => 1,
    };
    // Use saturating multiplication to handle overflow gracefully
    // Very large values will be clamped to maxInt(u64)
    return base *| multiplier;
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

// -- API token management --

/// read the API auth token from ~/.local/share/yoq/api_token.
/// returns the 64-char hex string in the provided buffer, or null on failure.
pub fn readApiToken(buf: *[64]u8) ?[]const u8 {
    return readApiTokenWithIo(std.Options.debug_io, buf);
}

/// read the API auth token from ~/.local/share/yoq/api_token.
/// returns the 64-char hex string in the provided buffer, or null on failure.
pub fn readApiTokenWithIo(io: std.Io, buf: *[64]u8) ?[]const u8 {
    var path_buf: [paths.max_path]u8 = undefined;
    const token_path = paths.dataPath(&path_buf, "api_token") catch return null;

    var file = std.Io.Dir.cwd().openFile(io, token_path, .{}) catch return null;
    defer file.close(io);

    if (!hasOwnerOnlyPermissions(io, file)) return null;

    var file_reader = file.reader(io, &.{});
    file_reader.interface.readSliceAll(buf) catch return null;

    // validate it's all hex
    for (buf) |c| {
        switch (c) {
            '0'...'9', 'a'...'f' => {},
            else => return null,
        }
    }
    return buf;
}

/// generate 32 random bytes, hex-encode to 64 chars, write to
/// ~/.local/share/yoq/api_token with 0o600 permissions.
/// returns the hex string in the provided buffer, or null on failure.
pub fn generateAndSaveToken(buf: *[64]u8) ?[]const u8 {
    return generateAndSaveTokenWithIo(std.Options.debug_io, buf);
}

/// generate 32 random bytes, hex-encode to 64 chars, write to
/// ~/.local/share/yoq/api_token with 0o600 permissions.
/// returns the hex string in the provided buffer, or null on failure.
pub fn generateAndSaveTokenWithIo(io: std.Io, buf: *[64]u8) ?[]const u8 {
    var raw: [32]u8 = undefined;
    linux_platform.randomBytes(&raw);
    defer std.crypto.secureZero(u8, &raw);

    const hex = std.fmt.bytesToHex(raw, .lower);
    buf.* = hex;

    // ensure data directory exists
    paths.ensureDataDirStrictWithIo(io, "") catch return null;

    var path_buf: [paths.max_path]u8 = undefined;
    const token_path = paths.dataPath(&path_buf, "api_token") catch return null;

    if (tokenFileExistsWithWeakPermissions(io, token_path)) return null;

    var file = std.Io.Dir.cwd().createFile(io, token_path, .{
        .permissions = std.Io.File.Permissions.fromMode(0o600),
        .truncate = true,
        .exclusive = false,
    }) catch return null;
    defer file.close(io);

    file.writeStreamingAll(io, buf) catch return null;
    return buf;
}

pub fn isValidApiToken(token: []const u8) bool {
    if (token.len != 64) return false;
    for (token) |c| {
        switch (c) {
            '0'...'9', 'a'...'f' => {},
            else => return false,
        }
    }
    return true;
}

fn hasOwnerOnlyPermissions(io: std.Io, file: std.Io.File) bool {
    const stat = file.stat(io) catch return false;
    return (stat.permissions.toMode() & 0o077) == 0;
}

fn tokenFileExistsWithWeakPermissions(io: std.Io, path: []const u8) bool {
    var file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return false;
    defer file.close(io);
    return !hasOwnerOnlyPermissions(io, file);
}

// -- tests --

const TokenTestBackup = struct {
    moved: bool,
    token_path_buf: [paths.max_path]u8,
    token_path_len: usize,
    backup_path_buf: [paths.max_path]u8,
    backup_path_len: usize,

    fn tokenPath(self: *const TokenTestBackup) []const u8 {
        return self.token_path_buf[0..self.token_path_len];
    }

    fn backupPath(self: *const TokenTestBackup) []const u8 {
        return self.backup_path_buf[0..self.backup_path_len];
    }

    fn restore(self: TokenTestBackup) void {
        if (!self.moved) return;
        std.Io.Dir.cwd().rename(self.backupPath(), std.Io.Dir.cwd(), self.tokenPath(), std.testing.io) catch |e| {
            log.warn("test cleanup: failed to restore token file: {}", .{e});
        };
    }
};

var token_test_mutex: std.Io.Mutex = .init;

fn backupExistingToken() ?TokenTestBackup {
    var backup: TokenTestBackup = .{
        .moved = false,
        .token_path_buf = undefined,
        .token_path_len = 0,
        .backup_path_buf = undefined,
        .backup_path_len = 0,
    };
    const token_path = paths.dataPath(&backup.token_path_buf, "api_token") catch return null;
    backup.token_path_len = token_path.len;

    const backup_path = paths.dataPath(&backup.backup_path_buf, "api_token.test_backup") catch return null;
    backup.backup_path_len = backup_path.len;

    paths.ensureDataDirStrict("") catch return null;
    std.Io.Dir.cwd().deleteFile(std.testing.io, backup.backupPath()) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return null,
    };

    const moved = blk: {
        std.Io.Dir.cwd().rename(token_path, std.Io.Dir.cwd(), backup_path, std.testing.io) catch |err| switch (err) {
            error.FileNotFound => break :blk false,
            else => return null,
        };
        break :blk true;
    };
    backup.moved = moved;
    return backup;
}

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

test "parse env var" {
    try std.testing.expectEqualStrings("FOO=bar", parseEnvVar("FOO=bar").?);
    try std.testing.expect(parseEnvVar("NOVALUE") == null);
    try std.testing.expect(parseEnvVar("=bar") == null);
}

test "parse volume mount" {
    const mount = parseVolumeMount("./src:/app").?;
    try std.testing.expectEqualStrings("./src", mount.source);
    try std.testing.expectEqualStrings("/app", mount.target);
    try std.testing.expect(mount.read_only);
}

test "parse volume mount rw" {
    const mount = parseVolumeMount("./src:/app:rw").?;
    try std.testing.expectEqualStrings("./src", mount.source);
    try std.testing.expectEqualStrings("/app", mount.target);
    try std.testing.expect(!mount.read_only);
}

test "parse volume mount invalid" {
    try std.testing.expect(parseVolumeMount(":/app") == null);
    try std.testing.expect(parseVolumeMount("./src") == null);
    try std.testing.expect(parseVolumeMount("./src:/app:ro:extra") == null);
    try std.testing.expect(parseVolumeMount("./src:/app:bad") == null);
}

test "parse memory size" {
    try std.testing.expectEqual(@as(?u64, 512), parseMemorySize("512"));
    try std.testing.expectEqual(@as(?u64, 512 * 1024), parseMemorySize("512k"));
    try std.testing.expectEqual(@as(?u64, 256 * 1024 * 1024), parseMemorySize("256m"));
    try std.testing.expectEqual(@as(?u64, 1024 * 1024 * 1024), parseMemorySize("1g"));
    try std.testing.expect(parseMemorySize("bad") == null);
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

test "generateAndSaveToken produces valid 64-char hex string" {
    token_test_mutex.lockUncancelable(std.testing.io);
    defer token_test_mutex.unlock(std.testing.io);

    const backup = backupExistingToken() orelse return;
    defer backup.restore();

    var buf: [64]u8 = undefined;
    const token = generateAndSaveToken(&buf);
    try std.testing.expect(token != null);
    try std.testing.expectEqual(@as(usize, 64), token.?.len);
    for (token.?) |c| {
        try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }

    var path_buf: [paths.max_path]u8 = undefined;
    const token_path = paths.dataPath(&path_buf, "api_token") catch return;
    std.Io.Dir.cwd().deleteFile(std.testing.io, token_path) catch {};
}

test "readApiToken round-trip with generateAndSaveToken" {
    token_test_mutex.lockUncancelable(std.testing.io);
    defer token_test_mutex.unlock(std.testing.io);

    const backup = backupExistingToken() orelse return;
    defer backup.restore();

    // generate a token
    var gen_buf: [64]u8 = undefined;
    const generated = generateAndSaveToken(&gen_buf).?;

    // read it back
    var read_buf: [64]u8 = undefined;
    const read_back = readApiToken(&read_buf).?;
    try std.testing.expectEqualSlices(u8, generated, read_back);

    var path_buf: [paths.max_path]u8 = undefined;
    const token_path = paths.dataPath(&path_buf, "api_token") catch return;
    std.Io.Dir.cwd().deleteFile(std.testing.io, token_path) catch {};
}

test "readApiToken returns null for missing file" {
    token_test_mutex.lockUncancelable(std.testing.io);
    defer token_test_mutex.unlock(std.testing.io);

    const backup = backupExistingToken() orelse return;
    defer backup.restore();

    var buf: [64]u8 = undefined;
    try std.testing.expect(readApiToken(&buf) == null);
}

test "readApiToken rejects weak file permissions" {
    token_test_mutex.lockUncancelable(std.testing.io);
    defer token_test_mutex.unlock(std.testing.io);

    var path_buf: [paths.max_path]u8 = undefined;
    const token_path = paths.dataPath(&path_buf, "api_token") catch return;

    var backup_buf: [paths.max_path]u8 = undefined;
    const backup_path = paths.dataPath(&backup_buf, "api_token.test_backup") catch return;

    // move existing file out of the way
    const moved = if (std.Io.Dir.cwd().rename(token_path, std.Io.Dir.cwd(), backup_path, std.testing.io)) |_| true else |_| false;
    defer if (moved) std.Io.Dir.cwd().rename(backup_path, std.Io.Dir.cwd(), token_path, std.testing.io) catch |e| {
        log.warn("test cleanup: failed to restore token file: {}", .{e});
    };

    var file = std.Io.Dir.cwd().createFile(std.testing.io, token_path, .{
        .permissions = std.Io.File.Permissions.fromMode(0o644),
    }) catch |e| {
        // If we can't create the test file, skip this test
        log.warn("test: skipping weak permissions test - cannot create file: {}", .{e});
        return;
    };
    defer {
        file.close(std.testing.io);
        std.Io.Dir.cwd().deleteFile(std.testing.io, token_path) catch |e| {
            log.warn("test cleanup: failed to delete test token file: {}", .{e});
        };
    }
    file.writeStreamingAll(std.testing.io, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") catch |e| {
        log.warn("test: failed to write test token: {}", .{e});
        return;
    };

    var buf: [64]u8 = undefined;
    try std.testing.expect(readApiToken(&buf) == null);
}

test "isValidApiToken validates hex token" {
    try std.testing.expect(isValidApiToken("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    try std.testing.expect(!isValidApiToken("short"));
    try std.testing.expect(!isValidApiToken("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
}

test "parseMemorySize handles normal values" {
    try std.testing.expectEqual(@as(u64, 1024), parseMemorySize("1k").?);
    try std.testing.expectEqual(@as(u64, 1024 * 1024), parseMemorySize("1m").?);
    try std.testing.expectEqual(@as(u64, 1024 * 1024 * 1024), parseMemorySize("1g").?);
    try std.testing.expectEqual(@as(u64, 512), parseMemorySize("512").?);
}

test "parseMemorySize handles overflow gracefully" {
    // Very large values should saturate to max u64, not return null
    // Use max u64 / 2 as base, multiplied by 4g should saturate
    const huge = parseMemorySize("4611686018427387903g"); // max_i64 / 2
    try std.testing.expect(huge != null);
    // Should be max u64 (saturated)
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), huge.?);
}

test "parseMemorySize handles invalid inputs" {
    try std.testing.expect(parseMemorySize("") == null);
    try std.testing.expect(parseMemorySize("abc") == null);
    try std.testing.expect(parseMemorySize("m") == null); // Just suffix, no number
}

test "output failure tracking" {
    // Reset counters
    stdout_write_failures = 0;
    stderr_write_failures = 0;

    // Normal writes should not increment counters
    write("test", .{});
    writeErr("test", .{});

    // Note: In normal operation, these should remain 0
    // We can't easily test actual failures without mocking stdout/stderr
    _ = stdout_write_failures;
    _ = stderr_write_failures;
}
