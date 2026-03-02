// log — structured logging for yoq
//
// simple leveled logging to stderr. keeps output consistent and
// easy to parse. production containers log to files via the
// container log capture system, not through this.

const std = @import("std");

pub const Level = enum {
    debug,
    info,
    warn,
    err,

    pub fn label(self: Level) []const u8 {
        return switch (self) {
            .debug => "DBG",
            .info => "INF",
            .warn => "WRN",
            .err => "ERR",
        };
    }
};

var min_level: Level = .info;

pub fn setLevel(level: Level) void {
    min_level = level;
}

pub fn debug(comptime fmt: []const u8, args: anytype) void {
    log(.debug, fmt, args);
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    log(.info, fmt, args);
}

pub fn warn(comptime fmt: []const u8, args: anytype) void {
    log(.warn, fmt, args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    log(.err, fmt, args);
}

fn log(level: Level, comptime fmt: []const u8, args: anytype) void {
    if (@intFromEnum(level) < @intFromEnum(min_level)) return;

    var buf: [8192]u8 = undefined;
    var w = std.fs.File.stderr().writer(&buf);
    const out = &w.interface;

    out.print("[{s}] " ++ fmt ++ "\n", .{level.label()} ++ args) catch {};
    out.flush() catch {};
}

test "log level filtering" {
    setLevel(.warn);
    defer setLevel(.info);

    // these should not crash — just verifying they compile and don't panic
    debug("this should be filtered", .{});
    info("this should be filtered", .{});
    warn("this should appear", .{});
    err("this should appear", .{});
}
