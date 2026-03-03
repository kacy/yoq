// cli — shared output helpers for CLI commands
//
// buffered write to stdout/stderr with error suppression.
// used by main.zig and orchestrator.zig to avoid duplicating
// the same 7-line write pattern.

const std = @import("std");

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
