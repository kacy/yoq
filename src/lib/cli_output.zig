const std = @import("std");
const platform = @import("platform");

pub const OutputMode = enum {
    human,
    json,
};

pub var output_mode: OutputMode = .human;

pub var stdout_write_failures: usize = 0;
pub var stderr_write_failures: usize = 0;

pub fn write(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var w = platform.File.stdout().writer(&buf);
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

pub fn writeErr(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var w = platform.File.stderr().writer(&buf);
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

test "output failure tracking" {
    stdout_write_failures = 0;
    stderr_write_failures = 0;

    write("test", .{});
    writeErr("test", .{});

    _ = stdout_write_failures;
    _ = stderr_write_failures;
}
