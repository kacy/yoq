// cmd — shared command execution for network modules
//
// provides a generic exec() for running system commands (iptables, wg, ip).
// shared by nat.zig and wireguard.zig to avoid duplicating the same
// spawn-and-wait boilerplate.

const std = @import("std");

pub const max_args = 20;
pub const ArgList = [max_args]?[]const u8;

pub const ExecError = error{
    /// command spawn or wait failed, or the command exited with a non-zero status
    ExecFailed,
};

/// run a command with the given arguments.
/// returns ExecFailed if spawn or wait fails, or if exit code is non-zero.
pub fn exec(args: *const ArgList) ExecError!void {
    // count non-null args
    var count: usize = 0;
    for (args) |arg| {
        if (arg == null) break;
        count += 1;
    }

    // build argv for Child
    var argv: [max_args][]const u8 = undefined;
    for (0..count) |i| {
        argv[i] = args[i].?;
    }

    var child = std.process.Child.init(argv[0..count], std.heap.page_allocator);
    child.stdin_behavior = .Close;
    child.stdout_behavior = .Close;
    child.stderr_behavior = .Close;

    child.spawn() catch return ExecError.ExecFailed;
    const result = child.wait() catch return ExecError.ExecFailed;

    switch (result) {
        .Exited => |code| if (code != 0) return ExecError.ExecFailed,
        else => return ExecError.ExecFailed, // Signal, Stopped, Continued all indicate failure
    }
}

/// format a port number into a caller-provided buffer, returning the slice.
pub fn portStr(buf: *[8]u8, port: u16) []const u8 {
    return std.fmt.bufPrint(buf, "{d}", .{port}) catch "0";
}

// -- tests --

test "exec handles zero exit code" {
    // Test that a command that exits with code 0 succeeds
    var argv: ArgList = .{null} ** max_args;
    argv[0] = "true"; // 'true' always exits 0
    try exec(&argv);
}

test "exec handles non-zero exit code" {
    // Test that a command that exits with non-zero code fails
    var argv: ArgList = .{null} ** max_args;
    argv[0] = "false"; // 'false' always exits 1
    try std.testing.expectError(ExecError.ExecFailed, exec(&argv));
}

test "portStr formats valid ports" {
    var buf: [8]u8 = undefined;
    try std.testing.expectEqualStrings("80", portStr(&buf, 80));
    try std.testing.expectEqualStrings("443", portStr(&buf, 443));
    try std.testing.expectEqualStrings("65535", portStr(&buf, 65535));
    try std.testing.expectEqualStrings("0", portStr(&buf, 0));
}
