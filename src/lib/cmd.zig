// cmd — shared command execution for network modules
//
// provides a generic exec() for running system commands (iptables, wg, ip).
// shared by nat.zig and wireguard.zig to avoid duplicating the same
// spawn-and-wait boilerplate.

const std = @import("std");

pub const max_args = 20;
pub const ArgList = [max_args]?[]const u8;

pub const ExecError = error{ExecFailed};

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

    if (result.Exited != 0) return ExecError.ExecFailed;
}

/// format a port number into a caller-provided buffer, returning the slice.
pub fn portStr(buf: *[8]u8, port: u16) []const u8 {
    return std.fmt.bufPrint(buf, "{d}", .{port}) catch "0";
}
