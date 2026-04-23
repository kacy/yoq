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

    var argv_z: [max_args + 1]?[*:0]const u8 = .{null} ** (max_args + 1);
    var owned_args: [max_args][:0]u8 = undefined;
    for (0..count) |i| {
        owned_args[i] = std.heap.page_allocator.dupeZ(u8, args[i].?) catch return ExecError.ExecFailed;
        argv_z[i] = owned_args[i].ptr;
    }
    defer for (owned_args[0..count]) |arg| std.heap.page_allocator.free(arg);

    const linux = std.os.linux;
    const fork_rc = linux.fork();
    switch (linux.errno(fork_rc)) {
        .SUCCESS => {},
        else => return ExecError.ExecFailed,
    }

    if (fork_rc == 0) {
        execInChild(@ptrCast(&argv_z));
    }

    const pid: linux.pid_t = @intCast(fork_rc);
    var status: u32 = 0;
    while (true) {
        const wait_rc = linux.waitpid(pid, &status, 0);
        switch (linux.errno(wait_rc)) {
            .SUCCESS => break,
            .INTR => continue,
            else => return ExecError.ExecFailed,
        }
    }

    if (!std.posix.W.IFEXITED(status) or std.posix.W.EXITSTATUS(status) != 0) {
        return ExecError.ExecFailed;
    }
}

fn execInChild(argv: [*:null]const ?[*:0]const u8) noreturn {
    const linux = std.os.linux;
    const envp: [*:null]const ?[*:0]const u8 = @ptrCast(std.c.environ);
    const arg0 = argv[0] orelse linux.exit(127);
    const arg0_slice = std.mem.span(arg0);

    if (std.mem.indexOfScalar(u8, arg0_slice, '/') != null) {
        _ = linux.execve(arg0, argv, envp);
        linux.exit(127);
    }

    const path_env = if (std.c.getenv("PATH")) |value| std.mem.span(value) else "/usr/local/bin:/bin:/usr/bin";
    var it = std.mem.tokenizeScalar(u8, path_env, ':');
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    while (it.next()) |dir| {
        const path = std.fmt.bufPrintZ(&path_buf, "{s}/{s}", .{ dir, arg0_slice }) catch continue;
        _ = linux.execve(path.ptr, argv, envp);
    }

    linux.exit(127);
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
