// exec — execute a command inside a running container
//
// enters a container's namespaces via setns() and executes a command.
// this is the implementation behind `yoq exec <id> <cmd>`.
//
// namespace entry order matters: user first (for permissions),
// mount last (to avoid confusing /proc lookups). pid namespace
// only takes effect for children, so we fork after setns.

const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const linux = std.os.linux;

const process = @import("process.zig");
const security = @import("security.zig");
const syscall_util = @import("../lib/syscall.zig");
const exec_helpers = @import("../lib/exec_helpers.zig");

pub const ExecError = error{
    /// the target container is not in a running state
    ContainerNotRunning,
    /// could not open a namespace fd from /proc/<pid>/ns/ (container may be gone)
    NamespaceOpenFailed,
    /// setns syscall failed — could not enter the container's namespace
    SetNsFailed,
    /// clone/fork failed when creating the child process inside the container
    ForkFailed,
    /// execve failed — command not found or not executable
    ExecFailed,
    /// waitpid failed while waiting for the exec'd command to finish
    WaitFailed,
};

/// configuration for executing a command in a running container
pub const ExecConfig = struct {
    /// PID of the container's init process (in host PID namespace)
    pid: posix.pid_t,
    /// command to execute
    command: []const u8,
    /// arguments to the command
    args: []const []const u8,
    /// environment variables (KEY=VALUE pairs)
    env: []const []const u8,
    /// working directory inside the container
    working_dir: []const u8,
};

/// enter a running container's namespaces and exec a command.
/// blocks until the command exits. returns the exit code.
pub fn execInContainer(config: ExecConfig) ExecError!u8 {
    // open all namespace fds first, before entering any.
    // this way we fail early if the container is gone, and
    // we don't end up half-entered into namespaces.
    var ns_fds: [ns_count]posix.fd_t = .{-1} ** ns_count;
    defer for (&ns_fds) |*fd| {
        if (fd.* >= 0) {
            linux_platform.posix.close(fd.*);
            fd.* = -1;
        }
    };

    for (ns_names, 0..) |ns, i| {
        ns_fds[i] = openNsFd(config.pid, ns) orelse
            return ExecError.NamespaceOpenFailed;
    }

    // enter each namespace via setns.
    // order matters: user first (grants permission for the rest),
    // mount last (so /proc lookups work during earlier setns calls).
    // pid namespace only affects future children, not the caller.
    for (ns_fds) |fd| {
        try sysSetns(fd, 0);
    }

    // fork so the PID namespace takes effect.
    // setns(CLONE_NEWPID) only moves future children into the new
    // PID namespace, not the calling process. the fork gives us a
    // child that's actually inside the container's PID namespace.
    const child_pid = try sysFork();

    if (child_pid == 0) {
        // child process — we're now fully inside the container.

        // close inherited namespace fds (not needed after setns)
        for (ns_fds) |fd| {
            if (fd >= 0) linux_platform.posix.close(fd);
        }

        // chdir to working directory (fall back to / if it doesn't exist)
        linux_platform.posix.chdir(config.working_dir) catch {
            linux_platform.posix.chdir("/") catch {};
        };

        // apply seccomp + capability restrictions so exec'd commands
        // are subject to the same security policy as the container
        security.apply() catch {
            linux.exit_group(1);
        };

        // exec the command — does not return on success
        const child_exit = execCommand(config.command, config.args, config.env);
        linux.exit_group(child_exit);
    }

    // parent process — close namespace fds early since we're done with them.
    // the defer will skip fds already set to -1.
    for (&ns_fds) |*fd| {
        if (fd.* >= 0) {
            linux_platform.posix.close(fd.*);
            fd.* = -1;
        }
    }

    // wait for the child to finish and relay its exit code
    const result = process.wait(child_pid, false) catch
        return ExecError.WaitFailed;

    return switch (result.status) {
        .exited => |code| code,
        .signaled => 128,
        .stopped => 128, // stopped processes treated as signaled
        .running => 0,
    };
}

// -- namespace helpers --

/// namespaces to enter, in order.
/// user first for permissions, mount last to avoid confusing /proc.
const ns_names = [_][]const u8{
    "user", "cgroup", "ipc", "uts", "net", "pid", "mnt",
};
const ns_count = ns_names.len;

/// open a namespace fd from /proc/<pid>/ns/<name>.
/// returns null if the file doesn't exist (container may be gone).
fn openNsFd(pid: posix.pid_t, ns: []const u8) ?posix.fd_t {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/ns/{s}", .{
        pid, ns,
    }) catch return null;

    const file = std.Io.Dir.cwd().openFile(std.Options.debug_io, path, .{}) catch return null;
    return file.handle;
}

/// enter a namespace via the setns syscall.
/// nstype=0 lets the kernel auto-detect the namespace type from the fd.
fn sysSetns(fd: posix.fd_t, nstype: u32) ExecError!void {
    const rc = linux.syscall2(
        .setns,
        @as(usize, @bitCast(@as(isize, fd))),
        nstype,
    );
    if (syscall_util.isError(rc)) return ExecError.SetNsFailed;
}

/// fork via clone(SIGCHLD, 0) — equivalent to fork() but uses
/// the clone syscall directly, matching the rest of the codebase.
fn sysFork() ExecError!posix.pid_t {
    const rc = linux.syscall2(
        .clone,
        @intFromEnum(linux.SIG.CHLD),
        @as(usize, 0),
    );
    if (syscall_util.isError(rc)) return ExecError.ForkFailed;
    return @intCast(rc);
}

// -- exec helpers --
//
// same pattern as container.zig — stack-based argv/envp construction
// to avoid heap allocation in the child process.

/// build null-terminated argv and envp arrays on the stack and call execve.
/// returns 127 if exec fails (convention for "command not found").
fn execCommand(command: []const u8, args: []const []const u8, env: []const []const u8) u8 {
    var str_buf: [65536]u8 = undefined;
    var str_pos: usize = 0;

    // argv: command + args + null terminator (max 256 entries)
    var argv: [257]?[*:0]const u8 = .{null} ** 257;
    argv[0] = exec_helpers.packString(&str_buf, &str_pos, command) orelse return 127;

    var argv_idx: usize = 1;
    for (args) |arg| {
        if (argv_idx >= argv.len - 1) break;
        argv[argv_idx] = exec_helpers.packString(&str_buf, &str_pos, arg) orelse return 127;
        argv_idx += 1;
    }

    // envp: env vars + null terminator (max 256 entries)
    var envp: [257]?[*:0]const u8 = .{null} ** 257;
    for (env, 0..) |e, i| {
        if (i >= envp.len - 1) break;
        envp[i] = exec_helpers.packString(&str_buf, &str_pos, e) orelse return 127;
    }

    // replace this process with the command
    _ = linux.syscall3(
        .execve,
        @intFromPtr(argv[0].?),
        @intFromPtr(&argv),
        @intFromPtr(&envp),
    );

    // if we get here, exec failed
    return 127;
}

// -- tests --

test "namespace path formatting" {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/ns/{s}", .{
        @as(i32, 12345), "mnt",
    }) catch unreachable;
    try std.testing.expectEqualStrings("/proc/12345/ns/mnt", path);
}

test "namespace entry order" {
    // user must be first (grants permissions for subsequent setns calls),
    // mount must be last (so /proc lookups work during earlier calls)
    try std.testing.expectEqualStrings("user", ns_names[0]);
    try std.testing.expectEqualStrings("mnt", ns_names[ns_names.len - 1]);
}

test "namespace count" {
    // we enter 7 namespaces: user, cgroup, ipc, uts, net, pid, mnt
    try std.testing.expectEqual(@as(usize, 7), ns_count);
}

test "exec config defaults" {
    const config = ExecConfig{
        .pid = 42,
        .command = "/bin/sh",
        .args = &.{},
        .env = &.{},
        .working_dir = "/",
    };
    try std.testing.expectEqual(@as(i32, 42), config.pid);
    try std.testing.expectEqualStrings("/bin/sh", config.command);
    try std.testing.expectEqual(@as(usize, 0), config.args.len);
}

test "pack string fills buffer correctly" {
    var buf: [65536]u8 = undefined;
    var pos: usize = 0;

    const ptr = exec_helpers.packString(&buf, &pos, "hello") orelse unreachable;
    try std.testing.expectEqualStrings("hello", std.mem.span(ptr));
    try std.testing.expectEqual(@as(usize, 6), pos); // 5 chars + null

    const ptr2 = exec_helpers.packString(&buf, &pos, "world") orelse unreachable;
    try std.testing.expectEqualStrings("world", std.mem.span(ptr2));
    try std.testing.expectEqual(@as(usize, 12), pos);
}

test "pack string returns null when buffer full" {
    var buf: [65536]u8 = undefined;
    var pos: usize = 65530;

    // try to pack a string that won't fit (7 chars + null = 8, but only 6 bytes left)
    const result = exec_helpers.packString(&buf, &pos, "toolong");
    try std.testing.expect(result == null);
}
