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
const process_config = @import("process_config.zig");
const session = @import("session.zig");

pub const ExecError = error{
    /// the target container is not in a running state
    ContainerNotRunning,
    InvalidArguments,
    SessionFailed,
    RootOpenFailed,
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
    interactive: bool = false,
    tty: bool = false,
};

/// enter a running container's namespaces and exec a command.
/// blocks until the command exits. returns the exit code.
pub fn execInContainer(config: ExecConfig) ExecError!u8 {
    process_config.validate(config.command, config.args, config.env) catch return ExecError.InvalidArguments;

    // setns changes mounts, but does not change the calling process root.
    // Keep the target root open before its /proc path becomes inaccessible.
    var root_path_buf: [64]u8 = undefined;
    const root_path = std.fmt.bufPrintZ(&root_path_buf, "/proc/{d}/root", .{config.pid}) catch return ExecError.RootOpenFailed;
    const root_fd = linux_platform.posix.open(root_path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0) catch return ExecError.RootOpenFailed;
    defer linux_platform.posix.close(root_fd);

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

    var channels = session.ProcessIo.init(config.interactive, config.tty) catch return ExecError.SessionFailed;
    defer channels.deinit();

    // Namespace entry stays in a helper process. The client retains its host
    // terminal and namespace context while relaying input and output.
    const helper_pid = try sysFork();
    if (helper_pid == 0) {
        for (ns_fds) |fd| sysSetns(fd, 0) catch linux.exit_group(126);
        const child_pid = sysFork() catch linux.exit_group(126);
        if (child_pid == 0) {
            for (ns_fds) |fd| linux_platform.posix.close(fd);
            channels.applyChild() catch linux.exit_group(126);
            if (linux.errno(linux.fchdir(root_fd)) != .SUCCESS) linux.exit_group(126);
            if (linux.errno(linux.chroot(".")) != .SUCCESS) linux.exit_group(126);
            linux_platform.posix.close(root_fd);
            linux_platform.posix.chdir(config.working_dir) catch linux.exit_group(126);
            security.apply() catch linux.exit_group(1);
            linux.exit_group(process_config.execCommand(config.command, config.args, config.env));
        }
        channels.deinit();
        const signals = session.foreground.Signals.install(child_pid);
        _ = signals;
        const result = process.waitForExit(child_pid) catch linux.exit_group(126);
        linux.exit_group(exitCode(result.status));
    }
    channels.closeChild();
    return session.foreground.run(&channels, helper_pid) catch {
        process.sendSignal(helper_pid, linux.SIG.TERM) catch {};
        _ = process.waitForExit(helper_pid) catch {};
        return ExecError.SessionFailed;
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

fn exitCode(status: process.ExitStatus) u8 {
    return switch (status) {
        .exited => |code| code,
        .signaled => |signal| @intCast(128 + signal),
        .stopped, .running => unreachable, // waitForExit only returns terminal states
    };
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

test "exec preserves signal exit status" {
    try std.testing.expectEqual(@as(u8, 143), exitCode(.{ .signaled = 15 }));
    try std.testing.expectEqual(@as(u8, 137), exitCode(.{ .signaled = 9 }));
    try std.testing.expectEqual(@as(u8, 23), exitCode(.{ .exited = 23 }));
}

test {
    _ = process_config;
    _ = session;
}
