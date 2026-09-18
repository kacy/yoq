// namespaces — Linux namespace isolation for containers
//
// creates isolated namespaces using clone3(). handles user namespace
// mapping so containers can run without root. the parent process
// coordinates uid/gid mapping after the child is created.
//
// supported namespaces: PID, NET, MNT, UTS, IPC, USER, CGROUP.

const std = @import("std");
const linux_platform = @import("linux_platform");
const linux = std.os.linux;
const posix = std.posix;
const syscall_util = @import("../lib/syscall.zig");
const log = @import("../lib/log.zig");
const session = @import("session.zig");

pub const NamespaceError = error{
    CloneFailed,
    PipeFailed,
    WriteFailed,
    WaitFailed,
    ForkFailed,
};

/// which namespaces to create for the container
pub const NamespaceFlags = struct {
    user: bool = true,
    pid: bool = true,
    net: bool = true,
    mount: bool = true,
    uts: bool = true,
    ipc: bool = true,
    cgroup: bool = true,

    /// convert to raw CLONE flags for the kernel
    pub fn toCloneFlags(self: NamespaceFlags) u64 {
        var flags: u64 = 0;
        if (self.user) flags |= linux.CLONE.NEWUSER;
        if (self.pid) flags |= linux.CLONE.NEWPID;
        if (self.net) flags |= linux.CLONE.NEWNET;
        if (self.mount) flags |= linux.CLONE.NEWNS;
        if (self.uts) flags |= linux.CLONE.NEWUTS;
        if (self.ipc) flags |= linux.CLONE.NEWIPC;
        if (self.cgroup) flags |= linux.CLONE.NEWCGROUP;
        return flags;
    }
};

/// user namespace identity mapping configuration
pub const UserMapping = struct {
    /// uid inside the container (usually 0 for root)
    inner_uid: u32 = 0,
    /// uid on the host to map from
    outer_uid: u32,
    /// number of uids to map
    count: u32 = 1,

    /// gid inside the container (usually 0 for root)
    inner_gid: u32 = 0,
    /// gid on the host to map from
    outer_gid: u32,
    /// number of gids to map
    gid_count: u32 = 1,
    /// Privileged mappings can retain setgroups so the child can clear its
    /// inherited supplementary groups. Unprivileged mappings must deny it.
    allow_setgroups: bool = false,
};

/// clone_args struct for the clone3 syscall.
/// all fields are u64, aligned to 8 bytes.
/// matches the kernel's struct clone_args from <linux/sched.h>.
const CloneArgs = extern struct {
    flags: u64 = 0,
    pidfd: u64 = 0,
    child_tid: u64 = 0,
    parent_tid: u64 = 0,
    exit_signal: u64 = 0,
    stack: u64 = 0,
    stack_size: u64 = 0,
    tls: u64 = 0,
    set_tid: u64 = 0,
    set_tid_size: u64 = 0,
    cgroup: u64 = 0,
};

/// result of spawning a namespaced process
pub const SpawnResult = struct {
    /// pid of the child process (in the parent's PID namespace)
    pid: posix.pid_t,
    /// read end of the child's stdout pipe (parent reads from this)
    stdout_fd: posix.fd_t,
    /// read end of the child's stderr pipe (parent reads from this)
    stderr_fd: posix.fd_t,
    /// write end of the sync pipe. close this to signal the child
    /// that setup (uid maps, networking) is complete and it can proceed.
    ready_fd: posix.fd_t,

    /// signal the child process that it can proceed.
    /// call this after all parent-side setup (uid maps, networking) is done.
    pub fn signalReady(self: *SpawnResult) void {
        linux_platform.posix.close(self.ready_fd);
        self.ready_fd = -1;
    }
};

/// spawn a new process in isolated namespaces.
///
/// the child will execute `child_fn` after namespace setup is complete.
/// if user namespaces are enabled, the parent writes uid/gid mappings
/// before signaling the child to proceed.
///
/// `child_fn` receives `child_arg` as its argument and should not return
/// (it should call exec or exit).
pub fn spawn(
    ns_flags: NamespaceFlags,
    user_mapping: ?UserMapping,
    child_fn: *const fn (arg: ?*anyopaque) callconv(.c) u8,
    child_arg: ?*anyopaque,
) NamespaceError!SpawnResult {
    return spawnWithIo(ns_flags, user_mapping, child_fn, child_arg, null);
}

pub fn spawnWithIo(
    ns_flags: NamespaceFlags,
    user_mapping: ?UserMapping,
    child_fn: *const fn (arg: ?*anyopaque) callconv(.c) u8,
    child_arg: ?*anyopaque,
    provided_io: ?*session.ProcessIo,
) NamespaceError!SpawnResult {
    var local_io = if (provided_io == null) session.ProcessIo.init(false, false) catch return NamespaceError.PipeFailed else session.ProcessIo{};
    defer local_io.deinit();
    const channels = provided_io orelse &local_io;
    errdefer channels.deinit();
    const ready = linux_platform.posix.pipe() catch return NamespaceError.PipeFailed;
    var owns_ready_read = true;
    errdefer {
        if (owns_ready_read) linux_platform.posix.close(ready[0]);
        linux_platform.posix.close(ready[1]);
    }

    var args = CloneArgs{
        .flags = ns_flags.toCloneFlags(),
        .exit_signal = @intFromEnum(linux.SIG.CHLD),
    };
    const rc = linux.syscall2(.clone3, @intFromPtr(&args), @sizeOf(CloneArgs));
    const pid = syscall_util.unwrap(rc) catch return NamespaceError.CloneFailed;
    if (pid == 0) {
        linux_platform.posix.close(ready[1]);
        var byte: [1]u8 = undefined;
        _ = posix.read(ready[0], &byte) catch {};
        linux_platform.posix.close(ready[0]);
        channels.applyChild() catch linux.exit_group(1);
        linux.exit_group(child_fn(child_arg));
    }
    linux_platform.posix.close(ready[0]);
    owns_ready_read = false;
    channels.closeChild();
    const child_pid: posix.pid_t = @intCast(pid);
    if (ns_flags.user) {
        const mapping = user_mapping orelse UserMapping{
            .outer_uid = std.os.linux.getuid(),
            .outer_gid = std.os.linux.getgid(),
        };
        writeUserMapping(child_pid, mapping) catch {
            _ = linux.syscall2(.kill, @as(usize, @bitCast(@as(isize, child_pid))), @intFromEnum(linux.SIG.KILL));
            while (linux.errno(linux.syscall4(.wait4, @as(usize, @bitCast(@as(isize, child_pid))), 0, 0, 0)) == .INTR) {}
            return NamespaceError.WriteFailed;
        };
    }
    const result: SpawnResult = .{
        .pid = child_pid,
        .stdout_fd = channels.stdout,
        .stderr_fd = channels.stderr,
        .ready_fd = ready[1],
    };
    channels.stdout = -1;
    channels.stderr = -1;
    return result;
}

/// write uid_map, gid_map, and setgroups for a child process.
/// must be called from the parent after clone3.
fn writeUserMapping(child_pid: posix.pid_t, mapping: UserMapping) !void {
    // use a larger buffer to handle max PID (2^22 = 4194304, 7 digits)
    // max path: /proc/4194304/uid_map = 22 chars, but we add margin
    var path_buf: [128]u8 = undefined;

    // Unprivileged gid mappings require setgroups to be permanently denied.
    // Privileged callers may keep it available for child credential setup.
    if (!mapping.allow_setgroups) {
        const setgroups_path = try std.fmt.bufPrint(&path_buf, "/proc/{d}/setgroups", .{child_pid});
        try writeProc(setgroups_path, "deny\n");
    }

    // step 2: write uid_map
    var map_buf: [128]u8 = undefined;
    const uid_map_path = try std.fmt.bufPrint(&path_buf, "/proc/{d}/uid_map", .{child_pid});
    const uid_val = try std.fmt.bufPrint(&map_buf, "{d} {d} {d}\n", .{
        mapping.inner_uid,
        mapping.outer_uid,
        mapping.count,
    });
    try writeProc(uid_map_path, uid_val);

    // step 3: write gid_map
    const gid_map_path = try std.fmt.bufPrint(&path_buf, "/proc/{d}/gid_map", .{child_pid});
    const gid_val = try std.fmt.bufPrint(&map_buf, "{d} {d} {d}\n", .{
        mapping.inner_gid,
        mapping.outer_gid,
        mapping.gid_count,
    });
    try writeProc(gid_map_path, gid_val);
}

/// write a value to a procfs file
fn writeProc(path: []const u8, value: []const u8) !void {
    // need a sentinel-terminated path for openat
    var path_z: [128]u8 = undefined;
    if (path.len >= path_z.len) {
        log.err("namespace: path too long for procfs write: {s}", .{path});
        return error.PathTooLong;
    }
    @memcpy(path_z[0..path.len], path);
    path_z[path.len] = 0;

    var file = std.Io.Dir.cwd().openFile(std.Options.debug_io, path_z[0..path.len :0], .{ .mode = .write_only }) catch |e| {
        log.err("namespace: failed to open {s}: {s}", .{ path, @errorName(e) });
        return error.WriteFailed;
    };
    defer file.close(std.Options.debug_io);
    file.writeStreamingAll(std.Options.debug_io, value) catch |e| {
        log.err("namespace: failed to write to {s}: {s}", .{ path, @errorName(e) });
        return error.WriteFailed;
    };
}

// -- tests --

test "namespace flags conversion" {
    const all = NamespaceFlags{};
    const flags = all.toCloneFlags();

    try std.testing.expect(flags & linux.CLONE.NEWUSER != 0);
    try std.testing.expect(flags & linux.CLONE.NEWPID != 0);
    try std.testing.expect(flags & linux.CLONE.NEWNET != 0);
    try std.testing.expect(flags & linux.CLONE.NEWNS != 0);
    try std.testing.expect(flags & linux.CLONE.NEWUTS != 0);
    try std.testing.expect(flags & linux.CLONE.NEWIPC != 0);
    try std.testing.expect(flags & linux.CLONE.NEWCGROUP != 0);
}

test "namespace flags selective" {
    const minimal = NamespaceFlags{
        .user = true,
        .pid = true,
        .net = false,
        .mount = true,
        .uts = false,
        .ipc = false,
        .cgroup = false,
    };
    const flags = minimal.toCloneFlags();

    try std.testing.expect(flags & linux.CLONE.NEWUSER != 0);
    try std.testing.expect(flags & linux.CLONE.NEWPID != 0);
    try std.testing.expect(flags & linux.CLONE.NEWNS != 0);
    try std.testing.expect(flags & linux.CLONE.NEWNET == 0);
    try std.testing.expect(flags & linux.CLONE.NEWUTS == 0);
}

test "clone_args struct size" {
    // kernel expects 88 bytes (11 fields * 8 bytes each)
    try std.testing.expectEqual(@as(usize, 88), @sizeOf(CloneArgs));
}

test "clone_args field offsets" {
    // verify struct layout matches kernel expectations
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(CloneArgs, "flags"));
    try std.testing.expectEqual(@as(usize, 8), @offsetOf(CloneArgs, "pidfd"));
    try std.testing.expectEqual(@as(usize, 32), @offsetOf(CloneArgs, "exit_signal"));
    try std.testing.expectEqual(@as(usize, 40), @offsetOf(CloneArgs, "stack"));
    try std.testing.expectEqual(@as(usize, 48), @offsetOf(CloneArgs, "stack_size"));
    try std.testing.expectEqual(@as(usize, 80), @offsetOf(CloneArgs, "cgroup"));
}

test "user mapping defaults" {
    const mapping = UserMapping{
        .outer_uid = 1000,
        .outer_gid = 1000,
    };

    try std.testing.expectEqual(@as(u32, 0), mapping.inner_uid);
    try std.testing.expectEqual(@as(u32, 1000), mapping.outer_uid);
    try std.testing.expectEqual(@as(u32, 1), mapping.count);
    try std.testing.expectEqual(@as(u32, 0), mapping.inner_gid);
    try std.testing.expectEqual(@as(u32, 1000), mapping.outer_gid);
}

fn testChildContinuation(isolated: bool) !void {
    const Context = struct {
        marker: u64,
        isolated: bool,

        fn child(arg: ?*anyopaque) callconv(.c) u8 {
            const context: *@This() = @ptrCast(@alignCast(arg));
            if (context.marker != 0x123456789abcdef0) return 41;
            if (context.isolated and linux.getpid() != 1) return 42;
            var output: [64]u8 = undefined;
            const message = std.fmt.bufPrint(&output, "child:{x}\n", .{context.marker}) catch return 43;
            _ = linux_platform.posix.write(posix.STDOUT_FILENO, message) catch return 44;
            _ = linux_platform.posix.write(posix.STDERR_FILENO, "child stderr\n") catch return 45;
            return 37;
        }
    };
    var context = Context{ .marker = 0x123456789abcdef0, .isolated = isolated };
    var child = try spawn(.{
        .user = false,
        .pid = isolated,
        .net = isolated,
        .mount = isolated,
        .uts = isolated,
        .ipc = isolated,
        .cgroup = false,
    }, null, Context.child, &context);
    defer linux_platform.posix.close(child.stdout_fd);
    defer linux_platform.posix.close(child.stderr_fd);
    var reaped = false;
    defer {
        if (child.ready_fd != -1) child.signalReady();
        if (!reaped) {
            _ = linux.kill(child.pid, linux.SIG.KILL);
            while (linux.errno(linux.syscall4(.wait4, @intCast(child.pid), 0, 0, 0)) == .INTR) {}
        }
    }
    // The child must wait for setup and retain its own copy of caller locals.
    context.marker = 0;
    var status: u32 = 0;
    const before_ready = try syscall_util.unwrap(linux.syscall4(.wait4, @intCast(child.pid), @intFromPtr(&status), linux.W.NOHANG, 0));
    reaped = before_ready != 0;
    try std.testing.expectEqual(@as(usize, 0), before_ready);
    child.signalReady();
    for (0..500) |_| {
        const waited = try syscall_util.unwrap(linux.syscall4(.wait4, @intCast(child.pid), @intFromPtr(&status), linux.W.NOHANG, 0));
        if (waited != 0) {
            reaped = true;
            break;
        }
        try std.Io.sleep(std.testing.io, .fromMilliseconds(10), .awake);
    }
    try std.testing.expect(reaped);
    try std.testing.expect(linux.W.IFEXITED(status));
    try std.testing.expectEqual(@as(u8, 37), linux.W.EXITSTATUS(status));
    var output: [64]u8 = undefined;
    const stdout_len = try posix.read(child.stdout_fd, &output);
    try std.testing.expectEqualStrings("child:123456789abcdef0\n", output[0..stdout_len]);
    const stderr_len = try posix.read(child.stderr_fd, &output);
    try std.testing.expectEqualStrings("child stderr\n", output[0..stderr_len]);
}

test "namespace child preserves caller stack and callback context" {
    try testChildContinuation(false);
}

test "namespace child preserves callback inside isolated namespaces" {
    if (linux.geteuid() != 0) return error.SkipZigTest;
    try testChildContinuation(true);
}
