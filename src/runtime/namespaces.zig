// namespaces — Linux namespace isolation for containers
//
// creates isolated namespaces using clone3(). handles user namespace
// mapping so containers can run without root. the parent process
// coordinates uid/gid mapping after the child is created.
//
// supported namespaces: PID, NET, MNT, UTS, IPC, USER, CGROUP.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const syscall_util = @import("../lib/syscall.zig");

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
        posix.close(self.ready_fd);
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
    // create a pipe for parent-child synchronization.
    // parent closes the write end after setting up uid/gid maps,
    // child blocks on read until then.
    const pipe_fds = posix.pipe() catch return NamespaceError.PipeFailed;
    const pipe_read = pipe_fds[0];
    const pipe_write = pipe_fds[1];

    // create stdout and stderr pipes for log capture.
    // parent gets the read ends, child gets the write ends (dup2'd to fd 1/2).
    const stdout_pipe = posix.pipe() catch return NamespaceError.PipeFailed;
    const stderr_pipe = posix.pipe() catch return NamespaceError.PipeFailed;

    // allocate child stack. clone3 needs an explicit stack for the child.
    const stack_size: usize = 1024 * 1024; // 1MB
    const stack_mem = posix.mmap(
        null,
        stack_size,
        posix.PROT.READ | posix.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    ) catch return NamespaceError.CloneFailed;

    // pack child context into a struct on the stack so child_fn can access it.
    // we pass the pipe read fd and the real child function through a trampoline.
    const ChildContext = struct {
        pipe_read_fd: posix.fd_t,
        stdout_write_fd: posix.fd_t,
        stderr_write_fd: posix.fd_t,
        real_fn: *const fn (arg: ?*anyopaque) callconv(.c) u8,
        real_arg: ?*anyopaque,

        fn trampoline(ctx_ptr: ?*anyopaque) callconv(.c) u8 {
            const ctx: *@This() = @ptrCast(@alignCast(ctx_ptr));

            // wait for parent to finish uid/gid mapping
            var buf: [1]u8 = undefined;
            _ = posix.read(ctx.pipe_read_fd, &buf) catch {};
            posix.close(ctx.pipe_read_fd);

            // redirect stdout and stderr to the log pipes
            posix.dup2(ctx.stdout_write_fd, posix.STDOUT_FILENO) catch {};
            posix.dup2(ctx.stderr_write_fd, posix.STDERR_FILENO) catch {};
            posix.close(ctx.stdout_write_fd);
            posix.close(ctx.stderr_write_fd);

            // run the real child function
            return ctx.real_fn(ctx.real_arg);
        }
    };

    var ctx = ChildContext{
        .pipe_read_fd = pipe_read,
        .stdout_write_fd = stdout_pipe[1],
        .stderr_write_fd = stderr_pipe[1],
        .real_fn = child_fn,
        .real_arg = child_arg,
    };

    var args = CloneArgs{
        .flags = ns_flags.toCloneFlags(),
        .exit_signal = linux.SIG.CHLD,
        .stack = @intFromPtr(stack_mem.ptr),
        .stack_size = stack_size,
    };

    const rc = linux.syscall2(
        .clone3,
        @intFromPtr(&args),
        @sizeOf(CloneArgs),
    );

    const pid = syscall_util.unwrap(rc) catch return NamespaceError.CloneFailed;

    if (pid == 0) {
        // child process — run through trampoline.
        // close parent-side fds before executing.
        posix.close(pipe_write);
        posix.close(stdout_pipe[0]);
        posix.close(stderr_pipe[0]);
        const exit_code = ChildContext.trampoline(@ptrCast(&ctx));
        linux.exit_group(exit_code);
    }

    // parent process — close child-side fds
    posix.close(pipe_read);
    posix.close(stdout_pipe[1]);
    posix.close(stderr_pipe[1]);

    // set up user namespace mappings if requested
    if (ns_flags.user) {
        const mapping = user_mapping orelse UserMapping{
            .outer_uid = std.os.linux.getuid(),
            .outer_gid = std.os.linux.getgid(),
        };
        writeUserMapping(@intCast(pid), mapping) catch {
            posix.close(pipe_write);
            return NamespaceError.WriteFailed;
        };
    }

    // don't close pipe_write here — return it as ready_fd so the caller
    // can do additional setup (networking) before signaling the child.

    // free the child stack now that clone3 has copied it.
    // the child has its own copy in the new address space.
    posix.munmap(@alignCast(stack_mem));

    return SpawnResult{
        .pid = @intCast(pid),
        .stdout_fd = stdout_pipe[0],
        .stderr_fd = stderr_pipe[0],
        .ready_fd = pipe_write,
    };
}

/// write uid_map, gid_map, and setgroups for a child process.
/// must be called from the parent after clone3.
fn writeUserMapping(child_pid: posix.pid_t, mapping: UserMapping) !void {
    var path_buf: [64]u8 = undefined;

    // step 1: deny setgroups (required before writing gid_map unprivileged)
    const setgroups_path = try std.fmt.bufPrint(&path_buf, "/proc/{d}/setgroups", .{child_pid});
    try writeProc(setgroups_path, "deny\n");

    // step 2: write uid_map
    var map_buf: [64]u8 = undefined;
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
    var path_z: [128]u8 = .{0} ** 128;
    if (path.len >= path_z.len) return error.PathTooLong;
    @memcpy(path_z[0..path.len], path);

    const file = std.fs.cwd().openFile(path_z[0..path.len :0], .{ .mode = .write_only }) catch
        return error.WriteFailed;
    defer file.close();
    file.writeAll(value) catch return error.WriteFailed;
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
