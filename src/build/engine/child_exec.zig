const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const linux = std.os.linux;

const namespaces = @import("../../runtime/namespaces.zig");
const filesystem = @import("../../runtime/filesystem.zig");
const identity = @import("identity.zig");
const exec_helpers = @import("../../lib/exec_helpers.zig");

const string_buf_capacity = 65536;
const max_argv = 16;
const max_envp = 257;
const exit_not_found: u8 = 127;

pub const BuildChildContext = struct {
    layer_dirs: []const []const u8,
    upper_dir: []const u8,
    work_dir: []const u8,
    merged_dir: []const u8,
    command: []const u8,
    env: []const []const u8,
    workdir: []const u8,
    shell: ?[]const u8,
    user: ?[]const u8 = null,
    create_workdir: bool = false,
    rootless: bool = false,
};

/// Build root always belongs to a new user namespace. A privileged launcher
/// can map every usable image ID while retaining only namespace-local caps.
pub fn spawn(child_fn: *const fn (?*anyopaque) callconv(.c) u8, arg: ?*anyopaque) namespaces.NamespaceError!namespaces.SpawnResult {
    const mapping: ?namespaces.UserMapping = if (linux.geteuid() == 0) .{
        .outer_uid = 0,
        .outer_gid = 0,
        .count = std.math.maxInt(u32),
        .gid_count = std.math.maxInt(u32),
        .allow_setgroups = true,
    } else null;
    return namespaces.spawn(.{ .net = false, .cgroup = false }, mapping, child_fn, arg);
}

pub fn buildChildMain(arg: ?*anyopaque) callconv(.c) u8 {
    const ctx: *const BuildChildContext = @ptrCast(@alignCast(arg));

    if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS) return 1;
    if (ctx.layer_dirs.len > 0) {
        filesystem.mountOverlay(.{
            .lower_dirs = ctx.layer_dirs,
            .upper_dir = ctx.upper_dir,
            .work_dir = ctx.work_dir,
            .merged_dir = ctx.merged_dir,
        }) catch return 1;

        filesystem.pivotRoot(ctx.merged_dir) catch return 1;
    } else {
        // Even an empty image must execute inside its own root.
        filesystem.pivotRoot(ctx.upper_dir) catch return 1;
    }

    const account = identity.resolve(ctx.user) catch return 1;
    if (ctx.create_workdir) {
        createWorkdir(ctx.workdir, account) catch return 1;
        return 0;
    }
    filesystem.mountEssential() catch return 1;
    identity.apply(account, ctx.rootless and ctx.user == null) catch return 1;
    linux_platform.posix.chdir(ctx.workdir) catch return 1;

    return execShellCommand(ctx.command, ctx.env, ctx.shell);
}

pub fn execShellCommand(command: []const u8, env: []const []const u8, shell: ?[]const u8) u8 {
    var str_buf: [string_buf_capacity]u8 = undefined;
    var str_pos: usize = 0;

    var argv: [max_argv]?[*:0]const u8 = .{null} ** max_argv;
    var argv_len: usize = 0;

    if (shell) |sh| {
        const trimmed = std.mem.trim(u8, sh, " \t[]");
        var iter = std.mem.splitScalar(u8, trimmed, ',');
        while (iter.next()) |entry| {
            if (argv_len >= argv.len - 2) break;
            const part = std.mem.trim(u8, entry, " \t\"");
            if (part.len == 0) continue;
            argv[argv_len] = exec_helpers.packString(&str_buf, &str_pos, part) orelse return exit_not_found;
            argv_len += 1;
        }
    }

    if (argv_len == 0) {
        argv[0] = exec_helpers.packString(&str_buf, &str_pos, "/bin/sh") orelse return exit_not_found;
        argv[1] = exec_helpers.packString(&str_buf, &str_pos, "-c") orelse return exit_not_found;
        argv_len = 2;
    }

    argv[argv_len] = exec_helpers.packString(&str_buf, &str_pos, command) orelse return exit_not_found;

    var envp: [max_envp]?[*:0]const u8 = .{null} ** max_envp;
    for (env, 0..) |e, i| {
        if (i >= envp.len - 1) break;
        envp[i] = exec_helpers.packString(&str_buf, &str_pos, e) orelse return exit_not_found;
    }

    _ = linux.syscall3(
        .execve,
        @intFromPtr(argv[0].?),
        @intFromPtr(&argv),
        @intFromPtr(&envp),
    );

    return exit_not_found;
}

/// Called only after pivot_root, so image symlinks cannot address host paths.
fn createWorkdir(path: []const u8, account: identity.Identity) !void {
    if (path.len == 0 or path[0] != '/' or path.len >= std.fs.max_path_bytes or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidPath;
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    @memcpy(buf[0..path.len], path);
    for (1..path.len + 1) |end| {
        if (end != path.len and path[end] != '/') continue;
        buf[end] = 0;
        const name: [*:0]const u8 = @ptrCast(&buf);
        switch (linux.errno(linux.mkdirat(linux.AT.FDCWD, name, 0o755))) {
            .SUCCESS => {
                if (linux.errno(linux.fchownat(linux.AT.FDCWD, name, account.uid, account.gid, 0)) != .SUCCESS) return error.IdentityFailed;
            },
            .EXIST => {},
            else => return error.CreateFailed,
        }
        if (end < path.len) buf[end] = '/';
    }
    linux_platform.posix.chdir(path) catch return error.InvalidPath;
}

test "build child kernel applies image USER WORKDIR and refuses invalid execution context" {
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    for ([_][]const u8{ "upper/etc", "upper/usr", "upper/protected", "work", "merged" }) |dir|
        try tmp.dir.createDirPath(io, dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "upper/etc/passwd", .data = "app:x:12345:23456::/:/bin/sh\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "upper/etc/group", .data = "staff:x:23456:\n" });
    try tmp.dir.symLink(io, "usr/bin", "upper/bin", .{});
    try tmp.dir.symLink(io, "usr/lib", "upper/lib", .{});
    try tmp.dir.symLink(io, "usr/lib64", "upper/lib64", .{});
    try tmp.dir.symLink(io, "/workspace", "upper/linked", .{});
    var root_buf: [4096]u8 = undefined;
    const len = try tmp.dir.realPath(io, &root_buf);
    try tmp.dir.symLink(io, root_buf[0..len], "upper/escape", .{});
    const upper = try std.fmt.allocPrint(alloc, "{s}/upper", .{root_buf[0..len]});
    defer alloc.free(upper);
    const work = try std.fmt.allocPrint(alloc, "{s}/work", .{root_buf[0..len]});
    defer alloc.free(work);
    const merged = try std.fmt.allocPrint(alloc, "{s}/merged", .{root_buf[0..len]});
    defer alloc.free(merged);
    var ctx: BuildChildContext = .{
        .layer_dirs = &.{},
        .upper_dir = upper,
        .work_dir = work,
        .merged_dir = merged,
        .command = "",
        .env = &.{"PATH=/usr/bin:/bin"},
        .workdir = "/workspace/src",
        .shell = null,
        .user = "app:staff",
        .create_workdir = true,
    };
    try expectBuildChild(&ctx, 0);
    ctx.workdir = "/linked/src";
    ctx.create_workdir = false;
    // Keep the identity and pwd assertions separate from the deliberately
    // failing redirection, so a failed assertion cannot be hidden by it.
    ctx.command = "test \"$(id -u)\" = 12345 || exit 91; test \"$(id -g)\" = 23456 || exit 92; test \"$(id -G)\" = 23456 || exit 95; test \"$(pwd -P)\" = /workspace/src || exit 93; if (echo denied > /protected/file) 2>/dev/null; then exit 94; fi; echo success > result";
    try expectBuildChild(&ctx, 0);
    const contents = try tmp.dir.readFileAlloc(io, "upper/workspace/src/result", alloc, .limited(100));
    defer alloc.free(contents);
    try std.testing.expectEqualStrings("success\n", contents);
    ctx.user = "12345:23456";
    ctx.command = "test \"$(id -u)\" = 12345 && test \"$(id -g)\" = 23456";
    try expectBuildChild(&ctx, 0);
    ctx.workdir = "/missing";
    ctx.command = "exit 0";
    try expectBuildChild(&ctx, 1);
    ctx.workdir = "/";
    ctx.user = "missing";
    try expectBuildChild(&ctx, 1);
    ctx.user = null;
    ctx.create_workdir = true;
    ctx.workdir = "/etc/passwd/child";
    try expectBuildChild(&ctx, 1);
    ctx.workdir = "/escape/outside-created";
    try expectBuildChild(&ctx, 1);
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "outside-created", .{}));
}

fn expectBuildChild(ctx: *BuildChildContext, expected: u8) !void {
    const Fixture = struct {
        ctx: *BuildChildContext,
        parent_userns: posix.fd_t,

        fn run(arg: ?*anyopaque) callconv(.c) u8 {
            const self: *@This() = @ptrCast(@alignCast(arg));
            // Root in the build namespace must not regain the launcher's
            // CAP_SYS_ADMIN. This check fails if NEWUSER is ever omitted.
            if (linux.errno(linux.setns(self.parent_userns, linux.CLONE.NEWUSER)) != .PERM) return 80;
            linux_platform.posix.close(self.parent_userns);
            if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS) return 81;
            // Read-only userspace supplies a real shell, loader and id utility.
            filesystem.bindMount(self.ctx.upper_dir, "/usr", "/usr", true) catch return 82;
            return buildChildMain(@ptrCast(self.ctx));
        }
    };
    const fd = try linux_platform.posix.open("/proc/self/ns/user", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    defer linux_platform.posix.close(fd);
    var fixture: Fixture = .{ .ctx = ctx, .parent_userns = fd };
    var child = try spawn(Fixture.run, @ptrCast(&fixture));
    defer linux_platform.posix.close(child.stdout_fd);
    defer linux_platform.posix.close(child.stderr_fd);
    child.signalReady();
    const result = try @import("../../runtime/process.zig").wait(child.pid, false);
    try std.testing.expectEqual(@import("../../runtime/process.zig").ExitStatus{ .exited = expected }, result.status);
}
