//! Mount the build's essential filesystems before pivot_root. The inherited
//! proc mount is still visible for kernel user-namespace checks and fd paths.
const std = @import("std");
const linux = std.os.linux;
const platform = @import("linux_platform");
const mount_ops = @import("mount_ops.zig");

pub fn mountAt(root: []const u8) !void {
    const root_fd = try platform.posix.open(root, .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    defer platform.posix.close(root_fd);
    try mountFilesystem(root_fd, "proc", "proc", linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC, null);
    try mountFilesystem(root_fd, "dev", "tmpfs", linux.MS.NOSUID | linux.MS.STRICTATIME, "mode=755,size=65536k");
    // Builds retain the launcher's network namespace. Its sysfs cannot be
    // freshly mounted with capabilities belonging only to our user namespace.
    // The existing mount is exposed recursively read-only instead.
    try mount_ops.bindMount(root, "/sys", "/sys", true);
    try mountFilesystem(root_fd, "tmp", "tmpfs", linux.MS.NOSUID | linux.MS.NODEV, "mode=1777,size=65536k");
    try mountFilesystem(root_fd, "dev/pts", "devpts", linux.MS.NOSUID | linux.MS.NOEXEC, "newinstance,ptmxmode=0666,mode=0620");

    const dev_fd = try openDirectory(root_fd, "dev");
    defer platform.posix.close(dev_fd);
    // A user namespace cannot create host device nodes. Bind only these
    // explicitly supported devices into the fresh, private /dev tmpfs.
    for ([_][:0]const u8{ "null", "zero", "full", "random", "urandom", "tty" }) |name| try bindDevice(dev_fd, name);
    const links = [_]struct { name: [:0]const u8, target: [:0]const u8 }{
        .{ .name = "fd", .target = "/proc/self/fd" },
        .{ .name = "stdin", .target = "/proc/self/fd/0" },
        .{ .name = "stdout", .target = "/proc/self/fd/1" },
        .{ .name = "stderr", .target = "/proc/self/fd/2" },
        .{ .name = "ptmx", .target = "pts/ptmx" },
    };
    for (links) |link| {
        if (linux.errno(linux.symlinkat(link.target.ptr, dev_fd, link.name.ptr)) != .SUCCESS) return error.MountFailed;
    }
}

fn mountFilesystem(root_fd: std.posix.fd_t, relative: [:0]const u8, kind: [:0]const u8, flags: u32, options: ?[:0]const u8) !void {
    const parent_name = std.fs.path.dirname(relative) orelse ".";
    const parent_fd = try openDirectory(root_fd, parent_name);
    defer platform.posix.close(parent_fd);
    const name = try std.posix.toPosixPath(std.fs.path.basename(relative));
    const made = linux.errno(linux.mkdirat(parent_fd, &name, 0o755));
    if (made != .SUCCESS and made != .EXIST) return error.MountFailed;
    const target = try openDirectory(root_fd, relative);
    defer platform.posix.close(target);
    var path_buf: [64]u8 = undefined;
    const path = try fdPath(target, &path_buf);
    if (linux.errno(linux.mount(kind.ptr, path.ptr, kind.ptr, flags, if (options) |o| @intFromPtr(o.ptr) else 0)) != .SUCCESS) return error.MountFailed;
}

fn openDirectory(root_fd: std.posix.fd_t, relative: []const u8) !std.posix.fd_t {
    const how = extern struct { flags: u64, mode: u64 = 0, resolve: u64 }{
        .flags = @as(u32, @bitCast(linux.O{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true })),
        // Fixed essential mount names must be real directories within root.
        .resolve = 0x10 | 0x04, // RESOLVE_IN_ROOT | RESOLVE_NO_SYMLINKS
    };
    const path = try std.posix.toPosixPath(relative);
    const rc = linux.syscall4(.openat2, @bitCast(@as(isize, root_fd)), @intFromPtr(&path), @intFromPtr(&how), @sizeOf(@TypeOf(how)));
    if (linux.errno(rc) != .SUCCESS) return error.MountFailed;
    return @intCast(rc);
}

fn bindDevice(dev_fd: std.posix.fd_t, name: [:0]const u8) !void {
    var source_buf: [64]u8 = undefined;
    const source_path = try std.fmt.bufPrint(&source_buf, "/dev/{s}", .{name});
    try bindDeviceFrom(dev_fd, name, source_path);
}

fn bindDeviceFrom(dev_fd: std.posix.fd_t, name: [:0]const u8, source_path: []const u8) !void {
    const source = try platform.posix.open(source_path, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    defer platform.posix.close(source);
    if ((try platform.posix.fstat(source)).mode & std.posix.S.IFMT != std.posix.S.IFCHR) return error.MountFailed;
    const created = linux.openat(dev_fd, name.ptr, .{ .ACCMODE = .RDWR, .CREAT = true, .EXCL = true, .CLOEXEC = true }, 0o600);
    if (linux.errno(created) != .SUCCESS) return error.MountFailed;
    const target: std.posix.fd_t = @intCast(created);
    defer platform.posix.close(target);
    var from_buf: [64]u8 = undefined;
    var to_buf: [64]u8 = undefined;
    if (linux.errno(linux.mount((try fdPath(source, &from_buf)).ptr, (try fdPath(target, &to_buf)).ptr, null, linux.MS.BIND, 0)) != .SUCCESS) return error.MountFailed;
    // Reopen through /dev after attachment: the original target fd refers to
    // the covered placeholder, while this fd belongs to the device bind.
    const attached = linux.openat(dev_fd, name.ptr, .{ .PATH = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.errno(attached) != .SUCCESS) return error.MountFailed;
    const mounted: std.posix.fd_t = @intCast(attached);
    defer platform.posix.close(mounted);
    // Read-only mount metadata prevents chmod/chown from changing the host
    // device inode. Device reads and writes still reach the character driver.
    if (linux.errno(linux.mount(null, (try fdPath(mounted, &to_buf)).ptr, null, linux.MS.BIND | linux.MS.REMOUNT | linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NOEXEC, 0)) != .SUCCESS) return error.MountFailed;
}

fn fdPath(fd: std.posix.fd_t, buf: []u8) ![:0]const u8 {
    return std.fmt.bufPrintZ(buf, "/proc/self/fd/{d}", .{fd});
}

test "build mounts kernel protects disposable device inode while retaining IO" {
    if (linux.geteuid() != 0) return error.SkipZigTest;
    const child_exec = @import("../../build/engine/child_exec.zig");
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(std.testing.io, "root", .default_dir);
    if (linux.errno(linux.mknodat(tmp.dir.handle, "owned-null", std.posix.S.IFCHR | 0o600, (1 << 8) | 3)) != .SUCCESS) return error.CreateFailed;
    const before = try tmp.dir.statFile(std.testing.io, "owned-null", .{});
    var path_buf: [4096]u8 = undefined;
    const len = try tmp.dir.realPath(std.testing.io, &path_buf);
    const root = try std.fmt.allocPrint(alloc, "{s}/root", .{path_buf[0..len]});
    defer alloc.free(root);
    const source = try std.fmt.allocPrint(alloc, "{s}/owned-null", .{path_buf[0..len]});
    defer alloc.free(source);
    const Fixture = struct {
        root: []const u8,
        source: []const u8,
        fn run(arg: ?*anyopaque) callconv(.c) u8 {
            const self: *@This() = @ptrCast(@alignCast(arg));
            if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS) return 10;
            mountAt(self.root) catch return 11;
            const root_fd = platform.posix.open(self.root, .{ .PATH = true, .DIRECTORY = true, .CLOEXEC = true }, 0) catch return 12;
            defer platform.posix.close(root_fd);
            const dev = openDirectory(root_fd, "dev") catch return 13;
            defer platform.posix.close(dev);
            bindDeviceFrom(dev, "owned-null", self.source) catch return 14;
            child_exec.dropMountCapability() catch return 15;
            if (linux.errno(linux.fchmodat(dev, "owned-null", 0o777)) != .ROFS) return 16;
            const file = linux.openat(dev, "owned-null", .{ .ACCMODE = .WRONLY, .CLOEXEC = true }, 0);
            if (linux.errno(file) != .SUCCESS) return 17;
            const fd: std.posix.fd_t = @intCast(file);
            defer platform.posix.close(fd);
            if ((platform.posix.write(fd, "x") catch return 18) != 1) return 19;
            return 0;
        }
    };
    var fixture: Fixture = .{ .root = root, .source = source };
    var child = try child_exec.spawn(Fixture.run, @ptrCast(&fixture));
    defer platform.posix.close(child.stdout_fd);
    defer platform.posix.close(child.stderr_fd);
    child.signalReady();
    const result = try @import("../process.zig").wait(child.pid, false);
    try std.testing.expectEqual(@import("../process.zig").ExitStatus{ .exited = 0 }, result.status);
    const after = try tmp.dir.statFile(std.testing.io, "owned-null", .{});
    try std.testing.expectEqual(before.permissions.toMode(), after.permissions.toMode());
    try std.testing.expectEqual(before.inode, after.inode);
}
