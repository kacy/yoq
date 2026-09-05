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
}

fn fdPath(fd: std.posix.fd_t, buf: []u8) ![:0]const u8 {
    return std.fmt.bufPrintZ(buf, "/proc/self/fd/{d}", .{fd});
}
