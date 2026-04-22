const std = @import("std");
const linux = std.os.linux;
const syscall_util = @import("../../lib/syscall.zig");
const log = @import("../../lib/log.zig");
const common = @import("common.zig");

pub const FilesystemError = common.FilesystemError;

pub fn mountEssential() FilesystemError!void {
    return mountEssentialAt("");
}

pub fn mountEssentialAt(target_root: []const u8) FilesystemError!void {
    var proc_path_buf: [4096]u8 = undefined;
    const proc_path = joinTargetPath(target_root, "/proc", &proc_path_buf) catch return FilesystemError.PathTooLong;
    mkdirIfNeeded(proc_path) catch return FilesystemError.MkdirFailed;
    const rc1 = linux.mount(
        @ptrCast("proc"),
        @ptrCast(proc_path.ptr),
        @ptrCast("proc"),
        linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
        0,
    );
    if (syscall_util.isError(rc1)) {
        const errno = syscall_util.getErrno(rc1);
        if (errno == 1 or errno == 13) return FilesystemError.MountPermissionDenied;
        return FilesystemError.MountFailed;
    }

    var dev_path_buf: [4096]u8 = undefined;
    const dev_path = joinTargetPath(target_root, "/dev", &dev_path_buf) catch return FilesystemError.PathTooLong;
    mkdirIfNeeded(dev_path) catch return FilesystemError.MkdirFailed;
    const rc2 = linux.mount(
        @ptrCast("tmpfs"),
        @ptrCast(dev_path.ptr),
        @ptrCast("tmpfs"),
        linux.MS.NOSUID | linux.MS.STRICTATIME,
        @intFromPtr(@as([*:0]const u8, "mode=755,size=65536k")),
    );
    if (syscall_util.isError(rc2)) {
        const errno = syscall_util.getErrno(rc2);
        if (errno == 1 or errno == 13) return FilesystemError.MountPermissionDenied;
        return FilesystemError.MountFailed;
    }

    var sys_path_buf: [4096]u8 = undefined;
    const sys_path = joinTargetPath(target_root, "/sys", &sys_path_buf) catch return FilesystemError.PathTooLong;
    mkdirIfNeeded(sys_path) catch return FilesystemError.MkdirFailed;
    const rc3 = linux.mount(
        @ptrCast("sysfs"),
        @ptrCast(sys_path.ptr),
        @ptrCast("sysfs"),
        linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC | linux.MS.RDONLY,
        0,
    );
    if (syscall_util.isError(rc3)) return FilesystemError.MountFailed;

    var tmp_path_buf: [4096]u8 = undefined;
    const tmp_path = joinTargetPath(target_root, "/tmp", &tmp_path_buf) catch return FilesystemError.PathTooLong;
    mkdirIfNeeded(tmp_path) catch return FilesystemError.MkdirFailed;
    const rc4 = linux.mount(
        @ptrCast("tmpfs"),
        @ptrCast(tmp_path.ptr),
        @ptrCast("tmpfs"),
        linux.MS.NOSUID | linux.MS.NODEV,
        @intFromPtr(@as([*:0]const u8, "mode=1777,size=65536k")),
    );
    if (syscall_util.isError(rc4)) return FilesystemError.MountFailed;

    var dev_pts_path_buf: [4096]u8 = undefined;
    const dev_pts_path = joinTargetPath(target_root, "/dev/pts", &dev_pts_path_buf) catch return FilesystemError.PathTooLong;
    mkdirIfNeeded(dev_pts_path) catch return FilesystemError.MkdirFailed;
    const rc5 = linux.mount(
        @ptrCast("devpts"),
        @ptrCast(dev_pts_path.ptr),
        @ptrCast("devpts"),
        linux.MS.NOSUID | linux.MS.NOEXEC,
        @intFromPtr(@as([*:0]const u8, "newinstance,ptmxmode=0666,mode=0620")),
    );
    if (syscall_util.isError(rc5)) return FilesystemError.MountFailed;

    createDeviceNodesAt(target_root);
}

fn createDeviceNodesAt(target_root: []const u8) void {
    const DeviceNode = struct {
        path: []const u8,
        major: u32,
        minor: u32,
        mode: u32,
    };

    const devices = [_]DeviceNode{
        .{ .path = "/dev/null", .major = 1, .minor = 3, .mode = 0o020666 },
        .{ .path = "/dev/zero", .major = 1, .minor = 5, .mode = 0o020666 },
        .{ .path = "/dev/random", .major = 1, .minor = 8, .mode = 0o020666 },
        .{ .path = "/dev/urandom", .major = 1, .minor = 9, .mode = 0o020666 },
    };

    for (devices) |dev| {
        var path_buf: [4096]u8 = undefined;
        const path = joinTargetPath(target_root, dev.path, &path_buf) catch continue;
        const device_num: u32 = (dev.major << 8) | dev.minor;
        const rc = linux.syscall4(
            .mknodat,
            @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
            @intFromPtr(path.ptr),
            dev.mode,
            device_num,
        );
        if (syscall_util.isError(rc)) {
            log.info("device node creation skipped (no CAP_MKNOD?): {s}", .{path});
        }
    }

    const Symlink = struct {
        target: []const u8,
        path: []const u8,
    };

    const symlinks = [_]Symlink{
        .{ .target = "/proc/self/fd", .path = "/dev/fd" },
        .{ .target = "/proc/self/fd/0", .path = "/dev/stdin" },
        .{ .target = "/proc/self/fd/1", .path = "/dev/stdout" },
        .{ .target = "/proc/self/fd/2", .path = "/dev/stderr" },
    };

    for (symlinks) |link| {
        var path_buf: [4096]u8 = undefined;
        const path = joinTargetPath(target_root, link.path, &path_buf) catch continue;
        const rc = linux.syscall4(
            .symlinkat,
            @intFromPtr(link.target.ptr),
            @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
            @intFromPtr(path.ptr),
            0,
        );
        if (syscall_util.isError(rc)) {
            log.info("symlink creation failed: {s}", .{path});
        }
    }
}

fn mkdirIfNeeded(path: []const u8) !void {
    @import("compat").cwd().makeDir(path) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
}

fn joinTargetPath(target_root: []const u8, suffix: []const u8, buf: []u8) ![:0]const u8 {
    if (target_root.len == 0) {
        if (suffix.len + 1 > buf.len) return error.PathTooLong;
        @memcpy(buf[0..suffix.len], suffix);
        buf[suffix.len] = 0;
        return buf[0..suffix.len :0];
    }

    const suffix_part = if (suffix.len > 0 and suffix[0] == '/') suffix[1..] else suffix;
    const joined = std.fmt.bufPrint(buf, "{s}/{s}", .{ target_root, suffix_part }) catch return error.PathTooLong;
    if (joined.len + 1 > buf.len) return error.PathTooLong;
    buf[joined.len] = 0;
    return buf[0..joined.len :0];
}
