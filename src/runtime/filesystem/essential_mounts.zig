const std = @import("std");
const linux = std.os.linux;
const syscall_util = @import("../../lib/syscall.zig");
const log = @import("../../lib/log.zig");
const common = @import("common.zig");

pub const FilesystemError = common.FilesystemError;

pub fn mountEssential() FilesystemError!void {
    mkdirIfNeeded("/proc") catch return FilesystemError.MkdirFailed;
    const rc1 = linux.mount(
        @ptrCast("proc"),
        @ptrCast("/proc"),
        @ptrCast("proc"),
        linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
        0,
    );
    if (syscall_util.isError(rc1)) {
        const errno = syscall_util.getErrno(rc1);
        if (errno == 1 or errno == 13) return FilesystemError.MountPermissionDenied;
        return FilesystemError.MountFailed;
    }

    mkdirIfNeeded("/dev") catch return FilesystemError.MkdirFailed;
    const rc2 = linux.mount(
        @ptrCast("tmpfs"),
        @ptrCast("/dev"),
        @ptrCast("tmpfs"),
        linux.MS.NOSUID | linux.MS.STRICTATIME,
        @intFromPtr(@as([*:0]const u8, "mode=755,size=65536k")),
    );
    if (syscall_util.isError(rc2)) {
        const errno = syscall_util.getErrno(rc2);
        if (errno == 1 or errno == 13) return FilesystemError.MountPermissionDenied;
        return FilesystemError.MountFailed;
    }

    mkdirIfNeeded("/sys") catch return FilesystemError.MkdirFailed;
    const rc3 = linux.mount(
        @ptrCast("sysfs"),
        @ptrCast("/sys"),
        @ptrCast("sysfs"),
        linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC | linux.MS.RDONLY,
        0,
    );
    if (syscall_util.isError(rc3)) return FilesystemError.MountFailed;

    mkdirIfNeeded("/tmp") catch return FilesystemError.MkdirFailed;
    const rc4 = linux.mount(
        @ptrCast("tmpfs"),
        @ptrCast("/tmp"),
        @ptrCast("tmpfs"),
        linux.MS.NOSUID | linux.MS.NODEV,
        @intFromPtr(@as([*:0]const u8, "mode=1777,size=65536k")),
    );
    if (syscall_util.isError(rc4)) return FilesystemError.MountFailed;

    mkdirIfNeeded("/dev/pts") catch return FilesystemError.MkdirFailed;
    const rc5 = linux.mount(
        @ptrCast("devpts"),
        @ptrCast("/dev/pts"),
        @ptrCast("devpts"),
        linux.MS.NOSUID | linux.MS.NOEXEC,
        @intFromPtr(@as([*:0]const u8, "newinstance,ptmxmode=0666,mode=0620")),
    );
    if (syscall_util.isError(rc5)) return FilesystemError.MountFailed;

    createDeviceNodes();
}

fn createDeviceNodes() void {
    const DeviceNode = struct {
        path: [*:0]const u8,
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
        const device_num: u32 = (dev.major << 8) | dev.minor;
        const rc = linux.syscall4(
            .mknodat,
            @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
            @intFromPtr(dev.path),
            dev.mode,
            device_num,
        );
        if (syscall_util.isError(rc)) {
            log.info("device node creation skipped (no CAP_MKNOD?): {s}", .{std.mem.span(dev.path)});
        }
    }

    const Symlink = struct {
        target: [*:0]const u8,
        path: [*:0]const u8,
    };

    const symlinks = [_]Symlink{
        .{ .target = "/proc/self/fd", .path = "/dev/fd" },
        .{ .target = "/proc/self/fd/0", .path = "/dev/stdin" },
        .{ .target = "/proc/self/fd/1", .path = "/dev/stdout" },
        .{ .target = "/proc/self/fd/2", .path = "/dev/stderr" },
    };

    for (symlinks) |link| {
        const rc = linux.syscall4(
            .symlinkat,
            @intFromPtr(link.target),
            @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
            @intFromPtr(link.path),
            0,
        );
        if (syscall_util.isError(rc)) {
            log.info("symlink creation failed: {s}", .{std.mem.span(link.path)});
        }
    }
}

fn mkdirIfNeeded(path: []const u8) !void {
    std.fs.cwd().makeDir(path) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
}
