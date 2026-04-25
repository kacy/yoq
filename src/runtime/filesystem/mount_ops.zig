const std = @import("std");
const platform = @import("platform");
const linux = std.os.linux;
const posix = std.posix;
const syscall_util = @import("../../lib/syscall.zig");
const log = @import("../../lib/log.zig");
const common = @import("common.zig");
const path_support = @import("path_support.zig");

pub const FilesystemError = common.FilesystemError;
pub const FilesystemConfig = common.FilesystemConfig;

pub fn mountOverlay(config: FilesystemConfig) FilesystemError!void {
    for (config.lower_dirs) |dir| {
        if (!path_support.isValidOverlayPath(dir)) {
            log.warn("overlayfs: lower dir contains invalid characters: {s}", .{dir});
            return FilesystemError.MountFailed;
        }
    }
    if (!path_support.isValidOverlayPath(config.upper_dir)) {
        log.warn("overlayfs: upper dir contains invalid characters: {s}", .{config.upper_dir});
        return FilesystemError.MountFailed;
    }
    if (!path_support.isValidOverlayPath(config.work_dir)) {
        log.warn("overlayfs: work dir contains invalid characters: {s}", .{config.work_dir});
        return FilesystemError.MountFailed;
    }

    for (config.lower_dirs) |dir| {
        if (path_support.isSymlink(dir)) {
            log.warn("overlayfs: lower dir is a symlink: {s}", .{dir});
            return FilesystemError.SymlinkNotAllowed;
        }
    }
    if (path_support.isSymlink(config.upper_dir)) {
        log.warn("overlayfs: upper dir is a symlink: {s}", .{config.upper_dir});
        return FilesystemError.SymlinkNotAllowed;
    }
    if (path_support.isSymlink(config.work_dir)) {
        log.warn("overlayfs: work dir is a symlink: {s}", .{config.work_dir});
        return FilesystemError.SymlinkNotAllowed;
    }

    var opts_buf: [4096]u8 = undefined;
    var pos: usize = 0;

    const lowerdir_prefix = "lowerdir=";
    if (lowerdir_prefix.len >= opts_buf.len) return FilesystemError.PathTooLong;
    @memcpy(opts_buf[pos..][0..lowerdir_prefix.len], lowerdir_prefix);
    pos += lowerdir_prefix.len;

    for (config.lower_dirs, 0..) |dir, i| {
        if (i > 0) {
            if (pos >= opts_buf.len) return FilesystemError.PathTooLong;
            opts_buf[pos] = ':';
            pos += 1;
        }
        if (pos + dir.len >= opts_buf.len) return FilesystemError.PathTooLong;
        @memcpy(opts_buf[pos..][0..dir.len], dir);
        pos += dir.len;
    }

    const upper_part = std.fmt.bufPrint(opts_buf[pos..], ",upperdir={s},workdir={s}", .{
        config.upper_dir,
        config.work_dir,
    }) catch return FilesystemError.PathTooLong;
    pos += upper_part.len;

    if (pos >= opts_buf.len) return FilesystemError.PathTooLong;
    opts_buf[pos] = 0;

    const merged_z = path_support.sentinelize(&config.merged_dir) catch return FilesystemError.PathTooLong;
    const rc = linux.mount(
        @ptrCast("overlay"),
        merged_z,
        @ptrCast("overlay"),
        0,
        @intFromPtr(&opts_buf),
    );
    if (syscall_util.isError(rc)) return FilesystemError.MountFailed;
}

pub fn pivotRoot(new_root: []const u8) FilesystemError!void {
    const root_z = path_support.sentinelize(&new_root) catch return FilesystemError.PathTooLong;
    const dot: [*:0]const u8 = ".";

    const rc1 = linux.mount(null, @ptrCast("/"), null, linux.MS.REC | linux.MS.PRIVATE, 0);
    if (syscall_util.isError(rc1)) return FilesystemError.MountFailed;

    const rc2 = linux.mount(root_z, root_z, @ptrCast("bind"), linux.MS.BIND | linux.MS.REC, 0);
    if (syscall_util.isError(rc2)) return FilesystemError.MountFailed;

    platform.posix.chdir(new_root) catch return FilesystemError.PivotFailed;

    const rc4 = linux.syscall2(.pivot_root, @intFromPtr(dot), @intFromPtr(dot));
    if (syscall_util.isError(rc4)) return FilesystemError.PivotFailed;

    const rc5 = linux.umount2(dot, linux.MNT.DETACH);
    if (syscall_util.isError(rc5)) return FilesystemError.UnmountFailed;
}

pub fn bindMount(target_root: []const u8, source: []const u8, target: []const u8, read_only: bool) FilesystemError!void {
    if (!path_support.isCanonicalAbsolutePath(source)) {
        log.warn("bind mount source must be canonical absolute path: {s}", .{source});
        return FilesystemError.MountFailed;
    }
    if (!path_support.isPathSafe(source)) {
        log.warn("bind mount source contains directory traversal: {s}", .{source});
        return FilesystemError.MountFailed;
    }
    if (!path_support.isPathSafe(target)) {
        log.warn("bind mount target contains directory traversal: {s}", .{target});
        return FilesystemError.MountFailed;
    }

    const validation_fd = path_support.validatePathNoSymlink(source) catch |e| {
        log.err("bind mount: source path validation failed for {s}: {s}", .{ source, @errorName(e) });
        return e;
    };
    defer platform.posix.close(validation_fd);

    var fd_path_buf: [64]u8 = undefined;
    const fd_path = std.fmt.bufPrint(&fd_path_buf, "/proc/self/fd/{d}\x00", .{validation_fd}) catch
        return FilesystemError.PathTooLong;
    const source_z: [*:0]const u8 = @ptrCast(fd_path.ptr);

    var target_buf: [4096]u8 = undefined;
    var target_pos: usize = 0;

    if (target_root.len + target.len + 1 >= target_buf.len) return FilesystemError.PathTooLong;

    @memcpy(target_buf[0..target_root.len], target_root);
    target_pos = target_root.len;

    if (target_root.len > 0 and target_root[target_root.len - 1] != '/' and
        (target.len == 0 or target[0] != '/'))
    {
        target_buf[target_pos] = '/';
        target_pos += 1;
    }

    @memcpy(target_buf[target_pos..][0..target.len], target);
    target_pos += target.len;
    target_buf[target_pos] = 0;

    const full_target: [*:0]const u8 = @ptrCast(&target_buf);

    std.Io.Dir.cwd().createDirPath(std.Options.debug_io, target_buf[0..target_pos]) catch return FilesystemError.MkdirFailed;

    var flags: u32 = linux.MS.BIND | linux.MS.REC;
    const rc = linux.mount(source_z, full_target, null, flags, 0);
    if (syscall_util.isError(rc)) {
        log.err("bind mount: mount syscall failed for {s} -> {s}", .{ source, target });
        return FilesystemError.MountFailed;
    }

    if (read_only) {
        flags = linux.MS.BIND | linux.MS.REC | linux.MS.REMOUNT | linux.MS.RDONLY;
        const rc2 = linux.mount(source_z, full_target, null, flags, 0);
        if (syscall_util.isError(rc2)) {
            log.err("bind mount: remount ro failed for {s}", .{target});
            return FilesystemError.MountFailed;
        }
    }
}
