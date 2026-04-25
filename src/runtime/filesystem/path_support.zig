const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const log = @import("../../lib/log.zig");
const common = @import("common.zig");

pub const FilesystemError = common.FilesystemError;

pub fn isPathSafe(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }
    return true;
}

pub fn isSymlink(path: []const u8) bool {
    const stat = linux_platform.posix.fstatat(posix.AT.FDCWD, path, posix.AT.SYMLINK_NOFOLLOW) catch return false;
    return stat.mode & posix.S.IFMT == posix.S.IFLNK;
}

pub fn validatePathNoSymlink(path: []const u8) FilesystemError!posix.fd_t {
    const fd = linux_platform.posix.open(path, .{ .NOFOLLOW = true, .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch |e| {
        if (e == error.NotDir or e == error.SymLinkLoop) {
            log.warn("filesystem: path is a symlink or contains symlinks: {s}", .{path});
            return FilesystemError.BindSourceIsSymlink;
        }
        log.warn("filesystem: could not validate path {s}: {s}", .{ path, @errorName(e) });
        return FilesystemError.BindSourceValidationFailed;
    };

    const stat = linux_platform.posix.fstat(fd) catch {
        linux_platform.posix.close(fd);
        return FilesystemError.BindSourceValidationFailed;
    };

    if (stat.mode & posix.S.IFMT == posix.S.IFLNK) {
        linux_platform.posix.close(fd);
        log.warn("filesystem: path is a symlink: {s}", .{path});
        return FilesystemError.BindSourceIsSymlink;
    }

    return fd;
}

pub fn isCanonicalAbsolutePath(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/') return false;

    var resolved_buf: [std.fs.max_path_bytes]u8 = undefined;
    const resolved_len = std.Io.Dir.cwd().realPathFile(std.Options.debug_io, path, &resolved_buf) catch return false;
    const resolved = resolved_buf[0..resolved_len];
    return std.mem.eql(u8, resolved, path);
}

pub fn isValidOverlayPath(path: []const u8) bool {
    for (path) |c| {
        if (c == ':' or c == ',') return false;
    }
    return true;
}

pub fn sentinelize(path: *const []const u8) ![:0]const u8 {
    const S = struct {
        threadlocal var buf: [4096:0]u8 = .{0} ** 4096;
    };
    if (path.len >= S.buf.len) return error.PathTooLong;
    @memcpy(S.buf[0..path.len], path.*);
    S.buf[path.len] = 0;
    return S.buf[0..path.len :0];
}
