const std = @import("std");
const linux_platform = @import("linux_platform");
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

    linux_platform.posix.chdir(new_root) catch return FilesystemError.PivotFailed;

    const rc4 = linux.syscall2(.pivot_root, @intFromPtr(dot), @intFromPtr(dot));
    if (syscall_util.isError(rc4)) return FilesystemError.PivotFailed;

    const rc5 = linux.umount2(dot, linux.MNT.DETACH);
    if (syscall_util.isError(rc5)) return FilesystemError.UnmountFailed;
}

/// Build and harden the bind as a detached mount. Nothing is attached if a
/// recursive read-only guarantee cannot be established on this kernel.
pub fn bindMount(target_root: []const u8, source: []const u8, target: []const u8, read_only: bool) FilesystemError!void {
    if (target_root.len + target.len + 1 >= std.fs.max_path_bytes) return error.PathTooLong;
    if (!path_support.isCanonicalAbsolutePath(source) or !path_support.isPathSafe(target) or
        std.mem.indexOfScalar(u8, target, 0) != null) return error.MountFailed;
    const source_fd = openSource(source) catch return error.BindSourceValidationFailed;
    defer linux_platform.posix.close(source_fd);
    const stat = linux_platform.posix.fstat(source_fd) catch return error.BindSourceValidationFailed;
    const is_directory = stat.mode & posix.S.IFMT == posix.S.IFDIR;
    if (!is_directory and stat.mode & posix.S.IFMT != posix.S.IFREG) return error.BindSourceValidationFailed;

    const root_fd = linux_platform.posix.open(target_root, .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0) catch return error.MountFailed;
    defer linux_platform.posix.close(root_fd);
    const target_fd = prepareTarget(root_fd, target, is_directory) catch return error.MountFailed;
    defer linux_platform.posix.close(target_fd);
    try attachTree(source_fd, target_fd, read_only);
}

const OpenHow = extern struct { flags: u64, mode: u64 = 0, resolve: u64 };
const resolve_no_symlinks: u64 = 0x04;
const resolve_in_root: u64 = 0x10;
const resolve_no_magiclinks: u64 = 0x02;
const mount_attr_readonly: u64 = 1;
const at_empty_path: usize = 0x1000;
const at_recursive: usize = 0x8000;
const open_tree_clone: usize = 1;
const move_mount_empty_paths: usize = 0x04 | 0x40;
const MountAttr = extern struct { attr_set: u64, attr_clr: u64 = 0, propagation: u64 = 0, userns_fd: u64 = 0 };

fn openResolved(root_fd: posix.fd_t, path: []const u8, directory: bool, resolve: u64) !posix.fd_t {
    const path_z = try posix.toPosixPath(path);
    const flags: linux.O = .{ .PATH = true, .CLOEXEC = true, .DIRECTORY = directory };
    const how = OpenHow{ .flags = @as(u32, @bitCast(flags)), .resolve = resolve };
    for (0..8) |_| {
        const rc = linux.syscall4(.openat2, @bitCast(@as(isize, root_fd)), @intFromPtr(&path_z), @intFromPtr(&how), @sizeOf(OpenHow));
        switch (linux.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            .NOENT => return error.FileNotFound,
            else => return error.UnsafeMountPath,
        }
    }
    return error.UnsafeMountPath;
}

fn openSource(source: []const u8) !posix.fd_t {
    // Reject intermediate symlinks too: a prior realpath check cannot protect
    // a later pathname open from concurrent link replacement.
    return openResolved(posix.AT.FDCWD, source, false, resolve_no_symlinks);
}

fn openTarget(root_fd: posix.fd_t, path: []const u8, directory: bool) !posix.fd_t {
    return openResolved(root_fd, path, directory, resolve_in_root | resolve_no_magiclinks);
}

fn ensureDirectory(root_fd: posix.fd_t, path: []const u8) !posix.fd_t {
    if (openTarget(root_fd, if (path.len == 0) "." else path, true)) |fd| return fd else |err| {
        if (err != error.FileNotFound) return err;
    }
    var current = try openTarget(root_fd, ".", true);
    errdefer linux_platform.posix.close(current);
    var components = std.mem.tokenizeScalar(u8, path, '/');
    while (components.next()) |name| {
        const prefix = path[0..components.index];
        const next = openTarget(root_fd, prefix, true) catch |err| blk: {
            if (err != error.FileNotFound) return err;
            const name_z = try posix.toPosixPath(name);
            const rc = linux.mkdirat(current, &name_z, 0o755);
            if (linux.errno(rc) != .SUCCESS and linux.errno(rc) != .EXIST) return error.MkdirFailed;
            break :blk try openTarget(root_fd, prefix, true);
        };
        linux_platform.posix.close(current);
        current = next;
    }
    return current;
}

fn prepareTarget(root_fd: posix.fd_t, path: []const u8, directory: bool) !posix.fd_t {
    if (!path_support.isPathSafe(path) or std.mem.indexOfScalar(u8, path, 0) != null) return error.UnsafeMountPath;
    if (directory) return ensureDirectory(root_fd, path);
    if (openTarget(root_fd, path, false)) |fd| return fd else |err| {
        if (err != error.FileNotFound) return err;
    }
    const parent = try ensureDirectory(root_fd, std.fs.path.dirname(path) orelse "");
    defer linux_platform.posix.close(parent);
    const name = try posix.toPosixPath(std.fs.path.basename(path));
    const rc = linux.openat(parent, &name, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o644);
    if (linux.errno(rc) == .SUCCESS) linux_platform.posix.close(@intCast(rc)) else if (linux.errno(rc) != .EXIST) return error.MkdirFailed;
    return openTarget(root_fd, path, false);
}

fn attachTree(source_fd: posix.fd_t, target_fd: posix.fd_t, read_only: bool) FilesystemError!void {
    const empty: [*:0]const u8 = "";
    const flags = open_tree_clone | @as(usize, @as(u32, @bitCast(linux.O{ .CLOEXEC = true }))) | at_empty_path | at_recursive;
    const opened = linux.syscall3(.open_tree, @intCast(source_fd), @intFromPtr(empty), flags);
    if (linux.errno(opened) != .SUCCESS) return error.MountFailed;
    const tree_fd: posix.fd_t = @intCast(opened);
    defer linux_platform.posix.close(tree_fd);
    if (read_only) {
        const attrs = MountAttr{ .attr_set = mount_attr_readonly };
        const changed = linux.syscall5(.mount_setattr, @intCast(tree_fd), @intFromPtr(empty), at_empty_path | at_recursive, @intFromPtr(&attrs), @sizeOf(MountAttr));
        if (linux.errno(changed) != .SUCCESS) return error.MountFailed;
    }
    const moved = linux.syscall5(.move_mount, @intCast(tree_fd), @intFromPtr(empty), @intCast(target_fd), @intFromPtr(empty), move_mount_empty_paths);
    if (linux.errno(moved) != .SUCCESS) return error.MountFailed;
}

test "mount destination resolves image symlinks inside pinned root" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "root/inside");
    try tmp.dir.createDirPath(io, "root/a");
    try tmp.dir.createDirPath(io, "outside");
    var root = try tmp.dir.openDir(io, "root", .{ .iterate = true });
    defer root.close(io);
    try root.symLink(io, "/inside", "absolute", .{});
    try root.symLink(io, "../../inside", "a/relative", .{});
    for ([_][]const u8{ "/absolute/new", "/a/relative/new", "/inside/new" }) |target| {
        const fd = try prepareTarget(root.handle, target, true);
        defer linux_platform.posix.close(fd);
        const expected = try root.openDir(io, "inside/new", .{ .iterate = true });
        defer expected.close(io);
        try std.testing.expectEqual(try testInode(expected.handle), try testInode(fd));
    }
    const pinned = try prepareTarget(root.handle, "/absolute/new", true);
    defer linux_platform.posix.close(pinned);
    const before = try testInode(pinned);
    try root.deleteFile(io, "absolute");
    try root.symLink(io, "../outside", "absolute", .{});
    try std.testing.expectEqual(before, try testInode(pinned));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "outside/new", .{}));
    try std.testing.expectError(error.UnsafeMountPath, prepareTarget(root.handle, "../outside", true));
}

test "mount destination file creation and dangling links fail safely" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const fd = try prepareTarget(tmp.dir.handle, "/nested/config", false);
    defer linux_platform.posix.close(fd);
    try std.testing.expectEqual(posix.S.IFREG, (try linux_platform.posix.fstat(fd)).mode & posix.S.IFMT);
    try tmp.dir.symLink(io, "/missing", "dangling", .{});
    try std.testing.expectError(error.FileNotFound, prepareTarget(tmp.dir.handle, "/dangling/file", true));
    try std.testing.expectError(error.FileNotFound, tmp.dir.access(io, "missing", .{}));
}

test "mount source open rejects intermediate symlinks after policy validation" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "real/source");
    try tmp.dir.symLink(io, "real", "link", .{});
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPath(io, &path_buf);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/link/source", .{path_buf[0..len]});
    defer std.testing.allocator.free(path);
    try std.testing.expectError(error.UnsafeMountPath, openSource(path));
}

fn testInode(fd: posix.fd_t) !std.Io.File.INode {
    const file: std.Io.File = .{ .handle = fd, .flags = .{ .nonblocking = false } };
    return (try file.stat(std.testing.io)).inode;
}
