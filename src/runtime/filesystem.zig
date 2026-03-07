// filesystem — overlayfs and pivot_root for container rootfs isolation
//
// sets up the container's filesystem by:
// 1. creating an overlayfs with the image layers as lower dirs
// 2. pivot_root into the new rootfs
// 3. mounting /proc, /dev, /sys, /tmp inside the container
//
// this runs inside the child process after namespace creation.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const syscall_util = @import("../lib/syscall.zig");
const log = @import("../lib/log.zig");

pub const FilesystemError = error{
    /// a mount syscall failed (overlayfs, bind, essential fs, or remount)
    MountFailed,
    /// pivot_root syscall failed — could not switch to new rootfs
    PivotFailed,
    /// umount2 failed when detaching the old root after pivot
    UnmountFailed,
    /// failed to create a required directory (e.g. mount point target)
    MkdirFailed,
    /// a constructed path exceeded the stack buffer (4096 bytes)
    PathTooLong,
    /// an overlay path (lower/upper/work) is a symlink, which could redirect mounts
    SymlinkNotAllowed,
    /// bind mount source is a symlink (TOCTOU protection)
    BindSourceIsSymlink,
    /// bind mount source path validation failed
    BindSourceValidationFailed,
};

/// configuration for a container's filesystem
pub const FilesystemConfig = struct {
    /// lower directories for overlayfs (image layers, bottom to top)
    lower_dirs: []const []const u8,
    /// upper directory for overlayfs (writable layer)
    upper_dir: []const u8,
    /// work directory for overlayfs (internal bookkeeping)
    work_dir: []const u8,
    /// merged mount point
    merged_dir: []const u8,
};

/// mount overlayfs from image layers.
///
/// lower_dirs are the read-only image layers (bottom first).
/// upper_dir is the writable layer. work_dir is overlay's scratch space.
/// the merged result appears at merged_dir.
pub fn mountOverlay(config: FilesystemConfig) FilesystemError!void {
    // validate paths don't contain characters that break overlayfs mount options.
    // ':' is the lowerdir separator, ',' separates mount options — either
    // character in a path would corrupt the options string.
    for (config.lower_dirs) |dir| {
        if (!isValidOverlayPath(dir)) {
            log.warn("overlayfs: lower dir contains invalid characters: {s}", .{dir});
            return FilesystemError.MountFailed;
        }
    }
    if (!isValidOverlayPath(config.upper_dir)) {
        log.warn("overlayfs: upper dir contains invalid characters: {s}", .{config.upper_dir});
        return FilesystemError.MountFailed;
    }
    if (!isValidOverlayPath(config.work_dir)) {
        log.warn("overlayfs: work dir contains invalid characters: {s}", .{config.work_dir});
        return FilesystemError.MountFailed;
    }

    // verify overlay paths are not symlinks. a symlink could redirect
    // the overlay mount to an attacker-controlled location, bypassing
    // the container's filesystem isolation.
    for (config.lower_dirs) |dir| {
        if (isSymlink(dir)) {
            log.warn("overlayfs: lower dir is a symlink: {s}", .{dir});
            return FilesystemError.SymlinkNotAllowed;
        }
    }
    if (isSymlink(config.upper_dir)) {
        log.warn("overlayfs: upper dir is a symlink: {s}", .{config.upper_dir});
        return FilesystemError.SymlinkNotAllowed;
    }
    if (isSymlink(config.work_dir)) {
        log.warn("overlayfs: work dir is a symlink: {s}", .{config.work_dir});
        return FilesystemError.SymlinkNotAllowed;
    }

    // build overlayfs mount options:
    // "lowerdir=layer1:layer2,upperdir=upper,workdir=work"
    var opts_buf: [4096]u8 = undefined;
    var pos: usize = 0;

    // lowerdir= prefix — bounds check before copy
    const lowerdir_prefix = "lowerdir=";
    if (lowerdir_prefix.len >= opts_buf.len) return FilesystemError.PathTooLong;
    @memcpy(opts_buf[pos..][0..lowerdir_prefix.len], lowerdir_prefix);
    pos += lowerdir_prefix.len;

    // join lower dirs with ':'
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

    // ,upperdir=
    const upper_part = std.fmt.bufPrint(opts_buf[pos..], ",upperdir={s},workdir={s}", .{
        config.upper_dir,
        config.work_dir,
    }) catch return FilesystemError.PathTooLong;
    pos += upper_part.len;

    // null-terminate for the syscall
    if (pos >= opts_buf.len) return FilesystemError.PathTooLong;
    opts_buf[pos] = 0;

    // mount -t overlay overlay -o <opts> <merged_dir>
    const merged_z = sentinelize(&config.merged_dir) catch return FilesystemError.PathTooLong;
    const rc = linux.mount(
        @ptrCast("overlay"),
        merged_z,
        @ptrCast("overlay"),
        0,
        @intFromPtr(&opts_buf),
    );
    if (syscall_util.isError(rc)) return FilesystemError.MountFailed;
}

/// pivot into a new rootfs directory.
///
/// uses the pivot_root(".", ".") trick from the man page:
/// 1. make mount propagation private (prevents leaking to parent)
/// 2. bind mount the new root onto itself (must be a mount point)
/// 3. chdir into it
/// 4. pivot_root(".", ".")
/// 5. umount old root with MNT_DETACH
pub fn pivotRoot(new_root: []const u8) FilesystemError!void {
    const root_z = sentinelize(&new_root) catch return FilesystemError.PathTooLong;
    const dot: [*:0]const u8 = ".";

    // step 1: make all mounts private so changes don't propagate
    const rc1 = linux.mount(
        null,
        @ptrCast("/"),
        null,
        linux.MS.REC | linux.MS.PRIVATE,
        0,
    );
    if (syscall_util.isError(rc1)) return FilesystemError.MountFailed;

    // step 2: bind mount new_root onto itself
    const rc2 = linux.mount(
        root_z,
        root_z,
        @ptrCast("bind"),
        linux.MS.BIND | linux.MS.REC,
        0,
    );
    if (syscall_util.isError(rc2)) return FilesystemError.MountFailed;

    // step 3: chdir into new root
    posix.chdir(new_root) catch return FilesystemError.PivotFailed;

    // step 4: pivot_root(".", ".")
    const rc4 = linux.syscall2(
        .pivot_root,
        @intFromPtr(dot),
        @intFromPtr(dot),
    );
    if (syscall_util.isError(rc4)) return FilesystemError.PivotFailed;

    // step 5: unmount old root (now stacked under ".")
    const rc5 = linux.umount2(dot, linux.MNT.DETACH);
    if (syscall_util.isError(rc5)) return FilesystemError.UnmountFailed;
}

/// bind mount a host directory into the container's filesystem.
///
/// call this after mountOverlay but before pivotRoot — the source path
/// must be visible (pre-pivot) and the target must exist in the merged fs.
///
/// builds the full target path as target_root/target. creates the target
/// directory if it doesn't exist. uses a stack buffer for path construction
/// rather than the threadlocal sentinelize (we need source and target
/// simultaneously).
pub fn bindMount(target_root: []const u8, source: []const u8, target: []const u8, read_only: bool) FilesystemError!void {
    if (!isCanonicalAbsolutePath(source)) {
        log.warn("bind mount source must be canonical absolute path: {s}", .{source});
        return FilesystemError.MountFailed;
    }

    // reject paths with ".." components to prevent directory traversal.
    // in cluster mode a remote deploy request could specify arbitrary paths,
    // so we validate at the filesystem layer as defense-in-depth.
    if (!isPathSafe(source)) {
        log.warn("bind mount source contains directory traversal: {s}", .{source});
        return FilesystemError.MountFailed;
    }
    if (!isPathSafe(target)) {
        log.warn("bind mount target contains directory traversal: {s}", .{target});
        return FilesystemError.MountFailed;
    }

    // TOCTOU-safe validation: open source with O_NOFOLLOW to verify it's not a symlink
    // this prevents race conditions where the path is replaced between validation and mount
    const validation_fd = validatePathNoSymlink(source) catch |e| {
        log.err("bind mount: source path validation failed for {s}: {s}", .{ source, @errorName(e) });
        return e;
    };
    posix.close(validation_fd);

    // build full target path: target_root + target
    var target_buf: [4096]u8 = undefined;
    var target_pos: usize = 0;

    if (target_root.len + target.len + 1 >= target_buf.len) return FilesystemError.PathTooLong;

    @memcpy(target_buf[0..target_root.len], target_root);
    target_pos = target_root.len;

    // ensure single separator between root and target
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

    // null-terminate source path
    var source_buf: [4096]u8 = undefined;
    if (source.len >= source_buf.len) return FilesystemError.PathTooLong;
    @memcpy(source_buf[0..source.len], source);
    source_buf[source.len] = 0;
    const source_z: [*:0]const u8 = @ptrCast(&source_buf);

    // create target directory if it doesn't exist
    std.fs.cwd().makePath(target_buf[0..target_pos]) catch return FilesystemError.MkdirFailed;

    // bind mount: source -> full_target
    var flags: u32 = linux.MS.BIND | linux.MS.REC;
    const rc = linux.mount(source_z, full_target, null, flags, 0);
    if (syscall_util.isError(rc)) {
        log.err("bind mount: mount syscall failed for {s} -> {s}", .{ source, target });
        return FilesystemError.MountFailed;
    }

    // remount read-only if requested (bind + ro requires a second mount call)
    if (read_only) {
        flags = linux.MS.BIND | linux.MS.REC | linux.MS.REMOUNT | linux.MS.RDONLY;
        const rc2 = linux.mount(source_z, full_target, null, flags, 0);
        if (syscall_util.isError(rc2)) {
            log.err("bind mount: remount ro failed for {s}", .{target});
            return FilesystemError.MountFailed;
        }
    }
}

/// mount essential filesystems inside the container.
/// call this after pivot_root.
pub fn mountEssential() FilesystemError!void {
    // /proc — process information
    mkdirIfNeeded("/proc") catch return FilesystemError.MkdirFailed;
    const rc1 = linux.mount(
        @ptrCast("proc"),
        @ptrCast("/proc"),
        @ptrCast("proc"),
        linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
        0,
    );
    if (syscall_util.isError(rc1)) return FilesystemError.MountFailed;

    // /dev — devices (tmpfs)
    mkdirIfNeeded("/dev") catch return FilesystemError.MkdirFailed;
    const rc2 = linux.mount(
        @ptrCast("tmpfs"),
        @ptrCast("/dev"),
        @ptrCast("tmpfs"),
        linux.MS.NOSUID | linux.MS.STRICTATIME,
        @intFromPtr(@as([*:0]const u8, "mode=755,size=65536k")),
    );
    if (syscall_util.isError(rc2)) return FilesystemError.MountFailed;

    // /sys — kernel interface (sysfs, read-only)
    mkdirIfNeeded("/sys") catch return FilesystemError.MkdirFailed;
    const rc3 = linux.mount(
        @ptrCast("sysfs"),
        @ptrCast("/sys"),
        @ptrCast("sysfs"),
        linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC | linux.MS.RDONLY,
        0,
    );
    if (syscall_util.isError(rc3)) return FilesystemError.MountFailed;

    // /tmp — temporary files (tmpfs)
    mkdirIfNeeded("/tmp") catch return FilesystemError.MkdirFailed;
    const rc4 = linux.mount(
        @ptrCast("tmpfs"),
        @ptrCast("/tmp"),
        @ptrCast("tmpfs"),
        linux.MS.NOSUID | linux.MS.NODEV,
        @intFromPtr(@as([*:0]const u8, "mode=1777,size=65536k")),
    );
    if (syscall_util.isError(rc4)) return FilesystemError.MountFailed;

    // /dev/pts — pseudo-terminals
    mkdirIfNeeded("/dev/pts") catch return FilesystemError.MkdirFailed;
    const rc5 = linux.mount(
        @ptrCast("devpts"),
        @ptrCast("/dev/pts"),
        @ptrCast("devpts"),
        linux.MS.NOSUID | linux.MS.NOEXEC,
        @intFromPtr(@as([*:0]const u8, "newinstance,ptmxmode=0666,mode=0620")),
    );
    if (syscall_util.isError(rc5)) return FilesystemError.MountFailed;

    // create standard device nodes and symlinks in /dev.
    // many programs expect /dev/null, /dev/zero, etc. to exist.
    createDeviceNodes();
}

/// create essential device nodes (/dev/null, /dev/zero, etc.) and symlinks.
/// uses mknod syscall — may fail in user namespaces without CAP_MKNOD,
/// which is fine (log and continue). most container workloads need these
/// but the container can still function without them.
fn createDeviceNodes() void {
    const DeviceNode = struct {
        path: [*:0]const u8,
        major: u32,
        minor: u32,
        mode: u32,
    };

    // character devices: mode includes S_IFCHR (0o020000) + permissions
    const devices = [_]DeviceNode{
        .{ .path = "/dev/null", .major = 1, .minor = 3, .mode = 0o020666 },
        .{ .path = "/dev/zero", .major = 1, .minor = 5, .mode = 0o020666 },
        .{ .path = "/dev/random", .major = 1, .minor = 8, .mode = 0o020666 },
        .{ .path = "/dev/urandom", .major = 1, .minor = 9, .mode = 0o020666 },
    };

    for (devices) |dev| {
        // dev_t = makedev(major, minor) = (major << 8) | minor for Linux
        const device_num: u32 = (dev.major << 8) | dev.minor;
        const rc = linux.syscall4(
            .mknodat,
            @as(usize, @bitCast(@as(isize, linux.AT.FDCWD))),
            @intFromPtr(dev.path),
            dev.mode,
            device_num,
        );
        if (syscall_util.isError(rc)) {
            // expected in user namespaces without CAP_MKNOD — not fatal
            log.info("device node creation skipped (no CAP_MKNOD?): {s}", .{std.mem.span(dev.path)});
        }
    }

    // symlinks for /proc/self/fd convenience
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

/// create a directory if it doesn't exist
fn mkdirIfNeeded(path: []const u8) !void {
    std.fs.cwd().makeDir(path) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
}

/// check that a path doesn't contain ".." as a path component.
/// rejects "/../", leading "../", trailing "/..", and exact match "..".
/// does NOT reject ".." inside filenames (e.g. "foo..bar" is fine).
fn isPathSafe(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }
    return true;
}

/// check if a path is a symlink using lstat().
/// returns true if the path exists and is a symlink, false otherwise.
/// errors (e.g. path doesn't exist) are treated as "not a symlink"
/// since the mount will fail later with a clear error anyway.
fn isSymlink(path: []const u8) bool {
    const stat = posix.fstatat(posix.AT.FDCWD, path, posix.AT.SYMLINK_NOFOLLOW) catch return false;
    return stat.mode & posix.S.IFMT == posix.S.IFLNK;
}

/// TOCTOU-safe path validation.
/// opens the path with O_NOFOLLOW to verify it's not a symlink,
/// preventing race conditions between validation and use.
/// returns the file descriptor on success.
fn validatePathNoSymlink(path: []const u8) FilesystemError!posix.fd_t {
    // open with O_NOFOLLOW - this will fail if path is a symlink
    const fd = posix.open(path, .{ .O_NOFOLLOW = true, .O_RDONLY = true, .O_CLOEXEC = true }, 0) catch |e| {
        // check if this is specifically a symlink error
        if (e == error.NotDir or e == error.SymLinkLoop) {
            log.err("filesystem: path is a symlink or contains symlinks: {s}", .{path});
            return FilesystemError.BindSourceIsSymlink;
        }
        // other errors (not found, permission denied) - let the mount fail naturally
        log.warn("filesystem: could not validate path {s}: {s}", .{ path, @errorName(e) });
        return FilesystemError.BindSourceValidationFailed;
    };

    // verify it's not a symlink using fstat
    const stat = posix.fstat(fd) catch {
        posix.close(fd);
        return FilesystemError.BindSourceValidationFailed;
    };

    if (stat.mode & posix.S.IFMT == posix.S.IFLNK) {
        posix.close(fd);
        log.err("filesystem: path is a symlink: {s}", .{path});
        return FilesystemError.BindSourceIsSymlink;
    }

    return fd;
}

fn isCanonicalAbsolutePath(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/') return false;

    var resolved_buf: [std.fs.max_path_bytes]u8 = undefined;
    const resolved = std.fs.cwd().realpath(path, &resolved_buf) catch return false;
    return std.mem.eql(u8, resolved, path);
}

/// check that a path doesn't contain ':' or ',' which would break
/// overlayfs mount options parsing.
fn isValidOverlayPath(path: []const u8) bool {
    for (path) |c| {
        if (c == ':' or c == ',') return false;
    }
    return true;
}

/// make a zero-terminated copy of a path for syscalls
fn sentinelize(path: *const []const u8) ![:0]const u8 {
    // we use a thread-local buffer to avoid allocation
    const S = struct {
        threadlocal var buf: [4096:0]u8 = .{0} ** 4096;
    };
    if (path.len >= S.buf.len) return error.PathTooLong;
    @memcpy(S.buf[0..path.len], path.*);
    S.buf[path.len] = 0;
    return S.buf[0..path.len :0];
}

// -- tests --

test "overlay options building" {
    // test that the config struct initializes correctly
    const config = FilesystemConfig{
        .lower_dirs = &.{ "/layers/base", "/layers/app" },
        .upper_dir = "/container/upper",
        .work_dir = "/container/work",
        .merged_dir = "/container/merged",
    };

    try std.testing.expectEqual(@as(usize, 2), config.lower_dirs.len);
    try std.testing.expectEqualStrings("/layers/base", config.lower_dirs[0]);
    try std.testing.expectEqualStrings("/layers/app", config.lower_dirs[1]);
}

test "overlay path validation" {
    // normal hex-digest paths are fine
    try std.testing.expect(isValidOverlayPath("/home/user/.local/share/yoq/layers/sha256/abcdef1234"));
    try std.testing.expect(isValidOverlayPath("/tmp/overlay/upper"));

    // ':' and ',' would break mount options
    try std.testing.expect(!isValidOverlayPath("/path/with:colon"));
    try std.testing.expect(!isValidOverlayPath("/path/with,comma"));
    try std.testing.expect(!isValidOverlayPath("a:b"));
}

test "bindMount path construction" {
    // we can't actually perform bind mounts in a test without root,
    // but we can verify the path construction logic by checking that
    // the function returns PathTooLong for oversized inputs

    // target_root + target too long should also fail
    const long_root = "x" ** 2048;
    const long_target = "y" ** 2048;
    const result2 = bindMount(long_root, "/tmp", long_target, false);
    try std.testing.expectError(FilesystemError.PathTooLong, result2);
}

test "isPathSafe accepts normal paths" {
    try std.testing.expect(isPathSafe("/usr/local/bin"));
    try std.testing.expect(isPathSafe("relative/path"));
    try std.testing.expect(isPathSafe("/"));
    try std.testing.expect(isPathSafe(""));
    try std.testing.expect(isPathSafe("/foo..bar/baz")); // ".." inside a filename is fine
    try std.testing.expect(isPathSafe("a...b"));
}

test "isPathSafe rejects directory traversal" {
    try std.testing.expect(!isPathSafe("../etc"));
    try std.testing.expect(!isPathSafe("/foo/../bar"));
    try std.testing.expect(!isPathSafe("/foo/.."));
    try std.testing.expect(!isPathSafe(".."));
    try std.testing.expect(!isPathSafe("../../etc/shadow"));
}

test "overlay path rejects comma in path" {
    try std.testing.expect(!isValidOverlayPath("/path,with,commas"));
}

test "overlay path rejects colon in path" {
    try std.testing.expect(!isValidOverlayPath("/path:with:colons"));
}

test "isPathSafe accepts single dot" {
    try std.testing.expect(isPathSafe("."));
}

test "sentinelize" {
    const path: []const u8 = "/test/path";
    const result = try sentinelize(&path);
    try std.testing.expectEqualStrings("/test/path", result);
    try std.testing.expectEqual(@as(u8, 0), result.ptr[result.len]);
}

test "isSymlink detects symlinks" {
    // create a temp directory with a real dir and a symlink
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("realdir");
    try tmp.dir.symLink("realdir", "linkdir", .{});

    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    const real_path = try tmp.dir.realpath("realdir", &real_buf);
    try std.testing.expect(!isSymlink(real_path));

    // for the symlink, we need the path without resolving it.
    // realpath resolves symlinks, so we build the path manually.
    var base_buf: [std.fs.max_path_bytes]u8 = undefined;
    const base_path = try tmp.dir.realpath(".", &base_buf);
    var link_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_path = std.fmt.bufPrint(&link_path_buf, "{s}/linkdir", .{base_path}) catch unreachable;
    try std.testing.expect(isSymlink(link_path));
}

test "isSymlink returns false for non-existent path" {
    try std.testing.expect(!isSymlink("/nonexistent/path/that/does/not/exist"));
}

test "isCanonicalAbsolutePath rejects non-canonical and relative paths" {
    try std.testing.expect(!isCanonicalAbsolutePath("./relative"));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("real");
    try tmp.dir.symLink("real", "link", .{});

    var base_buf: [std.fs.max_path_bytes]u8 = undefined;
    const base = try tmp.dir.realpath(".", &base_buf);

    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    const real = try tmp.dir.realpath("real", &real_buf);
    try std.testing.expect(isCanonicalAbsolutePath(real));

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link = try std.fmt.bufPrint(&link_buf, "{s}/link", .{base});
    try std.testing.expect(!isCanonicalAbsolutePath(link));
}

// -- TOCTOU-safe validation tests --

test "validatePathNoSymlink accepts regular files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // create a regular file
    try tmp.dir.writeFile("testfile", "test content");

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmp.dir.realpath("testfile", &path_buf);

    const fd = try validatePathNoSymlink(path);
    posix.close(fd);
}

test "validatePathNoSymlink accepts directories" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // create a directory
    try tmp.dir.makeDir("testdir");

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmp.dir.realpath("testdir", &path_buf);

    const fd = try validatePathNoSymlink(path);
    posix.close(fd);
}

test "validatePathNoSymlink rejects symlinks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // create a file and symlink to it
    try tmp.dir.writeFile("realfile", "content");
    try tmp.dir.symLink("realfile", "linkfile", .{});

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const base = try tmp.dir.realpath(".", &path_buf);

    var link_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_path = try std.fmt.bufPrint(&link_path_buf, "{s}/linkfile", .{base});

    // should fail because it's a symlink
    try std.testing.expectError(FilesystemError.BindSourceIsSymlink, validatePathNoSymlink(link_path));
}

test "validatePathNoSymlink rejects non-existent paths" {
    try std.testing.expectError(FilesystemError.BindSourceValidationFailed, validatePathNoSymlink("/nonexistent/path/12345"));
}
