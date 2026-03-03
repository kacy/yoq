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
    MountFailed,
    PivotFailed,
    UnmountFailed,
    MkdirFailed,
    PathTooLong,
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

    // build overlayfs mount options:
    // "lowerdir=layer1:layer2,upperdir=upper,workdir=work"
    var opts_buf: [4096]u8 = undefined;
    var pos: usize = 0;

    // lowerdir=
    const lowerdir_prefix = "lowerdir=";
    @memcpy(opts_buf[pos..][0..lowerdir_prefix.len], lowerdir_prefix);
    pos += lowerdir_prefix.len;

    // join lower dirs with ':'
    for (config.lower_dirs, 0..) |dir, i| {
        if (i > 0) {
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
    if (syscall_util.isError(rc)) return FilesystemError.MountFailed;

    // remount read-only if requested (bind + ro requires a second mount call)
    if (read_only) {
        flags = linux.MS.BIND | linux.MS.REC | linux.MS.REMOUNT | linux.MS.RDONLY;
        const rc2 = linux.mount(source_z, full_target, null, flags, 0);
        if (syscall_util.isError(rc2)) return FilesystemError.MountFailed;
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
}

/// create a directory if it doesn't exist
fn mkdirIfNeeded(path: []const u8) !void {
    std.fs.cwd().makeDir(path) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return e,
    };
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

    // path that's way too long should fail
    const long_path = "a" ** 4096;
    const result = bindMount("/root", long_path, "/target", false);
    try std.testing.expectError(FilesystemError.PathTooLong, result);

    // target_root + target too long should also fail
    const long_root = "x" ** 2048;
    const long_target = "y" ** 2048;
    const result2 = bindMount(long_root, "/src", long_target, false);
    try std.testing.expectError(FilesystemError.PathTooLong, result2);
}

test "sentinelize" {
    const path: []const u8 = "/test/path";
    const result = try sentinelize(&path);
    try std.testing.expectEqualStrings("/test/path", result);
    try std.testing.expectEqual(@as(u8, 0), result.ptr[result.len]);
}
