// filesystem — overlayfs and pivot_root for container rootfs isolation
//
// sets up the container's filesystem by:
// 1. creating an overlayfs with the image layers as lower dirs
// 2. pivot_root into the new rootfs
// 3. mounting /proc, /dev, /sys, /tmp inside the container
//
// this runs inside the child process after namespace creation.

const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const common = @import("filesystem/common.zig");
const path_support = @import("filesystem/path_support.zig");
const essential_mounts = @import("filesystem/essential_mounts.zig");
const mount_ops = @import("filesystem/mount_ops.zig");

pub const FilesystemError = common.FilesystemError;

/// configuration for a container's filesystem
pub const FilesystemConfig = common.FilesystemConfig;

/// mount overlayfs from image layers.
///
/// lower_dirs are the read-only image layers (bottom first).
/// upper_dir is the writable layer. work_dir is overlay's scratch space.
/// the merged result appears at merged_dir.
pub fn mountOverlay(config: FilesystemConfig) FilesystemError!void {
    return mount_ops.mountOverlay(config);
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
    return mount_ops.pivotRoot(new_root);
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
    return mount_ops.bindMount(target_root, source, target, read_only);
}

/// mount essential filesystems inside the container.
/// call this after pivot_root.
pub fn mountEssential() FilesystemError!void {
    return essential_mounts.mountEssential();
}

pub fn mountEssentialAt(target_root: []const u8) FilesystemError!void {
    return essential_mounts.mountEssentialAt(target_root);
}

fn isPathSafe(path: []const u8) bool {
    return path_support.isPathSafe(path);
}

/// check if a path is a symlink using lstat().
/// returns true if the path exists and is a symlink, false otherwise.
/// errors (e.g. path doesn't exist) are treated as "not a symlink"
/// since the mount will fail later with a clear error anyway.
fn isSymlink(path: []const u8) bool {
    return path_support.isSymlink(path);
}

/// TOCTOU-safe path validation.
/// opens the path with O_NOFOLLOW to verify it's not a symlink,
/// preventing race conditions between validation and use.
/// returns the file descriptor on success.
fn validatePathNoSymlink(path: []const u8) FilesystemError!posix.fd_t {
    return path_support.validatePathNoSymlink(path);
}

pub fn isCanonicalAbsolutePath(path: []const u8) bool {
    return path_support.isCanonicalAbsolutePath(path);
}

/// check that a path doesn't contain ':' or ',' which would break
/// overlayfs mount options parsing.
fn isValidOverlayPath(path: []const u8) bool {
    return path_support.isValidOverlayPath(path);
}

/// make a zero-terminated copy of a path for syscalls
fn sentinelize(path: *const []const u8) ![:0]const u8 {
    return path_support.sentinelize(path);
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

    try tmp.dir.createDir(std.testing.io, "realdir", .default_dir);
    try tmp.dir.symLink(std.testing.io, "realdir", "linkdir", .{});

    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    const real_path_len = try tmp.dir.realPathFile(std.testing.io, "realdir", &real_buf);
    const real_path = real_buf[0..real_path_len];
    try std.testing.expect(!isSymlink(real_path));

    // for the symlink, we need the path without resolving it.
    // realpath resolves symlinks, so we build the path manually.
    var base_buf: [std.fs.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPathFile(std.testing.io, ".", &base_buf);
    const base_path = base_buf[0..base_len];
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

    try tmp.dir.createDir(std.testing.io, "real", .default_dir);
    try tmp.dir.symLink(std.testing.io, "real", "link", .{});

    var base_buf: [std.fs.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPathFile(std.testing.io, ".", &base_buf);
    const base = base_buf[0..base_len];

    var real_buf: [std.fs.max_path_bytes]u8 = undefined;
    const real_len = try tmp.dir.realPathFile(std.testing.io, "real", &real_buf);
    const real = real_buf[0..real_len];
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
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "testfile", .data = "test content" });

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPathFile(std.testing.io, "testfile", &path_buf);
    const path = path_buf[0..path_len];

    const fd = try validatePathNoSymlink(path);
    linux_platform.posix.close(fd);
}

test "validatePathNoSymlink accepts directories" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // create a directory
    try tmp.dir.createDir(std.testing.io, "testdir", .default_dir);

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPathFile(std.testing.io, "testdir", &path_buf);
    const path = path_buf[0..path_len];

    const fd = try validatePathNoSymlink(path);
    linux_platform.posix.close(fd);
}

test "validatePathNoSymlink rejects symlinks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // create a file and symlink to it
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "realfile", .data = "content" });
    try tmp.dir.symLink(std.testing.io, "realfile", "linkfile", .{});

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPathFile(std.testing.io, ".", &path_buf);
    const base = path_buf[0..base_len];

    var link_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_path = try std.fmt.bufPrint(&link_path_buf, "{s}/linkfile", .{base});

    // should fail because it's a symlink
    try std.testing.expectError(FilesystemError.BindSourceIsSymlink, validatePathNoSymlink(link_path));
}

test "validatePathNoSymlink rejects non-existent paths" {
    try std.testing.expectError(FilesystemError.BindSourceValidationFailed, validatePathNoSymlink("/nonexistent/path/12345"));
}
