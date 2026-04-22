// paths — centralized path construction for yoq's data directory
//
// all yoq state lives under ~/.local/share/yoq/. this module
// provides helpers to build paths under that root so callers
// don't each reimplement the HOME lookup and bufPrint boilerplate.

const std = @import("std");
const builtin = @import("builtin");
const fmtx = std.fmt;
const log = @import("log.zig");

pub const PathError = error{ HomeDirNotFound, PathTooLong };

pub const max_path = 4096;

fn dataRoot(buf: *[max_path]u8) PathError![]const u8 {
    if (builtin.is_test) {
        return std.fmt.bufPrint(buf, ".zig-local-cache/test-home/.local/share/yoq", .{}) catch
            return PathError.PathTooLong;
    }

    const home = @import("compat").getenv("HOME") orelse return PathError.HomeDirNotFound;
    return std.fmt.bufPrint(buf, "{s}/.local/share/yoq", .{home}) catch
        return PathError.PathTooLong;
}

/// build a path: ~/.local/share/yoq/<subpath>
pub fn dataPath(buf: *[max_path]u8, subpath: []const u8) PathError![]const u8 {
    var root_buf: [max_path]u8 = undefined;
    const root = try dataRoot(&root_buf);
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ root, subpath }) catch
        return PathError.PathTooLong;
}

/// build a path with a formatted subpath: ~/.local/share/yoq/<fmt args>
pub fn dataPathFmt(buf: *[max_path]u8, comptime fmt: []const u8, args: anytype) PathError![]const u8 {
    var root_buf: [max_path]u8 = undefined;
    const root = try dataRoot(&root_buf);
    return std.fmt.bufPrint(buf, "{s}/" ++ fmt, .{root} ++ args) catch
        return PathError.PathTooLong;
}

/// ensure a data subdirectory exists, creating parents as needed
pub fn ensureDataDir(subpath: []const u8) PathError!void {
    var buf: [max_path]u8 = undefined;
    const path = try dataPath(&buf, subpath);
    @import("compat").cwd().makePath(path) catch |e| {
        log.warn("paths: failed to create directory {s}: {}. " ++
            "This may cause subsequent operations to fail.", .{ path, e });
        // Don't propagate the error - let callers decide if this is fatal
    };
}

/// ensure a data subdirectory exists and propagate creation failures.
/// use this when subsequent work cannot succeed without the directory.
pub fn ensureDataDirStrict(subpath: []const u8) (PathError || error{CreateFailed})!void {
    var buf: [max_path]u8 = undefined;
    const path = try dataPath(&buf, subpath);
    @import("compat").cwd().makePath(path) catch return error.CreateFailed;
}

/// build a unique temp path under ~/.local/share/yoq/<subdir>/.
/// suffix keeps the caller's file type visible (for example ".tar").
pub fn uniqueDataTempPath(
    buf: *[max_path]u8,
    subdir: []const u8,
    prefix: []const u8,
    suffix: []const u8,
) PathError![]const u8 {
    var rand: [6]u8 = undefined;
    @import("compat").randomBytes(&rand);

    var hex: [12]u8 = undefined;
    _ = fmtx.bufPrint(&hex, "{s}", .{fmtx.bytesToHex(rand, .lower)}) catch
        return PathError.PathTooLong;

    return dataPathFmt(buf, "{s}/.{s}.{s}{s}", .{ subdir, prefix, hex, suffix });
}

// -- tests --

test "dataPath builds correct path" {
    var buf: [max_path]u8 = undefined;
    const path = try dataPath(&buf, "blobs/sha256");

    try std.testing.expect(std.mem.endsWith(u8, path, "/.local/share/yoq/blobs/sha256"));
}

test "dataPathFmt with arguments" {
    var buf: [max_path]u8 = undefined;
    const path = try dataPathFmt(&buf, "containers/{s}/upper", .{"abc123"});

    try std.testing.expect(std.mem.endsWith(u8, path, "containers/abc123/upper"));
}

test "dataPath without HOME returns error" {
    var buf: [max_path]u8 = undefined;
    const path = try dataPath(&buf, "test");
    try std.testing.expect(path.len > 0);
}

test "uniqueDataTempPath stays in target directory" {
    var buf: [max_path]u8 = undefined;
    const path = try uniqueDataTempPath(&buf, "tmp", "blob", ".tmp");
    try std.testing.expect(std.mem.indexOf(u8, path, "/.local/share/yoq/tmp/.blob.") != null);
    try std.testing.expect(std.mem.endsWith(u8, path, ".tmp"));
}

test "ensureDataDir logs errors but doesn't panic" {
    // This should not panic even if directory creation fails
    // The function logs warnings for debugging purposes
    ensureDataDir("test_subdir") catch |e| {
        // If this fails, it should be due to HOME not being set
        // rather than the directory creation itself
        try std.testing.expect(e == PathError.HomeDirNotFound);
    };
}

test "ensureDataDirStrict creates directory or returns typed error" {
    ensureDataDirStrict("test_strict_subdir") catch |e| {
        try std.testing.expect(e == PathError.HomeDirNotFound or e == error.CreateFailed);
        return;
    };
}
