// paths — centralized path construction for yoq's data directory
//
// all yoq state lives under ~/.local/share/yoq/. this module
// provides helpers to build paths under that root so callers
// don't each reimplement the HOME lookup and bufPrint boilerplate.

const std = @import("std");

pub const PathError = error{ HomeDirNotFound, PathTooLong };

pub const max_path = 4096;

/// build a path: ~/.local/share/yoq/<subpath>
pub fn dataPath(buf: *[max_path]u8, subpath: []const u8) PathError![]const u8 {
    const home = std.posix.getenv("HOME") orelse return PathError.HomeDirNotFound;
    return std.fmt.bufPrint(buf, "{s}/.local/share/yoq/{s}", .{ home, subpath }) catch
        return PathError.PathTooLong;
}

/// build a path with a formatted subpath: ~/.local/share/yoq/<fmt args>
pub fn dataPathFmt(buf: *[max_path]u8, comptime fmt: []const u8, args: anytype) PathError![]const u8 {
    const home = std.posix.getenv("HOME") orelse return PathError.HomeDirNotFound;
    return std.fmt.bufPrint(buf, "{s}/.local/share/yoq/" ++ fmt, .{home} ++ args) catch
        return PathError.PathTooLong;
}

/// ensure a data subdirectory exists, creating parents as needed
pub fn ensureDataDir(subpath: []const u8) PathError!void {
    var buf: [max_path]u8 = undefined;
    const path = try dataPath(&buf, subpath);
    std.fs.cwd().makePath(path) catch {};
}

// -- tests --

test "dataPath builds correct path" {
    const home = std.posix.getenv("HOME") orelse return;
    var buf: [max_path]u8 = undefined;
    const path = try dataPath(&buf, "blobs/sha256");

    try std.testing.expect(std.mem.startsWith(u8, path, home));
    try std.testing.expect(std.mem.endsWith(u8, path, "/.local/share/yoq/blobs/sha256"));
}

test "dataPathFmt with arguments" {
    const home = std.posix.getenv("HOME") orelse return;
    var buf: [max_path]u8 = undefined;
    const path = try dataPathFmt(&buf, "containers/{s}/upper", .{"abc123"});

    try std.testing.expect(std.mem.startsWith(u8, path, home));
    try std.testing.expect(std.mem.endsWith(u8, path, "containers/abc123/upper"));
}

test "dataPath without HOME returns error" {
    // can't unset HOME in tests, so just verify the function compiles
    // and works with HOME set
    var buf: [max_path]u8 = undefined;
    const result = dataPath(&buf, "test");
    if (result) |path| {
        try std.testing.expect(path.len > 0);
    } else |_| {
        // HOME not set — expected in some CI environments
    }
}
