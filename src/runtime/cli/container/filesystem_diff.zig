const std = @import("std");
const linux = std.os.linux;
const copy = @import("filesystem_copy.zig");
const whiteout = @import("../../../lib/tar_whiteout.zig");

fn hasAttribute(fd: std.posix.fd_t, name: [:0]const u8, expect_opaque: bool) !bool {
    var value: [16]u8 = undefined;
    const rc = linux.fgetxattr(fd, name, &value, value.len);
    return switch (linux.errno(rc)) {
        .SUCCESS => if (expect_opaque) rc == 1 and value[0] == 'y' else true,
        .NODATA, .OPNOTSUPP, .ACCES, .PERM => false,
        else => error.AttributeReadFailed,
    };
}

fn isOpaque(dir: std.Io.Dir) !bool {
    return try hasAttribute(dir.handle, "trusted.overlay.opaque", true) or try hasAttribute(dir.handle, "user.overlay.opaque", true);
}

fn isWhiteout(io: std.Io, dir: std.Io.Dir, name: []const u8, kind: std.Io.File.Kind) !bool {
    if (kind == .character_device) return whiteout.isDeviceWhiteout(dir, name);
    if (kind != .file) return false;
    const file = try dir.openFile(io, name, .{});
    defer file.close(io);
    return try hasAttribute(file.handle, "trusted.overlay.whiteout", false) or try hasAttribute(file.handle, "user.overlay.whiteout", false);
}

fn lowerExists(io: std.Io, lower: std.Io.Dir, path: []const u8) !bool {
    const parent = copy.openContainerDir(lower, std.fs.path.dirname(path) orelse ".") catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => return err,
    };
    defer parent.close(io);
    _ = parent.statFile(io, std.fs.path.basename(path), .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => return false,
        else => return err,
    };
    return true;
}

fn line(writer: *std.Io.Writer, kind: u8, path: []const u8) !void {
    try writer.print("{c} /{s}\n", .{ kind, path });
}

/// compare upper metadata against the merged immutable image view. native
/// whiteouts and opaque directories represent deletions, including directories
/// removed as a whole. bind mounts and volumes are outside this writable layer.
pub fn diff(io: std.Io, alloc: std.mem.Allocator, upper: std.Io.Dir, lower: std.Io.Dir, writer: *std.Io.Writer) !void {
    try walk(io, alloc, upper, lower, "", writer, 0);
}

fn walk(io: std.Io, alloc: std.mem.Allocator, upper: std.Io.Dir, lower: std.Io.Dir, prefix: []const u8, writer: *std.Io.Writer, depth: usize) anyerror!void {
    if (depth > 256) return error.DirectoryDepthExceeded;
    if (try isOpaque(upper)) {
        const base = copy.openContainerDir(lower, if (prefix.len == 0) "." else prefix) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => null,
            else => return err,
        };
        if (base) |directory| {
            defer directory.close(io);
            var entries = directory.iterate();
            while (try entries.next(io)) |entry| {
                _ = upper.statFile(io, entry.name, .{ .follow_symlinks = false }) catch |err| switch (err) {
                    error.FileNotFound => {
                        const path = try join(alloc, prefix, entry.name);
                        defer alloc.free(path);
                        try line(writer, 'D', path);
                        continue;
                    },
                    else => return err,
                };
            }
        }
    }
    var entries = upper.iterate();
    while (try entries.next(io)) |entry| {
        const path = try join(alloc, prefix, entry.name);
        defer alloc.free(path);
        if (try isWhiteout(io, upper, entry.name, entry.kind)) {
            try line(writer, 'D', path);
            continue;
        }
        try line(writer, if (try lowerExists(io, lower, path)) 'C' else 'A', path);
        if (entry.kind == .directory) {
            var child = try upper.openDir(io, entry.name, .{ .iterate = true, .follow_symlinks = false });
            defer child.close(io);
            try walk(io, alloc, child, lower, path, writer, depth + 1);
        }
    }
}

fn join(alloc: std.mem.Allocator, prefix: []const u8, name: []const u8) ![]const u8 {
    return if (prefix.len == 0) alloc.dupe(u8, name) else std.fmt.allocPrint(alloc, "{s}/{s}", .{ prefix, name });
}

test "container diff distinguishes additions changes whiteouts and opaque deletions" {
    const io = std.testing.io;
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "lower/directory");
    try tmp.dir.createDirPath(io, "upper/directory");
    for ([_][]const u8{ "lower/changed", "lower/deleted", "lower/directory/hidden", "upper/changed", "upper/added", "upper/deleted", "upper/directory/new" }) |name|
        try tmp.dir.writeFile(io, .{ .sub_path = name, .data = "data" });
    const deleted = try tmp.dir.openFile(io, "upper/deleted", .{});
    defer deleted.close(io);
    if (linux.errno(linux.fsetxattr(deleted.handle, "user.overlay.whiteout", "", 0, 0)) != .SUCCESS) return error.SkipZigTest;
    const opaque_dir = try tmp.dir.openDir(io, "upper/directory", .{ .iterate = true });
    defer opaque_dir.close(io);
    if (linux.errno(linux.fsetxattr(opaque_dir.handle, "user.overlay.opaque", "y", 1, 0)) != .SUCCESS) return error.SkipZigTest;
    var lower = try tmp.dir.openDir(io, "lower", .{ .iterate = true });
    defer lower.close(io);
    var upper = try tmp.dir.openDir(io, "upper", .{ .iterate = true });
    defer upper.close(io);
    var output = std.Io.Writer.Allocating.init(alloc);
    defer output.deinit();
    try diff(io, alloc, upper, lower, &output.writer);
    const bytes = output.written();
    for ([_][]const u8{ "C /changed\n", "A /added\n", "D /deleted\n", "C /directory\n", "D /directory/hidden\n", "A /directory/new\n" }) |expected|
        try std.testing.expect(std.mem.indexOf(u8, bytes, expected) != null);
    try std.testing.expectEqual(@as(usize, 6), std.mem.count(u8, bytes, "\n"));
}
