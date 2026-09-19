const std = @import("std");
const linux = std.os.linux;

/// resolve container paths from its root, including absolute symlink targets.
/// the returned directory remains usable if the container exits during copying.
pub fn openContainerDir(root: std.Io.Dir, path: []const u8) !std.Io.Dir {
    const how = extern struct { flags: u64, mode: u64 = 0, resolve: u64 }{
        .flags = @as(u32, @bitCast(linux.O{ .DIRECTORY = true, .CLOEXEC = true })),
        .resolve = 0x10 | 0x02, // RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
    };
    const name = try std.posix.toPosixPath(if (path.len == 0) "." else path);
    const rc = linux.syscall4(.openat2, @bitCast(@as(isize, root.handle)), @intFromPtr(&name), @intFromPtr(&how), @sizeOf(@TypeOf(how)));
    return switch (linux.errno(rc)) {
        .SUCCESS => .{ .handle = @intCast(rc) },
        .NOENT => error.FileNotFound,
        .NOTDIR => error.NotDir,
        else => error.OpenDirectoryFailed,
    };
}

const Parent = struct {
    dir: std.Io.Dir,
    name: []const u8,
};

fn parent(io: std.Io, root: ?std.Io.Dir, path: []const u8) !Parent {
    const clean = std.mem.trimEnd(u8, path, "/");
    const name = if (clean.len == 0) "." else std.fs.path.basename(clean);
    if (root) |container_root| {
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, ".."))
            return .{ .dir = try openContainerDir(container_root, path), .name = "." };
    }
    const directory = if (clean.len == 0) "/" else std.fs.path.dirname(clean) orelse ".";
    const opened = if (root) |container_root|
        try openContainerDir(container_root, directory)
    else
        try std.Io.Dir.cwd().openDir(io, directory, .{ .iterate = true });
    return .{ .dir = opened, .name = name };
}

fn openDestination(io: std.Io, root: ?std.Io.Dir, path: []const u8) !?std.Io.Dir {
    return (if (root) |container_root| openContainerDir(container_root, path) else std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true })) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => null,
        else => return err,
    };
}

/// exactly one endpoint is container-relative. directories copied to an
/// existing directory retain their basename; a source ending in /. copies contents.
pub fn copy(io: std.Io, source_root: ?std.Io.Dir, source_path: []const u8, destination_root: ?std.Io.Dir, destination_path: []const u8) !void {
    if (source_path.len == 0 or destination_path.len == 0) return error.InvalidPath;
    const source = try parent(io, source_root, source_path);
    defer source.dir.close(io);
    const stat = try source.dir.statFile(io, source.name, .{ .follow_symlinks = false });
    if (try openDestination(io, destination_root, destination_path)) |destination| {
        defer destination.close(io);
        if (stat.kind == .directory and (std.mem.eql(u8, source.name, ".") or std.mem.eql(u8, source.name, ".."))) {
            var from = try source.dir.openDir(io, source.name, .{ .iterate = true, .follow_symlinks = false });
            defer from.close(io);
            try copyContents(io, from, destination, 0);
        } else try copyEntry(io, source.dir, source.name, destination, source.name, 0);
    } else {
        if (std.mem.endsWith(u8, destination_path, "/")) return error.DestinationDirectoryMissing;
        const destination = try parent(io, destination_root, destination_path);
        defer destination.dir.close(io);
        try copyEntry(io, source.dir, source.name, destination.dir, destination.name, 0);
    }
}

fn copyContents(io: std.Io, source: std.Io.Dir, destination: std.Io.Dir, depth: usize) !void {
    var iterator = source.iterate();
    while (try iterator.next(io)) |entry| try copyEntry(io, source, entry.name, destination, entry.name, depth + 1);
}

fn copyEntry(io: std.Io, source: std.Io.Dir, source_name: []const u8, destination: std.Io.Dir, destination_name: []const u8, depth: usize) anyerror!void {
    if (depth > 256) return error.DirectoryDepthExceeded;
    const stat = try source.statFile(io, source_name, .{ .follow_symlinks = false });
    switch (stat.kind) {
        .directory => {
            destination.createDir(io, destination_name, .fromMode(0o700)) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
            var from = try source.openDir(io, source_name, .{ .iterate = true, .follow_symlinks = false });
            defer from.close(io);
            var to = try destination.openDir(io, destination_name, .{ .iterate = true, .follow_symlinks = false });
            defer to.close(io);
            if (try sameDirectory(from, to)) return error.SameFile;
            try copyContents(io, from, to, depth);
            if (linux.errno(linux.fchmod(to.handle, (stat.permissions.toMode() & 0o7777))) != .SUCCESS) return error.ChmodFailed;
        },
        .file => try source.copyFile(source_name, destination, destination_name, io, .{}),
        .sym_link => {
            var target: [std.fs.max_path_bytes]u8 = undefined;
            const len = try source.readLink(io, source_name, &target);
            destination.deleteFile(io, destination_name) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            };
            try destination.symLink(io, target[0..len], destination_name, .{});
        },
        else => return error.UnsupportedFileType,
    }
}

fn sameDirectory(a: std.Io.Dir, b: std.Io.Dir) !bool {
    var first: linux.Statx = undefined;
    var second: linux.Statx = undefined;
    if (linux.errno(linux.statx(a.handle, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &first)) != .SUCCESS) return error.StatFailed;
    if (linux.errno(linux.statx(b.handle, "", linux.AT.EMPTY_PATH, .{ .INO = true }, &second)) != .SUCCESS) return error.StatFailed;
    return first.ino == second.ino and first.dev_major == second.dev_major and first.dev_minor == second.dev_minor;
}

test "container copy preserves files directories modes and symlinks in both directions" {
    const io = std.testing.io;
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "host/tree/nested");
    try tmp.dir.createDirPath(io, "container/data");
    try tmp.dir.createDirPath(io, "out");
    try tmp.dir.writeFile(io, .{ .sub_path = "host/tree/nested/file", .data = "bytes\x00tail" });
    const file = try tmp.dir.openFile(io, "host/tree/nested/file", .{});
    try file.setPermissions(io, .fromMode(0o751));
    file.close(io);
    try tmp.dir.symLink(io, "/data/tree/nested/file", "host/tree/link", .{});
    var root = try tmp.dir.openDir(io, "container", .{ .iterate = true });
    defer root.close(io);
    var path_buf: [4096]u8 = undefined;
    const len = try tmp.dir.realPath(io, &path_buf);
    const source = try std.fmt.allocPrint(alloc, "{s}/host/tree", .{path_buf[0..len]});
    defer alloc.free(source);
    const output = try std.fmt.allocPrint(alloc, "{s}/out", .{path_buf[0..len]});
    defer alloc.free(output);
    try copy(io, null, source, root, "/data");
    try copy(io, root, "/data/tree/.", null, output);
    const content = try tmp.dir.readFileAlloc(io, "out/nested/file", alloc, .limited(100));
    defer alloc.free(content);
    try std.testing.expectEqualStrings("bytes\x00tail", content);
    try std.testing.expectEqual(@as(u32, 0o751), (try tmp.dir.statFile(io, "out/nested/file", .{})).permissions.toMode() & 0o7777);
    var link: [128]u8 = undefined;
    const link_len = try tmp.dir.readLink(io, "out/link", &link);
    try std.testing.expectEqualStrings("/data/tree/nested/file", link[0..link_len]);
}

test "container paths resolve absolute directory symlinks within its root" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "real");
    try tmp.dir.writeFile(io, .{ .sub_path = "real/file", .data = "inside" });
    try tmp.dir.symLink(io, "/real", "alias", .{});
    const directory = try openContainerDir(tmp.dir, "/alias");
    defer directory.close(io);
    const content = try directory.readFileAlloc(io, "file", std.testing.allocator, .limited(100));
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("inside", content);
}
