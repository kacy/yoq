const std = @import("std");
const linux = std.os.linux;
const platform = @import("linux_platform");
const mounts = @import("mount_ops");
const preflight = @import("runtime_preflight");

fn writeFile(path: []const u8, text: []const u8) !void {
    const path_z = try std.posix.toPosixPath(path);
    const fd = linux.open(&path_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true }, 0o600);
    if (linux.errno(fd) != .SUCCESS) return error.FileOpenFailed;
    defer platform.posix.close(@intCast(fd));
    if (try platform.posix.write(@intCast(fd), text) != text.len) return error.ShortWrite;
}

fn expectReadOnly(path: []const u8) !void {
    const path_z = try std.posix.toPosixPath(path);
    const result = linux.open(&path_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .CLOEXEC = true }, 0o600);
    if (linux.errno(result) == .SUCCESS) platform.posix.close(@intCast(result));
    try std.testing.expectEqual(linux.E.ROFS, linux.errno(result));
}

fn expectContents(path: []const u8, expected: []const u8) !void {
    const path_z = try std.posix.toPosixPath(path);
    const fd = linux.open(&path_z, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(fd) != .SUCCESS) return error.FileOpenFailed;
    defer platform.posix.close(@intCast(fd));
    var bytes: [128]u8 = undefined;
    const n = try platform.posix.read(@intCast(fd), &bytes);
    try std.testing.expectEqualStrings(expected, bytes[0..n]);
}

fn exercise(root: []const u8, source: []const u8, nested: [:0]const u8, outside: []const u8, recursive: bool) !void {
    if (linux.errno(linux.unshare(linux.CLONE.NEWNS)) != .SUCCESS) return error.UnshareFailed;
    if (linux.errno(linux.mount(null, "/", null, linux.MS.REC | linux.MS.PRIVATE, 0)) != .SUCCESS) return error.PrivateMountFailed;
    if (recursive) {
        if (linux.errno(linux.mount("tmpfs", nested, "tmpfs", 0, 0)) != .SUCCESS) return error.SubmountFailed;
        var path: [4096]u8 = undefined;
        try writeFile(try std.fmt.bufPrint(&path, "{s}/nested/value", .{source}), "nested data");
        try mounts.bindMount(root, source, "/data", true);
        try expectContents(try std.fmt.bufPrint(&path, "{s}/data/nested/value", .{root}), "nested data");
        try expectReadOnly(try std.fmt.bufPrint(&path, "{s}/data/new", .{root}));
        try expectReadOnly(try std.fmt.bufPrint(&path, "{s}/data/nested/new", .{root}));
        // Hardening a detached clone must not make the host source read-only.
        try writeFile(try std.fmt.bufPrint(&path, "{s}/nested/still-writable", .{source}), "yes");
    } else {
        try mounts.bindMount(root, source, "/escape", false);
        var path: [4096]u8 = undefined;
        // The absolute image symlink is interpreted inside root, never against
        // the host pathname. The host target remains the original directory.
        try expectContents(try std.fmt.bufPrint(&path, "{s}/value", .{outside}), "host sentinel");
        try expectContents(try std.fmt.bufPrint(&path, "{s}{s}/value", .{ root, outside }), "source data");
    }
}

fn runCase(recursive: bool) !void {
    try preflight.requireRuntimeCore();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io, "root");
    try tmp.dir.createDirPath(io, "source/nested");
    try tmp.dir.createDirPath(io, "outside");
    try tmp.dir.writeFile(io, .{ .sub_path = "source/value", .data = "source data" });
    try tmp.dir.writeFile(io, .{ .sub_path = "outside/value", .data = "host sentinel" });
    var base: [4096]u8 = undefined;
    const len = try tmp.dir.realPath(io, &base);
    const alloc = std.testing.allocator;
    const root = try std.fmt.allocPrint(alloc, "{s}/root", .{base[0..len]});
    defer alloc.free(root);
    const source = try std.fmt.allocPrint(alloc, "{s}/source", .{base[0..len]});
    defer alloc.free(source);
    const nested = try std.fmt.allocPrintSentinel(alloc, "{s}/nested", .{source}, 0);
    defer alloc.free(nested);
    const outside = try std.fmt.allocPrint(alloc, "{s}/outside", .{base[0..len]});
    defer alloc.free(outside);
    const inner_target = try std.fmt.allocPrint(alloc, "{s}{s}", .{ root, outside });
    defer alloc.free(inner_target);
    try std.Io.Dir.cwd().createDirPath(io, inner_target);
    try tmp.dir.symLink(io, outside, "root/escape", .{});

    const pid = linux.fork();
    if (linux.errno(pid) != .SUCCESS) return error.ForkFailed;
    if (pid == 0) {
        exercise(root, source, nested, outside, recursive) catch |err| {
            std.debug.print("mount confinement child failed: {}\n", .{err});
            linux.exit(1);
        };
        linux.exit(0);
    }
    var status: u32 = 0;
    while (true) {
        const waited = linux.waitpid(@intCast(pid), &status, 0);
        if (linux.errno(waited) == .INTR) continue;
        if (linux.errno(waited) != .SUCCESS) return error.WaitFailed;
        break;
    }
    try std.testing.expectEqual(@as(u32, 0), status);
}

test "mount confinement keeps absolute image symlinks inside rootfs" {
    try runCase(false);
}

test "mount confinement recursively protects nested writable mounts" {
    try runCase(true);
}
