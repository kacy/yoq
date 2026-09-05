const std = @import("std");

const blob_store = @import("../../image/store.zig");
const log = @import("../../lib/log.zig");
const types = @import("types.zig");
const path_policy = @import("path_policy.zig");
const Hasher = @import("../hash_encoding.zig").Hasher;

pub fn hashFiles(
    alloc: std.mem.Allocator,
    context_dir: []const u8,
    src_path: []const u8,
) types.ContextError!blob_store.Digest {
    path_policy.validateContextSourcePath(alloc, context_dir, src_path) catch |err| {
        return switch (err) {
            error.NotFound => types.ContextError.NotFound,
            error.PathTraversal => {
                log.err("build: path traversal attempt in hashFiles: {s}", .{src_path});
                return types.ContextError.PathTraversal;
            },
            else => return types.ContextError.HashFailed,
        };
    };

    var dir = std.Io.Dir.cwd().openDir(std.Options.debug_io, context_dir, .{}) catch return types.ContextError.NotFound;
    defer dir.close(std.Options.debug_io);

    var hasher = Hasher.init("yoq.build-context.v2");
    const stat = dir.statFile(std.Options.debug_io, src_path, .{}) catch return types.ContextError.NotFound;
    const entry_stat = dir.statFile(std.Options.debug_io, src_path, .{ .follow_symlinks = false }) catch return types.ContextError.HashFailed;
    if (entry_stat.kind == .sym_link) try hashLink(dir, src_path, &hasher);
    if (stat.kind == .directory) {
        try hashDirectory(alloc, dir, src_path, &hasher);
    } else if (stat.kind == .file) {
        // COPY dereferences a selected file link after context confinement.
        try hashOpenFile(dir, src_path, &hasher);
    } else return types.ContextError.HashFailed;
    return .{ .hash = hasher.hash.finalResult() };
}

fn hashDirectory(
    alloc: std.mem.Allocator,
    base_dir: std.Io.Dir,
    sub_path: []const u8,
    hasher: *Hasher,
) types.ContextError!void {
    var sub_dir = base_dir.openDir(std.Options.debug_io, sub_path, .{ .iterate = true }) catch
        return types.ContextError.NotFound;
    defer sub_dir.close(std.Options.debug_io);
    const root_stat = sub_dir.stat(std.Options.debug_io) catch return types.ContextError.HashFailed;
    header(hasher, 2, ".", root_stat.permissions.toMode(), 0);

    var paths: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (paths.items) |path| alloc.free(path);
        paths.deinit(alloc);
    }
    var walker = sub_dir.walk(alloc) catch return types.ContextError.HashFailed;
    defer walker.deinit();
    while (walker.next(std.Options.debug_io) catch return types.ContextError.HashFailed) |entry| {
        if (entry.kind != .file and entry.kind != .directory and entry.kind != .sym_link) continue;
        const owned = alloc.dupe(u8, entry.path) catch return types.ContextError.HashFailed;
        paths.append(alloc, owned) catch {
            alloc.free(owned);
            return types.ContextError.HashFailed;
        };
    }
    std.mem.sort([]const u8, paths.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);
    for (paths.items) |path| {
        const stat = sub_dir.statFile(std.Options.debug_io, path, .{ .follow_symlinks = false }) catch return types.ContextError.HashFailed;
        switch (stat.kind) {
            .file => try hashOpenFile(sub_dir, path, hasher),
            .directory => header(hasher, 2, path, stat.permissions.toMode(), 0),
            // Directory COPY currently skips links. Including their literal
            // targets is conservative and never reads outside the context.
            .sym_link => try hashLink(sub_dir, path, hasher),
            else => return types.ContextError.HashFailed,
        }
    }
}

fn header(hasher: *Hasher, kind: u64, path: []const u8, mode: u32, length: u64) void {
    hasher.number(kind);
    hasher.bytes(path);
    hasher.number(mode & 0o7777);
    hasher.number(length);
}

fn hashLink(dir: std.Io.Dir, path: []const u8, hasher: *Hasher) types.ContextError!void {
    var target: [std.fs.max_path_bytes]u8 = undefined;
    const length = dir.readLink(std.Options.debug_io, path, &target) catch return types.ContextError.HashFailed;
    header(hasher, 3, path, 0, length);
    hasher.hash.update(target[0..length]);
}

fn hashOpenFile(dir: std.Io.Dir, path: []const u8, hasher: *Hasher) types.ContextError!void {
    var file = dir.openFile(std.Options.debug_io, path, .{}) catch return types.ContextError.HashFailed;
    defer file.close(std.Options.debug_io);
    const stat = file.stat(std.Options.debug_io) catch return types.ContextError.HashFailed;
    if (stat.kind != .file) return types.ContextError.HashFailed;
    header(hasher, 1, path, stat.permissions.toMode(), stat.size);
    var buf: [8192]u8 = undefined;
    var reader = file.reader(std.Options.debug_io, &buf);
    var read_buf: [8192]u8 = undefined;
    var remaining = stat.size;
    while (remaining != 0) {
        const n = reader.interface.readSliceShort(read_buf[0..@min(remaining, read_buf.len)]) catch return types.ContextError.HashFailed;
        if (n == 0) return types.ContextError.HashFailed;
        hasher.hash.update(read_buf[0..n]);
        remaining -= n;
    }
    // The record length must describe the bytes actually hashed, even when
    // another process changes the file during the scan.
    if ((reader.interface.readSliceShort(read_buf[0..1]) catch return types.ContextError.HashFailed) != 0)
        return types.ContextError.HashFailed;
}

fn hashTestDir(dir: std.Io.Dir, source: []const u8) !blob_store.Digest {
    var path: [std.fs.max_path_bytes]u8 = undefined;
    const length = try dir.realPath(std.testing.io, &path);
    return hashFiles(std.testing.allocator, path[0..length], source);
}

test "build identity context rejects the exact path-content concatenation collision" {
    const io = std.testing.io;
    var left = std.testing.tmpDir(.{});
    defer left.cleanup();
    var right = std.testing.tmpDir(.{});
    defer right.cleanup();
    try left.dir.writeFile(io, .{ .sub_path = "a", .data = "xb\x00y" });
    try right.dir.writeFile(io, .{ .sub_path = "a", .data = "x" });
    try right.dir.writeFile(io, .{ .sub_path = "b", .data = "y" });
    const a = try hashTestDir(left.dir, ".");
    const b = try hashTestDir(right.dir, ".");
    try std.testing.expect(!std.mem.eql(u8, &a.hash, &b.hash));
}

test "build identity context changes for executable mode and empty directories" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "script", .data = "echo ok" });
    const file = try tmp.dir.openFile(io, "script", .{});
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o644));
    const before = try hashTestDir(tmp.dir, ".");
    try file.setPermissions(io, .fromMode(0o755));
    const executable = try hashTestDir(tmp.dir, ".");
    try std.testing.expect(!std.mem.eql(u8, &before.hash, &executable.hash));
    try tmp.dir.createDir(io, "empty", .default_dir);
    const directory = try hashTestDir(tmp.dir, ".");
    try std.testing.expect(!std.mem.eql(u8, &executable.hash, &directory.hash));
    const again = try hashTestDir(tmp.dir, ".");
    try std.testing.expectEqualSlices(u8, &directory.hash, &again.hash);
}

test "build identity context covers link target and selected link contents" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "a", .data = "first" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b", .data = "second" });
    try tmp.dir.symLink(io, "a", "link", .{});
    const first = try hashTestDir(tmp.dir, "link");
    const tree = try hashTestDir(tmp.dir, ".");
    try tmp.dir.deleteFile(io, "link");
    try tmp.dir.symLink(io, "b", "link", .{});
    const second = try hashTestDir(tmp.dir, "link");
    const changed_tree = try hashTestDir(tmp.dir, ".");
    try std.testing.expect(!std.mem.eql(u8, &first.hash, &second.hash));
    try std.testing.expect(!std.mem.eql(u8, &tree.hash, &changed_tree.hash));
}
