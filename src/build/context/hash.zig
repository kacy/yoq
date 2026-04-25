const std = @import("std");

const blob_store = @import("../../image/store.zig");
const log = @import("../../lib/log.zig");
const types = @import("types.zig");
const path_policy = @import("path_policy.zig");

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

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});

    const stat = dir.statFile(std.Options.debug_io, src_path, .{}) catch {
        return hashDirectory(alloc, dir, src_path, &hasher);
    };

    if (stat.kind == .directory) {
        return hashDirectory(alloc, dir, src_path, &hasher);
    }

    hasher.update(src_path);
    hasher.update("\x00");
    try hashOpenFile(dir, src_path, &hasher);

    return blob_store.Digest{ .hash = hasher.finalResult() };
}

fn hashDirectory(
    alloc: std.mem.Allocator,
    base_dir: std.Io.Dir,
    sub_path: []const u8,
    hasher: *std.crypto.hash.sha2.Sha256,
) types.ContextError!blob_store.Digest {
    var sub_dir = base_dir.openDir(std.Options.debug_io, sub_path, .{ .iterate = true }) catch
        return types.ContextError.NotFound;
    defer sub_dir.close(std.Options.debug_io);

    var paths: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (paths.items) |path| alloc.free(path);
        paths.deinit(alloc);
    }

    var walker = sub_dir.walk(alloc) catch return types.ContextError.HashFailed;
    defer walker.deinit();

    while (walker.next(std.Options.debug_io) catch return types.ContextError.HashFailed) |entry| {
        if (entry.kind != .file) continue;

        const owned_path = alloc.dupe(u8, entry.path) catch return types.ContextError.HashFailed;
        paths.append(alloc, owned_path) catch {
            alloc.free(owned_path);
            return types.ContextError.HashFailed;
        };
    }

    std.mem.sort([]const u8, paths.items, {}, struct {
        fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    for (paths.items) |path| {
        hasher.update(path);
        hasher.update("\x00");
        try hashOpenFile(sub_dir, path, hasher);
    }

    return blob_store.Digest{ .hash = hasher.finalResult() };
}

fn hashOpenFile(
    dir: std.Io.Dir,
    path: []const u8,
    hasher: *std.crypto.hash.sha2.Sha256,
) types.ContextError!void {
    var file = dir.openFile(std.Options.debug_io, path, .{}) catch return types.ContextError.HashFailed;
    defer file.close(std.Options.debug_io);

    var buf: [8192]u8 = undefined;
    var reader = file.reader(std.Options.debug_io, &buf);
    var read_buf: [8192]u8 = undefined;
    while (true) {
        const n = reader.interface.readSliceShort(&read_buf) catch return types.ContextError.HashFailed;
        if (n == 0) break;
        hasher.update(read_buf[0..n]);
    }
}
