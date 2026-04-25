const std = @import("std");

const log = @import("../../lib/log.zig");
const types = @import("types.zig");
const path_policy = @import("path_policy.zig");

pub fn copyFiles(
    alloc: std.mem.Allocator,
    context_dir: []const u8,
    src: []const u8,
    layer_dir: []const u8,
    dest: []const u8,
) types.ContextError!void {
    path_policy.validateContextSourcePath(alloc, context_dir, src) catch |err| {
        return switch (err) {
            error.NotFound => types.ContextError.NotFound,
            error.PathTraversal => {
                log.err("build: path traversal attempt in copyFiles source: {s}", .{src});
                return types.ContextError.PathTraversal;
            },
            else => return types.ContextError.CopyFailed,
        };
    };

    var ctx_dir = std.Io.Dir.cwd().openDir(std.Options.debug_io, context_dir, .{}) catch
        return types.ContextError.NotFound;
    defer ctx_dir.close(std.Options.debug_io);

    var dst_dir = std.Io.Dir.cwd().openDir(std.Options.debug_io, layer_dir, .{}) catch
        return types.ContextError.CopyFailed;
    defer dst_dir.close(std.Options.debug_io);

    const dest_clean = normalizeDestination(dest) catch return types.ContextError.PathTraversal;

    const stat = ctx_dir.statFile(std.Options.debug_io, src, .{}) catch {
        return copyDirectory(ctx_dir, src, dst_dir, dest_clean);
    };

    if (stat.kind == .directory) {
        return copyDirectory(ctx_dir, src, dst_dir, dest_clean);
    }

    if (std.fs.path.dirname(dest_clean)) |parent| {
        dst_dir.createDirPath(std.Options.debug_io, parent) catch return types.ContextError.CopyFailed;
    }

    const target_path = if (dest.len > 0 and dest[dest.len - 1] == '/') blk: {
        const basename = std.fs.path.basename(src);
        var buf: [1024]u8 = undefined;
        const combined = std.fmt.bufPrint(&buf, "{s}{s}", .{ dest_clean, basename }) catch
            return types.ContextError.CopyFailed;
        break :blk combined;
    } else dest_clean;

    ctx_dir.copyFile(src, dst_dir, target_path, std.Options.debug_io, .{}) catch return types.ContextError.CopyFailed;
}

fn copyDirectory(
    src_dir: std.Io.Dir,
    src_sub: []const u8,
    dst_dir: std.Io.Dir,
    dst_sub: []const u8,
) types.ContextError!void {
    var source = src_dir.openDir(std.Options.debug_io, src_sub, .{ .iterate = true }) catch
        return types.ContextError.NotFound;
    defer source.close(std.Options.debug_io);

    if (dst_sub.len > 0) {
        dst_dir.createDirPath(std.Options.debug_io, dst_sub) catch return types.ContextError.CopyFailed;
    }

    var target = if (dst_sub.len > 0)
        dst_dir.openDir(std.Options.debug_io, dst_sub, .{}) catch return types.ContextError.CopyFailed
    else
        dst_dir.openDir(std.Options.debug_io, ".", .{}) catch return types.ContextError.CopyFailed;
    defer target.close(std.Options.debug_io);

    var walker = source.walk(std.heap.page_allocator) catch return types.ContextError.CopyFailed;
    defer walker.deinit();

    while (walker.next(std.Options.debug_io) catch return types.ContextError.CopyFailed) |entry| {
        switch (entry.kind) {
            .directory => {
                target.createDirPath(std.Options.debug_io, entry.path) catch return types.ContextError.CopyFailed;
            },
            .file => {
                if (std.fs.path.dirname(entry.path)) |parent| {
                    target.createDirPath(std.Options.debug_io, parent) catch return types.ContextError.CopyFailed;
                }
                source.copyFile(entry.path, target, entry.path, std.Options.debug_io, .{}) catch
                    return types.ContextError.CopyFailed;
            },
            else => continue,
        }
    }
}

fn normalizeDestination(dest: []const u8) error{PathTraversal}![]const u8 {
    const dest_clean = if (dest.len > 0 and dest[0] == '/') dest[1..] else dest;
    if (path_policy.containsPathTraversal(dest_clean)) return error.PathTraversal;
    return dest_clean;
}
