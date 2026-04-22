const std = @import("std");

pub const SourcePathError = error{
    NotFound,
    PathTraversal,
    ValidationFailed,
};

pub fn containsPathTraversal(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return true;
    }
    return false;
}

pub fn validateContextSourcePath(
    alloc: std.mem.Allocator,
    context_dir: []const u8,
    src_path: []const u8,
) SourcePathError!void {
    if (containsPathTraversal(src_path)) return error.PathTraversal;

    const root_real = @import("compat").cwd().realpathAlloc(alloc, context_dir) catch return error.NotFound;
    defer alloc.free(root_real);

    const joined = std.fs.path.join(alloc, &.{ context_dir, src_path }) catch
        return error.ValidationFailed;
    defer alloc.free(joined);

    const source_real = @import("compat").cwd().realpathAlloc(alloc, joined) catch |err| {
        return switch (err) {
            error.FileNotFound => error.NotFound,
            else => error.ValidationFailed,
        };
    };
    defer alloc.free(source_real);

    if (!isWithinRoot(root_real, source_real)) return error.PathTraversal;
}

fn isWithinRoot(root: []const u8, target: []const u8) bool {
    if (std.mem.eql(u8, root, target)) return true;
    if (!std.mem.startsWith(u8, target, root)) return false;
    if (root.len == 0) return false;
    if (root[root.len - 1] == '/') return true;
    return target.len > root.len and target[root.len] == '/';
}
