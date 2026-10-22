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

/// Turn a COPY or ADD source into a path relative to the build root.
///
/// sources are opened on the root's directory handle, and the kernel ignores
/// that handle for absolute paths. `COPY --from=stage /etc/shadow` must read
/// the stage's /etc/shadow, not the host's, so a leading slash means the
/// root here. "/" and "" both mean the root itself.
pub fn rootRelative(src: []const u8) SourcePathError![]const u8 {
    if (std.mem.indexOfScalar(u8, src, 0) != null) return error.PathTraversal;
    if (containsPathTraversal(src)) return error.PathTraversal;
    const relative = std.mem.trimStart(u8, src, "/");
    return if (relative.len == 0) "." else relative;
}

pub fn validateContextSourcePath(
    alloc: std.mem.Allocator,
    context_dir: []const u8,
    src_path: []const u8,
) SourcePathError!void {
    if (containsPathTraversal(src_path)) return error.PathTraversal;

    const root_real = std.Io.Dir.cwd().realPathFileAlloc(std.Options.debug_io, context_dir, alloc) catch return error.NotFound;
    defer alloc.free(root_real);

    const joined = std.fs.path.join(alloc, &.{ context_dir, src_path }) catch
        return error.ValidationFailed;
    defer alloc.free(joined);

    const source_real = std.Io.Dir.cwd().realPathFileAlloc(std.Options.debug_io, joined, alloc) catch |err| {
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
