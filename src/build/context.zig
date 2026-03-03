// context — build context file operations
//
// handles hashing and copying source files for COPY instructions
// during image builds. the content hash of source files is used
// as part of the build cache key, so identical files always produce
// the same cache entry.
//
// no glob patterns in v1 — just file or directory paths.

const std = @import("std");
const blob_store = @import("../image/store.zig");

pub const ContextError = error{
    HashFailed,
    CopyFailed,
    NotFound,
    PathTraversal,
};

/// compute a content hash of files at src_path (relative to context_dir).
/// for a file: hash its content. for a directory: recursively hash all
/// files (sorted by path for determinism).
pub fn hashFiles(alloc: std.mem.Allocator, context_dir: []const u8, src_path: []const u8) ContextError!blob_store.Digest {
    var dir = std.fs.cwd().openDir(context_dir, .{}) catch return ContextError.NotFound;
    defer dir.close();

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});

    // check if src_path is a file or directory
    const stat = dir.statFile(src_path) catch {
        // try as directory
        return hashDirectory(alloc, dir, src_path, &hasher);
    };

    if (stat.kind == .directory) {
        return hashDirectory(alloc, dir, src_path, &hasher);
    }

    // it's a file — hash its path and content
    hasher.update(src_path);
    hasher.update("\x00");

    const content = dir.readFileAlloc(alloc, src_path, 256 * 1024 * 1024) catch
        return ContextError.HashFailed;
    defer alloc.free(content);
    hasher.update(content);

    return blob_store.Digest{ .hash = hasher.finalResult() };
}

/// hash all files in a directory recursively.
/// feeds relative paths + file contents into the hasher, sorted by path.
fn hashDirectory(
    alloc: std.mem.Allocator,
    base_dir: std.fs.Dir,
    sub_path: []const u8,
    hasher: *std.crypto.hash.sha2.Sha256,
) ContextError!blob_store.Digest {
    var sub_dir = base_dir.openDir(sub_path, .{ .iterate = true }) catch
        return ContextError.NotFound;
    defer sub_dir.close();

    // collect all file paths for sorted hashing
    var paths: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (paths.items) |p| alloc.free(p);
        paths.deinit(alloc);
    }

    var walker = sub_dir.walk(alloc) catch return ContextError.HashFailed;
    defer walker.deinit();

    while (walker.next() catch return ContextError.HashFailed) |entry| {
        if (entry.kind == .file) {
            const path = alloc.dupe(u8, entry.path) catch return ContextError.HashFailed;
            paths.append(alloc, path) catch {
                alloc.free(path);
                return ContextError.HashFailed;
            };
        }
    }

    // sort paths for deterministic hashing
    std.mem.sort([]const u8, paths.items, {}, struct {
        pub fn lessThan(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    // hash each file: path + null separator + content
    for (paths.items) |path| {
        hasher.update(path);
        hasher.update("\x00");

        const content = sub_dir.readFileAlloc(alloc, path, 256 * 1024 * 1024) catch
            return ContextError.HashFailed;
        defer alloc.free(content);
        hasher.update(content);
    }

    return blob_store.Digest{ .hash = hasher.finalResult() };
}

/// copy files from the build context into a layer directory.
/// src is relative to context_dir, dest is the target path within layer_dir.
pub fn copyFiles(
    context_dir: []const u8,
    src: []const u8,
    layer_dir: []const u8,
    dest: []const u8,
) ContextError!void {
    var ctx_dir = std.fs.cwd().openDir(context_dir, .{}) catch
        return ContextError.NotFound;
    defer ctx_dir.close();

    var dst_dir = std.fs.cwd().openDir(layer_dir, .{}) catch
        return ContextError.CopyFailed;
    defer dst_dir.close();

    // determine the destination path (strip leading /)
    const dest_clean = if (dest.len > 0 and dest[0] == '/') dest[1..] else dest;

    // reject paths that could escape the layer directory
    if (containsPathTraversal(dest_clean)) return ContextError.PathTraversal;

    // check if source is a file or directory
    const stat = ctx_dir.statFile(src) catch {
        // try as directory
        return copyDirectory(ctx_dir, src, dst_dir, dest_clean);
    };

    if (stat.kind == .directory) {
        return copyDirectory(ctx_dir, src, dst_dir, dest_clean);
    }

    // single file copy
    // ensure parent directory exists
    if (std.fs.path.dirname(dest_clean)) |parent| {
        dst_dir.makePath(parent) catch return ContextError.CopyFailed;
    }

    // determine target filename: if dest ends with '/', use source filename
    const target_path = if (dest.len > 0 and dest[dest.len - 1] == '/') blk: {
        const basename = std.fs.path.basename(src);
        // combine dest_clean + basename
        var buf: [1024]u8 = undefined;
        const combined = std.fmt.bufPrint(&buf, "{s}{s}", .{ dest_clean, basename }) catch
            return ContextError.CopyFailed;
        break :blk combined;
    } else dest_clean;

    ctx_dir.copyFile(src, dst_dir, target_path) catch return ContextError.CopyFailed;
}

/// recursively copy a directory
fn copyDirectory(
    src_dir: std.fs.Dir,
    src_sub: []const u8,
    dst_dir: std.fs.Dir,
    dst_sub: []const u8,
) ContextError!void {
    var source = src_dir.openDir(src_sub, .{ .iterate = true }) catch
        return ContextError.NotFound;
    defer source.close();

    // ensure dest directory exists
    if (dst_sub.len > 0) {
        dst_dir.makePath(dst_sub) catch return ContextError.CopyFailed;
    }

    var target = if (dst_sub.len > 0)
        dst_dir.openDir(dst_sub, .{}) catch return ContextError.CopyFailed
    else
        dst_dir.openDir(".", .{}) catch return ContextError.CopyFailed;
    defer target.close();

    // use a page allocator for the walker since this runs during builds
    var walker = source.walk(std.heap.page_allocator) catch return ContextError.CopyFailed;
    defer walker.deinit();

    while (walker.next() catch return ContextError.CopyFailed) |entry| {
        switch (entry.kind) {
            .directory => {
                target.makePath(entry.path) catch return ContextError.CopyFailed;
            },
            .file => {
                // ensure parent exists
                if (std.fs.path.dirname(entry.path)) |parent| {
                    target.makePath(parent) catch return ContextError.CopyFailed;
                }
                source.copyFile(entry.path, target, entry.path) catch
                    return ContextError.CopyFailed;
            },
            else => continue,
        }
    }
}

/// check if a path contains ".." components that could escape a directory.
/// only matches exact ".." path segments, not filenames containing ".."
/// (e.g. "some..file" is fine, "../escape" is not).
fn containsPathTraversal(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return true;
    }
    return false;
}

// -- tests --

test "path traversal detection" {
    try std.testing.expect(containsPathTraversal("../etc/passwd"));
    try std.testing.expect(containsPathTraversal("foo/../../etc"));
    try std.testing.expect(containsPathTraversal(".."));
    try std.testing.expect(!containsPathTraversal("some..file"));
    try std.testing.expect(!containsPathTraversal("normal/path/here"));
    try std.testing.expect(!containsPathTraversal(""));
}

test "hash single file" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "test.txt", .data = "hello world\n" });

    var path_buf: [4096]u8 = undefined;
    const dir_path = try tmp.dir.realpath(".", &path_buf);

    const digest = try hashFiles(alloc, dir_path, "test.txt");

    // should produce a valid non-zero digest
    try std.testing.expect(!std.mem.eql(u8, &digest.hash, &([_]u8{0} ** 32)));
}

test "hash determinism" {
    const alloc = std.testing.allocator;

    // create two directories with identical content
    var tmp1 = std.testing.tmpDir(.{});
    defer tmp1.cleanup();
    try tmp1.dir.writeFile(.{ .sub_path = "a.txt", .data = "content a" });

    var tmp2 = std.testing.tmpDir(.{});
    defer tmp2.cleanup();
    try tmp2.dir.writeFile(.{ .sub_path = "a.txt", .data = "content a" });

    var buf1: [4096]u8 = undefined;
    var buf2: [4096]u8 = undefined;
    const path1 = try tmp1.dir.realpath(".", &buf1);
    const path2 = try tmp2.dir.realpath(".", &buf2);

    const d1 = try hashFiles(alloc, path1, "a.txt");
    const d2 = try hashFiles(alloc, path2, "a.txt");

    try std.testing.expect(d1.eql(d2));
}

test "hash changes on content change" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(.{ .sub_path = "file.txt", .data = "version 1" });

    var path_buf: [4096]u8 = undefined;
    const dir_path = try tmp.dir.realpath(".", &path_buf);

    const d1 = try hashFiles(alloc, dir_path, "file.txt");

    // change the content
    try tmp.dir.writeFile(.{ .sub_path = "file.txt", .data = "version 2" });

    const d2 = try hashFiles(alloc, dir_path, "file.txt");

    try std.testing.expect(!d1.eql(d2));
}

test "hash directory" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.makeDir("mydir");
    try tmp.dir.writeFile(.{ .sub_path = "mydir/a.txt", .data = "aaa" });
    try tmp.dir.writeFile(.{ .sub_path = "mydir/b.txt", .data = "bbb" });

    var path_buf: [4096]u8 = undefined;
    const dir_path = try tmp.dir.realpath(".", &path_buf);

    const digest = try hashFiles(alloc, dir_path, "mydir");

    try std.testing.expect(!std.mem.eql(u8, &digest.hash, &([_]u8{0} ** 32)));
}

test "copy single file" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try src.dir.writeFile(.{ .sub_path = "hello.txt", .data = "hello" });

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try src.dir.realpath(".", &src_buf);
    const dst_path = try dst.dir.realpath(".", &dst_buf);

    try copyFiles(src_path, "hello.txt", dst_path, "hello.txt");

    // verify the file was copied
    const content = try dst.dir.readFileAlloc(std.testing.allocator, "hello.txt", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("hello", content);
}

test "copy directory" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try src.dir.makeDir("subdir");
    try src.dir.writeFile(.{ .sub_path = "subdir/nested.txt", .data = "nested" });

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try src.dir.realpath(".", &src_buf);
    const dst_path = try dst.dir.realpath(".", &dst_buf);

    try copyFiles(src_path, "subdir", dst_path, "target");

    // verify nested file was copied
    const content = try dst.dir.readFileAlloc(std.testing.allocator, "target/nested.txt", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("nested", content);
}

test "hash missing file returns error" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [4096]u8 = undefined;
    const dir_path = try tmp.dir.realpath(".", &path_buf);

    const result = hashFiles(alloc, dir_path, "nonexistent.txt");
    try std.testing.expectError(ContextError.NotFound, result);
}

test "hash includes filename in digest" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // two files with identical content but different names
    try tmp.dir.writeFile(.{ .sub_path = "a.txt", .data = "same content" });
    try tmp.dir.writeFile(.{ .sub_path = "b.txt", .data = "same content" });

    var path_buf: [4096]u8 = undefined;
    const dir_path = try tmp.dir.realpath(".", &path_buf);

    const d1 = try hashFiles(alloc, dir_path, "a.txt");
    const d2 = try hashFiles(alloc, dir_path, "b.txt");

    // digests should differ because the filename is part of the hash
    try std.testing.expect(!d1.eql(d2));
}

test "copy file to directory destination" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try src.dir.writeFile(.{ .sub_path = "app.js", .data = "console.log('hi');" });

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();
    try dst.dir.makeDir("app");

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try src.dir.realpath(".", &src_buf);
    const dst_path = try dst.dir.realpath(".", &dst_buf);

    // trailing slash means "copy into this directory"
    try copyFiles(src_path, "app.js", dst_path, "/app/");

    // file should end up as app/app.js (basename preserved)
    const content = try dst.dir.readFileAlloc(std.testing.allocator, "app/app.js", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("console.log('hi');", content);
}

test "copy to nested destination creates parents" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try src.dir.writeFile(.{ .sub_path = "config.toml", .data = "[server]\nport = 8080" });

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try src.dir.realpath(".", &src_buf);
    const dst_path = try dst.dir.realpath(".", &dst_buf);

    // deep nested path — parent dirs must be created
    try copyFiles(src_path, "config.toml", dst_path, "/deep/nested/config.toml");

    const content = try dst.dir.readFileAlloc(std.testing.allocator, "deep/nested/config.toml", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("[server]\nport = 8080", content);
}
