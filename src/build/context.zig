const std = @import("std");
const hash_impl = @import("context/hash.zig");
const copy_impl = @import("context/copy.zig");
const path_policy = @import("context/path_policy.zig");
const types = @import("context/types.zig");

pub const ContextError = types.ContextError;

pub fn hashFiles(
    alloc: std.mem.Allocator,
    context_dir: []const u8,
    src_path: []const u8,
) ContextError!@import("../image/store.zig").Digest {
    return hash_impl.hashFiles(alloc, context_dir, src_path);
}

pub fn copyFiles(
    alloc: std.mem.Allocator,
    context_dir: []const u8,
    src: []const u8,
    layer_dir: []const u8,
    dest: []const u8,
) ContextError!void {
    return copy_impl.copyFiles(alloc, context_dir, src, layer_dir, dest);
}

fn containsPathTraversal(path: []const u8) bool {
    return path_policy.containsPathTraversal(path);
}

// -- tests --

fn tmpRealPath(dir: std.Io.Dir, buf: []u8) ![]const u8 {
    const len = try dir.realPathFile(std.testing.io, ".", buf);
    return buf[0..len];
}

fn tmpWriteFile(dir: std.Io.Dir, path: []const u8, data: []const u8) !void {
    try dir.writeFile(std.testing.io, .{ .sub_path = path, .data = data });
}

fn tmpReadFileAlloc(dir: std.Io.Dir, path: []const u8, limit: usize) ![]u8 {
    return dir.readFileAlloc(std.testing.io, path, std.testing.allocator, .limited(limit));
}

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

    try tmpWriteFile(tmp.dir, "test.txt", "hello world\n");

    var path_buf: [4096]u8 = undefined;
    const dir_path = try tmpRealPath(tmp.dir, &path_buf);

    const digest = try hashFiles(alloc, dir_path, "test.txt");

    try std.testing.expect(!std.mem.eql(u8, &digest.hash, &([_]u8{0} ** 32)));
}

test "hash determinism" {
    const alloc = std.testing.allocator;

    var tmp1 = std.testing.tmpDir(.{});
    defer tmp1.cleanup();
    try tmpWriteFile(tmp1.dir, "a.txt", "content a");

    var tmp2 = std.testing.tmpDir(.{});
    defer tmp2.cleanup();
    try tmpWriteFile(tmp2.dir, "a.txt", "content a");

    var buf1: [4096]u8 = undefined;
    var buf2: [4096]u8 = undefined;
    const path1 = try tmpRealPath(tmp1.dir, &buf1);
    const path2 = try tmpRealPath(tmp2.dir, &buf2);

    const d1 = try hashFiles(alloc, path1, "a.txt");
    const d2 = try hashFiles(alloc, path2, "a.txt");

    try std.testing.expect(d1.eql(d2));
}

test "hash changes on content change" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmpWriteFile(tmp.dir, "file.txt", "version 1");

    var path_buf: [4096]u8 = undefined;
    const dir_path = try tmpRealPath(tmp.dir, &path_buf);

    const d1 = try hashFiles(alloc, dir_path, "file.txt");

    try tmpWriteFile(tmp.dir, "file.txt", "version 2");

    const d2 = try hashFiles(alloc, dir_path, "file.txt");

    try std.testing.expect(!d1.eql(d2));
}

test "hash directory" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDir(std.testing.io, "mydir", .default_dir);
    try tmpWriteFile(tmp.dir, "mydir/a.txt", "aaa");
    try tmpWriteFile(tmp.dir, "mydir/b.txt", "bbb");

    var path_buf: [4096]u8 = undefined;
    const dir_path = try tmpRealPath(tmp.dir, &path_buf);

    const digest = try hashFiles(alloc, dir_path, "mydir");

    try std.testing.expect(!std.mem.eql(u8, &digest.hash, &([_]u8{0} ** 32)));
}

test "copy single file" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try tmpWriteFile(src.dir, "hello.txt", "hello");

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try tmpRealPath(src.dir, &src_buf);
    const dst_path = try tmpRealPath(dst.dir, &dst_buf);

    try copyFiles(std.testing.allocator, src_path, "hello.txt", dst_path, "hello.txt");

    const content = try tmpReadFileAlloc(dst.dir, "hello.txt", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("hello", content);
}

test "copy directory" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try src.dir.createDir(std.testing.io, "subdir", .default_dir);
    try tmpWriteFile(src.dir, "subdir/nested.txt", "nested");

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try tmpRealPath(src.dir, &src_buf);
    const dst_path = try tmpRealPath(dst.dir, &dst_buf);

    try copyFiles(std.testing.allocator, src_path, "subdir", dst_path, "target");

    const content = try tmpReadFileAlloc(dst.dir, "target/nested.txt", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("nested", content);
}

test "hash missing file returns error" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [4096]u8 = undefined;
    const dir_path = try tmpRealPath(tmp.dir, &path_buf);

    const result = hashFiles(alloc, dir_path, "nonexistent.txt");
    try std.testing.expectError(ContextError.NotFound, result);
}

test "hash includes filename in digest" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmpWriteFile(tmp.dir, "a.txt", "same content");
    try tmpWriteFile(tmp.dir, "b.txt", "same content");

    var path_buf: [4096]u8 = undefined;
    const dir_path = try tmpRealPath(tmp.dir, &path_buf);

    const d1 = try hashFiles(alloc, dir_path, "a.txt");
    const d2 = try hashFiles(alloc, dir_path, "b.txt");

    try std.testing.expect(!d1.eql(d2));
}

test "copy file to directory destination" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try tmpWriteFile(src.dir, "app.js", "console.log('hi');");

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();
    try dst.dir.createDir(std.testing.io, "app", .default_dir);

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try tmpRealPath(src.dir, &src_buf);
    const dst_path = try tmpRealPath(dst.dir, &dst_buf);

    try copyFiles(std.testing.allocator, src_path, "app.js", dst_path, "/app/");

    const content = try tmpReadFileAlloc(dst.dir, "app/app.js", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("console.log('hi');", content);
}

test "copy to nested destination creates parents" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try tmpWriteFile(src.dir, "config.toml", "[server]\nport = 8080");

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try tmpRealPath(src.dir, &src_buf);
    const dst_path = try tmpRealPath(dst.dir, &dst_buf);

    try copyFiles(std.testing.allocator, src_path, "config.toml", dst_path, "/deep/nested/config.toml");

    const content = try tmpReadFileAlloc(dst.dir, "deep/nested/config.toml", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("[server]\nport = 8080", content);
}

test "copy directory skips symlinks" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try tmpWriteFile(src.dir, "real.txt", "real content");
    src.dir.symLink(std.testing.io, "real.txt", "link.txt", .{}) catch {
        return;
    };

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try tmpRealPath(src.dir, &src_buf);
    const dst_path = try tmpRealPath(dst.dir, &dst_buf);

    try copyFiles(std.testing.allocator, src_path, ".", dst_path, "out");

    const content = try tmpReadFileAlloc(dst.dir, "out/real.txt", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("real content", content);

    const link_result = dst.dir.access(std.testing.io, "out/link.txt", .{});
    if (link_result) |_| {
        try std.testing.expect(false);
    } else |_| {}
}

test "hash rejects symlink escape from context" {
    const alloc = std.testing.allocator;

    var outside = std.testing.tmpDir(.{});
    defer outside.cleanup();
    try tmpWriteFile(outside.dir, "secret.txt", "secret");
    var outside_buf: [4096]u8 = undefined;
    const outside_len = try outside.dir.realPathFile(std.testing.io, "secret.txt", &outside_buf);
    const outside_target = outside_buf[0..outside_len];

    var ctx = std.testing.tmpDir(.{});
    defer ctx.cleanup();
    ctx.dir.symLink(std.testing.io, outside_target, "escape.txt", .{}) catch {
        return;
    };

    var ctx_buf: [4096]u8 = undefined;
    const ctx_path = try tmpRealPath(ctx.dir, &ctx_buf);

    const result = hashFiles(alloc, ctx_path, "escape.txt");
    try std.testing.expectError(ContextError.PathTraversal, result);
}

test "copy rejects symlink escape from context" {
    var outside = std.testing.tmpDir(.{});
    defer outside.cleanup();
    try tmpWriteFile(outside.dir, "secret.txt", "secret");
    var outside_buf: [4096]u8 = undefined;
    const outside_len = try outside.dir.realPathFile(std.testing.io, "secret.txt", &outside_buf);
    const outside_target = outside_buf[0..outside_len];

    var ctx = std.testing.tmpDir(.{});
    defer ctx.cleanup();
    ctx.dir.symLink(std.testing.io, outside_target, "escape.txt", .{}) catch {
        return;
    };

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var ctx_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const ctx_path = try tmpRealPath(ctx.dir, &ctx_buf);
    const dst_path = try tmpRealPath(dst.dir, &dst_buf);

    const result = copyFiles(std.testing.allocator, ctx_path, "escape.txt", dst_path, "secret.txt");
    try std.testing.expectError(ContextError.PathTraversal, result);
}

test "copy rejects destination traversal" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try tmpWriteFile(src.dir, "hello.txt", "hello");

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try tmpRealPath(src.dir, &src_buf);
    const dst_path = try tmpRealPath(dst.dir, &dst_buf);

    const result = copyFiles(std.testing.allocator, src_path, "hello.txt", dst_path, "../escape.txt");
    try std.testing.expectError(ContextError.PathTraversal, result);
}
