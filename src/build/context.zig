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

    try @import("compat").Dir.from(tmp.dir).writeFile(.{ .sub_path = "test.txt", .data = "hello world\n" });

    var path_buf: [4096]u8 = undefined;
    const dir_path = try @import("compat").Dir.from(tmp.dir).realpath(".", &path_buf);

    const digest = try hashFiles(alloc, dir_path, "test.txt");

    // should produce a valid non-zero digest
    try std.testing.expect(!std.mem.eql(u8, &digest.hash, &([_]u8{0} ** 32)));
}

test "hash determinism" {
    const alloc = std.testing.allocator;

    // create two directories with identical content
    var tmp1 = std.testing.tmpDir(.{});
    defer tmp1.cleanup();
    try @import("compat").Dir.from(tmp1.dir).writeFile(.{ .sub_path = "a.txt", .data = "content a" });

    var tmp2 = std.testing.tmpDir(.{});
    defer tmp2.cleanup();
    try @import("compat").Dir.from(tmp2.dir).writeFile(.{ .sub_path = "a.txt", .data = "content a" });

    var buf1: [4096]u8 = undefined;
    var buf2: [4096]u8 = undefined;
    const path1 = try @import("compat").Dir.from(tmp1.dir).realpath(".", &buf1);
    const path2 = try @import("compat").Dir.from(tmp2.dir).realpath(".", &buf2);

    const d1 = try hashFiles(alloc, path1, "a.txt");
    const d2 = try hashFiles(alloc, path2, "a.txt");

    try std.testing.expect(d1.eql(d2));
}

test "hash changes on content change" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try @import("compat").Dir.from(tmp.dir).writeFile(.{ .sub_path = "file.txt", .data = "version 1" });

    var path_buf: [4096]u8 = undefined;
    const dir_path = try @import("compat").Dir.from(tmp.dir).realpath(".", &path_buf);

    const d1 = try hashFiles(alloc, dir_path, "file.txt");

    // change the content
    try @import("compat").Dir.from(tmp.dir).writeFile(.{ .sub_path = "file.txt", .data = "version 2" });

    const d2 = try hashFiles(alloc, dir_path, "file.txt");

    try std.testing.expect(!d1.eql(d2));
}

test "hash directory" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try @import("compat").Dir.from(tmp.dir).makeDir("mydir");
    try @import("compat").Dir.from(tmp.dir).writeFile(.{ .sub_path = "mydir/a.txt", .data = "aaa" });
    try @import("compat").Dir.from(tmp.dir).writeFile(.{ .sub_path = "mydir/b.txt", .data = "bbb" });

    var path_buf: [4096]u8 = undefined;
    const dir_path = try @import("compat").Dir.from(tmp.dir).realpath(".", &path_buf);

    const digest = try hashFiles(alloc, dir_path, "mydir");

    try std.testing.expect(!std.mem.eql(u8, &digest.hash, &([_]u8{0} ** 32)));
}

test "copy single file" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try @import("compat").Dir.from(src.dir).writeFile(.{ .sub_path = "hello.txt", .data = "hello" });

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try @import("compat").Dir.from(src.dir).realpath(".", &src_buf);
    const dst_path = try @import("compat").Dir.from(dst.dir).realpath(".", &dst_buf);

    try copyFiles(std.testing.allocator, src_path, "hello.txt", dst_path, "hello.txt");

    // verify the file was copied
    const content = try @import("compat").Dir.from(dst.dir).readFileAlloc(std.testing.allocator, "hello.txt", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("hello", content);
}

test "copy directory" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try @import("compat").Dir.from(src.dir).makeDir("subdir");
    try @import("compat").Dir.from(src.dir).writeFile(.{ .sub_path = "subdir/nested.txt", .data = "nested" });

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try @import("compat").Dir.from(src.dir).realpath(".", &src_buf);
    const dst_path = try @import("compat").Dir.from(dst.dir).realpath(".", &dst_buf);

    try copyFiles(std.testing.allocator, src_path, "subdir", dst_path, "target");

    // verify nested file was copied
    const content = try @import("compat").Dir.from(dst.dir).readFileAlloc(std.testing.allocator, "target/nested.txt", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("nested", content);
}

test "hash missing file returns error" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var path_buf: [4096]u8 = undefined;
    const dir_path = try @import("compat").Dir.from(tmp.dir).realpath(".", &path_buf);

    const result = hashFiles(alloc, dir_path, "nonexistent.txt");
    try std.testing.expectError(ContextError.NotFound, result);
}

test "hash includes filename in digest" {
    const alloc = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // two files with identical content but different names
    try @import("compat").Dir.from(tmp.dir).writeFile(.{ .sub_path = "a.txt", .data = "same content" });
    try @import("compat").Dir.from(tmp.dir).writeFile(.{ .sub_path = "b.txt", .data = "same content" });

    var path_buf: [4096]u8 = undefined;
    const dir_path = try @import("compat").Dir.from(tmp.dir).realpath(".", &path_buf);

    const d1 = try hashFiles(alloc, dir_path, "a.txt");
    const d2 = try hashFiles(alloc, dir_path, "b.txt");

    // digests should differ because the filename is part of the hash
    try std.testing.expect(!d1.eql(d2));
}

test "copy file to directory destination" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try @import("compat").Dir.from(src.dir).writeFile(.{ .sub_path = "app.js", .data = "console.log('hi');" });

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();
    try @import("compat").Dir.from(dst.dir).makeDir("app");

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try @import("compat").Dir.from(src.dir).realpath(".", &src_buf);
    const dst_path = try @import("compat").Dir.from(dst.dir).realpath(".", &dst_buf);

    // trailing slash means "copy into this directory"
    try copyFiles(std.testing.allocator, src_path, "app.js", dst_path, "/app/");

    // file should end up as app/app.js (basename preserved)
    const content = try @import("compat").Dir.from(dst.dir).readFileAlloc(std.testing.allocator, "app/app.js", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("console.log('hi');", content);
}

test "copy to nested destination creates parents" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try @import("compat").Dir.from(src.dir).writeFile(.{ .sub_path = "config.toml", .data = "[server]\nport = 8080" });

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try @import("compat").Dir.from(src.dir).realpath(".", &src_buf);
    const dst_path = try @import("compat").Dir.from(dst.dir).realpath(".", &dst_buf);

    // deep nested path — parent dirs must be created
    try copyFiles(std.testing.allocator, src_path, "config.toml", dst_path, "/deep/nested/config.toml");

    const content = try @import("compat").Dir.from(dst.dir).readFileAlloc(std.testing.allocator, "deep/nested/config.toml", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("[server]\nport = 8080", content);
}

test "copy directory skips symlinks" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try @import("compat").Dir.from(src.dir).writeFile(.{ .sub_path = "real.txt", .data = "real content" });
    // create a symlink — should be skipped during copy
    @import("compat").Dir.from(src.dir).symLink("real.txt", "link.txt", .{}) catch {
        // symlink creation may fail in some test environments
        return;
    };

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try @import("compat").Dir.from(src.dir).realpath(".", &src_buf);
    const dst_path = try @import("compat").Dir.from(dst.dir).realpath(".", &dst_buf);

    try copyFiles(std.testing.allocator, src_path, ".", dst_path, "out");

    // real file should be copied
    const content = try @import("compat").Dir.from(dst.dir).readFileAlloc(std.testing.allocator, "out/real.txt", 1024);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings("real content", content);

    // symlink should NOT be copied (walker skips non-file, non-directory entries)
    const link_result = @import("compat").Dir.from(dst.dir).access("out/link.txt", .{});
    if (link_result) |_| {
        // symlink was copied — this should not happen
        try std.testing.expect(false);
    } else |_| {
        // expected — symlink was skipped
    }
}

test "hash rejects symlink escape from context" {
    const alloc = std.testing.allocator;

    var outside = std.testing.tmpDir(.{});
    defer outside.cleanup();
    try @import("compat").Dir.from(outside.dir).writeFile(.{ .sub_path = "secret.txt", .data = "secret" });
    var outside_buf: [4096]u8 = undefined;
    const outside_target = try @import("compat").Dir.from(outside.dir).realpath("secret.txt", &outside_buf);

    var ctx = std.testing.tmpDir(.{});
    defer ctx.cleanup();
    @import("compat").Dir.from(ctx.dir).symLink(outside_target, "escape.txt", .{}) catch {
        return;
    };

    var ctx_buf: [4096]u8 = undefined;
    const ctx_path = try @import("compat").Dir.from(ctx.dir).realpath(".", &ctx_buf);

    const result = hashFiles(alloc, ctx_path, "escape.txt");
    try std.testing.expectError(ContextError.PathTraversal, result);
}

test "copy rejects symlink escape from context" {
    var outside = std.testing.tmpDir(.{});
    defer outside.cleanup();
    try @import("compat").Dir.from(outside.dir).writeFile(.{ .sub_path = "secret.txt", .data = "secret" });
    var outside_buf: [4096]u8 = undefined;
    const outside_target = try @import("compat").Dir.from(outside.dir).realpath("secret.txt", &outside_buf);

    var ctx = std.testing.tmpDir(.{});
    defer ctx.cleanup();
    @import("compat").Dir.from(ctx.dir).symLink(outside_target, "escape.txt", .{}) catch {
        return;
    };

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var ctx_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const ctx_path = try @import("compat").Dir.from(ctx.dir).realpath(".", &ctx_buf);
    const dst_path = try @import("compat").Dir.from(dst.dir).realpath(".", &dst_buf);

    const result = copyFiles(std.testing.allocator, ctx_path, "escape.txt", dst_path, "secret.txt");
    try std.testing.expectError(ContextError.PathTraversal, result);
}

test "copy rejects destination traversal" {
    var src = std.testing.tmpDir(.{});
    defer src.cleanup();
    try @import("compat").Dir.from(src.dir).writeFile(.{ .sub_path = "hello.txt", .data = "hello" });

    var dst = std.testing.tmpDir(.{});
    defer dst.cleanup();

    var src_buf: [4096]u8 = undefined;
    var dst_buf: [4096]u8 = undefined;
    const src_path = try @import("compat").Dir.from(src.dir).realpath(".", &src_buf);
    const dst_path = try @import("compat").Dir.from(dst.dir).realpath(".", &dst_buf);

    const result = copyFiles(std.testing.allocator, src_path, "hello.txt", dst_path, "../escape.txt");
    try std.testing.expectError(ContextError.PathTraversal, result);
}
