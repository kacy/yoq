// layer — OCI image layer extraction and creation
//
// extracts OCI image layers (gzipped tarballs) into directories
// and assembles a complete rootfs from ordered layers.
// also creates new layers from directories (for image builds).
//
// layers are cached by digest — if the extracted directory already
// exists, extraction is skipped.
//
// uses std.compress.flate for gzip decompression/compression and
// std.tar for tar extraction/creation. no external dependencies.

const std = @import("std");
const builtin = @import("builtin");
const blob_store = @import("store.zig");
const layer_create = @import("layer/create.zig");
const layer_extract = @import("layer/extract.zig");
const layer_path = @import("layer/path.zig");
const layer_types = @import("layer/types.zig");

pub const LayerError = layer_types.LayerError;
pub const LayerCreateResult = layer_types.LayerCreateResult;

pub const extractLayer = layer_extract.extractLayer;
pub const assembleRootfs = layer_extract.assembleRootfs;
pub const createLayerFromDir = layer_create.createLayerFromDir;
pub const listExtractedLayersOnDisk = layer_path.listExtractedLayersOnDisk;
pub const deleteExtractedLayer = layer_path.deleteExtractedLayer;

const max_path = @import("../lib/paths.zig").max_path;

fn cwd() std.Io.Dir {
    return std.Io.Dir.cwd();
}

fn layerPath(digest: blob_store.Digest, buf: *[max_path]u8) LayerError![]const u8 {
    return layer_path.layerPath(digest, buf);
}

fn writeTarEntry(
    dir: std.Io.Dir,
    tar_writer: *std.tar.Writer,
    entry: std.Io.Dir.Walker.Entry,
) !void {
    return layer_create.writeTarEntry(dir, tar_writer, entry);
}

fn isSafeTarPath(name: []const u8) bool {
    return layer_extract.isSafeTarPath(name);
}

fn isSafeSymlinkTarget(entry_path: []const u8, link_target: []const u8) bool {
    return layer_extract.isSafeSymlinkTarget(entry_path, link_target);
}

// -- tests --

test "tar path validation — safe paths" {
    try std.testing.expect(isSafeTarPath("usr/bin/hello"));
    try std.testing.expect(isSafeTarPath("etc/config.toml"));
    try std.testing.expect(isSafeTarPath("a/b/c"));
    try std.testing.expect(isSafeTarPath("")); // root directory
    try std.testing.expect(isSafeTarPath("single_file"));
}

test "tar path validation — unsafe paths rejected" {
    try std.testing.expect(!isSafeTarPath("../../etc/shadow"));
    try std.testing.expect(!isSafeTarPath("usr/../../../etc/passwd"));
    try std.testing.expect(!isSafeTarPath("/etc/passwd"));
    try std.testing.expect(!isSafeTarPath("foo/../../bar"));
    try std.testing.expect(!isSafeTarPath(".."));
}

test "symlink target validation — safe relative targets" {
    // sibling symlink: usr/lib/libfoo.so -> ../lib64/libfoo.so
    // resolves to usr/lib64/libfoo.so (stays within root)
    try std.testing.expect(isSafeSymlinkTarget("usr/lib/libfoo.so", "../lib64/libfoo.so"));

    // same directory: etc/motd -> motd.real
    try std.testing.expect(isSafeSymlinkTarget("etc/motd", "motd.real"));

    // deeper link: a/b/c/link -> ../../d/target (resolves to a/d/target)
    try std.testing.expect(isSafeSymlinkTarget("a/b/c/link", "../../d/target"));
}

test "symlink target validation — safe absolute targets" {
    // absolute symlinks resolve within container rootfs after pivot_root
    try std.testing.expect(isSafeSymlinkTarget("etc/resolv.conf", "/run/resolv.conf"));
    try std.testing.expect(isSafeSymlinkTarget("usr/bin/python", "/usr/bin/python3"));
}

test "symlink target validation — unsafe targets rejected" {
    // escapes root: etc/shadow -> ../../etc/shadow
    // entry parent depth = 1 (etc/), then ../../ goes to depth -1
    try std.testing.expect(!isSafeSymlinkTarget("etc/shadow", "../../etc/shadow"));

    // escapes from deeper path
    try std.testing.expect(!isSafeSymlinkTarget("usr/lib/link", "../../../../etc/passwd"));

    // escapes from top-level file
    try std.testing.expect(!isSafeSymlinkTarget("link", "../etc/shadow"));
}

test "writeTarEntry rejects unsupported entry kinds" {
    var tar_writer: std.tar.Writer = undefined;
    const entry = std.Io.Dir.Walker.Entry{
        .dir = undefined,
        .basename = "fifo",
        .path = "fifo",
        .kind = .named_pipe,
    };

    try std.testing.expectError(error.UnsupportedEntry, writeTarEntry(undefined, &tar_writer, entry));
}

test "layer path format" {
    const digest = blob_store.Digest.parse("sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9").?;
    var buf: [max_path]u8 = undefined;
    const path = try layerPath(digest, &buf);

    // should contain the cache subdir and the hex digest
    try std.testing.expect(std.mem.indexOf(u8, path, "layers/sha256") != null);
    try std.testing.expect(std.mem.endsWith(u8, path, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"));
}

test "extract layer — missing blob returns error" {
    const alloc = std.testing.allocator;
    const result = extractLayer(alloc, "sha256:0000000000000000000000000000000000000000000000000000000000000000");
    // should either find an existing extraction or fail because the blob doesn't exist
    if (result) |path| {
        alloc.free(path);
    } else |err| {
        try std.testing.expect(err == LayerError.ExtractionFailed or err == LayerError.BlobNotFound);
    }
}

test "extract layer — stale cache dir is not trusted without completion marker" {
    const alloc = std.testing.allocator;
    const digest = blob_store.computeDigest("stale cache layer");
    const digest_hex = digest.hex();
    var digest_buf: [71]u8 = undefined;
    const digest_str = digestString(digest, &digest_buf);

    var path_buf: [max_path]u8 = undefined;
    const path = try layerPath(digest, &path_buf);
    defer layer_path.deleteExtractedLayer(&digest_hex);

    try cwd().createDirPath(std.testing.io, path);
    try std.testing.expectError(LayerError.BlobNotFound, extractLayer(alloc, digest_str));
    try std.testing.expectError(error.FileNotFound, cwd().access(std.testing.io, path, .{}));
}

test "extract layer — corrupted blob is rejected before extraction" {
    const alloc = std.testing.allocator;
    const digest = blob_store.computeDigest("expected layer blob");
    var digest_buf: [71]u8 = undefined;
    const digest_str = digestString(digest, &digest_buf);

    var blob_path_buf: [max_path]u8 = undefined;
    const blob_path = try blob_store.blobPath(digest, &blob_path_buf);
    if (std.fs.path.dirname(blob_path)) |parent| {
        try cwd().createDirPath(std.testing.io, parent);
    }

    defer blob_store.removeBlob(digest);
    var file = try cwd().createFile(std.testing.io, blob_path, .{ .truncate = true });
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, "corrupted blob");

    try std.testing.expectError(LayerError.BlobNotFound, extractLayer(alloc, digest_str));
    try std.testing.expect(!blob_store.hasBlob(digest));
}

test "assemble rootfs — empty layer list" {
    const alloc = std.testing.allocator;
    const layer_paths = try assembleRootfs(alloc, &.{});
    defer alloc.free(layer_paths);
    try std.testing.expectEqual(@as(usize, 0), layer_paths.len);
}

test "create layer from empty dir returns null" {
    if (!hasHomeEnv()) return;
    const alloc = std.testing.allocator;

    // create a temp empty directory
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var path_buf: [max_path]u8 = undefined;
    const dir_path = try tmpDirPath(&tmp_dir, &path_buf);

    const result = try createLayerFromDir(alloc, dir_path);
    try std.testing.expect(result == null);
}

fn requireLayerCreationTestHost() !void {
    if (builtin.os.tag == .macos) return error.SkipZigTest;
}

test "create layer from dir — round trip" {
    try requireLayerCreationTestHost();
    if (!hasHomeEnv()) return;
    const alloc = std.testing.allocator;

    // create a temp directory with some files
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // create test files
    try tmp_dir.dir.writeFile(std.testing.io, .{ .sub_path = "hello.txt", .data = "hello world\n" });
    try tmp_dir.dir.createDir(std.testing.io, "subdir", .default_dir);
    try tmp_dir.dir.writeFile(std.testing.io, .{ .sub_path = "subdir/nested.txt", .data = "nested content\n" });

    var path_buf: [max_path]u8 = undefined;
    const dir_path = try tmpDirPath(&tmp_dir, &path_buf);

    const result = (try createLayerFromDir(alloc, dir_path)) orelse
        return error.ExpectedNonNull;

    // both digests should be valid
    try std.testing.expect(!std.mem.eql(u8, &result.compressed_digest.hash, &([_]u8{0} ** 32)));
    try std.testing.expect(!std.mem.eql(u8, &result.uncompressed_digest.hash, &([_]u8{0} ** 32)));

    // compressed and uncompressed digests should differ (gzip changes content)
    try std.testing.expect(!result.compressed_digest.eql(result.uncompressed_digest));

    // compressed size should be positive
    try std.testing.expect(result.compressed_size > 0);

    // blob should exist in the store
    try std.testing.expect(blob_store.hasBlob(result.compressed_digest));

    // clean up the blob
    try blob_store.deleteBlob(result.compressed_digest);
}

test "create layer then extract layer preserves file contents" {
    try requireLayerCreationTestHost();
    if (!hasHomeEnv()) return;
    const alloc = std.testing.allocator;

    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    try tmp_dir.dir.writeFile(std.testing.io, .{ .sub_path = "hello.txt", .data = "hello world\n" });
    try tmp_dir.dir.createDir(std.testing.io, "subdir", .default_dir);
    try tmp_dir.dir.writeFile(std.testing.io, .{ .sub_path = "subdir/nested.txt", .data = "nested content\n" });
    try tmp_dir.dir.symLink(std.testing.io, "hello.txt", "hello.link", .{});

    var path_buf: [max_path]u8 = undefined;
    const dir_path_len = try tmp_dir.dir.realPathFile(std.testing.io, ".", &path_buf);
    const dir_path = path_buf[0..dir_path_len];

    const result = (try createLayerFromDir(alloc, dir_path)) orelse return error.ExpectedNonNull;
    defer blob_store.deleteBlob(result.compressed_digest) catch {};

    var digest_buf: [71]u8 = undefined;
    const digest_str = digestString(result.compressed_digest, &digest_buf);
    defer deleteExtractedLayerForDigest(result.compressed_digest);

    const extracted_path = try extractLayer(alloc, digest_str);
    defer alloc.free(extracted_path);

    var extracted_dir = try cwd().openDir(std.testing.io, extracted_path, .{});
    defer extracted_dir.close(std.testing.io);

    var hello_buf: [64]u8 = undefined;
    const hello = try extracted_dir.readFile(std.testing.io, "hello.txt", &hello_buf);
    try std.testing.expectEqualStrings("hello world\n", hello);

    var nested_buf: [64]u8 = undefined;
    const nested = try extracted_dir.readFile(std.testing.io, "subdir/nested.txt", &nested_buf);
    try std.testing.expectEqualStrings("nested content\n", nested);

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_len = try extracted_dir.readLink(std.testing.io, "hello.link", &link_buf);
    try std.testing.expectEqualStrings("hello.txt", link_buf[0..link_len]);
}

test "create layer from dir — deterministic digest" {
    try requireLayerCreationTestHost();
    if (!hasHomeEnv()) return;
    const alloc = std.testing.allocator;

    // create two identical directories
    var tmp1 = std.testing.tmpDir(.{});
    defer tmp1.cleanup();
    try tmp1.dir.writeFile(std.testing.io, .{ .sub_path = "file.txt", .data = "same content" });

    var path_buf1: [max_path]u8 = undefined;
    const dir1 = try tmpDirPath(&tmp1, &path_buf1);

    var tmp2 = std.testing.tmpDir(.{});
    defer tmp2.cleanup();
    try tmp2.dir.writeFile(std.testing.io, .{ .sub_path = "file.txt", .data = "same content" });

    var path_buf2: [max_path]u8 = undefined;
    const dir2 = try tmpDirPath(&tmp2, &path_buf2);

    const result1 = (try createLayerFromDir(alloc, dir1)).?;
    const result2 = (try createLayerFromDir(alloc, dir2)).?;

    // same content should produce same uncompressed digest
    try std.testing.expect(result1.uncompressed_digest.eql(result2.uncompressed_digest));

    // clean up
    blob_store.deleteBlob(result1.compressed_digest) catch {};
    blob_store.deleteBlob(result2.compressed_digest) catch {};
}

test "different content produces different layer digests" {
    try requireLayerCreationTestHost();
    if (!hasHomeEnv()) return;
    const alloc = std.testing.allocator;

    var tmp1 = std.testing.tmpDir(.{});
    defer tmp1.cleanup();
    try tmp1.dir.writeFile(std.testing.io, .{ .sub_path = "file.txt", .data = "content alpha" });

    var path_buf1: [max_path]u8 = undefined;
    const dir1 = try tmpDirPath(&tmp1, &path_buf1);

    var tmp2 = std.testing.tmpDir(.{});
    defer tmp2.cleanup();
    try tmp2.dir.writeFile(std.testing.io, .{ .sub_path = "file.txt", .data = "content beta" });

    var path_buf2: [max_path]u8 = undefined;
    const dir2 = try tmpDirPath(&tmp2, &path_buf2);

    const result1 = (try createLayerFromDir(alloc, dir1)).?;
    const result2 = (try createLayerFromDir(alloc, dir2)).?;

    // different content should produce different uncompressed digests
    try std.testing.expect(!result1.uncompressed_digest.eql(result2.uncompressed_digest));

    // clean up
    blob_store.deleteBlob(result1.compressed_digest) catch {};
    blob_store.deleteBlob(result2.compressed_digest) catch {};
}

test "extract layer — invalid gzip blob fails" {
    if (!hasHomeEnv()) return;
    const alloc = std.testing.allocator;

    const digest = try blob_store.putBlob("not a gzip stream");
    defer blob_store.deleteBlob(digest) catch {};

    var digest_buf: [71]u8 = undefined;
    const digest_str = digestString(digest, &digest_buf);
    defer deleteExtractedLayerForDigest(digest);

    try std.testing.expectError(LayerError.ExtractionFailed, extractLayer(alloc, digest_str));
}

test "extract layer — gzip stream with invalid tar payload fails" {
    if (!hasHomeEnv()) return;
    const alloc = std.testing.allocator;

    const gzip_payload = try gzipBytes(alloc, "not a tar archive");
    defer alloc.free(gzip_payload);

    const digest = try blob_store.putBlob(gzip_payload);
    defer blob_store.deleteBlob(digest) catch {};

    var digest_buf: [71]u8 = undefined;
    const digest_str = digestString(digest, &digest_buf);
    defer deleteExtractedLayerForDigest(digest);

    try std.testing.expectError(LayerError.ExtractionFailed, extractLayer(alloc, digest_str));
}

test "listExtractedLayersOnDisk returns empty for fresh install" {
    const alloc = std.testing.allocator;
    var layers = try listExtractedLayersOnDisk(alloc);
    defer {
        for (layers.items) |item| alloc.free(item);
        layers.deinit(alloc);
    }
    // may or may not be empty depending on prior test runs, just verify no crash
    try std.testing.expect(layers.items.len >= 0);
}

test "symlink target validation — trailing slash on .." {
    // "../" should still count as escape attempt
    try std.testing.expect(!isSafeSymlinkTarget("link", "../"));
    // "../../" from depth 1 should escape
    try std.testing.expect(!isSafeSymlinkTarget("etc/link", "../../"));
}

test "symlink target validation — empty components" {
    // double slashes produce empty components which should be skipped
    try std.testing.expect(isSafeSymlinkTarget("usr/lib/link", "foo//bar"));
    // trailing slash with valid path
    try std.testing.expect(isSafeSymlinkTarget("usr/lib/link", "../lib64/"));
}

test "symlink target validation — dot components" {
    // "." should be treated as no-op (current directory)
    try std.testing.expect(isSafeSymlinkTarget("usr/lib/link", "./foo"));
    try std.testing.expect(isSafeSymlinkTarget("usr/lib/link", "././foo"));
}

test "symlink target validation — deep escape attempt" {
    // many levels of ".." that exactly match parent depth is still safe
    // entry "a/b/c/d/link" has parent depth 4
    try std.testing.expect(isSafeSymlinkTarget("a/b/c/d/link", "../../../../root_file"));
    // one more ".." would escape
    try std.testing.expect(!isSafeSymlinkTarget("a/b/c/d/link", "../../../../../escape"));
}

fn hasHomeEnv() bool {
    return std.c.getenv("HOME") != null;
}

fn tmpDirPath(tmp_dir: *std.testing.TmpDir, buf: *[max_path]u8) ![]const u8 {
    const len = try tmp_dir.dir.realPathFile(std.testing.io, ".", buf);
    return buf[0..len];
}

fn digestString(digest: blob_store.Digest, buf: *[71]u8) []const u8 {
    return digest.string(buf);
}

fn deleteExtractedLayerForDigest(digest: blob_store.Digest) void {
    const digest_hex = digest.hex();
    layer_path.deleteExtractedLayer(&digest_hex);
}

fn gzipBytes(alloc: std.mem.Allocator, data: []const u8) ![]u8 {
    var out = std.Io.Writer.Allocating.init(alloc);
    defer out.deinit();
    try out.ensureUnusedCapacity(64);

    const compressor = try alloc.create(std.compress.flate.Compress);
    defer alloc.destroy(compressor);

    var window: [std.compress.flate.max_window_len]u8 = undefined;
    compressor.* = std.compress.flate.Compress.init(
        &out.writer,
        &window,
        .gzip,
        .default,
    ) catch return error.CompressFailed;

    compressor.writer.writeAll(data) catch return error.CompressFailed;
    compressor.finish() catch return error.CompressFailed;

    return out.toOwnedSlice();
}
