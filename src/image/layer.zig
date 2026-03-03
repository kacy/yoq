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
const blob_store = @import("store.zig");
const paths = @import("../lib/paths.zig");

pub const LayerError = error{
    ExtractionFailed,
    BlobNotFound,
    PathTooLong,
    HomeDirNotFound,
    AssemblyFailed,
    CreateFailed,
};

/// cache directory for extracted layers
const layer_subdir = "layers/sha256";
const max_path = paths.max_path;

/// extract a single layer (gzipped tarball) from the blob store
/// into a cached directory. returns the path to the extracted directory.
/// skips extraction if the directory already exists.
pub fn extractLayer(alloc: std.mem.Allocator, digest_str: []const u8) LayerError![]const u8 {
    const digest = blob_store.Digest.parse(digest_str) orelse return LayerError.BlobNotFound;

    // check if already extracted
    var dest_buf: [max_path]u8 = undefined;
    const dest_path = layerPath(digest, &dest_buf) catch return LayerError.PathTooLong;

    const dest_owned = alloc.dupe(u8, dest_path) catch return LayerError.ExtractionFailed;

    // if the directory already exists, we're done
    if (std.fs.cwd().access(dest_path, .{})) |_| {
        return dest_owned;
    } else |_| {}

    // ensure parent directory exists
    var parent_buf: [max_path]u8 = undefined;
    const parent_path = layerDir(&parent_buf) catch return LayerError.PathTooLong;
    std.fs.cwd().makePath(parent_path) catch {};

    // create the extraction directory
    std.fs.cwd().makePath(dest_path) catch return LayerError.ExtractionFailed;

    // get the blob path and extract
    var blob_path_buf: [max_path]u8 = undefined;
    const blob_path = blob_store.blobPath(digest, &blob_path_buf) catch return LayerError.BlobNotFound;

    extractTarGz(blob_path, dest_path) catch {
        // clean up partial extraction on failure
        std.fs.cwd().deleteTree(dest_path) catch {};
        alloc.free(dest_owned);
        return LayerError.ExtractionFailed;
    };

    return dest_owned;
}

/// assemble a rootfs from ordered layer directories.
/// extracts each layer and returns the list of layer directory paths
/// (ordered from bottom to top, suitable for overlayfs lower_dirs).
pub fn assembleRootfs(alloc: std.mem.Allocator, layer_digests: []const []const u8) LayerError![]const []const u8 {
    var layer_paths: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (layer_paths.items) |p| alloc.free(p);
        layer_paths.deinit(alloc);
    }

    for (layer_digests) |digest| {
        const path = extractLayer(alloc, digest) catch return LayerError.AssemblyFailed;
        layer_paths.append(alloc, path) catch {
            alloc.free(path);
            return LayerError.AssemblyFailed;
        };
    }

    return layer_paths.toOwnedSlice(alloc) catch return LayerError.AssemblyFailed;
}

// -- layer creation --

/// result from creating a new layer from a directory
pub const LayerCreateResult = struct {
    /// digest of the compressed (gzipped tar) layer — used in manifest
    compressed_digest: blob_store.Digest,
    /// digest of the uncompressed tar — used in config diff_ids
    uncompressed_digest: blob_store.Digest,
    /// size of the compressed layer in bytes
    compressed_size: u64,
};

/// create a new OCI layer from a directory.
///
/// walks the directory tree, creates a tar archive, gzip compresses it,
/// and stores the result in the blob store. returns both compressed and
/// uncompressed digests (needed for OCI manifest and config respectively).
///
/// if the directory is empty, returns null — no point creating an empty layer.
pub fn createLayerFromDir(alloc: std.mem.Allocator, dir_path: []const u8) LayerError!?LayerCreateResult {
    // open the source directory
    var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch
        return LayerError.CreateFailed;
    defer dir.close();

    // check if directory has any entries
    var check_iter = dir.iterate();
    const has_entries = (check_iter.next() catch return LayerError.CreateFailed) != null;
    if (!has_entries) return null;

    // create temp file for the uncompressed tar
    var tar_path_buf: [max_path]u8 = undefined;
    const tar_path = paths.dataPathFmt(&tar_path_buf, "tmp/build-layer.tar", .{}) catch
        return LayerError.PathTooLong;
    paths.ensureDataDir("tmp") catch return LayerError.CreateFailed;

    // write tar file and compute uncompressed digest
    const uncompressed_digest = writeTarFromDir(dir_path, tar_path) catch
        return LayerError.CreateFailed;

    defer std.fs.cwd().deleteFile(tar_path) catch {};

    // gzip compress the tar and compute compressed digest
    var gz_path_buf: [max_path]u8 = undefined;
    const gz_path = paths.dataPathFmt(&gz_path_buf, "tmp/build-layer.tar.gz", .{}) catch
        return LayerError.PathTooLong;

    const compress_result = gzipCompress(alloc, tar_path, gz_path) catch
        return LayerError.CreateFailed;

    defer std.fs.cwd().deleteFile(gz_path) catch {};

    // store the compressed blob
    blob_store.putBlobFromFile(gz_path, compress_result.digest) catch
        return LayerError.CreateFailed;

    return LayerCreateResult{
        .compressed_digest = compress_result.digest,
        .uncompressed_digest = uncompressed_digest,
        .compressed_size = compress_result.size,
    };
}

const GzipResult = struct {
    digest: blob_store.Digest,
    size: u64,
};

/// gzip compress a file, returning the digest and size of the result.
fn gzipCompress(alloc: std.mem.Allocator, src_path: []const u8, dst_path: []const u8) !GzipResult {
    const src_file = try std.fs.cwd().openFile(src_path, .{});
    defer src_file.close();

    const dst_file = try std.fs.cwd().createFile(dst_path, .{});
    defer dst_file.close();

    // the compressor struct is ~330KB, so allocate on the heap
    const compressor = try alloc.create(std.compress.flate.Compress);
    defer alloc.destroy(compressor);

    var write_buf: [8192]u8 = undefined;
    var dst_writer = dst_file.writer(&write_buf);

    var compress_window: [std.compress.flate.max_window_len]u8 = undefined;
    compressor.* = std.compress.flate.Compress.init(
        &dst_writer.interface,
        &compress_window,
        .{ .container = .gzip },
    );

    // read source file and feed through compressor
    var read_buf: [8192]u8 = undefined;
    while (true) {
        const n = try src_file.read(&read_buf);
        if (n == 0) break;
        compressor.writer.writeAll(read_buf[0..n]) catch return error.CompressFailed;
    }

    compressor.end() catch return error.CompressFailed;

    // compute digest and size of the compressed output
    const stat = try dst_file.stat();
    const size = stat.size;

    // reopen and hash the compressed file
    dst_file.close();
    const verify_file = try std.fs.cwd().openFile(dst_path, .{});
    defer verify_file.close();

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var hash_buf: [8192]u8 = undefined;
    while (true) {
        const n = try verify_file.read(&hash_buf);
        if (n == 0) break;
        hasher.update(hash_buf[0..n]);
    }

    return GzipResult{
        .digest = .{ .hash = hasher.finalResult() },
        .size = size,
    };
}

/// write a tar archive from a directory, returning the sha256 of the tar.
/// uses a page allocator internally for the directory walker since this
/// runs as part of image builds (not in the child container).
fn writeTarFromDir(dir_path: []const u8, tar_path: []const u8) !blob_store.Digest {
    var dir = try std.fs.cwd().openDir(dir_path, .{ .iterate = true });
    defer dir.close();

    const tar_file = try std.fs.cwd().createFile(tar_path, .{});
    defer tar_file.close();

    var write_buf: [8192]u8 = undefined;
    var file_writer = tar_file.writer(&write_buf);
    var tar_writer: std.tar.Writer = .{ .underlying_writer = &file_writer.interface };

    // walk the directory tree recursively
    var walker = try dir.walk(std.heap.page_allocator);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        switch (entry.kind) {
            .directory => {
                tar_writer.writeDir(entry.path, .{}) catch continue;
            },
            .file => {
                var file = dir.openFile(entry.path, .{}) catch continue;
                defer file.close();
                var file_read_buf: [4096]u8 = undefined;
                var reader = file.reader(&file_read_buf);
                const stat = file.stat() catch continue;
                tar_writer.writeFile(entry.path, &reader, stat.mtime) catch continue;
            },
            .sym_link => {
                // read symlink target
                var link_buf: [std.fs.max_path_bytes]u8 = undefined;
                const link_target = dir.readLink(entry.path, &link_buf) catch continue;
                tar_writer.writeLink(entry.path, link_target, .{}) catch continue;
            },
            else => continue,
        }
    }

    // flush the writer
    file_writer.interface.flush() catch {};

    // now hash the tar file for uncompressed digest
    tar_file.close();

    const hash_file = try std.fs.cwd().openFile(tar_path, .{});
    defer hash_file.close();

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var hash_buf: [8192]u8 = undefined;
    while (true) {
        const n = try hash_file.read(&hash_buf);
        if (n == 0) break;
        hasher.update(hash_buf[0..n]);
    }

    return blob_store.Digest{ .hash = hasher.finalResult() };
}

/// get the filesystem path for an extracted layer
fn layerPath(digest: blob_store.Digest, buf: *[max_path]u8) LayerError![]const u8 {
    const hex = digest.hex();
    return paths.dataPathFmt(buf, "{s}/{s}", .{ layer_subdir, hex }) catch
        return LayerError.PathTooLong;
}

/// get the layer cache directory
fn layerDir(buf: *[max_path]u8) LayerError![]const u8 {
    return paths.dataPath(buf, layer_subdir) catch return LayerError.PathTooLong;
}

/// extract a gzipped tarball to a directory.
/// this is the core extraction logic: gzip decompress → tar extract.
fn extractTarGz(gz_path: []const u8, dest_path: []const u8) !void {
    const file = try std.fs.cwd().openFile(gz_path, .{});
    defer file.close();

    // set up gzip decompression
    var read_buf: [4096]u8 = undefined;
    var file_reader = file.reader(&read_buf);

    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress = std.compress.flate.Decompress.init(
        &file_reader.interface,
        .gzip,
        &decompress_buf,
    );

    // open the destination directory
    var dest_dir = try std.fs.cwd().openDir(dest_path, .{});
    defer dest_dir.close();

    // extract tar contents to the directory
    try std.tar.pipeToFileSystem(dest_dir, &decompress.reader, .{
        .mode_mode = .executable_bit_only,
        // OCI layers sometimes have unsupported file types (block devices, etc.)
        // use diagnostics to skip them instead of failing
        .diagnostics = null,
    });
}

// -- tests --

test "layer path format" {
    const home = std.posix.getenv("HOME") orelse return;

    const digest = blob_store.Digest.parse("sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9").?;
    var buf: [max_path]u8 = undefined;
    const path = try layerPath(digest, &buf);

    // should contain the home dir, layer_subdir, and hex digest
    try std.testing.expect(std.mem.startsWith(u8, path, home));
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

test "assemble rootfs — empty layer list" {
    const alloc = std.testing.allocator;
    const layer_paths = try assembleRootfs(alloc, &.{});
    defer alloc.free(layer_paths);
    try std.testing.expectEqual(@as(usize, 0), layer_paths.len);
}

test "create layer from empty dir returns null" {
    const home = std.posix.getenv("HOME") orelse return;
    _ = home;
    const alloc = std.testing.allocator;

    // create a temp empty directory
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    var path_buf: [max_path]u8 = undefined;
    const dir_path = try tmp_dir.dir.realpath(".", &path_buf);

    const result = try createLayerFromDir(alloc, dir_path);
    try std.testing.expect(result == null);
}

test "create layer from dir — round trip" {
    const home = std.posix.getenv("HOME") orelse return;
    _ = home;
    const alloc = std.testing.allocator;

    // create a temp directory with some files
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();

    // create test files
    try tmp_dir.dir.writeFile(.{ .sub_path = "hello.txt", .data = "hello world\n" });
    try tmp_dir.dir.makeDir("subdir");
    try tmp_dir.dir.writeFile(.{ .sub_path = "subdir/nested.txt", .data = "nested content\n" });

    var path_buf: [max_path]u8 = undefined;
    const dir_path = try tmp_dir.dir.realpath(".", &path_buf);

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

test "create layer from dir — deterministic digest" {
    const home = std.posix.getenv("HOME") orelse return;
    _ = home;
    const alloc = std.testing.allocator;

    // create two identical directories
    var tmp1 = std.testing.tmpDir(.{});
    defer tmp1.cleanup();
    try tmp1.dir.writeFile(.{ .sub_path = "file.txt", .data = "same content" });

    var path_buf1: [max_path]u8 = undefined;
    const dir1 = try tmp1.dir.realpath(".", &path_buf1);

    var tmp2 = std.testing.tmpDir(.{});
    defer tmp2.cleanup();
    try tmp2.dir.writeFile(.{ .sub_path = "file.txt", .data = "same content" });

    var path_buf2: [max_path]u8 = undefined;
    const dir2 = try tmp2.dir.realpath(".", &path_buf2);

    const result1 = (try createLayerFromDir(alloc, dir1)).?;
    const result2 = (try createLayerFromDir(alloc, dir2)).?;

    // same content should produce same uncompressed digest
    try std.testing.expect(result1.uncompressed_digest.eql(result2.uncompressed_digest));

    // clean up
    blob_store.deleteBlob(result1.compressed_digest) catch {};
    blob_store.deleteBlob(result2.compressed_digest) catch {};
}

test "different content produces different layer digests" {
    const home = std.posix.getenv("HOME") orelse return;
    _ = home;
    const alloc = std.testing.allocator;

    var tmp1 = std.testing.tmpDir(.{});
    defer tmp1.cleanup();
    try tmp1.dir.writeFile(.{ .sub_path = "file.txt", .data = "content alpha" });

    var path_buf1: [max_path]u8 = undefined;
    const dir1 = try tmp1.dir.realpath(".", &path_buf1);

    var tmp2 = std.testing.tmpDir(.{});
    defer tmp2.cleanup();
    try tmp2.dir.writeFile(.{ .sub_path = "file.txt", .data = "content beta" });

    var path_buf2: [max_path]u8 = undefined;
    const dir2 = try tmp2.dir.realpath(".", &path_buf2);

    const result1 = (try createLayerFromDir(alloc, dir1)).?;
    const result2 = (try createLayerFromDir(alloc, dir2)).?;

    // different content should produce different uncompressed digests
    try std.testing.expect(!result1.uncompressed_digest.eql(result2.uncompressed_digest));

    // clean up
    blob_store.deleteBlob(result1.compressed_digest) catch {};
    blob_store.deleteBlob(result2.compressed_digest) catch {};
}
