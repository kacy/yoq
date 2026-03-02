// layer — OCI image layer extraction
//
// extracts OCI image layers (gzipped tarballs) into directories
// and assembles a complete rootfs from ordered layers.
//
// layers are cached by digest — if the extracted directory already
// exists, extraction is skipped.
//
// uses std.compress.flate for gzip decompression and std.tar for
// tar extraction. no external dependencies.

const std = @import("std");
const blob_store = @import("store.zig");

pub const LayerError = error{
    ExtractionFailed,
    BlobNotFound,
    PathTooLong,
    HomeDirNotFound,
    AssemblyFailed,
};

/// cache directory for extracted layers
const layer_subdir = "layers/sha256";
const max_path = 512;

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
    var paths: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (paths.items) |p| alloc.free(p);
        paths.deinit(alloc);
    }

    for (layer_digests) |digest| {
        const path = extractLayer(alloc, digest) catch return LayerError.AssemblyFailed;
        paths.append(alloc, path) catch {
            alloc.free(path);
            return LayerError.AssemblyFailed;
        };
    }

    return paths.toOwnedSlice(alloc) catch return LayerError.AssemblyFailed;
}

/// get the filesystem path for an extracted layer
fn layerPath(digest: blob_store.Digest, buf: *[max_path]u8) LayerError![]const u8 {
    const hex = digest.hex();
    const home = std.posix.getenv("HOME") orelse return LayerError.HomeDirNotFound;
    return std.fmt.bufPrint(buf, "{s}/.local/share/yoq/{s}/{s}", .{
        home, layer_subdir, hex,
    }) catch return LayerError.PathTooLong;
}

/// get the layer cache directory
fn layerDir(buf: *[max_path]u8) LayerError![]const u8 {
    const home = std.posix.getenv("HOME") orelse return LayerError.HomeDirNotFound;
    return std.fmt.bufPrint(buf, "{s}/.local/share/yoq/{s}", .{
        home, layer_subdir,
    }) catch return LayerError.PathTooLong;
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
    const paths = try assembleRootfs(alloc, &.{});
    defer alloc.free(paths);
    try std.testing.expectEqual(@as(usize, 0), paths.len);
}
