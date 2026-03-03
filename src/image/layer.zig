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
const paths = @import("../lib/paths.zig");

pub const LayerError = error{
    ExtractionFailed,
    BlobNotFound,
    PathTooLong,
    HomeDirNotFound,
    AssemblyFailed,
    PathTraversal,
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
///
/// uses the tar iterator directly (instead of pipeToFileSystem) so we
/// can validate each entry's path before extraction. this prevents
/// path traversal attacks where a malicious tar contains entries like
/// "../../../etc/crontab" that would write outside the extraction dir.
/// (similar to CVE-2019-14271 in Docker.)
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

    // iterate tar entries with path validation
    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var file_contents_buffer: [1024]u8 = undefined;

    var it: std.tar.Iterator = .init(&decompress.reader, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    while (it.next() catch null) |entry| {
        // reject paths that could escape the extraction directory
        if (!isSafeTarPath(entry.name)) continue;

        switch (entry.kind) {
            .directory => {
                if (entry.name.len > 0) {
                    dest_dir.makePath(entry.name) catch {};
                }
            },
            .file => {
                const fs_file = createFileWithParents(dest_dir, entry.name, entry.mode) catch continue;
                defer fs_file.close();
                var file_writer = fs_file.writer(&file_contents_buffer);
                it.streamRemaining(entry, &file_writer.interface) catch {};
                file_writer.interface.flush() catch {};
            },
            .sym_link => {
                // validate symlink target too — a symlink pointing to ../../etc/shadow
                // is just as dangerous as a file with that path
                if (!isSafeTarPath(entry.link_name)) continue;
                dest_dir.symLink(entry.link_name, entry.name, .{}) catch {};
            },
        }
    }
}

/// create a file inside dir, creating parent directories as needed.
/// applies the executable bit from the tar mode.
fn createFileWithParents(dir: std.fs.Dir, name: []const u8, tar_mode: u32) !std.fs.File {
    const mode: std.fs.File.Mode = if (tar_mode & 0o100 != 0) 0o755 else 0o644;
    return dir.createFile(name, .{ .exclusive = true, .mode = mode }) catch |err| {
        if (err == error.FileNotFound) {
            if (std.fs.path.dirname(name)) |dir_name| {
                try dir.makePath(dir_name);
                return try dir.createFile(name, .{ .exclusive = true, .mode = mode });
            }
        }
        return err;
    };
}

/// check if a tar entry path is safe to extract.
/// rejects absolute paths and any path containing ".." components,
/// which could escape the extraction directory.
fn isSafeTarPath(path: []const u8) bool {
    if (path.len == 0) return true;

    // reject absolute paths
    if (path[0] == '/') return false;

    // reject paths containing ".." components
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }

    return true;
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

test "path traversal — rejects ../ paths" {
    try std.testing.expect(!isSafeTarPath("../etc/passwd"));
    try std.testing.expect(!isSafeTarPath("foo/../../etc/shadow"));
    try std.testing.expect(!isSafeTarPath(".."));
    try std.testing.expect(!isSafeTarPath("foo/bar/../../../etc/crontab"));
}

test "path traversal — rejects absolute paths" {
    try std.testing.expect(!isSafeTarPath("/etc/passwd"));
    try std.testing.expect(!isSafeTarPath("/usr/bin/something"));
}

test "path traversal — allows normal paths" {
    try std.testing.expect(isSafeTarPath("usr/bin/app"));
    try std.testing.expect(isSafeTarPath("etc/config.toml"));
    try std.testing.expect(isSafeTarPath("single_file"));
    try std.testing.expect(isSafeTarPath(""));
    try std.testing.expect(isSafeTarPath("a/b/c/d"));
}

test "path traversal — allows paths with dots that aren't .." {
    try std.testing.expect(isSafeTarPath(".hidden"));
    try std.testing.expect(isSafeTarPath("dir/.config"));
    try std.testing.expect(isSafeTarPath("file.tar.gz"));
    try std.testing.expect(isSafeTarPath("..."));
}
