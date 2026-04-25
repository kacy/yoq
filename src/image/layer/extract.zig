const std = @import("std");

const blob_store = @import("../store.zig");
const paths = @import("../../lib/paths.zig");
const log = @import("../../lib/log.zig");
const tar_extract = @import("../../lib/tar_extract.zig");
const layer_path = @import("path.zig");
const types = @import("types.zig");

const max_path = paths.max_path;
const cache_marker_name = ".yoq_complete";

fn cwd() std.Io.Dir {
    return std.Io.Dir.cwd();
}

pub fn extractLayer(alloc: std.mem.Allocator, digest_str: []const u8) types.LayerError![]const u8 {
    const digest = blob_store.Digest.parse(digest_str) orelse return types.LayerError.BlobNotFound;

    var dest_buf: [max_path]u8 = undefined;
    const dest_path = layer_path.layerPath(digest, &dest_buf) catch
        return types.LayerError.PathTooLong;
    const dest_owned = alloc.dupe(u8, dest_path) catch return types.LayerError.ExtractionFailed;

    if (cwd().access(std.Options.debug_io, dest_path, .{})) |_| {
        if (hasCompleteCacheMarker(dest_path)) {
            if (blob_store.verifyBlob(digest)) {
                return dest_owned;
            }
            blob_store.removeBlob(digest);
            alloc.free(dest_owned);
            return types.LayerError.BlobNotFound;
        }
        removeExtractedLayer(dest_path);
    } else |_| {}

    if (!blob_store.verifyBlob(digest)) {
        blob_store.removeBlob(digest);
        alloc.free(dest_owned);
        return types.LayerError.BlobNotFound;
    }

    var parent_buf: [max_path]u8 = undefined;
    const parent_path = layer_path.layerDir(&parent_buf) catch return types.LayerError.PathTooLong;
    cwd().createDirPath(std.Options.debug_io, parent_path) catch |err| {
        log.warn("failed to create layer cache dir: {}", .{err});
    };

    cwd().createDirPath(std.Options.debug_io, dest_path) catch return types.LayerError.ExtractionFailed;

    var blob_path_buf: [max_path]u8 = undefined;
    const blob_path = blob_store.blobPath(digest, &blob_path_buf) catch
        return types.LayerError.BlobNotFound;

    extractTarGz(blob_path, dest_path) catch {
        removeExtractedLayer(dest_path);
        alloc.free(dest_owned);
        return types.LayerError.ExtractionFailed;
    };

    createCompleteCacheMarker(dest_path) catch {
        removeExtractedLayer(dest_path);
        alloc.free(dest_owned);
        return types.LayerError.ExtractionFailed;
    };

    return dest_owned;
}

pub fn assembleRootfs(
    alloc: std.mem.Allocator,
    layer_digests: []const []const u8,
) types.LayerError![]const []const u8 {
    var layer_paths: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (layer_paths.items) |path| alloc.free(path);
        layer_paths.deinit(alloc);
    }

    for (layer_digests) |digest| {
        const path = extractLayer(alloc, digest) catch return types.LayerError.AssemblyFailed;
        layer_paths.append(alloc, path) catch {
            alloc.free(path);
            return types.LayerError.AssemblyFailed;
        };
    }

    return layer_paths.toOwnedSlice(alloc) catch return types.LayerError.AssemblyFailed;
}

pub fn isSafeTarPath(name: []const u8) bool {
    return tar_extract.isSafeTarPath(name);
}

pub fn isSafeSymlinkTarget(entry_path: []const u8, link_target: []const u8) bool {
    return tar_extract.isSafeSymlinkTarget(entry_path, link_target);
}

fn extractTarGz(gz_path: []const u8, dest_path: []const u8) !void {
    try tar_extract.extractTarGzFile(gz_path, dest_path, "extract");
}

fn hasCompleteCacheMarker(dest_path: []const u8) bool {
    var marker_buf: [max_path]u8 = undefined;
    const marker_path = cacheMarkerPath(&marker_buf, dest_path) catch return false;
    cwd().access(std.Options.debug_io, marker_path, .{}) catch return false;
    return true;
}

fn createCompleteCacheMarker(dest_path: []const u8) !void {
    var marker_buf: [max_path]u8 = undefined;
    const marker_path = try cacheMarkerPath(&marker_buf, dest_path);
    var file = try cwd().createFile(std.Options.debug_io, marker_path, .{ .truncate = true });
    defer file.close(std.Options.debug_io);
    try file.writeStreamingAll(std.Options.debug_io, "ok\n");
}

fn cacheMarkerPath(buf: *[max_path]u8, dest_path: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ dest_path, cache_marker_name });
}

fn removeExtractedLayer(dest_path: []const u8) void {
    cwd().deleteTree(std.Options.debug_io, dest_path) catch {
        cwd().deleteFile(std.Options.debug_io, dest_path) catch {};
    };
}
