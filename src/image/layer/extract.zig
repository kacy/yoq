const std = @import("std");

const blob_store = @import("../store.zig");
const paths = @import("../../lib/paths.zig");
const log = @import("../../lib/log.zig");
const tar_extract = @import("../../lib/tar_extract.zig");
const layer_path = @import("path.zig");
const types = @import("types.zig");

const max_path = paths.max_path;
const platform = @import("linux_platform");
const linux = std.os.linux;
const cache_lock = @import("cache_lock.zig");
const cache_marker_name = "complete";

fn cwd() std.Io.Dir {
    return std.Io.Dir.cwd();
}

pub fn extractLayer(alloc: std.mem.Allocator, digest_str: []const u8) types.LayerError![]const u8 {
    const digest = blob_store.Digest.parse(digest_str) orelse return error.BlobNotFound;
    const hex = digest.hex();
    var parent_buf: [max_path]u8 = undefined;
    const parent_path = try layer_path.layerDir(&parent_buf);
    cwd().createDirPath(std.Options.debug_io, parent_path) catch return error.ExtractionFailed;
    var parent = cwd().openDir(std.Options.debug_io, parent_path, .{ .iterate = true }) catch return error.ExtractionFailed;
    defer parent.close(std.Options.debug_io);
    const lock = cache_lock.Lock.acquire(parent, &hex) catch return error.ExtractionFailed;
    defer lock.deinit();

    var dest_buf: [max_path]u8 = undefined;
    const dest_path = try layer_path.layerPath(digest, &dest_buf);
    if (hasCompleteCacheMarker(parent, &hex)) {
        if (!blob_store.verifyBlob(digest)) {
            blob_store.removeBlob(digest);
            return error.BlobNotFound;
        }
        return alloc.dupe(u8, dest_path) catch error.ExtractionFailed;
    }
    // Only unpublished/stale entries are removed, while holding the same lock
    // as extractors and garbage collection. Published entries never mutate.
    parent.deleteTree(std.Options.debug_io, &hex) catch |err| {
        if (err != error.FileNotFound) return error.ExtractionFailed;
    };
    if (!blob_store.verifyBlob(digest)) {
        blob_store.removeBlob(digest);
        return error.BlobNotFound;
    }

    var random: [16]u8 = undefined;
    platform.randomBytes(&random);
    var stage_name_buf: [64]u8 = undefined;
    const stage_name = std.fmt.bufPrintZ(&stage_name_buf, ".staging-{s}", .{std.fmt.bytesToHex(random, .lower)}) catch return error.PathTooLong;
    parent.createDir(std.Options.debug_io, stage_name, .fromMode(0o700)) catch return error.ExtractionFailed;
    defer parent.deleteTree(std.Options.debug_io, stage_name) catch {};
    var stage = parent.openDir(std.Options.debug_io, stage_name, .{ .iterate = true }) catch return error.ExtractionFailed;
    defer stage.close(std.Options.debug_io);
    stage.createDir(std.Options.debug_io, "rootfs", .fromMode(0o755)) catch return error.ExtractionFailed;
    var stage_path_buf: [max_path]u8 = undefined;
    const stage_path = std.fmt.bufPrint(&stage_path_buf, "{s}/{s}/rootfs", .{ parent_path, stage_name }) catch return error.PathTooLong;
    var blob_path_buf: [max_path]u8 = undefined;
    const blob_path = blob_store.blobPath(digest, &blob_path_buf) catch return error.BlobNotFound;
    extractTarGz(blob_path, stage_path) catch return error.ExtractionFailed;

    // Flush the complete tree before publishing metadata. syncfs also covers
    // archive directories whose final modes intentionally prohibit traversal.
    if (linux.errno(linux.syscall1(.syncfs, @intCast(stage.handle))) != .SUCCESS) return error.ExtractionFailed;
    var marker = stage.createFile(std.Options.debug_io, cache_marker_name, .{ .exclusive = true, .permissions = .fromMode(0o600) }) catch return error.ExtractionFailed;
    defer marker.close(std.Options.debug_io);
    marker.writeStreamingAll(std.Options.debug_io, &hex) catch return error.ExtractionFailed;
    marker.sync(std.Options.debug_io) catch return error.ExtractionFailed;
    (platform.File{ .handle = stage.handle }).sync() catch return error.ExtractionFailed;
    const dest_name = std.posix.toPosixPath(&hex) catch return error.PathTooLong;
    if (linux.errno(linux.renameat2(parent.handle, stage_name, parent.handle, &dest_name, .{ .NOREPLACE = true })) != .SUCCESS) return error.ExtractionFailed;
    (platform.File{ .handle = parent.handle }).sync() catch return error.ExtractionFailed;
    return alloc.dupe(u8, dest_path) catch error.ExtractionFailed;
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

fn hasCompleteCacheMarker(parent: std.Io.Dir, hex: []const u8) bool {
    var entry = parent.openDir(std.Options.debug_io, hex, .{}) catch return false;
    defer entry.close(std.Options.debug_io);
    var marker = entry.openFile(std.Options.debug_io, cache_marker_name, .{ .follow_symlinks = false }) catch return false;
    defer marker.close(std.Options.debug_io);
    const stat = marker.stat(std.Options.debug_io) catch return false;
    if (stat.size != hex.len or stat.kind != .file) return false;
    var bytes: [64]u8 = undefined;
    var reader = marker.reader(std.Options.debug_io, &.{});
    reader.interface.readSliceAll(&bytes) catch return false;
    if (!std.mem.eql(u8, &bytes, hex)) return false;
    var root = entry.openDir(std.Options.debug_io, "rootfs", .{}) catch return false;
    root.close(std.Options.debug_io);
    return true;
}
