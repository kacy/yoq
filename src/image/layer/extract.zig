const std = @import("std");

const blob_store = @import("../store.zig");
const paths = @import("../../lib/paths.zig");
const log = @import("../../lib/log.zig");
const layer_path = @import("path.zig");
const types = @import("types.zig");

const max_path = paths.max_path;
const max_file_size: u64 = 10 * 1024 * 1024 * 1024;
const cache_marker_name = ".yoq_complete";

pub fn extractLayer(alloc: std.mem.Allocator, digest_str: []const u8) types.LayerError![]const u8 {
    const digest = blob_store.Digest.parse(digest_str) orelse return types.LayerError.BlobNotFound;

    var dest_buf: [max_path]u8 = undefined;
    const dest_path = layer_path.layerPath(digest, &dest_buf) catch
        return types.LayerError.PathTooLong;
    const dest_owned = alloc.dupe(u8, dest_path) catch return types.LayerError.ExtractionFailed;

    if (@import("compat").cwd().access(dest_path, .{})) |_| {
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
    @import("compat").cwd().makePath(parent_path) catch |err| {
        log.warn("failed to create layer cache dir: {}", .{err});
    };

    @import("compat").cwd().makePath(dest_path) catch return types.LayerError.ExtractionFailed;

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
    if (name.len == 0) return true;
    if (name[0] == '/') return false;

    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, "..")) return false;
    }

    return true;
}

pub fn isSafeSymlinkTarget(entry_path: []const u8, link_target: []const u8) bool {
    if (link_target.len > 0 and link_target[0] == '/') return true;

    var parent_depth: isize = 0;
    var entry_it = std.mem.splitScalar(u8, entry_path, '/');
    var component_count: usize = 0;
    while (entry_it.next()) |_| {
        component_count += 1;
    }
    if (component_count > 0) {
        parent_depth = @intCast(component_count - 1);
    }

    var depth = parent_depth;
    var link_it = std.mem.splitScalar(u8, link_target, '/');
    while (link_it.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
        if (std.mem.eql(u8, component, "..")) {
            depth -= 1;
            if (depth < 0) return false;
        } else {
            depth += 1;
        }
    }

    return true;
}

fn extractTarGz(gz_path: []const u8, dest_path: []const u8) !void {
    // TODO: simplify this after the Zig upgrade if upstream flate decompression
    // no longer needs the direct-mode temp-file workaround.
    var tmp_path_buf: [max_path]u8 = undefined;
    const tmp_path = paths.uniqueDataTempPath(&tmp_path_buf, "tmp", "layer-extract", ".tar") catch
        return error.PathTooLong;
    paths.ensureDataDir("tmp") catch return error.FileNotFound;

    {
        const gz_file = try @import("compat").cwd().openFile(gz_path, .{});
        defer gz_file.close();

        const tmp_file = try @import("compat").cwd().createFile(tmp_path, .{});
        defer tmp_file.close();

        var read_buf: [4096]u8 = undefined;
        var gz_reader = gz_file.reader(&read_buf);

        var decompress = std.compress.flate.Decompress.init(
            &gz_reader.interface,
            .gzip,
            &.{},
        );

        var write_buf: [std.compress.flate.max_window_len]u8 = undefined;
        var tmp_writer = tmp_file.writer(&write_buf);

        _ = try decompress.reader.streamRemaining(&tmp_writer.interface);
        tmp_writer.interface.flush() catch return error.FileNotFound;
        tmp_file.sync() catch {};
    }
    defer @import("compat").cwd().deleteFile(tmp_path) catch {};

    const tar_file = try @import("compat").cwd().openFile(tmp_path, .{});
    defer tar_file.close();

    var tar_read_buf: [4096]u8 = undefined;
    var tar_reader = tar_file.reader(&tar_read_buf);

    var dest_dir = try @import("compat").cwd().openDir(dest_path, .{});
    defer dest_dir.close();

    var file_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var it: std.tar.Iterator = .init(&tar_reader.interface, .{
        .file_name_buffer = &file_name_buffer,
        .link_name_buffer = &link_name_buffer,
    });

    while (try it.next()) |entry| {
        if (!isSafeTarPath(entry.name)) continue;

        switch (entry.kind) {
            .directory => {
                if (entry.name.len > 0) try dest_dir.makePath(entry.name);
            },
            .file => {
                const mode: @import("compat").File.Mode = @intCast(entry.mode & 0o777);
                const fs_file = try createDirAndFile(dest_dir, entry.name, mode);
                defer fs_file.close();
                try copyTarEntryToFile(&it, entry, fs_file);
            },
            .sym_link => {
                if (!isSafeSymlinkTarget(entry.name, entry.link_name)) {
                    log.warn("extract: skipping unsafe symlink '{s}' -> '{s}'", .{
                        entry.name,
                        entry.link_name,
                    });
                    continue;
                }
                try createDirAndSymlink(dest_dir, entry.link_name, entry.name);
            },
        }
    }
}

fn copyTarEntryToFile(it: *std.tar.Iterator, entry: std.tar.Iterator.File, fs_file: @import("compat").File) !void {
    if (entry.size > max_file_size) {
        log.warn("tar entry exceeds max file size ({d} bytes): skipping", .{entry.size});
        return error.FileTooBig;
    }

    var remaining = entry.size;
    var buf: [8192]u8 = undefined;
    while (remaining > 0) {
        const chunk_len: usize = @intCast(@min(remaining, buf.len));
        try it.reader.readSliceAll(buf[0..chunk_len]);
        try fs_file.writeAll(buf[0..chunk_len]);
        remaining -= chunk_len;
    }

    it.unread_file_bytes = 0;
}

fn createDirAndFile(dir: @import("compat").Dir, name: []const u8, mode: @import("compat").File.Mode) !@import("compat").File {
    return dir.createFile(name, .{ .mode = mode }) catch |err| {
        if (err == error.FileNotFound) {
            if (std.fs.path.dirname(name)) |dir_name| {
                try dir.makePath(dir_name);
                return try dir.createFile(name, .{ .mode = mode });
            }
        }
        return err;
    };
}

fn createDirAndSymlink(dir: @import("compat").Dir, link_name: []const u8, file_name: []const u8) !void {
    dir.symLink(link_name, file_name, .{}) catch |err| {
        if (err == error.FileNotFound) {
            if (std.fs.path.dirname(file_name)) |dir_name| {
                try dir.makePath(dir_name);
                return try dir.symLink(link_name, file_name, .{});
            }
        }
        return err;
    };
}

fn hasCompleteCacheMarker(dest_path: []const u8) bool {
    var marker_buf: [max_path]u8 = undefined;
    const marker_path = cacheMarkerPath(&marker_buf, dest_path) catch return false;
    @import("compat").cwd().access(marker_path, .{}) catch return false;
    return true;
}

fn createCompleteCacheMarker(dest_path: []const u8) !void {
    var marker_buf: [max_path]u8 = undefined;
    const marker_path = try cacheMarkerPath(&marker_buf, dest_path);
    const file = try @import("compat").cwd().createFile(marker_path, .{ .truncate = true });
    defer file.close();
    try file.writeAll("ok\n");
}

fn cacheMarkerPath(buf: *[max_path]u8, dest_path: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ dest_path, cache_marker_name });
}

fn removeExtractedLayer(dest_path: []const u8) void {
    @import("compat").cwd().deleteTree(dest_path) catch {
        @import("compat").cwd().deleteFile(dest_path) catch {};
    };
}
