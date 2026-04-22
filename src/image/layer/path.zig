const std = @import("std");
const platform = @import("platform");

const blob_store = @import("../store.zig");
const paths = @import("../../lib/paths.zig");
const log = @import("../../lib/log.zig");
const types = @import("types.zig");

pub const layer_subdir = "layers/sha256";
const max_path = paths.max_path;

pub fn layerPath(digest: blob_store.Digest, buf: *[max_path]u8) types.LayerError![]const u8 {
    const hex = digest.hex();
    return paths.dataPathFmt(buf, "{s}/{s}", .{ layer_subdir, hex }) catch
        return types.LayerError.PathTooLong;
}

pub fn layerDir(buf: *[max_path]u8) types.LayerError![]const u8 {
    return paths.dataPath(buf, layer_subdir) catch return types.LayerError.PathTooLong;
}

pub fn listExtractedLayersOnDisk(alloc: std.mem.Allocator) types.LayerError!std.ArrayList([]const u8) {
    var dir_buf: [max_path]u8 = undefined;
    const dir_path = layerDir(&dir_buf) catch return types.LayerError.PathTooLong;

    var dir = platform.cwd().openDir(dir_path, .{ .iterate = true }) catch {
        return std.ArrayList([]const u8).empty;
    };
    defer dir.close();

    var layers = std.ArrayList([]const u8).empty;
    errdefer {
        for (layers.items) |item| alloc.free(item);
        layers.deinit(alloc);
    }

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        if (entry.name.len != 64) continue;
        const owned = alloc.dupe(u8, entry.name) catch continue;
        layers.append(alloc, owned) catch {
            alloc.free(owned);
            continue;
        };
    }

    return layers;
}

pub fn deleteExtractedLayer(hex: []const u8) void {
    var path_buf: [max_path]u8 = undefined;
    const path = paths.dataPathFmt(&path_buf, "{s}/{s}", .{ layer_subdir, hex }) catch return;
    platform.cwd().deleteTree(path) catch |err| {
        if (err != error.FileNotFound) {
            log.warn("failed to delete extracted layer {s}: {}", .{ hex, err });
        }
    };
}
