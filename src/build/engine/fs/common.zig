const std = @import("std");
const platform = @import("platform");

const blob_store = @import("../../../image/store.zig");
const layer = @import("../../../image/layer.zig");
const paths = @import("../../../lib/paths.zig");
const cache = @import("../cache.zig");
const types = @import("../types.zig");

pub fn commitLayerResult(
    state: *types.BuildState,
    lr: anytype,
    cache_key: ?[]const u8,
) types.BuildError!void {
    var compressed_buf: [71]u8 = undefined;
    const compressed_str = lr.compressed_digest.string(&compressed_buf);
    var diff_buf: [71]u8 = undefined;
    const diff_str = lr.uncompressed_digest.string(&diff_buf);
    state.addLayer(compressed_str, diff_str, lr.compressed_size) catch return types.BuildError.LayerFailed;
    if (cache_key) |key| cache.storeCache(key, compressed_str, diff_str, lr.compressed_size);
}

pub fn ensureDestParents(layer_dir: []const u8, dest: []const u8) types.BuildError!void {
    if (dest.len == 0) return;
    const dest_in_layer = if (dest[0] == '/') dest[1..] else dest;
    if (std.fs.path.dirname(dest_in_layer)) |parent| {
        var dir = platform.cwd().openDir(layer_dir, .{}) catch return types.BuildError.CopyStepFailed;
        defer dir.close();
        dir.makePath(parent) catch return types.BuildError.CopyStepFailed;
    }
}

pub fn resolveDestination(
    workdir: []const u8,
    dest: []const u8,
    out: []u8,
) types.BuildError![]const u8 {
    if (dest.len > 0 and dest[0] != '/') {
        const total_len = workdir.len + 1 + dest.len;
        if (total_len > out.len) return types.BuildError.CopyStepFailed;
        return std.fmt.bufPrint(out, "{s}/{s}", .{ workdir, dest }) catch
            types.BuildError.CopyStepFailed;
    }
    if (dest.len > out.len) return types.BuildError.CopyStepFailed;
    return dest;
}

pub fn withTempLayerDir(
    out_path: *[paths.max_path]u8,
    prefix: []const u8,
) types.BuildError![]const u8 {
    paths.ensureDataDir("tmp") catch return types.BuildError.CopyStepFailed;
    const layer_dir = paths.uniqueDataTempPath(out_path, "tmp", prefix, "") catch
        return types.BuildError.CopyStepFailed;
    platform.cwd().makePath(layer_dir) catch return types.BuildError.CopyStepFailed;
    return layer_dir;
}

pub fn withExtractedLayers(
    alloc: std.mem.Allocator,
    layer_digests: []const []const u8,
    out_list: *std.ArrayListUnmanaged([]const u8),
) types.BuildError!void {
    for (layer_digests) |digest| {
        const path = layer.extractLayer(alloc, digest) catch return types.BuildError.RunStepFailed;
        out_list.append(alloc, path) catch {
            alloc.free(path);
            return types.BuildError.RunStepFailed;
        };
    }
}

pub fn withCache(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    instruction: []const u8,
    args: []const u8,
    extra: ?[]const u8,
) types.BuildError!?[]const u8 {
    if (extra) |extra_hash| {
        var cache_input_buf: [2048]u8 = undefined;
        const cache_input = std.fmt.bufPrint(&cache_input_buf, "{s}\n{s}\n{s}\n{s}", .{
            instruction,
            args,
            state.parent_digest,
            extra_hash,
        }) catch return types.BuildError.CacheFailed;

        const cache_digest = blob_store.computeDigest(cache_input);
        var cache_key_buf: [71]u8 = undefined;
        const cache_key = cache_digest.string(&cache_key_buf);

        if (cache.checkCache(alloc, cache_key, state)) return null;
        return alloc.dupe(u8, cache_key) catch types.BuildError.CacheFailed;
    }

    const cache_key = cache.computeCacheKey(alloc, instruction, args, state) catch
        return types.BuildError.CacheFailed;
    if (cache.checkCache(alloc, cache_key, state)) {
        alloc.free(cache_key);
        return null;
    }
    return cache_key;
}
