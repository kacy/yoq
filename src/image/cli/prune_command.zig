const std = @import("std");
const cli = @import("../../lib/cli.zig");
const json_out = @import("../../lib/json_output.zig");
const spec = @import("../spec.zig");
const layer = @import("../layer.zig");
const blob_store = @import("../store.zig");
const store = @import("../../state/store.zig");
const common = @import("common.zig");

const write = cli.write;
const writeErr = cli.writeErr;

pub fn prune(alloc: std.mem.Allocator) !void {
    var referenced = std.StringHashMap(void).init(alloc);
    defer referenced.deinit();

    var imgs = store.listImages(alloc) catch |err| {
        writeErr("failed to list images: {}\n", .{err});
        return common.ImageCommandsError.StoreFailed;
    };
    defer {
        for (imgs.items) |img| img.deinit(alloc);
        imgs.deinit(alloc);
    }

    for (imgs.items) |img| {
        common.addDigestHex(&referenced, img.manifest_digest);
        common.addDigestHex(&referenced, img.config_digest);

        const manifest_digest = blob_store.Digest.parse(img.manifest_digest) orelse continue;
        const manifest_bytes = blob_store.getBlob(alloc, manifest_digest) catch continue;
        defer alloc.free(manifest_bytes);

        var parsed_manifest = spec.parseManifest(alloc, manifest_bytes) catch continue;
        defer parsed_manifest.deinit();

        for (parsed_manifest.value.layers) |entry| {
            common.addDigestHex(&referenced, entry.digest);
        }

        const config_digest = blob_store.Digest.parse(img.config_digest) orelse continue;
        const config_bytes = blob_store.getBlob(alloc, config_digest) catch continue;
        defer alloc.free(config_bytes);

        var parsed_config = spec.parseImageConfig(alloc, config_bytes) catch continue;
        defer parsed_config.deinit();

        if (parsed_config.value.rootfs) |rootfs| {
            for (rootfs.diff_ids) |diff_id| {
                common.addDigestHex(&referenced, diff_id);
            }
        }
    }

    var cache_digests = store.listBuildCacheDigests(alloc) catch std.ArrayList([]const u8).empty;
    defer {
        for (cache_digests.items) |digest| alloc.free(digest);
        cache_digests.deinit(alloc);
    }
    for (cache_digests.items) |digest| {
        common.addDigestHex(&referenced, digest);
    }

    var blobs = blob_store.listBlobsOnDisk(alloc) catch |err| {
        writeErr("failed to list blobs: {}\n", .{err});
        std.process.exit(1);
    };
    defer {
        for (blobs.items) |item| alloc.free(item);
        blobs.deinit(alloc);
    }

    var blobs_removed: usize = 0;
    var bytes_reclaimed: u64 = 0;

    for (blobs.items) |hex| {
        if (referenced.contains(hex)) continue;
        if (blob_store.Digest.fromHex(hex)) |digest| {
            const size = blob_store.getBlobSize(digest) orelse 0;
            blob_store.removeBlob(digest);
            blobs_removed += 1;
            bytes_reclaimed += size;
        }
    }

    var layers = layer.listExtractedLayersOnDisk(alloc) catch |err| {
        writeErr("failed to list layers: {}\n", .{err});
        std.process.exit(1);
    };
    defer {
        for (layers.items) |item| alloc.free(item);
        layers.deinit(alloc);
    }

    var layers_removed: usize = 0;
    for (layers.items) |hex| {
        if (referenced.contains(hex)) continue;
        layer.deleteExtractedLayer(hex);
        layers_removed += 1;
    }

    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        w.beginObject();
        w.uintField("blobs_removed", blobs_removed);
        w.uintField("layers_removed", layers_removed);
        w.uintField("bytes_reclaimed", bytes_reclaimed);
        w.endObject();
        w.flush();
        return;
    }

    if (blobs_removed == 0 and layers_removed == 0) {
        write("nothing to prune\n", .{});
        return;
    }

    const mb = @divTrunc(bytes_reclaimed, 1024 * 1024);
    write("pruned {d} blob(s), {d} layer(s), reclaimed {d} MB\n", .{
        blobs_removed,
        layers_removed,
        mb,
    });
}
