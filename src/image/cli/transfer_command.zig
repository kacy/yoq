const std = @import("std");
const cli = @import("../../lib/cli.zig");
const spec = @import("../spec.zig");
const registry = @import("../registry.zig");
const layer = @import("../layer.zig");
const blob_store = @import("../store.zig");
const store = @import("../../state/store.zig");
const common = @import("common.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const requireArg = cli.requireArg;

pub fn pull(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    const image_str = requireArg(args, "usage: yoq pull <image>\n");
    const ref = spec.parseImageRef(image_str);

    writeErr("pulling {s}...\n", .{image_str});

    var result = registry.pull(alloc, ref) catch |err| {
        common.writePullError(image_str, err);
        return common.ImageCommandsError.PullFailed;
    };
    defer result.deinit();

    const layer_paths = layer.assembleRootfs(alloc, result.layer_digests) catch |err| {
        writeErr("failed to extract image layers: {}\n", .{err});
        return common.ImageCommandsError.PullFailed;
    };
    defer {
        for (layer_paths) |p| alloc.free(p);
        alloc.free(layer_paths);
    }

    common.saveImageRecord(ref, result);

    const size_mb = result.total_size / (1024 * 1024);
    write("{s}: pulled ({d} layers, {d} MB)\n", .{
        image_str,
        result.layer_digests.len,
        size_mb,
    });
}

pub fn push(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    const source_str = requireArg(args, "usage: yoq push <source> [target]\n");
    const target_str = args.next() orelse source_str;

    const source_ref = spec.parseImageRef(source_str);
    const image_record = store.findImage(alloc, source_ref.repository, source_ref.reference) catch |err| {
        writeErr("image not found: {s} ({})", .{ source_str, err });
        writeErr("hint: pull or build the image first, then push\n", .{});
        return common.ImageCommandsError.ImageNotFound;
    };
    defer image_record.deinit(alloc);

    const blobs = common.loadImageBlobs(alloc, image_record) catch return common.ImageCommandsError.StoreFailed;
    defer blobs.deinit(alloc);

    var parsed_manifest = spec.parseManifest(alloc, blobs.manifest_bytes) catch |err| {
        writeErr("failed to parse image manifest: {}\n", .{err});
        return common.ImageCommandsError.InvalidDigest;
    };
    defer parsed_manifest.deinit();

    var layer_digest_strs: std.ArrayListUnmanaged([]const u8) = .empty;
    defer layer_digest_strs.deinit(alloc);
    for (parsed_manifest.value.layers) |entry| {
        layer_digest_strs.append(alloc, entry.digest) catch return common.ImageCommandsError.OutOfMemory;
    }

    const target_ref = spec.parseImageRef(target_str);

    writeErr("pushing {s}...\n", .{target_str});

    var result = registry.push(alloc, target_ref, blobs.manifest_bytes, blobs.config_bytes, layer_digest_strs.items) catch |err| {
        writeErr("failed to push image: {}\n", .{err});
        return common.ImageCommandsError.PushFailed;
    };
    defer result.deinit();

    write("{s}: pushed ({d} layers uploaded, {d} skipped)\n", .{
        target_str,
        result.layers_uploaded,
        result.layers_skipped,
    });
}
