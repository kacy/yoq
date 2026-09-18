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

const DigestSet = std.AutoHashMap([32]u8, void);

fn markDigest(referenced: *DigestSet, text: []const u8) !void {
    const digest = blob_store.Digest.parse(text) orelse return error.InvalidDigest;
    try referenced.put(digest.hash, {});
}

// finish reading every reference before allowing the destructive sweep.
fn markImages(alloc: std.mem.Allocator, referenced: *DigestSet) !void {
    var imgs = store.listImages(alloc) catch |err| {
        writeErr("failed to list images: {}\n", .{err});
        return common.ImageCommandsError.StoreFailed;
    };
    defer {
        for (imgs.items) |img| img.deinit(alloc);
        imgs.deinit(alloc);
    }

    for (imgs.items) |img| {
        try markManifest(alloc, referenced, img.manifest_digest, img.config_digest);
    }

    var cache_digests = try store.listBuildCacheDigests(alloc);
    defer {
        for (cache_digests.items) |digest| alloc.free(digest);
        cache_digests.deinit(alloc);
    }
    for (cache_digests.items) |digest| {
        try markDigest(referenced, digest);
    }
}

fn markManifest(alloc: std.mem.Allocator, referenced: *DigestSet, manifest_text: []const u8, expected_config: ?[]const u8) !void {
    try markDigest(referenced, manifest_text);
    const manifest_digest = blob_store.Digest.parse(manifest_text) orelse return error.InvalidDigest;
    const manifest_bytes = blob_store.getBlob(alloc, manifest_digest) catch return error.PruneFailed;
    defer alloc.free(manifest_bytes);
    var manifest = spec.parseManifest(alloc, manifest_bytes) catch return error.PruneFailed;
    defer manifest.deinit();
    try markDigest(referenced, manifest.value.config.digest);
    for (manifest.value.layers) |entry| try markDigest(referenced, entry.digest);

    const config_digest = blob_store.Digest.parse(manifest.value.config.digest) orelse return error.InvalidDigest;
    if (expected_config) |text| {
        const expected = blob_store.Digest.parse(text) orelse return error.InvalidDigest;
        if (!expected.eql(config_digest)) return error.PruneFailed;
    }
    const config_bytes = blob_store.getBlob(alloc, config_digest) catch return error.PruneFailed;
    defer alloc.free(config_bytes);
    var config = spec.parseImageConfig(alloc, config_bytes) catch return error.PruneFailed;
    defer config.deinit();
    if (config.value.rootfs) |rootfs| {
        for (rootfs.diff_ids) |diff_id| try markDigest(referenced, diff_id);
    }
}

// Older configurations only recorded extracted paths. Their final components
// identify the layer digest even when the cache directory version has changed.
fn markLayerPath(referenced: *DigestSet, path: []const u8) !void {
    if (!std.mem.eql(u8, std.fs.path.basename(path), "rootfs")) return;
    const parent = std.fs.path.dirname(path) orelse return;
    const digest = blob_store.Digest.fromHex(std.fs.path.basename(parent)) orelse return;
    try referenced.put(digest.hash, {});
}

fn markContainers(alloc: std.mem.Allocator, referenced: *DigestSet) !void {
    const paths = @import("../../lib/paths.zig");
    const run_state = @import("../../runtime/run_state.zig");
    const io = std.Options.debug_io;
    var buffer: [paths.max_path]u8 = undefined;
    const path = try paths.dataPath(&buffer, "run_configs");
    var directory = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer directory.close(io);
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".bin")) continue;
        const id = entry.name[0 .. entry.name.len - 4];
        if (!@import("../../runtime/container.zig").isValidContainerId(id)) continue;
        const config = run_state.loadConfig(alloc, id) catch |err| switch (err) {
            // Container removal can finish while the directory is being read.
            error.NotFound => continue,
            else => return err,
        };
        defer config.deinit(alloc);
        if (config.image_reference) |reference| try markManifest(alloc, referenced, reference, null);
        for (config.lower_dirs) |lower| try markLayerPath(referenced, lower);
        try markLayerPath(referenced, config.rootfs);
    }
}

pub fn prune(alloc: std.mem.Allocator) !void {
    var lease = try @import("../store_lock.zig").Lock.acquire(.exclusive);
    defer lease.deinit();
    var referenced = DigestSet.init(alloc);
    defer referenced.deinit();
    try markImages(alloc, &referenced);
    try markContainers(alloc, &referenced);

    var blobs = blob_store.listBlobsOnDisk(alloc) catch |err| {
        writeErr("failed to list blobs: {}\n", .{err});
        return error.PruneFailed;
    };
    defer {
        for (blobs.items) |item| alloc.free(item);
        blobs.deinit(alloc);
    }

    var layers = layer.listExtractedLayersOnDisk(alloc) catch |err| {
        writeErr("failed to list layers: {}\n", .{err});
        return error.PruneFailed;
    };
    defer {
        for (layers.items) |item| alloc.free(item);
        layers.deinit(alloc);
    }

    var blobs_removed: usize = 0;
    var bytes_reclaimed: u64 = 0;

    for (blobs.items) |hex| {
        if (blob_store.Digest.fromHex(hex)) |digest| {
            if (referenced.contains(digest.hash)) continue;
            const size = blob_store.getBlobSize(digest) orelse 0;
            blob_store.removeBlob(digest);
            blobs_removed += 1;
            bytes_reclaimed += size;
        }
    }

    var layers_removed: usize = 0;
    for (layers.items) |hex| {
        const digest = blob_store.Digest.fromHex(hex) orelse continue;
        if (referenced.contains(digest.hash)) continue;
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

test "image reliability prune keeps owned layer marks and rejects incomplete images" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    const live = try blob_store.putBlob("prune referenced layer");
    defer blob_store.removeBlob(live);
    const garbage = try blob_store.putBlob("prune unreferenced layer");
    defer blob_store.removeBlob(garbage);
    var live_buf: [71]u8 = undefined;
    const config_bytes = try std.fmt.allocPrint(alloc, "{{\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[\"{s}\"]}}}}", .{live.string(&live_buf)});
    defer alloc.free(config_bytes);
    const config = try blob_store.putBlob(config_bytes);
    defer blob_store.removeBlob(config);
    var config_buf: [71]u8 = undefined;
    const manifest_bytes = try std.json.Stringify.valueAlloc(alloc, spec.Manifest{
        .config = .{ .mediaType = spec.media_type.oci_config, .digest = config.string(&config_buf), .size = config_bytes.len },
        .layers = &.{.{ .mediaType = spec.media_type.oci_layer_tar, .digest = live.string(&live_buf), .size = 22 }},
    }, .{});
    defer alloc.free(manifest_bytes);
    const manifest = try blob_store.putBlob(manifest_bytes);
    defer blob_store.removeBlob(manifest);
    var manifest_buf: [71]u8 = undefined;
    try store.saveImage(.{ .id = manifest.string(&manifest_buf), .repository = "prune-test", .tag = "latest", .manifest_digest = manifest.string(&manifest_buf), .config_digest = config.string(&config_buf), .total_size = 22, .created_at = 1 });

    // the testing allocator poisons freed bytes. marks must survive both parsers.
    const paths = @import("../../lib/paths.zig");
    var path_buf: [paths.max_path]u8 = undefined;
    const extracted = try @import("../layer/path.zig").layerPath(live, &path_buf);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, extracted);
    defer layer.deleteExtractedLayer(&live.hex());
    try prune(alloc);
    var live_dir = try std.Io.Dir.cwd().openDir(std.testing.io, extracted, .{});
    live_dir.close(std.testing.io);
    try std.testing.expect(blob_store.hasBlob(live));
    try std.testing.expect(blob_store.hasBlob(config));
    try std.testing.expect(blob_store.hasBlob(manifest));
    try std.testing.expect(!blob_store.hasBlob(garbage));

    _ = try blob_store.putBlob("prune unreferenced layer");
    var failing = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    try std.testing.expectError(error.StoreFailed, prune(failing.allocator()));
    try std.testing.expect(blob_store.hasBlob(garbage));
    blob_store.removeBlob(config);
    try std.testing.expectError(error.PruneFailed, prune(alloc));
    try std.testing.expect(blob_store.hasBlob(garbage));
    try std.testing.expect(blob_store.hasBlob(live));

    try blob_store.putBlobDirect("not a config", config);
    try std.testing.expectError(error.PruneFailed, prune(alloc));
    try std.testing.expect(blob_store.hasBlob(garbage));
    blob_store.removeBlob(config);
    _ = try blob_store.putBlob(config_bytes);
    blob_store.removeBlob(manifest);
    try std.testing.expectError(error.PruneFailed, prune(alloc));
    try std.testing.expect(blob_store.hasBlob(garbage));
}

fn checkMarkAllocation(alloc: std.mem.Allocator) !void {
    var referenced = DigestSet.init(alloc);
    defer referenced.deinit();
    const digest = blob_store.computeDigest("mark allocation");
    var buf: [71]u8 = undefined;
    try markDigest(&referenced, digest.string(&buf));
    try std.testing.expect(referenced.contains(digest.hash));
}

test "image reliability prune propagates mark allocation failure and invalid digests" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkMarkAllocation, .{});
    var referenced = DigestSet.init(std.testing.allocator);
    defer referenced.deinit();
    try std.testing.expectError(error.InvalidDigest, markDigest(&referenced, "sha256:" ++ "z" ** 64));
}

test "image reliability prune rejects conflicting config references before deletion" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    const live = try blob_store.putBlob("layer referenced only by manifest config");
    defer blob_store.removeBlob(live);
    var live_buf: [71]u8 = undefined;
    const config_bytes = try std.fmt.allocPrint(alloc, "{{\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[\"{s}\"]}}}}", .{live.string(&live_buf)});
    defer alloc.free(config_bytes);
    const actual_config = try blob_store.putBlob(config_bytes);
    defer blob_store.removeBlob(actual_config);
    const stale_config = try blob_store.putBlob("{}");
    defer blob_store.removeBlob(stale_config);
    var config_buf: [71]u8 = undefined;
    const manifest_bytes = try std.json.Stringify.valueAlloc(alloc, spec.Manifest{
        .config = .{ .mediaType = spec.media_type.oci_config, .digest = actual_config.string(&config_buf), .size = config_bytes.len },
        .layers = &.{},
    }, .{});
    defer alloc.free(manifest_bytes);
    const manifest = try blob_store.putBlob(manifest_bytes);
    defer blob_store.removeBlob(manifest);
    var manifest_buf: [71]u8 = undefined;
    var stale_buf: [71]u8 = undefined;
    try store.saveImage(.{ .id = manifest.string(&manifest_buf), .repository = "prune-mismatch", .tag = "latest", .manifest_digest = manifest.string(&manifest_buf), .config_digest = stale_config.string(&stale_buf), .total_size = 0, .created_at = 1 });
    try std.testing.expectError(error.PruneFailed, prune(alloc));
    try std.testing.expect(blob_store.hasBlob(live));
    try std.testing.expect(blob_store.hasBlob(actual_config));
}

fn savedLayerFixture(rootfs: []const u8) @import("../../runtime/run_state.zig").SavedRunConfig {
    return .{
        .rootfs = rootfs,
        .command = "/bin/sh",
        .hostname = "prune-fixture",
        .working_dir = "/",
        .args = &.{},
        .env = &.{},
        .lower_dirs = &.{},
        .mounts = &.{},
        .network_enabled = false,
        .port_maps = &.{},
        .limits = .{},
        .restart_policy = .no,
    };
}

test "image reliability prune retains untagged container manifests and legacy lower directories" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    const run_state = @import("../../runtime/run_state.zig");
    const live = try blob_store.putBlob("untagged container layer");
    defer blob_store.removeBlob(live);
    const legacy = try blob_store.putBlob("legacy container layer");
    defer blob_store.removeBlob(legacy);
    const garbage = try blob_store.putBlob("unused container layer");
    defer blob_store.removeBlob(garbage);
    const config = try blob_store.putBlob("{}");
    defer blob_store.removeBlob(config);
    var config_buffer: [71]u8 = undefined;
    var live_buffer: [71]u8 = undefined;
    const manifest_bytes = try std.json.Stringify.valueAlloc(alloc, spec.Manifest{
        .config = .{ .mediaType = spec.media_type.oci_config, .digest = config.string(&config_buffer), .size = 2 },
        .layers = &.{.{ .mediaType = spec.media_type.oci_layer_tar, .digest = live.string(&live_buffer), .size = 23 }},
    }, .{});
    defer alloc.free(manifest_bytes);
    const manifest = try blob_store.putBlob(manifest_bytes);
    defer blob_store.removeBlob(manifest);
    var manifest_buffer: [71]u8 = undefined;
    const paths = @import("../../lib/paths.zig");
    var live_path_buffer: [paths.max_path]u8 = undefined;
    const live_path = try @import("../layer/path.zig").layerPath(live, &live_path_buffer);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, live_path);
    defer layer.deleteExtractedLayer(&live.hex());
    var legacy_path_buffer: [paths.max_path]u8 = undefined;
    const legacy_path = try @import("../layer/path.zig").layerPath(legacy, &legacy_path_buffer);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, legacy_path);
    defer layer.deleteExtractedLayer(&legacy.hex());

    var random: [12]u8 = undefined;
    @import("linux_platform").randomBytes(&random);
    const first_id = std.fmt.bytesToHex(random[0..6].*, .lower);
    const second_id = std.fmt.bytesToHex(random[6..12].*, .lower);
    var saved = savedLayerFixture(live_path);
    saved.image_reference = manifest.string(&manifest_buffer);
    try run_state.saveConfig(&first_id, saved);
    defer run_state.removeConfig(&first_id);
    var lower_dirs = [_][]const u8{legacy_path};
    var old_saved = savedLayerFixture("/unused");
    old_saved.lower_dirs = &lower_dirs;
    try run_state.saveConfig(&second_id, old_saved);
    defer run_state.removeConfig(&second_id);

    try prune(alloc);
    for ([_]blob_store.Digest{ live, legacy, manifest, config }) |digest| try std.testing.expect(blob_store.hasBlob(digest));
    try std.testing.expect(!blob_store.hasBlob(garbage));
    try std.Io.Dir.cwd().access(std.testing.io, live_path, .{});
    try std.Io.Dir.cwd().access(std.testing.io, legacy_path, .{});

    run_state.removeConfig(&first_id);
    run_state.removeConfig(&second_id);
    try prune(alloc);
    for ([_]blob_store.Digest{ live, legacy, manifest, config }) |digest| try std.testing.expect(!blob_store.hasBlob(digest));
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(std.testing.io, live_path, .{}));
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(std.testing.io, legacy_path, .{}));
}

test "image reliability prune refuses to sweep when a saved config is unreadable" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const run_state = @import("../../runtime/run_state.zig");
    const garbage = try blob_store.putBlob("retained when container references cannot be read");
    defer blob_store.removeBlob(garbage);
    var random: [6]u8 = undefined;
    @import("linux_platform").randomBytes(&random);
    const id = std.fmt.bytesToHex(random, .lower);
    try run_state.saveConfig(&id, savedLayerFixture("/rootfs"));
    defer run_state.removeConfig(&id);
    const paths = @import("../../lib/paths.zig");
    var buffer: [paths.max_path]u8 = undefined;
    const path = try paths.dataPathFmt(&buffer, "run_configs/{s}.bin", .{id});
    try std.Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = path, .data = "broken" });
    try std.testing.expectError(error.InvalidFormat, prune(std.testing.allocator));
    try std.testing.expect(blob_store.hasBlob(garbage));
}
