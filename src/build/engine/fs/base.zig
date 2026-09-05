const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;

const blob_store = @import("../../../image/store.zig");
const layer = @import("../../../image/layer.zig");
const spec = @import("../../../image/spec.zig");
const registry = @import("../../../image/registry.zig");
const state_store = @import("../../../state/store.zig");
const container = @import("../../../runtime/container.zig");
const process = @import("../../../runtime/process.zig");
const log = @import("../../../lib/log.zig");
const config_inherit = @import("../config_inherit.zig");
const child_exec = @import("../child_exec.zig");
const common = @import("common.zig");
const types = @import("../types.zig");

const signal_exit_base: u8 = 128;

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

pub fn processFrom(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    args: []const u8,
) types.BuildError!void {
    const image_str = if (std.mem.indexOf(u8, args, " AS ") orelse std.mem.indexOf(u8, args, " as ")) |idx|
        args[0..idx]
    else
        args;

    const ref = spec.parseImageRef(image_str);
    log.info("FROM {s}", .{image_str});

    const local = state_store.findImage(alloc, ref.repository, ref.reference) catch null;
    if (local) |img| {
        defer img.deinit(alloc);
        return loadLocalBaseImage(alloc, state, img.manifest_digest);
    }

    var threaded_io = std.Io.Threaded.init(alloc, .{});
    defer threaded_io.deinit();

    var result = registry.pull(threaded_io.io(), alloc, ref) catch return types.BuildError.PullFailed;
    defer result.deinit();

    const pulled_config_digest = blob_store.computeDigest(result.config_bytes);
    var pulled_config_buf: [71]u8 = undefined;
    const pulled_config_str = pulled_config_digest.string(&pulled_config_buf);

    state_store.saveImage(.{
        .id = result.manifest_digest,
        .repository = ref.repository,
        .tag = ref.reference,
        .manifest_digest = result.manifest_digest,
        .config_digest = pulled_config_str,
        .total_size = @intCast(result.total_size),
        .created_at = nowRealSeconds(),
    }) catch |err| {
        log.warn("failed to save base image record: {}", .{err});
    };

    const layer_paths = layer.assembleRootfs(alloc, result.layer_digests) catch
        return types.BuildError.PullFailed;
    defer {
        for (layer_paths) |path| alloc.free(path);
        alloc.free(layer_paths);
    }

    var parsed_manifest = spec.parseManifest(alloc, result.manifest_bytes) catch
        return types.BuildError.PullFailed;
    defer parsed_manifest.deinit();

    try inheritBase(alloc, state, parsed_manifest.value.layers, result.config_bytes);
}

pub fn processRun(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    args: []const u8,
) types.BuildError!void {
    log.info("RUN {s}", .{args});

    const cache_key = (try common.withCache(alloc, state, "RUN", args, null, null)) orelse return;
    defer alloc.free(cache_key);

    try executeStep(alloc, state, args, state.workdir, false, cache_key);
}

pub fn createWorkdir(alloc: std.mem.Allocator, state: *types.BuildState, path: []const u8) types.BuildError!void {
    try executeStep(alloc, state, "", path, true, null);
}

fn executeStep(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8, workdir: []const u8, create_workdir: bool, cache_key: ?[]const u8) types.BuildError!void {
    var layer_paths_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (layer_paths_list.items) |path| alloc.free(path);
        layer_paths_list.deinit(alloc);
    }
    try common.withExtractedLayers(alloc, state.layers.items, &layer_paths_list);

    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf) catch return types.BuildError.RunStepFailed;
    const build_id = id_buf[0..];

    const dirs = container.createContainerDirs(build_id) catch return types.BuildError.RunStepFailed;
    defer container.cleanupContainerDirs(build_id);

    var child_ctx = child_exec.BuildChildContext{
        .layer_dirs = layer_paths_list.items,
        .upper_dir = dirs.upperPath(),
        .work_dir = dirs.workPath(),
        .merged_dir = dirs.mergedPath(),
        .command = args,
        .env = state.env.items,
        .workdir = workdir,
        .user = state.user,
        .create_workdir = create_workdir,
        .rootless = std.os.linux.geteuid() != 0,
        .shell = state.shell,
    };

    var spawn_result = child_exec.spawn(
        child_exec.buildChildMain,
        @ptrCast(&child_ctx),
    ) catch return types.BuildError.RunStepFailed;

    spawn_result.signalReady();
    defer linux_platform.posix.close(spawn_result.stdout_fd);
    defer linux_platform.posix.close(spawn_result.stderr_fd);
    // Both pipes must be consumed: closing them breaks ordinary RUN output,
    // while reading one to completion can deadlock a child writing the other.
    drainOutput(spawn_result.stdout_fd, spawn_result.stderr_fd) catch {
        _ = std.os.linux.kill(spawn_result.pid, .KILL);
        _ = process.wait(spawn_result.pid, false) catch {};
        return error.RunStepFailed;
    };

    const wait_result = process.wait(spawn_result.pid, false) catch return types.BuildError.RunStepFailed;
    const exit_code: u8 = switch (wait_result.status) {
        .exited => |code| code,
        .signaled => signal_exit_base,
        .running, .stopped => return error.RunStepFailed,
    };
    if (exit_code != 0) return types.BuildError.RunStepFailed;

    const layer_result = layer.createLayerFromDir(alloc, dirs.upperPath()) catch return types.BuildError.LayerFailed;
    if (layer_result) |lr| try common.commitLayerResult(state, lr, cache_key);
}

fn loadLocalBaseImage(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    manifest_digest_str: []const u8,
) types.BuildError!void {
    const manifest_digest = blob_store.Digest.parse(manifest_digest_str) orelse
        return types.BuildError.PullFailed;
    const manifest_bytes = blob_store.getBlob(alloc, manifest_digest) catch
        return types.BuildError.PullFailed;
    defer alloc.free(manifest_bytes);

    var parsed_manifest = spec.parseManifest(alloc, manifest_bytes) catch
        return types.BuildError.PullFailed;
    defer parsed_manifest.deinit();

    const config_digest = blob_store.Digest.parse(parsed_manifest.value.config.digest) orelse
        return types.BuildError.PullFailed;
    const config_bytes = blob_store.getBlob(alloc, config_digest) catch
        return types.BuildError.PullFailed;
    defer alloc.free(config_bytes);

    try inheritBase(alloc, state, parsed_manifest.value.layers, config_bytes);
}

// Validate the entire relationship before adding any layers. Manifest digests
// identify compressed blobs; the config records their uncompressed tar hashes.
fn inheritBase(alloc: std.mem.Allocator, state: *types.BuildState, layers: []const spec.Descriptor, config_bytes: []const u8) types.BuildError!void {
    var parsed = spec.parseImageConfig(alloc, config_bytes) catch return error.PullFailed;
    defer parsed.deinit();
    const rootfs = parsed.value.rootfs orelse return error.PullFailed;
    if (!std.mem.eql(u8, rootfs.type, "layers") or rootfs.diff_ids.len != layers.len) return error.PullFailed;
    for (rootfs.diff_ids) |digest| {
        if (blob_store.Digest.parse(digest) == null) return error.PullFailed;
    }
    for (layers, rootfs.diff_ids) |entry, diff_id| {
        state.addLayer(entry.digest, diff_id, entry.size) catch return error.PullFailed;
    }
    try config_inherit.inheritConfig(alloc, state, parsed.value);
}

fn drainOutput(stdout: posix.fd_t, stderr: posix.fd_t) !void {
    var pipes = [_]posix.pollfd{
        .{ .fd = stdout, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = stderr, .events = posix.POLL.IN, .revents = 0 },
    };
    var remaining: usize = pipes.len;
    var buf: [8192]u8 = undefined;
    while (remaining != 0) {
        _ = try posix.poll(&pipes, -1);
        for (&pipes) |*pipe| {
            if (pipe.fd < 0 or pipe.revents == 0) continue;
            if (try posix.read(pipe.fd, &buf) == 0) {
                pipe.fd = -1;
                remaining -= 1;
            }
        }
    }
}

test "build base gzip diff IDs survive exported config and reject invalid metadata" {
    const alloc = std.testing.allocator;
    var tar_bytes: std.Io.Writer.Allocating = .init(alloc);
    defer tar_bytes.deinit();
    var tar: std.tar.Writer = .{ .underlying_writer = &tar_bytes.writer };
    try tar.writeFileBytes("base-file", "gzip base contents", .{});
    try tar.finishPedantically();
    var compressed: std.Io.Writer.Allocating = try .initCapacity(alloc, 4096);
    defer compressed.deinit();
    const compressor = try alloc.create(std.compress.flate.Compress);
    defer alloc.destroy(compressor);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    compressor.* = try std.compress.flate.Compress.init(&compressed.writer, &window, .gzip, .default);
    try compressor.writer.writeAll(tar_bytes.written());
    try compressor.finish();
    var compressed_buf: [71]u8 = undefined;
    var diff_buf: [71]u8 = undefined;
    const digest = blob_store.computeDigest(compressed.written()).string(&compressed_buf);
    const diff_id = blob_store.computeDigest(tar_bytes.written()).string(&diff_buf);
    try std.testing.expect(!std.mem.eql(u8, digest, diff_id));
    const layers = [_]spec.Descriptor{.{ .mediaType = spec.media_type.oci_layer_gzip, .digest = digest, .size = compressed.written().len }};
    const config = try std.fmt.allocPrint(alloc, "{{\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[\"{s}\"]}}}}", .{diff_id});
    defer alloc.free(config);
    var state = types.BuildState.init(alloc);
    defer state.deinit();
    try inheritBase(alloc, &state, &layers, config);
    const exported = try @import("../image_output.zig").buildConfigJson(alloc, &state);
    defer alloc.free(exported);
    var parsed = try spec.parseImageConfig(alloc, exported);
    defer parsed.deinit();
    try std.testing.expectEqualStrings(diff_id, parsed.value.rootfs.?.diff_ids[0]);
    for ([_][]const u8{
        "{}",
        "{\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[]}}",
        "{\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[\"sha256:bad\"]}}",
        "{\"rootfs\":{\"type\":\"other\",\"diff_ids\":[]}}",
    }) |invalid| {
        var rejected = types.BuildState.init(alloc);
        defer rejected.deinit();
        try std.testing.expectError(error.PullFailed, inheritBase(alloc, &rejected, &layers, invalid));
        const empty_config = try @import("../image_output.zig").buildConfigJson(alloc, &rejected);
        defer alloc.free(empty_config);
        var empty = try spec.parseImageConfig(alloc, empty_config);
        defer empty.deinit();
        try std.testing.expectEqual(@as(usize, 0), empty.value.rootfs.?.diff_ids.len);
    }
}

test "build base preserves config layer order" {
    const alloc = std.testing.allocator;
    const first = "sha256:" ++ "1" ** 64;
    const second = "sha256:" ++ "2" ** 64;
    const layers = [_]spec.Descriptor{
        .{ .mediaType = spec.media_type.oci_layer_gzip, .digest = "sha256:" ++ "a" ** 64, .size = 10 },
        .{ .mediaType = spec.media_type.oci_layer_gzip, .digest = "sha256:" ++ "b" ** 64, .size = 20 },
    };
    var state = types.BuildState.init(alloc);
    defer state.deinit();
    const config = "{\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[\"" ++ second ++ "\",\"" ++ first ++ "\"]}}";
    try inheritBase(alloc, &state, &layers, config);
    const exported = try @import("../image_output.zig").buildConfigJson(alloc, &state);
    defer alloc.free(exported);
    var parsed = try spec.parseImageConfig(alloc, exported);
    defer parsed.deinit();
    try std.testing.expectEqualStrings(second, parsed.value.rootfs.?.diff_ids[0]);
    try std.testing.expectEqualStrings(first, parsed.value.rootfs.?.diff_ids[1]);
}
