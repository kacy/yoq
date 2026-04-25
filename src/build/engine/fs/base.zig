const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;

const blob_store = @import("../../../image/store.zig");
const layer = @import("../../../image/layer.zig");
const spec = @import("../../../image/spec.zig");
const registry = @import("../../../image/registry.zig");
const state_store = @import("../../../state/store.zig");
const container = @import("../../../runtime/container.zig");
const namespaces = @import("../../../runtime/namespaces.zig");
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

    for (parsed_manifest.value.layers) |entry| {
        state.addLayer(entry.digest, entry.digest, entry.size) catch
            return types.BuildError.PullFailed;
    }

    config_inherit.inheritConfig(alloc, state, result.config_bytes);
    replaceParentDigest(alloc, state, result.manifest_digest) catch return types.BuildError.PullFailed;
}

pub fn processRun(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    args: []const u8,
) types.BuildError!void {
    log.info("RUN {s}", .{args});

    const cache_key = (try common.withCache(alloc, state, "RUN", args, null)) orelse return;
    defer alloc.free(cache_key);

    var layer_paths_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (layer_paths_list.items) |path| alloc.free(path);
        layer_paths_list.deinit(alloc);
    }
    try common.withExtractedLayers(alloc, state.layer_digests.items, &layer_paths_list);

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
        .workdir = state.workdir,
        .shell = state.shell,
    };

    var spawn_result = namespaces.spawn(
        .{ .net = false, .cgroup = false },
        null,
        child_exec.buildChildMain,
        @ptrCast(&child_ctx),
    ) catch return types.BuildError.RunStepFailed;

    spawn_result.signalReady();
    linux_platform.posix.close(spawn_result.stdout_fd);
    linux_platform.posix.close(spawn_result.stderr_fd);

    const wait_result = process.wait(spawn_result.pid, false) catch return types.BuildError.RunStepFailed;
    const exit_code: u8 = switch (wait_result.status) {
        .exited => |code| code,
        .signaled => signal_exit_base,
        .running => 0,
        .stopped => 0,
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

    for (parsed_manifest.value.layers) |entry| {
        state.addLayer(entry.digest, entry.digest, entry.size) catch
            return types.BuildError.PullFailed;
    }

    const config_digest = blob_store.Digest.parse(parsed_manifest.value.config.digest) orelse
        return types.BuildError.PullFailed;
    const config_bytes = blob_store.getBlob(alloc, config_digest) catch
        return types.BuildError.PullFailed;
    defer alloc.free(config_bytes);

    config_inherit.inheritConfig(alloc, state, config_bytes);
    replaceParentDigest(alloc, state, manifest_digest_str) catch return types.BuildError.PullFailed;
}

fn replaceParentDigest(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    value: []const u8,
) !void {
    if (state.parent_digest.len > 0) alloc.free(state.parent_digest);
    state.parent_digest = try alloc.dupe(u8, value);
}
