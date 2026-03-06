const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

const context = @import("../context.zig");
const blob_store = @import("../../image/store.zig");
const layer = @import("../../image/layer.zig");
const spec = @import("../../image/spec.zig");
const registry = @import("../../image/registry.zig");
const state_store = @import("../../state/store.zig");
const container = @import("../../runtime/container.zig");
const filesystem = @import("../../runtime/filesystem.zig");
const namespaces = @import("../../runtime/namespaces.zig");
const process = @import("../../runtime/process.zig");
const paths = @import("../../lib/paths.zig");
const log = @import("../../lib/log.zig");

const types = @import("types.zig");
const stages_mod = @import("stages.zig");
const cache = @import("cache.zig");
const config_inherit = @import("config_inherit.zig");
const child_exec = @import("child_exec.zig");

pub fn processFrom(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    const image_str = if (std.mem.indexOf(u8, args, " AS ") orelse std.mem.indexOf(u8, args, " as ")) |idx|
        args[0..idx]
    else
        args;

    const ref = spec.parseImageRef(image_str);
    log.info("FROM {s}", .{image_str});

    const local = state_store.findImage(alloc, ref.repository, ref.reference) catch null;

    if (local) |img| {
        defer img.deinit(alloc);
        const manifest_digest = blob_store.Digest.parse(img.manifest_digest) orelse return types.BuildError.PullFailed;
        const manifest_bytes = blob_store.getBlob(alloc, manifest_digest) catch return types.BuildError.PullFailed;
        defer alloc.free(manifest_bytes);

        var parsed_manifest = spec.parseManifest(alloc, manifest_bytes) catch return types.BuildError.PullFailed;
        defer parsed_manifest.deinit();

        for (parsed_manifest.value.layers) |l| {
            state.addLayer(l.digest, l.digest, l.size) catch return types.BuildError.PullFailed;
        }

        const config_digest = blob_store.Digest.parse(parsed_manifest.value.config.digest) orelse return types.BuildError.PullFailed;
        const config_bytes = blob_store.getBlob(alloc, config_digest) catch return types.BuildError.PullFailed;
        defer alloc.free(config_bytes);

        config_inherit.inheritConfig(alloc, state, config_bytes);

        if (state.parent_digest.len > 0) alloc.free(state.parent_digest);
        state.parent_digest = alloc.dupe(u8, img.manifest_digest) catch return types.BuildError.PullFailed;
    } else {
        var result = registry.pull(alloc, ref) catch return types.BuildError.PullFailed;
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
            .created_at = std.time.timestamp(),
        }) catch |err| {
            log.warn("failed to save base image record: {}", .{err});
        };

        const layer_paths = layer.assembleRootfs(alloc, result.layer_digests) catch return types.BuildError.PullFailed;
        defer {
            for (layer_paths) |p| alloc.free(p);
            alloc.free(layer_paths);
        }

        var parsed_manifest = spec.parseManifest(alloc, result.manifest_bytes) catch return types.BuildError.PullFailed;
        defer parsed_manifest.deinit();

        for (parsed_manifest.value.layers) |l| {
            state.addLayer(l.digest, l.digest, l.size) catch return types.BuildError.PullFailed;
        }

        config_inherit.inheritConfig(alloc, state, result.config_bytes);

        if (state.parent_digest.len > 0) alloc.free(state.parent_digest);
        state.parent_digest = alloc.dupe(u8, result.manifest_digest) catch return types.BuildError.PullFailed;
    }
}

fn resolveDestination(workdir: []const u8, dest: []const u8, out: []u8) types.BuildError![]const u8 {
    if (dest.len > 0 and dest[0] != '/') {
        return std.fmt.bufPrint(out, "{s}/{s}", .{ workdir, dest }) catch types.BuildError.CopyStepFailed;
    }
    return dest;
}

fn withTempLayerDir(
    out_path: *[paths.max_path]u8,
    comptime name_fmt: []const u8,
    args: anytype,
) types.BuildError![]const u8 {
    paths.ensureDataDir("tmp") catch return types.BuildError.CopyStepFailed;
    const layer_dir = paths.dataPathFmt(out_path, name_fmt, args) catch return types.BuildError.CopyStepFailed;
    std.fs.cwd().deleteTree(layer_dir) catch {};
    std.fs.cwd().makePath(layer_dir) catch return types.BuildError.CopyStepFailed;
    return layer_dir;
}

fn withExtractedLayers(
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

fn withCache(
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

    const cache_key = cache.computeCacheKey(alloc, instruction, args, state) catch return types.BuildError.CacheFailed;
    if (cache.checkCache(alloc, cache_key, state)) {
        alloc.free(cache_key);
        return null;
    }
    return cache_key;
}

pub fn processRun(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    log.info("RUN {s}", .{args});

    const cache_key = (try withCache(alloc, state, "RUN", args, null)) orelse return;
    defer alloc.free(cache_key);

    var layer_paths_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (layer_paths_list.items) |p| alloc.free(p);
        layer_paths_list.deinit(alloc);
    }
    try withExtractedLayers(alloc, state.layer_digests.items, &layer_paths_list);

    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf);
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
    posix.close(spawn_result.stdout_fd);
    posix.close(spawn_result.stderr_fd);

    const wait_result = process.wait(spawn_result.pid, false) catch return types.BuildError.RunStepFailed;
    const exit_code: u8 = switch (wait_result.status) {
        .exited => |code| code,
        .signaled => 128,
        .running => 0,
    };

    if (exit_code != 0) return types.BuildError.RunStepFailed;

    const layer_result = layer.createLayerFromDir(alloc, dirs.upperPath()) catch return types.BuildError.LayerFailed;
    if (layer_result) |lr| {
        var digest_buf: [71]u8 = undefined;
        const compressed_str = lr.compressed_digest.string(&digest_buf);
        var diff_buf: [71]u8 = undefined;
        const diff_str = lr.uncompressed_digest.string(&diff_buf);

        state.addLayer(compressed_str, diff_str, lr.compressed_size) catch return types.BuildError.LayerFailed;
        cache.storeCache(cache_key, compressed_str, diff_str, lr.compressed_size);
    }
}

pub fn parseCopyArgs(args: []const u8) types.CopyArgs {
    var trimmed = std.mem.trim(u8, args, " \t");
    var from_stage: ?[]const u8 = null;

    if (std.mem.startsWith(u8, trimmed, "--from=")) {
        const rest = trimmed["--from=".len..];
        var end: usize = 0;
        while (end < rest.len and rest[end] != ' ' and rest[end] != '\t') end += 1;
        from_stage = rest[0..end];
        if (end < rest.len) {
            trimmed = std.mem.trimLeft(u8, rest[end..], " \t");
        } else {
            trimmed = "";
        }
    }

    var i: usize = trimmed.len;
    while (i > 0) {
        i -= 1;
        if (trimmed[i] == ' ' or trimmed[i] == '\t') {
            return .{
                .src = std.mem.trim(u8, trimmed[0..i], " \t"),
                .dest = std.mem.trim(u8, trimmed[i + 1 ..], " \t"),
                .from_stage = from_stage,
            };
        }
    }

    return .{ .src = trimmed, .dest = trimmed, .from_stage = from_stage };
}

pub fn processCopy(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8, context_dir: []const u8) types.BuildError!void {
    const split = parseCopyArgs(args);

    const file_hash = context.hashFiles(alloc, context_dir, split.src) catch return types.BuildError.CopyStepFailed;
    var file_hash_buf: [71]u8 = undefined;
    const file_hash_str = file_hash.string(&file_hash_buf);

    const cache_key = (try withCache(alloc, state, "COPY", args, file_hash_str)) orelse return;
    defer alloc.free(cache_key);

    var layer_dir_buf: [paths.max_path]u8 = undefined;
    const layer_dir = try withTempLayerDir(&layer_dir_buf, "tmp/build-copy-layer", .{});
    defer std.fs.cwd().deleteTree(layer_dir) catch {};

    var actual_dest_buf: [1024]u8 = undefined;
    const actual_dest = try resolveDestination(state.workdir, split.dest, &actual_dest_buf);

    if (actual_dest.len > 0) {
        const dest_in_layer = if (actual_dest[0] == '/') actual_dest[1..] else actual_dest;
        if (std.fs.path.dirname(dest_in_layer)) |parent| {
            var full_dir = std.fs.cwd().openDir(layer_dir, .{}) catch return types.BuildError.CopyStepFailed;
            defer full_dir.close();
            full_dir.makePath(parent) catch return types.BuildError.CopyStepFailed;
        }
    }

    context.copyFiles(context_dir, split.src, layer_dir, actual_dest) catch return types.BuildError.CopyStepFailed;

    const layer_result = layer.createLayerFromDir(alloc, layer_dir) catch return types.BuildError.LayerFailed;
    if (layer_result) |lr| {
        var digest_buf: [71]u8 = undefined;
        const compressed_str = lr.compressed_digest.string(&digest_buf);
        var diff_buf: [71]u8 = undefined;
        const diff_str = lr.uncompressed_digest.string(&diff_buf);

        state.addLayer(compressed_str, diff_str, lr.compressed_size) catch return types.BuildError.LayerFailed;
        cache.storeCache(cache_key, compressed_str, diff_str, lr.compressed_size);
    }
}

pub fn processCopyFromStage(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    src: []const u8,
    dest: []const u8,
    stage_ref: []const u8,
    stages: []const types.BuildStage,
    completed_states: []const types.BuildState,
) types.BuildError!void {
    const source_state = stages_mod.findStageByRef(stages, completed_states, stage_ref) orelse return types.BuildError.CopyStepFailed;

    var layer_paths_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (layer_paths_list.items) |p| alloc.free(p);
        layer_paths_list.deinit(alloc);
    }

    try withExtractedLayers(alloc, source_state.layer_digests.items, &layer_paths_list);
    if (layer_paths_list.items.len == 0) return;

    paths.ensureDataDir("tmp") catch return types.BuildError.CopyStepFailed;

    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf);

    var upper_buf: [paths.max_path]u8 = undefined;
    const upper_dir = paths.dataPathFmt(&upper_buf, "tmp/stage-copy-upper-{s}", .{id_buf}) catch return types.BuildError.CopyStepFailed;
    var work_buf: [paths.max_path]u8 = undefined;
    const work_dir = paths.dataPathFmt(&work_buf, "tmp/stage-copy-work-{s}", .{id_buf}) catch return types.BuildError.CopyStepFailed;
    var merged_buf: [paths.max_path]u8 = undefined;
    const merged_dir = paths.dataPathFmt(&merged_buf, "tmp/stage-copy-merged-{s}", .{id_buf}) catch return types.BuildError.CopyStepFailed;

    std.fs.cwd().makePath(upper_dir) catch return types.BuildError.CopyStepFailed;
    std.fs.cwd().makePath(work_dir) catch return types.BuildError.CopyStepFailed;
    std.fs.cwd().makePath(merged_dir) catch return types.BuildError.CopyStepFailed;

    defer {
        std.fs.cwd().deleteTree(upper_dir) catch {};
        std.fs.cwd().deleteTree(work_dir) catch {};
        const merged_z = std.posix.toPosixPath(merged_dir) catch unreachable;
        _ = linux.syscall2(.umount2, @intFromPtr(&merged_z), 0);
        std.fs.cwd().deleteTree(merged_dir) catch {};
    }

    filesystem.mountOverlay(.{
        .lower_dirs = layer_paths_list.items,
        .upper_dir = upper_dir,
        .work_dir = work_dir,
        .merged_dir = merged_dir,
    }) catch return types.BuildError.CopyStepFailed;

    var layer_dir_buf: [paths.max_path]u8 = undefined;
    const layer_dir = paths.dataPathFmt(&layer_dir_buf, "tmp/build-stage-copy-layer-{s}", .{id_buf}) catch return types.BuildError.CopyStepFailed;
    std.fs.cwd().deleteTree(layer_dir) catch {};
    std.fs.cwd().makePath(layer_dir) catch return types.BuildError.CopyStepFailed;
    defer std.fs.cwd().deleteTree(layer_dir) catch {};

    var actual_dest_buf: [1024]u8 = undefined;
    const actual_dest = try resolveDestination(state.workdir, dest, &actual_dest_buf);

    if (actual_dest.len > 0) {
        const dest_in_layer = if (actual_dest[0] == '/') actual_dest[1..] else actual_dest;
        if (std.fs.path.dirname(dest_in_layer)) |parent| {
            var full_dir = std.fs.cwd().openDir(layer_dir, .{}) catch return types.BuildError.CopyStepFailed;
            defer full_dir.close();
            full_dir.makePath(parent) catch return types.BuildError.CopyStepFailed;
        }
    }

    context.copyFiles(merged_dir, src, layer_dir, actual_dest) catch return types.BuildError.CopyStepFailed;

    const layer_result = layer.createLayerFromDir(alloc, layer_dir) catch return types.BuildError.LayerFailed;
    if (layer_result) |lr| {
        var digest_buf: [71]u8 = undefined;
        const compressed_str = lr.compressed_digest.string(&digest_buf);
        var diff_buf: [71]u8 = undefined;
        const diff_str = lr.uncompressed_digest.string(&diff_buf);
        state.addLayer(compressed_str, diff_str, lr.compressed_size) catch return types.BuildError.LayerFailed;
    }
}

pub fn processCopyMultiStage(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    args: []const u8,
    context_dir: []const u8,
    stages: []const types.BuildStage,
    completed_states: []const types.BuildState,
) types.BuildError!void {
    const split = parseCopyArgs(args);

    if (split.from_stage) |stage_ref| {
        return processCopyFromStage(alloc, state, split.src, split.dest, stage_ref, stages, completed_states);
    }

    return processCopy(alloc, state, args, context_dir);
}

pub fn isTarArchive(path: []const u8) bool {
    return std.mem.endsWith(u8, path, ".tar") or
        std.mem.endsWith(u8, path, ".tar.gz") or
        std.mem.endsWith(u8, path, ".tgz") or
        std.mem.endsWith(u8, path, ".tar.bz2") or
        std.mem.endsWith(u8, path, ".tar.xz");
}

fn processAddExtract(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8, context_dir: []const u8) types.BuildError!void {
    const split = parseCopyArgs(args);
    const src = split.src;
    const dest = split.dest;

    const file_hash = context.hashFiles(alloc, context_dir, src) catch return types.BuildError.CopyStepFailed;
    var file_hash_buf: [71]u8 = undefined;
    const file_hash_str = file_hash.string(&file_hash_buf);

    const cache_key = (try withCache(alloc, state, "ADD", args, file_hash_str)) orelse return;
    defer alloc.free(cache_key);

    var layer_dir_buf: [paths.max_path]u8 = undefined;
    const layer_dir = try withTempLayerDir(&layer_dir_buf, "tmp/build-add-layer", .{});
    defer std.fs.cwd().deleteTree(layer_dir) catch {};

    var actual_dest_buf: [1024]u8 = undefined;
    const actual_dest = try resolveDestination(state.workdir, dest, &actual_dest_buf);

    const extract_rel = if (actual_dest.len > 0 and actual_dest[0] == '/') actual_dest[1..] else actual_dest;

    var extract_dir_buf: [2048]u8 = undefined;
    const extract_dir = if (extract_rel.len > 0)
        std.fmt.bufPrint(&extract_dir_buf, "{s}/{s}", .{ layer_dir, extract_rel }) catch return types.BuildError.CopyStepFailed
    else
        layer_dir;

    std.fs.cwd().makePath(extract_dir) catch return types.BuildError.CopyStepFailed;

    var archive_path_buf: [2048]u8 = undefined;
    const archive_path = std.fmt.bufPrint(&archive_path_buf, "{s}/{s}", .{ context_dir, src }) catch return types.BuildError.CopyStepFailed;

    var child = std.process.Child.init(&[_][]const u8{ "tar", "xf", archive_path, "-C", extract_dir }, alloc);
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    const term = child.spawnAndWait() catch return types.BuildError.CopyStepFailed;
    switch (term) {
        .Exited => |code| if (code != 0) return types.BuildError.CopyStepFailed,
        else => return types.BuildError.CopyStepFailed,
    }

    const layer_result = layer.createLayerFromDir(alloc, layer_dir) catch return types.BuildError.LayerFailed;
    if (layer_result) |lr| {
        var digest_buf: [71]u8 = undefined;
        const compressed_str = lr.compressed_digest.string(&digest_buf);
        var diff_buf: [71]u8 = undefined;
        const diff_str = lr.uncompressed_digest.string(&diff_buf);

        state.addLayer(compressed_str, diff_str, lr.compressed_size) catch return types.BuildError.LayerFailed;
        cache.storeCache(cache_key, compressed_str, diff_str, lr.compressed_size);
    }
}

pub fn processAdd(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8, context_dir: []const u8) types.BuildError!void {
    const split = parseCopyArgs(args);
    if (isTarArchive(split.src)) return processAddExtract(alloc, state, args, context_dir);
    return processCopy(alloc, state, args, context_dir);
}

pub fn processAddMultiStage(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    args: []const u8,
    context_dir: []const u8,
    stages: []const types.BuildStage,
    completed_states: []const types.BuildState,
) types.BuildError!void {
    const split = parseCopyArgs(args);

    if (split.from_stage) |stage_ref| {
        return processCopyFromStage(alloc, state, split.src, split.dest, stage_ref, stages, completed_states);
    }

    return processAdd(alloc, state, args, context_dir);
}

test "parse copy args" {
    const result = parseCopyArgs("package.json /app/");
    try std.testing.expectEqualStrings("package.json", result.src);
    try std.testing.expectEqualStrings("/app/", result.dest);
}

test "parseCopyArgs — with --from flag" {
    const result = parseCopyArgs("--from=builder /app/dist /usr/share/nginx/html");
    try std.testing.expectEqualStrings("builder", result.from_stage.?);
}

test "isTarArchive detects tar extensions" {
    try std.testing.expect(isTarArchive("archive.tar"));
    try std.testing.expect(isTarArchive("archive.tar.gz"));
}
