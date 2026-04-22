const std = @import("std");
const linux = std.os.linux;

const context = @import("../../context.zig");
const layer = @import("../../../image/layer.zig");
const container = @import("../../../runtime/container.zig");
const filesystem = @import("../../../runtime/filesystem.zig");
const paths = @import("../../../lib/paths.zig");
const log = @import("../../../lib/log.zig");
const stages_mod = @import("../stages.zig");
const common = @import("common.zig");
const copy_args = @import("copy_args.zig");
const types = @import("../types.zig");

pub fn processCopy(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    args: []const u8,
    context_dir: []const u8,
) types.BuildError!void {
    const split = copy_args.parseCopyArgs(args);

    const file_hash = context.hashFiles(alloc, context_dir, split.src) catch
        return types.BuildError.CopyStepFailed;
    var file_hash_buf: [71]u8 = undefined;
    const file_hash_str = file_hash.string(&file_hash_buf);

    const cache_key = (try common.withCache(alloc, state, "COPY", args, file_hash_str)) orelse return;
    defer alloc.free(cache_key);

    var layer_dir_buf: [paths.max_path]u8 = undefined;
    const layer_dir = try common.withTempLayerDir(&layer_dir_buf, "build-copy-layer");
    defer @import("compat").cwd().deleteTree(layer_dir) catch {};

    var actual_dest_buf: [paths.max_path]u8 = undefined;
    const actual_dest = try common.resolveDestination(state.workdir, split.dest, &actual_dest_buf);

    try common.ensureDestParents(layer_dir, actual_dest);
    context.copyFiles(alloc, context_dir, split.src, layer_dir, actual_dest) catch
        return types.BuildError.CopyStepFailed;

    const layer_result = layer.createLayerFromDir(alloc, layer_dir) catch return types.BuildError.LayerFailed;
    if (layer_result) |lr| try common.commitLayerResult(state, lr, cache_key);
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
    const source_state = stages_mod.findStageByRef(stages, completed_states, stage_ref) orelse
        return types.BuildError.CopyStepFailed;

    var layer_paths_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (layer_paths_list.items) |path| alloc.free(path);
        layer_paths_list.deinit(alloc);
    }

    try common.withExtractedLayers(alloc, source_state.layer_digests.items, &layer_paths_list);
    if (layer_paths_list.items.len == 0) return;

    paths.ensureDataDir("tmp") catch return types.BuildError.CopyStepFailed;

    var id_buf: [12]u8 = undefined;
    container.generateId(&id_buf) catch return types.BuildError.CopyStepFailed;

    var upper_buf: [paths.max_path]u8 = undefined;
    const upper_dir = paths.dataPathFmt(&upper_buf, "tmp/stage-copy-upper-{s}", .{id_buf}) catch
        return types.BuildError.CopyStepFailed;
    var work_buf: [paths.max_path]u8 = undefined;
    const work_dir = paths.dataPathFmt(&work_buf, "tmp/stage-copy-work-{s}", .{id_buf}) catch
        return types.BuildError.CopyStepFailed;
    var merged_buf: [paths.max_path]u8 = undefined;
    const merged_dir = paths.dataPathFmt(&merged_buf, "tmp/stage-copy-merged-{s}", .{id_buf}) catch
        return types.BuildError.CopyStepFailed;

    @import("compat").cwd().makePath(upper_dir) catch return types.BuildError.CopyStepFailed;
    @import("compat").cwd().makePath(work_dir) catch return types.BuildError.CopyStepFailed;
    @import("compat").cwd().makePath(merged_dir) catch return types.BuildError.CopyStepFailed;

    defer {
        @import("compat").cwd().deleteTree(upper_dir) catch {};
        @import("compat").cwd().deleteTree(work_dir) catch {};
        if (std.posix.toPosixPath(merged_dir)) |merged_z| {
            _ = linux.syscall2(.umount2, @intFromPtr(&merged_z), 0);
        } else |_| {
            log.warn("copy handler: merged_dir path too long for unmount", .{});
        }
        @import("compat").cwd().deleteTree(merged_dir) catch {};
    }

    filesystem.mountOverlay(.{
        .lower_dirs = layer_paths_list.items,
        .upper_dir = upper_dir,
        .work_dir = work_dir,
        .merged_dir = merged_dir,
    }) catch return types.BuildError.CopyStepFailed;

    var layer_dir_buf: [paths.max_path]u8 = undefined;
    const layer_dir = paths.dataPathFmt(&layer_dir_buf, "tmp/build-stage-copy-layer-{s}", .{id_buf}) catch
        return types.BuildError.CopyStepFailed;
    @import("compat").cwd().deleteTree(layer_dir) catch {};
    @import("compat").cwd().makePath(layer_dir) catch return types.BuildError.CopyStepFailed;
    defer @import("compat").cwd().deleteTree(layer_dir) catch {};

    var actual_dest_buf: [paths.max_path]u8 = undefined;
    const actual_dest = try common.resolveDestination(state.workdir, dest, &actual_dest_buf);

    try common.ensureDestParents(layer_dir, actual_dest);
    context.copyFiles(alloc, merged_dir, src, layer_dir, actual_dest) catch
        return types.BuildError.CopyStepFailed;

    const layer_result = layer.createLayerFromDir(alloc, layer_dir) catch return types.BuildError.LayerFailed;
    if (layer_result) |lr| try common.commitLayerResult(state, lr, null);
}

pub fn processCopyMultiStage(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    args: []const u8,
    context_dir: []const u8,
    stages: []const types.BuildStage,
    completed_states: []const types.BuildState,
) types.BuildError!void {
    const split = copy_args.parseCopyArgs(args);
    if (split.from_stage) |stage_ref| {
        return processCopyFromStage(alloc, state, split.src, split.dest, stage_ref, stages, completed_states);
    }
    return processCopy(alloc, state, args, context_dir);
}
