const std = @import("std");

const context = @import("../../context.zig");
const layer = @import("../../../image/layer.zig");
const paths = @import("../../../lib/paths.zig");
const common = @import("common.zig");
const archive = @import("archive.zig");
const copy = @import("copy.zig");
const copy_args = @import("copy_args.zig");
const types = @import("../types.zig");

pub fn processAdd(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    args: []const u8,
    context_dir: []const u8,
) types.BuildError!void {
    const split = copy_args.parseCopyArgs(args);
    const format = copy_args.archiveFormat(split.src) orelse
        return copy.processCopy(alloc, state, args, context_dir);

    return processArchiveAdd(alloc, state, args, split.src, split.dest, context_dir, format);
}

pub fn processAddMultiStage(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    args: []const u8,
    context_dir: []const u8,
    stages: []const types.BuildStage,
    completed_states: []const types.BuildState,
) types.BuildError!void {
    const split = copy_args.parseCopyArgs(args);
    if (split.from_stage) |stage_ref| {
        return copy.processCopyFromStage(alloc, state, split.src, split.dest, stage_ref, stages, completed_states);
    }
    return processAdd(alloc, state, args, context_dir);
}

fn processArchiveAdd(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    args: []const u8,
    src: []const u8,
    dest: []const u8,
    context_dir: []const u8,
    format: copy_args.ArchiveFormat,
) types.BuildError!void {
    const file_hash = context.hashFiles(alloc, context_dir, src) catch
        return types.BuildError.CopyStepFailed;
    var file_hash_buf: [71]u8 = undefined;
    const file_hash_str = file_hash.string(&file_hash_buf);

    const cache_key = (try common.withCache(alloc, state, "ADD", args, file_hash_str)) orelse return;
    defer alloc.free(cache_key);

    var layer_dir_buf: [paths.max_path]u8 = undefined;
    const layer_dir = try common.withTempLayerDir(&layer_dir_buf, "build-add-layer");
    defer std.fs.cwd().deleteTree(layer_dir) catch {};

    var actual_dest_buf: [paths.max_path]u8 = undefined;
    const actual_dest = try common.resolveDestination(state.workdir, dest, &actual_dest_buf);
    const extract_rel = if (actual_dest.len > 0 and actual_dest[0] == '/') actual_dest[1..] else actual_dest;

    var extract_dir_buf: [paths.max_path]u8 = undefined;
    const extract_dir = if (extract_rel.len > 0)
        std.fmt.bufPrint(&extract_dir_buf, "{s}/{s}", .{ layer_dir, extract_rel }) catch
            return types.BuildError.CopyStepFailed
    else
        layer_dir;
    std.fs.cwd().makePath(extract_dir) catch return types.BuildError.CopyStepFailed;

    const archive_path = buildArchivePath(alloc, context_dir, src) catch
        return types.BuildError.CopyStepFailed;
    defer alloc.free(archive_path);

    archive.extractArchive(alloc, archive_path, format, extract_dir) catch
        return types.BuildError.CopyStepFailed;

    const layer_result = layer.createLayerFromDir(alloc, layer_dir) catch return types.BuildError.LayerFailed;
    if (layer_result) |lr| try common.commitLayerResult(state, lr, cache_key);
}

fn buildArchivePath(
    alloc: std.mem.Allocator,
    context_dir: []const u8,
    src: []const u8,
) ![]u8 {
    return std.fs.path.join(alloc, &.{ context_dir, src });
}
