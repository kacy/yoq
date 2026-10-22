const std = @import("std");

const context = @import("../../context.zig");
const layer = @import("../../../image/layer.zig");
const paths = @import("../../../lib/paths.zig");
const common = @import("common.zig");
const archive = @import("archive.zig");
const copy = @import("copy.zig");
const copy_args = @import("copy_args.zig");
const types = @import("../types.zig");

fn cwd() std.Io.Dir {
    return std.Io.Dir.cwd();
}

pub fn processAdd(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    args: []const u8,
    context_dir: []const u8,
) types.BuildError!void {
    const split = try copy.parseArgs(args);
    const sources = split.sources();
    for (sources) |src| {
        const format = copy_args.archiveFormat(src) orelse continue;
        if (sources.len > 1) {
            @import("../../../lib/log.zig").err("build: ADD extracts one archive per step; split '{s}' into separate steps", .{args});
            return types.BuildError.CopyStepFailed;
        }
        return processArchiveAdd(alloc, state, args, src, split.dest, context_dir, format);
    }
    return copy.processCopy(alloc, state, args, context_dir);
}

pub fn processAddMultiStage(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    args: []const u8,
    context_dir: []const u8,
    stages: []const types.BuildStage,
    completed_states: []const types.BuildState,
) types.BuildError!void {
    const split = try copy.parseArgs(args);
    if (split.from_stage) |stage_ref| {
        return copy.processCopyFromStage(alloc, state, split.sources(), split.dest, stage_ref, stages, completed_states);
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
    var actual_dest_buf: [paths.max_path]u8 = undefined;
    const actual_dest = try common.Destination.resolve(state.workdir, dest, &actual_dest_buf);

    const file_hash = context.hashFiles(alloc, context_dir, src) catch
        return types.BuildError.CopyStepFailed;
    var file_hash_buf: [71]u8 = undefined;
    const file_hash_str = file_hash.string(&file_hash_buf);

    const cache_key = (try common.withCache(alloc, state, "ADD", args, file_hash_str, actual_dest.path)) orelse return;
    defer alloc.free(cache_key);

    var layer_dir_buf: [paths.max_path]u8 = undefined;
    const layer_dir = try common.withTempLayerDir(&layer_dir_buf, "build-add-layer");
    defer cwd().deleteTree(std.Options.debug_io, layer_dir) catch {};

    var extract_dir_buf: [paths.max_path]u8 = undefined;
    const extract_dir = try actual_dest.createDirectory(layer_dir, &extract_dir_buf);

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
    return std.fs.path.join(alloc, &.{ context_dir, try context.rootRelative(src) });
}
