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

fn cwd() std.Io.Dir {
    return std.Io.Dir.cwd();
}

pub fn processCopy(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    args: []const u8,
    context_dir: []const u8,
) types.BuildError!void {
    const split = try parseArgs(args);
    var actual_dest_buf: [paths.max_path]u8 = undefined;
    const actual_dest = try common.Destination.resolve(state.workdir, split.dest, &actual_dest_buf);

    var file_hash_buf: [71]u8 = undefined;
    const file_hash_str = try hashSources(alloc, context_dir, split.sources(), &file_hash_buf);

    const cache_key = (try common.withCache(alloc, state, "COPY", args, file_hash_str, actual_dest.path)) orelse return;
    defer alloc.free(cache_key);

    var layer_dir_buf: [paths.max_path]u8 = undefined;
    const layer_dir = try common.withTempLayerDir(&layer_dir_buf, "build-copy-layer");
    defer cwd().deleteTree(std.Options.debug_io, layer_dir) catch {};

    try actual_dest.ensureParents(layer_dir);
    try copySources(alloc, context_dir, split.sources(), layer_dir, actual_dest.path);

    const layer_result = layer.createLayerFromDir(alloc, layer_dir) catch return types.BuildError.LayerFailed;
    if (layer_result) |lr| try common.commitLayerResult(state, lr, cache_key);
}

/// parse COPY or ADD arguments, logging why a step is refused.
pub fn parseArgs(args: []const u8) types.BuildError!types.CopyArgs {
    return copy_args.parseCopyArgs(args) catch |err| {
        log.err("build: cannot use COPY/ADD arguments '{s}': {s}", .{ args, @errorName(err) });
        return types.BuildError.CopyStepFailed;
    };
}

/// one digest for the cache key. a single source keeps its own digest, so
/// cache entries from before multi-source support stay valid.
fn hashSources(alloc: std.mem.Allocator, root: []const u8, sources: []const []const u8, out: *[71]u8) types.BuildError![]const u8 {
    if (sources.len == 1) {
        const digest = context.hashFiles(alloc, root, sources[0]) catch return types.BuildError.CopyStepFailed;
        return digest.string(out);
    }
    var combined = std.crypto.hash.sha2.Sha256.init(.{});
    for (sources) |src| {
        const digest = context.hashFiles(alloc, root, src) catch return types.BuildError.CopyStepFailed;
        var buf: [71]u8 = undefined;
        combined.update(digest.string(&buf));
    }
    const hex = std.fmt.bytesToHex(combined.finalResult(), .lower);
    return std.fmt.bufPrint(out, "sha256:{s}", .{&hex}) catch types.BuildError.CopyStepFailed;
}

fn copySources(alloc: std.mem.Allocator, root: []const u8, sources: []const []const u8, layer_dir: []const u8, dest: []const u8) types.BuildError!void {
    for (sources) |src| {
        context.copyFiles(alloc, root, src, layer_dir, dest) catch return types.BuildError.CopyStepFailed;
    }
}

pub fn processCopyFromStage(
    alloc: std.mem.Allocator,
    state: *types.BuildState,
    sources: []const []const u8,
    dest: []const u8,
    stage_ref: []const u8,
    stages: []const types.BuildStage,
    completed_states: []const types.BuildState,
) types.BuildError!void {
    var actual_dest_buf: [paths.max_path]u8 = undefined;
    const actual_dest = try common.Destination.resolve(state.workdir, dest, &actual_dest_buf);

    const source_state = stages_mod.findStageByRef(stages, completed_states, stage_ref) orelse
        return types.BuildError.CopyStepFailed;

    var layer_paths_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer {
        for (layer_paths_list.items) |path| alloc.free(path);
        layer_paths_list.deinit(alloc);
    }

    try common.withExtractedLayers(alloc, source_state.layers.items, &layer_paths_list);
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

    cwd().createDirPath(std.Options.debug_io, upper_dir) catch return types.BuildError.CopyStepFailed;
    cwd().createDirPath(std.Options.debug_io, work_dir) catch return types.BuildError.CopyStepFailed;
    cwd().createDirPath(std.Options.debug_io, merged_dir) catch return types.BuildError.CopyStepFailed;

    defer {
        cwd().deleteTree(std.Options.debug_io, upper_dir) catch {};
        cwd().deleteTree(std.Options.debug_io, work_dir) catch {};
        if (std.posix.toPosixPath(merged_dir)) |merged_z| {
            _ = linux.syscall2(.umount2, @intFromPtr(&merged_z), 0);
        } else |_| {
            log.warn("copy handler: merged_dir path too long for unmount", .{});
        }
        cwd().deleteTree(std.Options.debug_io, merged_dir) catch {};
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
    cwd().deleteTree(std.Options.debug_io, layer_dir) catch {};
    cwd().createDirPath(std.Options.debug_io, layer_dir) catch return types.BuildError.CopyStepFailed;
    defer cwd().deleteTree(std.Options.debug_io, layer_dir) catch {};

    try actual_dest.ensureParents(layer_dir);
    try copySources(alloc, merged_dir, sources, layer_dir, actual_dest.path);

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
    const split = try parseArgs(args);
    if (split.from_stage) |stage_ref| {
        return processCopyFromStage(alloc, state, split.sources(), split.dest, stage_ref, stages, completed_states);
    }
    return processCopy(alloc, state, args, context_dir);
}

test "several COPY sources land in one destination directory" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "layer", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "build.zig", .data = "one" });
    try tmp.dir.writeFile(io, .{ .sub_path = "build.zig.zon", .data = "two" });
    var root_buf: [paths.max_path]u8 = undefined;
    const root = root_buf[0..try tmp.dir.realPath(io, &root_buf)];
    var layer_buf: [paths.max_path]u8 = undefined;
    const layer_dir = try std.fmt.bufPrint(&layer_buf, "{s}/layer", .{root});

    // the first lines of this repo's own Dockerfile
    const split = try parseArgs("build.zig build.zig.zon ./");
    var dest_buf: [paths.max_path]u8 = undefined;
    const dest = try common.Destination.resolve("/src", split.dest, &dest_buf);
    try dest.ensureParents(layer_dir);
    try copySources(alloc, root, split.sources(), layer_dir, dest.path);

    var buf: [8]u8 = undefined;
    try std.testing.expectEqualStrings("one", try tmp.dir.readFile(io, "layer/src/build.zig", &buf));
    try std.testing.expectEqualStrings("two", try tmp.dir.readFile(io, "layer/src/build.zig.zon", &buf));

    // the cache key changes when any source changes
    var first_buf: [71]u8 = undefined;
    const first = try hashSources(alloc, root, split.sources(), &first_buf);
    try tmp.dir.writeFile(io, .{ .sub_path = "build.zig.zon", .data = "changed" });
    var second_buf: [71]u8 = undefined;
    try std.testing.expect(!std.mem.eql(u8, first, try hashSources(alloc, root, split.sources(), &second_buf)));
}
