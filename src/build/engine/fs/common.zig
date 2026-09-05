const std = @import("std");

const blob_store = @import("../../../image/store.zig");
const layer = @import("../../../image/layer.zig");
const paths = @import("../../../lib/paths.zig");
const cache = @import("../cache.zig");
const types = @import("../types.zig");

fn cwd() std.Io.Dir {
    return std.Io.Dir.cwd();
}

pub fn commitLayerResult(
    state: *types.BuildState,
    lr: anytype,
    cache_key: ?[]const u8,
) types.BuildError!void {
    var compressed_buf: [71]u8 = undefined;
    const compressed_str = lr.compressed_digest.string(&compressed_buf);
    var diff_buf: [71]u8 = undefined;
    const diff_str = lr.uncompressed_digest.string(&diff_buf);
    state.addLayer(compressed_str, diff_str, lr.compressed_size) catch return types.BuildError.LayerFailed;
    if (cache_key) |key| cache.storeCache(key, compressed_str, diff_str, lr.compressed_size);
}

/// A normalized container path, borrowed from the caller's buffer. Resolve
/// it before cache lookup or filesystem work so rejected input has no effects.
pub const Destination = struct {
    path: []const u8,

    pub fn resolve(workdir: []const u8, dest: []const u8, out: []u8) types.BuildError!Destination {
        if (dest.len == 0 or out.len == 0) return types.BuildError.CopyStepFailed;
        out[0] = '/';
        var len: usize = 1;
        if (dest[0] != '/') try appendComponents(out, &len, workdir);
        try appendComponents(out, &len, dest);
        // COPY uses a trailing slash to distinguish a directory destination.
        if (len > 1 and (dest[dest.len - 1] == '/' or std.mem.eql(u8, std.fs.path.basename(dest), "."))) {
            if (len == out.len) return types.BuildError.CopyStepFailed;
            out[len] = '/';
            len += 1;
        }
        return .{ .path = out[0..len] };
    }

    fn appendComponents(out: []u8, len: *usize, path: []const u8) types.BuildError!void {
        if (std.mem.indexOfScalar(u8, path, 0) != null) return types.BuildError.CopyStepFailed;
        var parts = std.mem.tokenizeScalar(u8, path, '/');
        while (parts.next()) |part| {
            if (std.mem.eql(u8, part, "..")) return types.BuildError.CopyStepFailed;
            if (std.mem.eql(u8, part, ".")) continue;
            const separator: usize = if (len.* > 1) 1 else 0;
            if (separator > out.len - len.* or part.len > out.len - len.* - separator) return types.BuildError.CopyStepFailed;
            if (separator != 0) {
                out[len.*] = '/';
                len.* += 1;
            }
            @memcpy(out[len.*..][0..part.len], part);
            len.* += part.len;
        }
    }

    pub fn ensureParents(self: Destination, layer_dir: []const u8) types.BuildError!void {
        const relative = self.path[1..];
        if (std.fs.path.dirname(relative)) |parent| {
            var dir = cwd().openDir(std.Options.debug_io, layer_dir, .{}) catch return types.BuildError.CopyStepFailed;
            defer dir.close(std.Options.debug_io);
            dir.createDirPath(std.Options.debug_io, parent) catch return types.BuildError.CopyStepFailed;
        }
    }

    pub fn createDirectory(self: Destination, layer_dir: []const u8, out: []u8) types.BuildError![]const u8 {
        const path = std.fmt.bufPrint(out, "{s}{s}", .{ layer_dir, self.path }) catch return types.BuildError.CopyStepFailed;
        cwd().createDirPath(std.Options.debug_io, path) catch return types.BuildError.CopyStepFailed;
        return path;
    }
};

pub fn withTempLayerDir(
    out_path: *[paths.max_path]u8,
    prefix: []const u8,
) types.BuildError![]const u8 {
    paths.ensureDataDir("tmp") catch return types.BuildError.CopyStepFailed;
    const layer_dir = paths.uniqueDataTempPath(out_path, "tmp", prefix, "") catch
        return types.BuildError.CopyStepFailed;
    cwd().createDirPath(std.Options.debug_io, layer_dir) catch return types.BuildError.CopyStepFailed;
    return layer_dir;
}

pub fn withExtractedLayers(
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

pub fn withCache(
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

    const cache_key = cache.computeCacheKey(alloc, instruction, args, state) catch
        return types.BuildError.CacheFailed;
    if (cache.checkCache(alloc, cache_key, state)) {
        alloc.free(cache_key);
        return null;
    }
    return cache_key;
}

test "build destination rejects traversal and preserves container path semantics" {
    var buf: [128]u8 = undefined;
    const cases = [_]struct { workdir: []const u8, input: []const u8, expected: []const u8 }{
        .{ .workdir = "/work", .input = "out/", .expected = "/work/out/" },
        .{ .workdir = "/work", .input = "///etc//./config", .expected = "/etc/config" },
        .{ .workdir = "/work", .input = ".", .expected = "/work/" },
        .{ .workdir = "/work", .input = "/", .expected = "/" },
        .{ .workdir = "work", .input = "some..file", .expected = "/work/some..file" },
    };
    for (cases) |case| {
        const dest = try Destination.resolve(case.workdir, case.input, &buf);
        try std.testing.expectEqualStrings(case.expected, dest.path);
    }
    for ([_][]const u8{ "../outside", "/../outside", "sub/../../outside", "", "bad\x00name" }) |input| {
        try std.testing.expectError(error.CopyStepFailed, Destination.resolve("/work", input, &buf));
    }
    try std.testing.expectError(error.CopyStepFailed, Destination.resolve("/../outside", "file", &buf));
    try std.testing.expectError(error.CopyStepFailed, Destination.resolve("/", "long", buf[0..2]));
}

test "build destination keeps absolute COPY and archive ADD paths inside a layer" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "layer", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "source", .data = "copied" });
    var root_buf: [paths.max_path]u8 = undefined;
    const root_len = try tmp.dir.realPath(io, &root_buf);
    const root = root_buf[0..root_len];
    var layer_buf: [paths.max_path]u8 = undefined;
    const layer_dir = try std.fmt.bufPrint(&layer_buf, "{s}/layer", .{root});
    var dest_buf: [paths.max_path]u8 = undefined;
    const copy_dest = try Destination.resolve("/work", "///etc//config", &dest_buf);
    try copy_dest.ensureParents(layer_dir);
    try @import("../../context.zig").copyFiles(alloc, root, "source", layer_dir, copy_dest.path);
    const copied = try tmp.dir.readFileAlloc(io, "layer/etc/config", alloc, .limited(32));
    defer alloc.free(copied);
    try std.testing.expectEqualStrings("copied", copied);

    var output: std.Io.Writer.Allocating = .init(alloc);
    defer output.deinit();
    var tar: std.tar.Writer = .{ .underlying_writer = &output.writer };
    try tar.writeFileBytes("payload", "extracted", .{});
    try tar.finishPedantically();
    try tmp.dir.writeFile(io, .{ .sub_path = "source.tar", .data = output.written() });
    var archive_buf: [paths.max_path]u8 = undefined;
    const archive_path = try std.fmt.bufPrint(&archive_buf, "{s}/source.tar", .{root});
    const add_dest = try Destination.resolve("/work", "///opt//./data/", &dest_buf);
    var extract_buf: [paths.max_path]u8 = undefined;
    const extract_path = try add_dest.createDirectory(layer_dir, &extract_buf);
    try @import("archive.zig").extractArchive(alloc, archive_path, .tar, extract_path);
    const extracted = try tmp.dir.readFileAlloc(io, "layer/opt/data/payload", alloc, .limited(32));
    defer alloc.free(extracted);
    try std.testing.expectEqualStrings("extracted", extracted);
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "etc", .{}));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "opt", .{}));
}

test "build destination is rejected before hashing cache lookup or stage extraction" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "input.tar", .data = "input" });
    var root_buf: [paths.max_path]u8 = undefined;
    const root_len = try tmp.dir.realPath(std.testing.io, &root_buf);
    const root = root_buf[0..root_len];
    var state = types.BuildState.init(std.testing.allocator);
    defer state.deinit();
    for ([_][]const u8{ "input.tar ../outside/", "input.tar /../../outside/" }) |args| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        try std.testing.expectError(error.CopyStepFailed, @import("add.zig").processAdd(failing.allocator(), &state, args, root));
        try std.testing.expectError(error.CopyStepFailed, @import("copy.zig").processCopy(failing.allocator(), &state, args, root));
        // Hashing uses allocation. Rejecting before even that read-side work
        // also rules out consulting a cached layer or creating temp paths.
        try std.testing.expect(!failing.has_induced_failure);
    }
    state.workdir = try std.testing.allocator.dupe(u8, "/../outside");
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.CopyStepFailed, @import("add.zig").processAdd(failing.allocator(), &state, "input.tar relative/", root));
    try std.testing.expectError(error.CopyStepFailed, @import("copy.zig").processCopy(failing.allocator(), &state, "input.tar relative/", root));
    try std.testing.expect(!failing.has_induced_failure);
    const completed = [_]types.BuildState{types.BuildState.init(std.testing.allocator)};
    try std.testing.expectError(error.CopyStepFailed, @import("copy.zig").processCopyFromStage(std.testing.allocator, &state, "/source", "../../outside", "0", &.{}, &completed));
}
