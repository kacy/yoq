const std = @import("std");
const blob_store = @import("../../image/store.zig");
const state_store = @import("../../state/store.zig");
const log = @import("../../lib/log.zig");
const types = @import("types.zig");
const context = @import("../context.zig");

pub const CacheStoreResult = struct {
    layer_digest: []const u8,
    diff_id: []const u8,
    size: u64,
};

pub fn computeCacheKey(
    alloc: std.mem.Allocator,
    instruction: []const u8,
    args: []const u8,
    state: *const types.BuildState,
) ![]const u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(instruction);
    hasher.update("\n");
    hasher.update(args);
    hasher.update("\n");
    hasher.update(state.parent_digest);
    hasher.update("\n");

    for (state.env.items) |env| {
        hasher.update(env);
        hasher.update("\n");
    }

    if (state.shell) |sh| {
        hasher.update("shell:");
        hasher.update(sh);
        hasher.update("\n");
    }

    const digest = blob_store.Digest{ .hash = hasher.finalResult() };
    var buf: [71]u8 = undefined;
    return try alloc.dupe(u8, digest.string(&buf));
}

pub fn checkCache(alloc: std.mem.Allocator, cache_key: []const u8, state: *types.BuildState) bool {
    const entry = state_store.lookupBuildCache(alloc, cache_key) catch return false;
    if (entry) |e| {
        defer e.deinit(alloc);

        const cached_digest = blob_store.Digest.parse(e.layer_digest) orelse return false;
        if (!blob_store.hasBlob(cached_digest)) return false;

        log.info("  -> cached", .{});
        state.addLayer(e.layer_digest, e.diff_id, @intCast(e.layer_size)) catch return false;
        return true;
    }
    return false;
}

pub fn storeCache(cache_key: []const u8, layer_digest: []const u8, diff_id: []const u8, size: u64) void {
    state_store.storeBuildCache(.{
        .cache_key = cache_key,
        .layer_digest = layer_digest,
        .diff_id = diff_id,
        .layer_size = @intCast(size),
        .created_at = std.time.timestamp(),
    }) catch |err| {
        log.warn("failed to store build cache: {}", .{err});
    };
}

/// compute cache key for COPY/ADD operations including file content hash.
/// this ensures that changing source files invalidates the cache.
pub fn computeCacheKeyWithContent(
    alloc: std.mem.Allocator,
    instruction: []const u8,
    args: []const u8,
    state: *const types.BuildState,
    context_dir: []const u8,
    src_path: []const u8,
) ![]const u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(instruction);
    hasher.update("\n");
    hasher.update(args);
    hasher.update("\n");
    hasher.update(state.parent_digest);
    hasher.update("\n");

    // include file content hash for proper cache invalidation
    const content_hash = context.hashFiles(alloc, context_dir, src_path) catch |e| {
        log.warn("build: failed to hash source files for cache key: {s}", .{@errorName(e)});
        // if we can't hash, use a placeholder to avoid caching
        hasher.update("ERROR:");
        hasher.update(@errorName(e));
        hasher.update("\n");
        // continue with rest of cache key computation
        return computeCacheKey(alloc, instruction, args, state);
    };
    hasher.update("content:");
    hasher.update(&content_hash.hash);
    hasher.update("\n");

    for (state.env.items) |env| {
        hasher.update(env);
        hasher.update("\n");
    }

    if (state.shell) |sh| {
        hasher.update("shell:");
        hasher.update(sh);
        hasher.update("\n");
    }

    const digest = blob_store.Digest{ .hash = hasher.finalResult() };
    var buf: [71]u8 = undefined;
    return try alloc.dupe(u8, digest.string(&buf));
}

test "compute cache key determinism" {
    const alloc = std.testing.allocator;
    var state1 = types.BuildState.init(alloc);
    defer state1.deinit();
    var state2 = types.BuildState.init(alloc);
    defer state2.deinit();

    const key1 = try computeCacheKey(alloc, "RUN", "echo hello", &state1);
    defer alloc.free(key1);
    const key2 = try computeCacheKey(alloc, "RUN", "echo hello", &state2);
    defer alloc.free(key2);

    try std.testing.expectEqualStrings(key1, key2);
}

test "cache key changes when shell changes" {
    const alloc = std.testing.allocator;

    var state1 = types.BuildState.init(alloc);
    defer state1.deinit();

    var state2 = types.BuildState.init(alloc);
    defer state2.deinit();
    state2.shell = try alloc.dupe(u8, "[\"/bin/bash\", \"-c\"]");

    const key1 = try computeCacheKey(alloc, "RUN", "echo hello", &state1);
    defer alloc.free(key1);
    const key2 = try computeCacheKey(alloc, "RUN", "echo hello", &state2);
    defer alloc.free(key2);

    try std.testing.expect(!std.mem.eql(u8, key1, key2));
}
