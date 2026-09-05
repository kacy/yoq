const std = @import("std");
const blob_store = @import("../../image/store.zig");
const state_store = @import("../../state/store.zig");
const log = @import("../../lib/log.zig");
const types = @import("types.zig");

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

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
    return computeCacheKeyWithContext(alloc, instruction, args, state, null, null);
}

pub fn computeCacheKeyWithContext(
    alloc: std.mem.Allocator,
    instruction: []const u8,
    args: []const u8,
    state: *const types.BuildState,
    source_hash: ?[]const u8,
    destination: ?[]const u8,
) ![]const u8 {
    var hasher = @import("../hash_encoding.zig").Hasher.init("yoq.build-cache.v2");
    hasher.bytes(instruction);
    hasher.bytes(args);
    hasher.number(state.layers.items.len);
    for (state.layers.items) |item| {
        hasher.bytes(item.digest);
        hasher.bytes(item.diff_id);
        hasher.number(item.size);
    }
    hasher.bytes(state.workdir);
    hasher.optional(state.user);
    hasher.optional(state.shell);
    hasher.number(state.env.items.len);
    for (state.env.items) |env| hasher.bytes(env);
    hasher.optional(source_hash);
    hasher.optional(destination);

    const digest = blob_store.Digest{ .hash = hasher.hash.finalResult() };
    var buf: [71]u8 = undefined;
    return try alloc.dupe(u8, digest.string(&buf));
}

pub fn checkCache(alloc: std.mem.Allocator, cache_key: []const u8, state: *types.BuildState) bool {
    const entry = state_store.lookupBuildCache(alloc, cache_key) catch return false;
    if (entry) |e| {
        defer e.deinit(alloc);

        const cached_digest = blob_store.Digest.parse(e.layer_digest) orelse return false;
        if (!blob_store.verifyBlob(cached_digest)) return false;

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
        .created_at = nowRealSeconds(),
    }) catch |err| {
        log.warn("failed to store build cache: {}", .{err});
    };
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

test "build identity retains lower ancestry when last layers match" {
    const alloc = std.testing.allocator;
    var left = types.BuildState.init(alloc);
    defer left.deinit();
    var right = types.BuildState.init(alloc);
    defer right.deinit();
    try left.addLayer("base-left", "diff-left", 1);
    try right.addLayer("base-right", "diff-right", 1);
    try left.addLayer("common-last", "common-diff", 2);
    try right.addLayer("common-last", "common-diff", 2);
    const left_key = try computeCacheKey(alloc, "RUN", "cat /base", &left);
    defer alloc.free(left_key);
    const right_key = try computeCacheKey(alloc, "RUN", "cat /base", &right);
    defer alloc.free(right_key);
    try std.testing.expect(!std.mem.eql(u8, left_key, right_key));
}

test "build identity includes effective workdir user and destination" {
    const alloc = std.testing.allocator;
    var state = types.BuildState.init(alloc);
    defer state.deinit();
    const initial = try computeCacheKey(alloc, "RUN", "id > result", &state);
    defer alloc.free(initial);
    state.workdir = try alloc.dupe(u8, "/work");
    const moved = try computeCacheKey(alloc, "RUN", "id > result", &state);
    defer alloc.free(moved);
    try std.testing.expect(!std.mem.eql(u8, initial, moved));
    state.user = try alloc.dupe(u8, "1000:1000");
    const user = try computeCacheKey(alloc, "RUN", "id > result", &state);
    defer alloc.free(user);
    try std.testing.expect(!std.mem.eql(u8, moved, user));
    for ([_][]const u8{ "COPY", "ADD" }) |instruction| {
        const left = try computeCacheKeyWithContext(alloc, instruction, "source relative", &state, "same-source", "/left/relative");
        defer alloc.free(left);
        const right = try computeCacheKeyWithContext(alloc, instruction, "source relative", &state, "same-source", "/right/relative");
        defer alloc.free(right);
        try std.testing.expect(!std.mem.eql(u8, left, right));
    }
}

test "build identity separates newline-containing environment fields" {
    const alloc = std.testing.allocator;
    var left = types.BuildState.init(alloc);
    defer left.deinit();
    var right = types.BuildState.init(alloc);
    defer right.deinit();
    try left.env.append(alloc, try alloc.dupe(u8, "A=x\nB=y"));
    try right.env.append(alloc, try alloc.dupe(u8, "A=x"));
    try right.env.append(alloc, try alloc.dupe(u8, "B=y"));
    const left_key = try computeCacheKey(alloc, "RUN", "env", &left);
    defer alloc.free(left_key);
    const right_key = try computeCacheKey(alloc, "RUN", "env", &right);
    defer alloc.free(right_key);
    try std.testing.expect(!std.mem.eql(u8, left_key, right_key));
}
