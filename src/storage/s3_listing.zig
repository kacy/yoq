const std = @import("std");
const paths = @import("../lib/paths.zig");
const s3 = @import("s3.zig");
const io = std.Options.debug_io;

pub const Page = struct {
    objects: []s3.ObjectEntry,
    truncated: bool,

    pub fn deinit(self: Page, alloc: std.mem.Allocator) void {
        for (self.objects) |entry| alloc.free(entry.key);
        alloc.free(self.objects);
    }
};

fn latestKeyFirst(_: void, a: []const u8, b: []const u8) std.math.Order {
    return std.mem.order(u8, b, a);
}

/// retain at most one page plus a lookahead key while scanning the bucket.
/// a continuation token is the hex-encoded last key of the preceding page.
pub fn list(alloc: std.mem.Allocator, bucket: []const u8, prefix: []const u8, after: []const u8, max_keys: usize) !Page {
    try s3.validateBucketName(bucket);
    if (max_keys > 1000) return error.InvalidArgument;
    var path_buf: [paths.max_path]u8 = undefined;
    const path = try paths.dataPathFmt(&path_buf, "s3/{s}", .{bucket});
    var dir = std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return error.BucketNotFound,
        else => return err,
    };
    defer dir.close(io);
    if (max_keys == 0) return .{ .objects = try alloc.alloc(s3.ObjectEntry, 0), .truncated = false };

    var keys = std.PriorityQueue([]const u8, void, latestKeyFirst).initContext({});
    defer {
        for (keys.items) |key| alloc.free(key);
        keys.deinit(alloc);
    }
    var walker = try dir.walk(alloc);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.startsWith(u8, entry.path, prefix)) continue;
        if (after.len != 0 and std.mem.order(u8, entry.path, after) != .gt) continue;
        if (keys.count() == max_keys + 1) {
            if (std.mem.order(u8, entry.path, keys.peek().?) != .lt) continue;
            alloc.free(keys.pop().?);
        }
        const key = try alloc.dupe(u8, entry.path);
        keys.push(alloc, key) catch |err| {
            alloc.free(key);
            return err;
        };
    }

    const truncated = keys.count() > max_keys;
    if (truncated) alloc.free(keys.pop().?);
    const objects = try alloc.alloc(s3.ObjectEntry, keys.count());
    var initialized: usize = 0;
    errdefer {
        for (objects[objects.len - initialized ..]) |entry| alloc.free(entry.key);
        alloc.free(objects);
    }
    while (keys.peek()) |key| {
        const meta = try s3.headObject(bucket, key);
        const index = objects.len - initialized - 1;
        objects[index] = .{ .key = keys.pop().?, .size = meta.size, .last_modified = meta.last_modified, .etag = meta.etag };
        initialized += 1;
    }
    return .{ .objects = objects, .truncated = truncated };
}

test "s3 listing orders pages and returns actual object etags" {
    const alloc = std.testing.allocator;
    const bucket = "listing-pages";
    var path_buf: [paths.max_path]u8 = undefined;
    const path = try paths.dataPathFmt(&path_buf, "s3/{s}", .{bucket});
    defer std.Io.Dir.cwd().deleteTree(io, path) catch {};
    try s3.createBucket(bucket);
    for ([_][]const u8{ "z", "a", "nested/c", "b" }) |key| _ = try s3.putObject(bucket, key, key);
    const first = try list(alloc, bucket, "", "", 2);
    defer first.deinit(alloc);
    try std.testing.expect(first.truncated);
    try std.testing.expectEqualStrings("a", first.objects[0].key);
    try std.testing.expectEqualStrings("b", first.objects[1].key);
    try std.testing.expectEqual(s3.computeEtag("a"), first.objects[0].etag);
    const second = try list(alloc, bucket, "", first.objects[1].key, 2);
    defer second.deinit(alloc);
    try std.testing.expect(!second.truncated);
    try std.testing.expectEqualStrings("nested/c", second.objects[0].key);
    try std.testing.expectEqualStrings("z", second.objects[1].key);
    const empty = try list(alloc, bucket, "", "", 0);
    defer empty.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 0), empty.objects.len);
    try std.testing.expect(!empty.truncated);
}
