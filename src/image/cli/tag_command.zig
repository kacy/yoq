const std = @import("std");
const cli = @import("../../lib/cli.zig");
const spec = @import("../spec.zig");
const store = @import("../../state/store.zig");
const blob_store = @import("../store.zig");
const common = @import("common.zig");

pub fn tag(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) common.ImageCommandsError!void {
    const source = args.next() orelse return usage();
    const target = args.next() orelse return usage();
    if (args.next() != null) return usage();
    try tagImage(alloc, source, target);
}

fn usage() common.ImageCommandsError {
    cli.writeErr("usage: yoq tag <source-image> <target-image>\n", .{});
    return error.InvalidArgument;
}

pub fn tagImage(alloc: std.mem.Allocator, source: []const u8, target: []const u8) common.ImageCommandsError!void {
    const source_ref = spec.parseImageRef(source);
    const target_ref = spec.parseImageRef(target);
    if (target.len == 0 or target[0] == '-' or target_ref.digest_reference or
        target_ref.repository.len == 0 or target_ref.reference.len == 0 or blob_store.Digest.parse(target) != null)
        return error.InvalidArgument;
    const image = (if (blob_store.Digest.parse(source) != null)
        store.loadImage(alloc, source)
    else if (source_ref.digest_reference)
        store.loadImage(alloc, source_ref.reference)
    else
        store.findImage(alloc, source_ref.host, source_ref.repository, source_ref.reference)) catch |err| switch (err) {
        error.NotFound => return error.ImageNotFound,
        else => return error.StoreFailed,
    };
    defer image.deinit(alloc);
    var tagged = image;
    tagged.registry = target_ref.host;
    tagged.repository = target_ref.repository;
    tagged.tag = target_ref.reference;
    store.saveImage(tagged) catch return error.StoreFailed;
}

test "image tag creates a reference without changing the source image" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    const digest = "sha256:" ++ "1" ** 64;
    try store.saveImage(.{ .id = digest, .repository = "source", .tag = "latest", .manifest_digest = digest, .config_digest = "sha256:" ++ "2" ** 64, .total_size = 12, .created_at = 10 });
    try tagImage(alloc, "source", "localhost:5000/team/target:stable");
    const original = try store.findImage(alloc, "docker.io", "source", "latest");
    defer original.deinit(alloc);
    const target = try store.findImage(alloc, "localhost:5000", "team/target", "stable");
    defer target.deinit(alloc);
    try std.testing.expectEqualStrings(original.manifest_digest, target.manifest_digest);
    try std.testing.expectEqual(@as(i64, 12), target.total_size);
    try tagImage(alloc, digest, "another");
    try std.testing.expectError(error.ImageNotFound, tagImage(alloc, "missing", "unused"));
    try std.testing.expectError(error.InvalidArgument, tagImage(alloc, "source", "target@" ++ digest));
}
