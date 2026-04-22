// store — content-addressable blob store
//
// stores image blobs (manifests, configs, layers) addressed by their
// sha256 digest. blobs are immutable — same content always gets the
// same path. deduplication is automatic.
//
// layout: ~/.local/share/yoq/blobs/sha256/<hex>
//
// this module only handles raw blob storage. image metadata tracking
// (which images are pulled, tags, etc.) lives in state/store.zig.

const std = @import("std");
const blob_runtime = @import("store/blob_runtime.zig");
const digest_support = @import("store/digest_support.zig");
const types = @import("store/types.zig");

pub const BlobError = types.BlobError;
pub const BlobHandle = types.BlobHandle;
pub const Digest = digest_support.Digest;

const max_path = types.max_path;

pub fn putBlob(data: []const u8) BlobError!Digest {
    return blob_runtime.putBlob(data);
}

pub fn putBlobFromFile(source_path: []const u8, expected_digest: Digest) BlobError!void {
    return blob_runtime.putBlobFromFile(source_path, expected_digest);
}

pub fn putBlobDirect(data: []const u8, digest: Digest) BlobError!void {
    return blob_runtime.putBlobDirect(data, digest);
}

pub fn getBlob(alloc: std.mem.Allocator, digest: Digest) BlobError![]u8 {
    return blob_runtime.getBlob(alloc, digest);
}

pub fn openBlob(digest: Digest) BlobError!BlobHandle {
    return blob_runtime.openBlob(digest);
}

pub fn hasBlob(digest: Digest) bool {
    return blob_runtime.hasBlob(digest);
}

pub fn deleteBlob(digest: Digest) BlobError!void {
    return blob_runtime.deleteBlob(digest);
}

pub fn verifyBlob(digest: Digest) bool {
    return blob_runtime.verifyBlob(digest);
}

pub fn removeBlob(digest: Digest) void {
    return blob_runtime.removeBlob(digest);
}

pub fn tempBlobPath(buf: *[max_path]u8) BlobError![]const u8 {
    return blob_runtime.tempBlobPath(buf);
}

pub fn commitTempBlob(tmp_path: []const u8, digest: Digest) BlobError!void {
    return blob_runtime.commitTempBlob(tmp_path, digest);
}

pub fn blobPath(digest: Digest, buf: *[max_path]u8) BlobError![]const u8 {
    return blob_runtime.blobPath(digest, buf);
}

pub fn computeDigest(data: []const u8) Digest {
    return digest_support.computeDigest(data);
}

pub fn listBlobsOnDisk(alloc: std.mem.Allocator) BlobError!std.ArrayList([]const u8) {
    return blob_runtime.listBlobsOnDisk(alloc);
}

pub fn getBlobSize(digest: Digest) ?u64 {
    return blob_runtime.getBlobSize(digest);
}

fn blobAllocSize(size: u64) BlobError!usize {
    return blob_runtime.blobAllocSize(size);
}

// -- tests --

test "compute digest" {
    const digest = computeDigest("hello world");
    const hex = digest.hex();
    try std.testing.expectEqualStrings("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", &hex);
}

test "digest parse and round-trip" {
    const original = computeDigest("test data");
    var buf: [71]u8 = undefined;
    const str = original.string(&buf);

    try std.testing.expect(std.mem.startsWith(u8, str, "sha256:"));

    const parsed = Digest.parse(str).?;
    try std.testing.expect(original.eql(parsed));
}

test "digest parse — invalid" {
    try std.testing.expect(Digest.parse("md5:abc") == null);
    try std.testing.expect(Digest.parse("sha256:tooshort") == null);
    try std.testing.expect(Digest.parse("not-a-digest") == null);
}

test "put and get blob" {
    const home = @import("compat").getenv("HOME") orelse return;
    _ = home;

    const data = "test blob content for yoq store";
    const digest = try putBlob(data);

    try std.testing.expect(hasBlob(digest));

    const alloc = std.testing.allocator;
    const read_back = try getBlob(alloc, digest);
    defer alloc.free(read_back);
    try std.testing.expectEqualStrings(data, read_back);

    try deleteBlob(digest);
    try std.testing.expect(!hasBlob(digest));
}

test "put blob is idempotent" {
    const home = @import("compat").getenv("HOME") orelse return;
    _ = home;

    const data = "idempotent test blob";
    const d1 = try putBlob(data);
    const d2 = try putBlob(data);

    try std.testing.expect(d1.eql(d2));

    try deleteBlob(d1);
}

test "has blob returns false for missing" {
    const digest = computeDigest("definitely not stored");
    try std.testing.expect(!hasBlob(digest));
}

test "verify blob — valid blob passes" {
    const home = @import("compat").getenv("HOME") orelse return;
    _ = home;

    const data = "verify blob test content";
    const digest = try putBlob(data);
    defer deleteBlob(digest) catch {};

    try std.testing.expect(verifyBlob(digest));
}

test "verify blob — corrupted blob fails" {
    const home = @import("compat").getenv("HOME") orelse return;
    _ = home;

    const data = "original content for corruption test";
    const digest = try putBlob(data);
    defer removeBlob(digest);

    var path_buf: [max_path]u8 = undefined;
    const path = try blobPath(digest, &path_buf);
    const file = try @import("compat").cwd().createFile(path, .{});
    defer file.close();
    try file.writeAll("corrupted data");

    try std.testing.expect(!verifyBlob(digest));
}

test "verify blob — missing blob returns false" {
    const digest = computeDigest("blob that was never stored");
    try std.testing.expect(!verifyBlob(digest));
}

test "putBlobDirect repairs corrupted existing blob" {
    const home = @import("compat").getenv("HOME") orelse return;
    _ = home;

    const data = "repair corrupted blob content";
    const digest = try putBlob(data);
    defer deleteBlob(digest) catch {};

    var path_buf: [max_path]u8 = undefined;
    const path = try blobPath(digest, &path_buf);
    const file = try @import("compat").cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll("corrupted data");
    try std.testing.expect(!verifyBlob(digest));

    try putBlobDirect(data, digest);
    try std.testing.expect(verifyBlob(digest));

    const alloc = std.testing.allocator;
    const repaired = try getBlob(alloc, digest);
    defer alloc.free(repaired);
    try std.testing.expectEqualStrings(data, repaired);
}

test "remove blob — silently handles missing blob" {
    const digest = computeDigest("never stored blob for remove test");
    removeBlob(digest);
}

test "listBlobsOnDisk returns stored blobs" {
    const home = @import("compat").getenv("HOME") orelse return;
    _ = home;
    const alloc = std.testing.allocator;

    const d1 = try putBlob("blob one for list test");
    defer deleteBlob(d1) catch {};

    var blobs = try listBlobsOnDisk(alloc);
    defer {
        for (blobs.items) |item| alloc.free(item);
        blobs.deinit(alloc);
    }

    try std.testing.expect(blobs.items.len >= 1);

    const our_hex = d1.hex();
    var found = false;
    for (blobs.items) |item| {
        if (std.mem.eql(u8, item, &our_hex)) {
            found = true;
            break;
        }
    }
    try std.testing.expect(found);
}

test "getBlobSize returns correct size" {
    const home = @import("compat").getenv("HOME") orelse return;
    _ = home;

    const data = "blob size test content";
    const digest = try putBlob(data);
    defer deleteBlob(digest) catch {};

    const size = getBlobSize(digest);
    try std.testing.expect(size != null);
    try std.testing.expectEqual(@as(u64, data.len), size.?);
}

test "getBlobSize returns null for missing blob" {
    const digest = computeDigest("never stored blob for size test");
    try std.testing.expect(getBlobSize(digest) == null);
}

test "blobAllocSize accepts blobs larger than 256 MiB" {
    const size = try blobAllocSize(300 * 1024 * 1024);
    try std.testing.expectEqual(@as(usize, 300 * 1024 * 1024), size);
}

test "openBlob returns size and readable handle" {
    const home = @import("compat").getenv("HOME") orelse return;
    _ = home;

    const data = "blob handle test content";
    const digest = putBlob(data) catch |err| switch (err) {
        error.WriteFailed, error.HomeDirNotFound => return,
        else => return err,
    };
    defer deleteBlob(digest) catch {};

    var blob = try openBlob(digest);
    defer blob.close();

    try std.testing.expectEqual(@as(u64, data.len), blob.size);
    var read_buf: [64]u8 = undefined;
    const n = try blob.file.readAll(&read_buf);
    try std.testing.expectEqualStrings(data, read_buf[0..n]);
}
