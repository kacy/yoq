const std = @import("std");
const spec = @import("../spec.zig");
const blobs = @import("../store.zig");
const store = @import("../../state/store.zig");
const save_archive = @import("save.zig");
const load_archive = @import("load.zig");
const common = @import("common.zig");
const alloc = std.testing.allocator;
const io = std.Options.debug_io;

const Fixture = struct {
    layer: []u8,
    config: []u8,
    manifest: []u8,
    layer_digest: blobs.Digest,
    config_digest: blobs.Digest,
    manifest_digest: blobs.Digest,

    fn init() !Fixture {
        var layer_writer: std.Io.Writer.Allocating = .init(alloc);
        defer layer_writer.deinit();
        var tar: std.tar.Writer = .{ .underlying_writer = &layer_writer.writer };
        try tar.writeFileBytes("archive-fixture.txt", "image archive fixture contents", .{});
        try tar.finishPedantically();
        const layer = try layer_writer.toOwnedSlice();
        errdefer alloc.free(layer);
        const layer_digest = try blobs.putBlob(layer);
        var layer_buf: [71]u8 = undefined;
        const config = try std.fmt.allocPrint(
            alloc,
            "{{\"architecture\":\"amd64\",\"os\":\"linux\",\"config\":{{\"Cmd\":[\"echo\",\"archive\"],\"Labels\":{{\"fixture\":\"preserved\"}},\"StopSignal\":\"SIGQUIT\"}},\"rootfs\":{{\"type\":\"layers\",\"diff_ids\":[\"{s}\"]}}}}",
            .{layer_digest.string(&layer_buf)},
        );
        errdefer alloc.free(config);
        const config_digest = try blobs.putBlob(config);
        var config_buf: [71]u8 = undefined;
        const manifest = try std.fmt.allocPrint(
            alloc,
            "{{\"schemaVersion\":2,\"mediaType\":\"{s}\",\"config\":{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
            .{ spec.media_type.oci_manifest, spec.media_type.oci_config, config_digest.string(&config_buf), config.len, spec.media_type.oci_layer_tar, layer_digest.string(&layer_buf), layer.len },
        );
        errdefer alloc.free(manifest);
        const manifest_digest = try blobs.putBlob(manifest);
        var manifest_buf: [71]u8 = undefined;
        const record: store.ImageRecord = .{
            .id = manifest_digest.string(&manifest_buf),
            .repository = "archive-fixture",
            .tag = "latest",
            .manifest_digest = manifest_digest.string(&manifest_buf),
            .config_digest = config_digest.string(&config_buf),
            .total_size = @intCast(layer.len),
            .created_at = 1,
        };
        try store.saveImage(record);
        var second = record;
        second.registry = "localhost:5001";
        second.repository = "team/archive";
        second.tag = "stable";
        try store.saveImage(second);
        return .{ .layer = layer, .config = config, .manifest = manifest, .layer_digest = layer_digest, .config_digest = config_digest, .manifest_digest = manifest_digest };
    }

    fn remove(self: Fixture) !void {
        var buf: [71]u8 = undefined;
        try store.removeImage(self.manifest_digest.string(&buf));
    }

    fn removeBlobs(self: Fixture) void {
        blobs.removeBlob(self.layer_digest);
        blobs.removeBlob(self.config_digest);
        blobs.removeBlob(self.manifest_digest);
    }

    fn deinit(self: Fixture) void {
        self.removeBlobs();
        alloc.free(self.layer);
        alloc.free(self.config);
        alloc.free(self.manifest);
    }

    fn archive(self: Fixture, writer: *std.Io.Writer, include_layer: bool, size_offset: u64) !void {
        var tar: std.tar.Writer = .{ .underlying_writer = writer };
        var digest_buf: [71]u8 = undefined;
        const descriptors = [_]common.Descriptor{.{
            .mediaType = spec.media_type.oci_manifest,
            .digest = self.manifest_digest.string(&digest_buf),
            .size = self.manifest.len + size_offset,
            .annotations = .{ .@"org.opencontainers.image.ref.name" = "archive-fixture:latest" },
        }};
        const index = try std.json.Stringify.valueAlloc(alloc, common.Index{ .manifests = &descriptors }, .{});
        defer alloc.free(index);
        // put index last to cover archives from tools with a different ordering.
        try tar.writeFileBytes("oci-layout", "{\"imageLayoutVersion\":\"1.0.0\"}", .{});
        try writeBlob(&tar, self.manifest_digest, self.manifest);
        try writeBlob(&tar, self.config_digest, self.config);
        if (include_layer) try writeBlob(&tar, self.layer_digest, self.layer);
        try tar.writeFileBytes("index.json", index, .{});
        try tar.finishPedantically();
    }
};

fn writeBlob(tar: *std.tar.Writer, digest: blobs.Digest, bytes: []const u8) !void {
    var name_buf: [80]u8 = undefined;
    try tar.writeFileBytes(try std.fmt.bufPrint(&name_buf, "blobs/sha256/{s}", .{digest.hex()}), bytes, .{});
}

test "image archive roundtrip preserves tags digests metadata and layer bytes" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const fixture = try Fixture.init();
    defer fixture.deinit();
    var bytes: std.Io.Writer.Allocating = .init(alloc);
    defer bytes.deinit();
    try save_archive.save(io, alloc, &bytes.writer, &.{ "archive-fixture", "localhost:5001/team/archive:stable" });
    try fixture.remove();
    fixture.removeBlobs();
    var reader = std.Io.Reader.fixed(bytes.written());
    try std.testing.expectEqual(@as(usize, 2), try load_archive.load(io, alloc, &reader));
    var digest_buf: [71]u8 = undefined;
    const first = try store.findImage(alloc, "docker.io", "archive-fixture", "latest");
    defer first.deinit(alloc);
    const second = try store.findImage(alloc, "localhost:5001", "team/archive", "stable");
    defer second.deinit(alloc);
    try std.testing.expectEqualStrings(fixture.manifest_digest.string(&digest_buf), first.manifest_digest);
    try std.testing.expectEqualStrings(first.manifest_digest, second.manifest_digest);
    const config = try blobs.getBlob(alloc, fixture.config_digest);
    defer alloc.free(config);
    try std.testing.expectEqualStrings(fixture.config, config);
    const layer = try blobs.getBlob(alloc, fixture.layer_digest);
    defer alloc.free(layer);
    try std.testing.expectEqualSlices(u8, fixture.layer, layer);
}

test "image archive rejects corrupt missing and size mismatched content before publishing references" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.remove();
    {
        var bytes: std.Io.Writer.Allocating = .init(alloc);
        defer bytes.deinit();
        try fixture.archive(&bytes.writer, true, 0);
        const offset = std.mem.indexOf(u8, bytes.written(), "image archive fixture contents").?;
        const corrupt = try alloc.dupe(u8, bytes.written());
        defer alloc.free(corrupt);
        corrupt[offset] ^= 1;
        var reader = std.Io.Reader.fixed(corrupt);
        try std.testing.expectError(error.DigestMismatch, load_archive.load(io, alloc, &reader));
    }
    {
        var bytes: std.Io.Writer.Allocating = .init(alloc);
        defer bytes.deinit();
        try fixture.archive(&bytes.writer, false, 0);
        var reader = std.Io.Reader.fixed(bytes.written());
        // existing local blobs cannot conceal an incomplete transfer archive.
        try std.testing.expectError(error.MissingBlob, load_archive.load(io, alloc, &reader));
    }
    {
        var bytes: std.Io.Writer.Allocating = .init(alloc);
        defer bytes.deinit();
        try fixture.archive(&bytes.writer, true, 1);
        var reader = std.Io.Reader.fixed(bytes.written());
        try std.testing.expectError(error.BlobSizeMismatch, load_archive.load(io, alloc, &reader));
    }
    try std.testing.expectError(error.NotFound, store.findImage(alloc, "docker.io", "archive-fixture", "latest"));
}

test "image archive accepts index after blobs and skips regular layout extensions" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.remove();
    var bytes: std.Io.Writer.Allocating = .init(alloc);
    defer bytes.deinit();
    var tar: std.tar.Writer = .{ .underlying_writer = &bytes.writer };
    try tar.writeFileBytes("extra/readme.txt", "optional layout extension", .{});
    try fixture.archive(&bytes.writer, true, 0);
    var reader = std.Io.Reader.fixed(bytes.written());
    try std.testing.expectEqual(@as(usize, 1), try load_archive.load(io, alloc, &reader));
}

test "image archive rejects traversal links and oversized metadata" {
    {
        var bytes: std.Io.Writer.Allocating = .init(alloc);
        defer bytes.deinit();
        var tar: std.tar.Writer = .{ .underlying_writer = &bytes.writer };
        try tar.writeFileBytes("../index.json", "{}", .{});
        try tar.finishPedantically();
        var reader = std.Io.Reader.fixed(bytes.written());
        try std.testing.expectError(error.InvalidArchivePath, load_archive.load(io, alloc, &reader));
    }
    {
        var bytes: std.Io.Writer.Allocating = .init(alloc);
        defer bytes.deinit();
        var tar: std.tar.Writer = .{ .underlying_writer = &bytes.writer };
        try tar.writeLink("index.json", "elsewhere", .{});
        try tar.finishPedantically();
        var reader = std.Io.Reader.fixed(bytes.written());
        try std.testing.expectError(error.InvalidArchiveEntry, load_archive.load(io, alloc, &reader));
    }
    {
        var bytes: std.Io.Writer.Allocating = .init(alloc);
        defer bytes.deinit();
        var header = std.tar.Writer.Header.init(.regular);
        try header.setPath("", "index.json");
        try header.setSize(common.max_metadata + 1);
        try header.write(&bytes.writer);
        var reader = std.Io.Reader.fixed(bytes.written());
        try std.testing.expectError(error.ArchiveLimitExceeded, load_archive.load(io, alloc, &reader));
    }
}

test "image archive failed save preserves an existing output file" {
    try store.initTestDb();
    defer store.deinitTestDb();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(io, "images.tar", .{});
    try file.writeStreamingAll(io, "previous archive");
    file.close(io);
    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/images.tar", .{tmp.sub_path});
    try std.testing.expectError(error.NotFound, @import("../cli/archive_command.zig").saveFile(io, alloc, path, &.{"missing-archive-image"}));
    const contents = try tmp.dir.readFileAlloc(io, "images.tar", alloc, .limited(1024));
    defer alloc.free(contents);
    try std.testing.expectEqualStrings("previous archive", contents);
}

test "image archive truncated blob never publishes a reference" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const fixture = try Fixture.init();
    defer fixture.deinit();
    try fixture.remove();
    var bytes: std.Io.Writer.Allocating = .init(alloc);
    defer bytes.deinit();
    try fixture.archive(&bytes.writer, true, 0);
    const offset = std.mem.indexOf(u8, bytes.written(), "image archive fixture contents").?;
    var reader = std.Io.Reader.fixed(bytes.written()[0 .. offset + 1]);
    try std.testing.expectError(error.EndOfStream, load_archive.load(io, alloc, &reader));
    try std.testing.expectError(error.NotFound, store.findImage(alloc, "docker.io", "archive-fixture", "latest"));
}
