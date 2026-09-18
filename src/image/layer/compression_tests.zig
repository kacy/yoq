const std = @import("std");
const layer = @import("../layer.zig");
const spec = @import("../spec.zig");
const store = @import("../store.zig");

// the same ustar archive encoded by gzip and libzstd, independent of yoq.
const gzip =
    "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xed\xd4\x41\x0a\x83\x30\x10\x85\xe1\x59\xf7\x14\x39\x81\x4c\x24\xc6\xf3\xb8\x10\x22\x86" ++
    "\x0a\x1a\xa1\xbd\x7d\x53\x37\x05\xc1\xa5\x81\x92\xff\xdb\xbc\x21\x9b\x2c\x86\x37\x61\x8c\x71\x69\xd2\x2b\xc9\x7d\x34\xf3\x4e\x8f" ++
    "\xcc\xce\xa9\x6a\xdd\x6f\x3e\xde\x7b\x9f\xc3\xa8\x14\xb0\x6f\x69\x58\xf3\x97\x52\xa7\xf0\xdd\xbf\x89\xc3\x7b\x5c\x1f\x82\x3a\xf7" ++
    "\xdf\xc4\xe9\x39\xdf\xdd\x7f\x77\xdd\xff\xf3\x6c\x6d\xe7\xad\x98\x36\x14\x38\x4e\x95\xf7\x1f\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++
    "\x00\x00\x00\xff\xed\x03\xdc\x4e\xf4\x92\x00\x28\x00\x00";
const zstd =
    "\x28\xb5\x2f\xfd\x60\x00\x27\x05\x04\x00\x22\x44\x0e\x16\x80\xc5\xe9\x11\x46\x38\x08\xe3\xad\x01\x13\xf4\x34\x76\xd7\x9f\xab\x3b" ++
    "\x42\xd1\x5d\x06\x82\xf5\x70\xb8\xbb\x07\x0f\xc4\x48\x13\xa8\x14\x40\x69\x57\xa1\xa5\x2c\xdd\xfa\x48\x7c\x7b\xee\xff\x83\xff\x5d" ++
    "\x80\x65\x92\xcc\x54\x04\x18\x00\x60\x0f\x32\x3d\x68\x00\x05\x60\x40\x05\x0d\xa0\x80\x3f\x40\xa6\x40\x00\x25\x27\xe2\x56\xb8\x20" ++
    "\x73\xb0\x82\xc0\x79\x51\xa8\x5d\x82\x70\xa9\x6b\x14\xb4\x91\x09\x54\x50\x60\x6c\x80\x68\x01\x02\x14\x10\x6f\x48\x0d\x00\xc9\x01" ++
    "\x06\xd0\x6a\x30\xf1\x8a\x60\x6e\x02\x48";

test "layer compression preserves contents and modes across raw gzip and zstd" {
    const alloc = std.testing.allocator;
    var source = std.Io.Reader.fixed(gzip);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decoder = std.compress.flate.Decompress.init(&source, .gzip, &window);
    var raw: std.Io.Writer.Allocating = .init(alloc);
    defer raw.deinit();
    _ = try decoder.reader.streamRemaining(&raw.writer);
    const cases = [_]struct { bytes: []const u8, media: []const u8 }{
        .{ .bytes = raw.written(), .media = spec.media_type.oci_layer_tar },
        .{ .bytes = gzip, .media = spec.media_type.oci_layer_gzip },
        .{ .bytes = zstd, .media = spec.media_type.oci_layer_zstd },
    };
    for (cases) |case| {
        const digest = try store.putBlob(case.bytes);
        defer store.deleteBlob(digest) catch {};
        const hex = digest.hex();
        defer layer.deleteExtractedLayer(&hex);
        var digest_buffer: [71]u8 = undefined;
        const descriptor = spec.Descriptor{ .mediaType = case.media, .digest = digest.string(&digest_buffer), .size = case.bytes.len };
        const extracted = try layer.extractLayerDescriptor(alloc, descriptor);
        defer alloc.free(extracted);
        var directory = try std.Io.Dir.cwd().openDir(std.testing.io, extracted, .{});
        defer directory.close(std.testing.io);
        var buffer: [64]u8 = undefined;
        try std.testing.expectEqualStrings("hello layer\n", try directory.readFile(std.testing.io, "hello.txt", &buffer));
        const stat = try directory.statFile(std.testing.io, "hello.txt", .{});
        try std.testing.expectEqual(@as(u32, 0o640), stat.permissions.toMode());
        const length = try directory.readLink(std.testing.io, "hello.link", &buffer);
        try std.testing.expectEqualStrings("hello.txt", buffer[0..length]);
        const cached = try layer.extractLayer(alloc, descriptor.digest);
        defer alloc.free(cached);
        try std.testing.expectEqualStrings(extracted, cached);
        var wrong = descriptor;
        wrong.mediaType = if (std.mem.eql(u8, case.media, spec.media_type.oci_layer_tar)) spec.media_type.oci_layer_gzip else spec.media_type.oci_layer_tar;
        try std.testing.expectError(error.ExtractionFailed, layer.extractLayerDescriptor(alloc, wrong));
    }
}

test "layer compression refuses unsupported descriptors and truncated zstd before publishing" {
    try std.testing.expectError(error.UnsupportedMediaType, layer.extractLayerDescriptor(std.testing.allocator, .{ .digest = "unused", .size = 0, .mediaType = "application/unknown" }));
    const digest = try store.putBlob(zstd[0 .. zstd.len - 3]);
    defer store.deleteBlob(digest) catch {};
    const hex = digest.hex();
    defer layer.deleteExtractedLayer(&hex);
    var buffer: [71]u8 = undefined;
    try std.testing.expectError(error.ExtractionFailed, layer.extractLayerDescriptor(std.testing.allocator, .{ .digest = digest.string(&buffer), .size = zstd.len - 3, .mediaType = spec.media_type.oci_layer_zstd }));
}
