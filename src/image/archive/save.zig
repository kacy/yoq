const std = @import("std");
const spec = @import("../spec.zig");
const blobs = @import("../store.zig");
const store = @import("../../state/store.zig");
const common = @import("common.zig");

pub fn save(io: std.Io, alloc: std.mem.Allocator, writer: *std.Io.Writer, references: []const []const u8) !void {
    if (references.len == 0 or references.len > common.max_images) return error.InvalidArgument;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const scratch = arena.allocator();
    var descriptors: std.ArrayList(common.Descriptor) = .empty;
    var wanted: std.AutoArrayHashMapUnmanaged(blobs.Digest, u64) = .empty;
    var total: u64 = 0;
    for (references) |reference| {
        const ref = spec.parseImageRef(reference);
        const record = if (blobs.Digest.parse(reference) != null)
            try store.loadImage(scratch, reference)
        else if (ref.digest_reference)
            try store.loadImage(scratch, ref.reference)
        else
            try store.findImage(scratch, ref.host, ref.repository, ref.reference);
        const digest = blobs.Digest.parse(record.manifest_digest) orelse return error.InvalidDigest;
        const size = blobs.getBlobSize(digest) orelse return error.MissingBlob;
        const bytes = try common.readMetadata(alloc, record.manifest_digest, size);
        defer alloc.free(bytes);
        var parsed = try spec.parseManifest(alloc, bytes);
        defer parsed.deinit();
        const manifest = parsed.value;
        try common.validateManifest(manifest);
        try addBlob(scratch, &wanted, digest, size, &total);
        const config_digest = blobs.Digest.parse(manifest.config.digest) orelse return error.InvalidDigest;
        try addBlob(scratch, &wanted, config_digest, manifest.config.size, &total);
        for (manifest.layers) |layer| {
            try addBlob(scratch, &wanted, blobs.Digest.parse(layer.digest) orelse return error.InvalidDigest, layer.size, &total);
        }
        const name = if (ref.digest_reference)
            try common.referenceName(scratch, ref.host, ref.repository, ref.reference)
        else
            try common.referenceName(scratch, record.registry orelse "registry-1.docker.io", record.repository, record.tag);
        try descriptors.append(scratch, .{
            .mediaType = try scratch.dupe(u8, manifest.mediaType orelse spec.media_type.manifest_v2),
            .digest = record.manifest_digest,
            .size = size,
            .annotations = .{ .@"org.opencontainers.image.ref.name" = name },
        });
    }
    const index = try std.json.Stringify.valueAlloc(scratch, common.Index{ .manifests = descriptors.items }, .{ .emit_null_optional_fields = false });
    if (index.len > common.max_metadata) return error.ArchiveLimitExceeded;
    var tar: std.tar.Writer = .{ .underlying_writer = writer };
    try tar.writeFileBytes("oci-layout", "{\"imageLayoutVersion\":\"1.0.0\"}", .{});
    try tar.writeFileBytes("index.json", index, .{});
    try tar.writeDir("blobs", .{});
    try tar.writeDir("blobs/sha256", .{});
    for (wanted.keys(), wanted.values()) |digest, size| {
        if (!blobs.verifyBlob(digest)) return error.DigestMismatch;
        var blob = try blobs.openBlob(digest);
        defer blob.close();
        if (blob.size != size) return error.BlobSizeMismatch;
        var name_buf: [80]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "blobs/sha256/{s}", .{digest.hex()});
        var buffer: [64 * 1024]u8 = undefined;
        var reader = blob.file.readerStreaming(io, &buffer);
        try tar.writeFileStream(name, size, &reader.interface, .{});
    }
    try tar.finishPedantically();
}

fn addBlob(alloc: std.mem.Allocator, wanted: *std.AutoArrayHashMapUnmanaged(blobs.Digest, u64), digest: blobs.Digest, size: u64, total: *u64) !void {
    if (size > common.max_blob) return error.ArchiveLimitExceeded;
    const entry = try wanted.getOrPut(alloc, digest);
    if (entry.found_existing) {
        if (entry.value_ptr.* != size) return error.BlobSizeMismatch;
        return;
    }
    if (wanted.count() > common.max_entries - 4) return error.ArchiveLimitExceeded;
    total.* = std.math.add(u64, total.*, size) catch return error.ArchiveLimitExceeded;
    if (total.* > common.max_total) return error.ArchiveLimitExceeded;
    entry.value_ptr.* = size;
}
