const std = @import("std");
const spec = @import("../spec.zig");
const blobs = @import("../store.zig");
const store = @import("../../state/store.zig");
const common = @import("common.zig");
const TarIterator = @import("../../lib/tar_entries.zig").Iterator;

pub fn load(io: std.Io, alloc: std.mem.Allocator, reader: *std.Io.Reader) !usize {
    var store_lease = try @import("../store_lock.zig").Lock.acquire(.shared);
    defer store_lease.deinit();
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const scratch = arena.allocator();
    const archive = try readArchive(io, scratch, reader);
    var layout = try spec.parseJson(common.Layout, scratch, archive.layout_bytes);
    defer layout.deinit();
    if (!std.mem.eql(u8, layout.value.imageLayoutVersion, "1.0.0")) return error.UnsupportedArchive;
    var index = try spec.parseJson(common.Index, scratch, archive.index_bytes);
    defer index.deinit();
    if (index.value.schemaVersion != 2 or !std.mem.eql(u8, index.value.mediaType, spec.media_type.oci_index)) return error.UnsupportedArchive;
    if (index.value.manifests.len == 0 or index.value.manifests.len > common.max_images) return error.ArchiveLimitExceeded;

    var records: std.ArrayList(store.ImageRecord) = .empty;
    var references: std.StringHashMap([]const u8) = .init(scratch);
    for (index.value.manifests) |descriptor| {
        const image = try validateImage(alloc, scratch, &archive.present, descriptor);
        const annotation = if (descriptor.annotations) |annotations| annotations.@"org.opencontainers.image.ref.name" else null;
        const name = annotation orelse try std.fmt.allocPrint(scratch, "loaded@{s}", .{descriptor.digest});
        if (name.len == 0 or name.len > 4096) return error.InvalidImageReference;
        for (name) |ch| if (std.ascii.isWhitespace(ch) or std.ascii.isControl(ch)) return error.InvalidImageReference;
        const ref = spec.parseImageRef(name);
        if (ref.host.len == 0 or ref.repository.len == 0 or ref.reference.len == 0) return error.InvalidImageReference;
        if (ref.digest_reference and !std.mem.eql(u8, ref.reference, descriptor.digest)) return error.InvalidImageReference;
        const key = try canonicalReference(scratch, ref);
        if (references.get(key)) |previous| {
            if (!std.mem.eql(u8, previous, descriptor.digest)) return error.ConflictingImageReferences;
            continue;
        }
        try references.put(key, descriptor.digest);
        try records.append(scratch, .{
            .id = descriptor.digest,
            .registry = ref.host,
            .repository = ref.repository,
            .tag = ref.reference,
            .manifest_digest = descriptor.digest,
            .config_digest = image.config_digest,
            .total_size = std.math.cast(i64, image.total_size) orelse return error.ArchiveLimitExceeded,
            .created_at = std.Io.Clock.real.now(io).toSeconds(),
        });
    }
    // no image reference changes until every descriptor and blob is validated.
    // verified blobs from an interrupted import are harmless cache entries.
    try store.saveImages(records.items);
    return records.items.len;
}

// these buffers and the blob map live in the load operation's arena.
const Archive = struct {
    present: std.AutoHashMap(blobs.Digest, u64),
    index_bytes: []const u8,
    layout_bytes: []const u8,
};

fn readArchive(io: std.Io, scratch: std.mem.Allocator, reader: *std.Io.Reader) !Archive {
    var present: std.AutoHashMap(blobs.Digest, u64) = .init(scratch);
    var index_bytes: ?[]u8 = null;
    var layout_bytes: ?[]u8 = null;
    var total: u64 = 0;
    var entries: usize = 0;
    var name_buffer: [4096]u8 = undefined;
    var link_buffer: [4096]u8 = undefined;
    var iterator = TarIterator.init(reader, .{ .file_name_buffer = &name_buffer, .link_name_buffer = &link_buffer });
    while (try iterator.next()) |entry| {
        entries += 1;
        if (entries > common.max_entries) return error.ArchiveLimitExceeded;
        if (entry.size > common.max_blob) return error.ArchiveLimitExceeded;
        total = std.math.add(u64, total, entry.size) catch return error.ArchiveLimitExceeded;
        if (total > common.max_total) return error.ArchiveLimitExceeded;
        if (!@import("../../lib/tar_extract.zig").isSafeTarPath(entry.name)) return error.InvalidArchivePath;
        var name = entry.name;
        while (std.mem.startsWith(u8, name, "./")) name = name[2..];
        if (entry.kind == .directory) {
            if (entry.size != 0) return error.InvalidArchiveEntry;
            continue;
        }
        if (entry.kind != .file) return error.InvalidArchiveEntry;
        if (std.mem.eql(u8, name, "index.json")) {
            if (index_bytes != null) return error.DuplicateArchiveEntry;
            index_bytes = try readSmall(scratch, reader, entry.size);
            iterator.unread_file_bytes = 0;
        } else if (std.mem.eql(u8, name, "oci-layout")) {
            if (layout_bytes != null) return error.DuplicateArchiveEntry;
            layout_bytes = try readSmall(scratch, reader, entry.size);
            iterator.unread_file_bytes = 0;
        } else if (std.mem.startsWith(u8, name, "blobs/")) {
            const prefix = "blobs/sha256/";
            if (!std.mem.startsWith(u8, name, prefix)) return error.UnsupportedArchive;
            const digest = blobs.Digest.fromHex(name[prefix.len..]) orelse return error.InvalidDigest;
            if (present.contains(digest)) return error.DuplicateArchiveEntry;
            try readBlob(io, reader, digest, entry.size);
            iterator.unread_file_bytes = 0;
            try present.put(digest, entry.size);
        }
        // other regular files are allowed by OCI layout extensions. the
        // iterator discards their contents without creating archive paths.
    }
    return .{
        .present = present,
        .index_bytes = index_bytes orelse return error.UnsupportedArchive,
        .layout_bytes = layout_bytes orelse return error.UnsupportedArchive,
    };
}

const ValidatedImage = struct {
    config_digest: []const u8,
    total_size: u64,
};

fn validateImage(alloc: std.mem.Allocator, scratch: std.mem.Allocator, present: *const std.AutoHashMap(blobs.Digest, u64), descriptor: common.Descriptor) !ValidatedImage {
    if (!spec.isManifestMediaType(descriptor.mediaType)) return error.UnsupportedArchive;
    try requireBlob(present, descriptor.digest, descriptor.size);
    const manifest_bytes = try common.readMetadata(alloc, descriptor.digest, descriptor.size);
    defer alloc.free(manifest_bytes);
    var parsed = try spec.parseManifest(alloc, manifest_bytes);
    defer parsed.deinit();
    const manifest = parsed.value;
    try common.validateManifest(manifest);
    if (manifest.mediaType) |media| {
        if (!std.mem.eql(u8, media, descriptor.mediaType)) return error.UnsupportedArchive;
    }
    try requireBlob(present, manifest.config.digest, manifest.config.size);
    const config_bytes = try common.readMetadata(alloc, manifest.config.digest, manifest.config.size);
    defer alloc.free(config_bytes);
    var config = try spec.parseImageConfig(alloc, config_bytes);
    defer config.deinit();
    const rootfs = config.value.rootfs orelse return error.InvalidImageConfig;
    if (!std.mem.eql(u8, rootfs.type, "layers") or rootfs.diff_ids.len != manifest.layers.len) return error.InvalidImageConfig;
    for (rootfs.diff_ids) |diff_id| {
        if (blobs.Digest.parse(diff_id) == null) return error.InvalidImageConfig;
    }
    var image_size: u64 = 0;
    for (manifest.layers) |layer| {
        try requireBlob(present, layer.digest, layer.size);
        image_size = std.math.add(u64, image_size, layer.size) catch return error.ArchiveLimitExceeded;
    }
    return .{
        .config_digest = try scratch.dupe(u8, manifest.config.digest),
        .total_size = image_size,
    };
}

fn canonicalReference(alloc: std.mem.Allocator, ref: spec.ImageRef) ![]u8 {
    const host = try std.ascii.allocLowerString(alloc, ref.host);
    defer alloc.free(host);
    const hub = std.mem.eql(u8, host, "docker.io") or std.mem.eql(u8, host, "index.docker.io") or std.mem.eql(u8, host, "registry-1.docker.io");
    const expanded_repository = if (hub and std.mem.indexOfScalar(u8, ref.repository, '/') == null)
        try std.fmt.allocPrint(alloc, "library/{s}", .{ref.repository})
    else
        null;
    defer if (expanded_repository) |repository| alloc.free(repository);
    return common.referenceName(alloc, if (hub) "registry-1.docker.io" else host, expanded_repository orelse ref.repository, ref.reference);
}

fn requireBlob(present: *const std.AutoHashMap(blobs.Digest, u64), text: []const u8, size: u64) !void {
    const digest = blobs.Digest.parse(text) orelse return error.InvalidDigest;
    const actual = present.get(digest) orelse return error.MissingBlob;
    if (actual != size) return error.BlobSizeMismatch;
}

fn readSmall(alloc: std.mem.Allocator, reader: *std.Io.Reader, size: u64) ![]u8 {
    if (size > common.max_metadata) return error.ArchiveLimitExceeded;
    const bytes = try alloc.alloc(u8, @intCast(size));
    errdefer alloc.free(bytes);
    try reader.readSliceAll(bytes);
    return bytes;
}

fn readBlob(io: std.Io, reader: *std.Io.Reader, digest: blobs.Digest, size: u64) !void {
    var path_buffer: [4096]u8 = undefined;
    const path = try blobs.tempBlobPath(&path_buffer);
    const file = try std.Io.Dir.cwd().createFile(io, path, .{ .exclusive = true });
    defer file.close(io);
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};
    var hasher: std.crypto.hash.sha2.Sha256 = .init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var remaining = size;
    while (remaining > 0) {
        const len: usize = @intCast(@min(buffer.len, remaining));
        try reader.readSliceAll(buffer[0..len]);
        hasher.update(buffer[0..len]);
        try file.writeStreamingAll(io, buffer[0..len]);
        remaining -= len;
    }
    if (!std.mem.eql(u8, &hasher.finalResult(), &digest.hash)) return error.DigestMismatch;
    try file.sync(io);
    try blobs.commitTempBlob(path, digest);
}
