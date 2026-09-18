const std = @import("std");
const spec = @import("../spec.zig");
const blobs = @import("../store.zig");

pub const max_metadata: usize = 20 * 1024 * 1024;
// The portable ustar size field holds eleven octal digits.
pub const max_blob: u64 = 8 * 1024 * 1024 * 1024 - 1;
pub const max_total: u64 = 1024 * 1024 * 1024 * 1024;
pub const max_entries: usize = 65536;
pub const max_images: usize = 4096;

pub const Annotations = struct {
    @"org.opencontainers.image.ref.name": ?[]const u8 = null,
};

pub const Descriptor = struct {
    mediaType: []const u8,
    digest: []const u8,
    size: u64,
    annotations: ?Annotations = null,
};

pub const Index = struct {
    schemaVersion: u32 = 2,
    mediaType: []const u8 = spec.media_type.oci_index,
    manifests: []const Descriptor,
};

pub const Layout = struct { imageLayoutVersion: []const u8 };

pub fn readMetadata(alloc: std.mem.Allocator, digest_text: []const u8, size: u64) ![]u8 {
    if (size > max_metadata) return error.ArchiveLimitExceeded;
    const digest = blobs.Digest.parse(digest_text) orelse return error.InvalidDigest;
    if (blobs.getBlobSize(digest) != size) return error.BlobSizeMismatch;
    const bytes = try blobs.getBlob(alloc, digest);
    errdefer alloc.free(bytes);
    if (!blobs.computeDigest(bytes).eql(digest)) return error.DigestMismatch;
    return bytes;
}

pub fn validateManifest(manifest: spec.Manifest) !void {
    if (manifest.schemaVersion != 2) return error.UnsupportedArchive;
    if (manifest.mediaType) |media| {
        if (!spec.isManifestMediaType(media)) return error.UnsupportedArchive;
    }
    if (!std.mem.eql(u8, manifest.config.mediaType, spec.media_type.oci_config) and
        !std.mem.eql(u8, manifest.config.mediaType, "application/vnd.docker.container.image.v1+json"))
        return error.UnsupportedArchive;
    if (manifest.layers.len > max_entries) return error.ArchiveLimitExceeded;
    for (manifest.layers) |layer| {
        if (spec.layerCompression(layer.mediaType) == null) return error.UnsupportedArchive;
        if (layer.size > max_blob) return error.ArchiveLimitExceeded;
    }
}

pub fn referenceName(alloc: std.mem.Allocator, host: []const u8, repository: []const u8, tag: []const u8) ![]u8 {
    return std.fmt.allocPrint(alloc, "{s}/{s}{s}{s}", .{ host, repository, if (blobs.Digest.parse(tag) != null) "@" else ":", tag });
}
