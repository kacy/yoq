// spec — OCI image specification types
//
// types for parsing OCI image manifests, configs, and descriptors.
// follows the OCI image spec v1.1:
// https://github.com/opencontainers/image-spec/blob/main/manifest.md
//
// struct field names match the JSON keys exactly so std.json can
// parse them without any field name mapping. this means some fields
// use camelCase (mediaType, schemaVersion) — intentional tradeoff
// for zero-config JSON parsing.

const std = @import("std");

/// a content descriptor — points to a blob by digest and size.
/// used in manifests to reference configs and layers.
pub const Descriptor = struct {
    mediaType: []const u8,
    digest: []const u8,
    size: u64,
    /// platform info, present on image index entries
    platform: ?Platform = null,
};

/// target platform for an image
pub const Platform = struct {
    architecture: []const u8,
    os: []const u8,
    variant: ?[]const u8 = null,
};

/// OCI image manifest — the top-level document for a single-platform image.
/// lists the config blob and ordered layer blobs.
pub const Manifest = struct {
    schemaVersion: u32 = 2,
    mediaType: ?[]const u8 = null,
    config: Descriptor,
    layers: []const Descriptor,
};

/// OCI image index (aka "fat manifest") — lists manifests for multiple platforms.
/// docker hub returns this for multi-arch images like nginx:latest.
pub const ImageIndex = struct {
    schemaVersion: u32 = 2,
    mediaType: ?[]const u8 = null,
    manifests: []const Descriptor,
};

/// container runtime configuration from the image config blob.
/// these are the defaults for Cmd, Env, WorkingDir, etc.
/// field names match OCI spec exactly (PascalCase).
pub const ContainerConfig = struct {
    Cmd: ?[]const []const u8 = null,
    Env: ?[]const []const u8 = null,
    WorkingDir: ?[]const u8 = null,
    Entrypoint: ?[]const []const u8 = null,
    ExposedPorts: ?std.json.Value = null,
    User: ?[]const u8 = null,
};

/// rootfs description in the image config
pub const RootFs = struct {
    type: []const u8,
    diff_ids: []const []const u8,
};

/// OCI image configuration — metadata about how to run the image.
/// this is the blob referenced by manifest.config.
pub const ImageConfig = struct {
    architecture: ?[]const u8 = null,
    os: ?[]const u8 = null,
    config: ?ContainerConfig = null,
    rootfs: ?RootFs = null,
};

// -- media types --

pub const media_type = struct {
    pub const manifest_v2 = "application/vnd.docker.distribution.manifest.v2+json";
    pub const manifest_list = "application/vnd.docker.distribution.manifest.list.v2+json";
    pub const oci_manifest = "application/vnd.oci.image.manifest.v1+json";
    pub const oci_index = "application/vnd.oci.image.index.v1+json";
    pub const oci_layer_gzip = "application/vnd.oci.image.layer.v1.tar+gzip";
    pub const docker_layer_gzip = "application/vnd.docker.image.rootfs.diff.tar.gzip";
    pub const oci_config = "application/vnd.oci.image.config.v1+json";
    pub const docker_config = "application/vnd.docker.container.image.v1+json";
};

// -- parsing helpers --

/// parse result wraps the parsed value and the arena that owns its memory.
/// caller must call deinit() when done with the value.
pub fn ParseResult(comptime T: type) type {
    return struct {
        value: T,
        _parsed: std.json.Parsed(T),

        pub fn deinit(self: *@This()) void {
            self._parsed.deinit();
        }
    };
}

/// parse JSON bytes into a typed result. shared implementation for all
/// OCI spec types — ignores unknown fields for forward compatibility.
/// caller must call .deinit() on the result when done.
pub fn parseJson(comptime T: type, alloc: std.mem.Allocator, json_bytes: []const u8) !ParseResult(T) {
    const parsed = try std.json.parseFromSlice(T, alloc, json_bytes, .{
        .ignore_unknown_fields = true,
    });
    return .{ .value = parsed.value, ._parsed = parsed };
}

/// convenience wrappers — named for readability at call sites
pub fn parseManifest(alloc: std.mem.Allocator, json_bytes: []const u8) !ParseResult(Manifest) {
    return parseJson(Manifest, alloc, json_bytes);
}

pub fn parseImageIndex(alloc: std.mem.Allocator, json_bytes: []const u8) !ParseResult(ImageIndex) {
    return parseJson(ImageIndex, alloc, json_bytes);
}

pub fn parseImageConfig(alloc: std.mem.Allocator, json_bytes: []const u8) !ParseResult(ImageConfig) {
    return parseJson(ImageConfig, alloc, json_bytes);
}

/// check if a media type indicates an image index (multi-platform)
pub fn isIndexMediaType(mt: []const u8) bool {
    return std.mem.eql(u8, mt, media_type.manifest_list) or
        std.mem.eql(u8, mt, media_type.oci_index);
}

/// check if a media type indicates a single manifest
pub fn isManifestMediaType(mt: []const u8) bool {
    return std.mem.eql(u8, mt, media_type.manifest_v2) or
        std.mem.eql(u8, mt, media_type.oci_manifest);
}

/// parse an image reference like "nginx:latest" or "library/nginx:1.25"
pub const ImageRef = struct {
    /// the registry host (e.g. "registry-1.docker.io")
    host: []const u8,
    /// the repository path (e.g. "library/nginx")
    repository: []const u8,
    /// the tag or digest (e.g. "latest")
    reference: []const u8,
};

pub fn parseImageRef(ref: []const u8) ImageRef {
    // check for explicit host (contains '.' or ':' before first '/')
    var host: []const u8 = "registry-1.docker.io";
    var remainder = ref;

    if (std.mem.indexOfScalar(u8, ref, '/')) |slash_idx| {
        const prefix = ref[0..slash_idx];
        // if prefix contains a dot or colon, it's a hostname
        if (std.mem.indexOfScalar(u8, prefix, '.') != null or
            std.mem.indexOfScalar(u8, prefix, ':') != null)
        {
            host = prefix;
            remainder = ref[slash_idx + 1 ..];
        }
    }

    // split repository:tag
    var repository = remainder;
    var reference: []const u8 = "latest";

    // check for @sha256: digest reference first
    if (std.mem.indexOf(u8, remainder, "@sha256:")) |at_idx| {
        repository = remainder[0..at_idx];
        reference = remainder[at_idx + 1 ..]; // include "sha256:..."
    } else if (std.mem.lastIndexOfScalar(u8, remainder, ':')) |colon_idx| {
        repository = remainder[0..colon_idx];
        reference = remainder[colon_idx + 1 ..];
    }

    // docker hub: bare names get "library/" prefix.
    // we can't allocate here, so the registry client handles
    // prepending "library/" for bare docker hub names.

    return ImageRef{
        .host = host,
        .repository = repository,
        .reference = reference,
    };
}

// -- tests --

test "parse image ref — simple" {
    const ref = parseImageRef("nginx:latest");
    try std.testing.expectEqualStrings("registry-1.docker.io", ref.host);
    try std.testing.expectEqualStrings("nginx", ref.repository);
    try std.testing.expectEqualStrings("latest", ref.reference);
}

test "parse image ref — no tag defaults to latest" {
    const ref = parseImageRef("ubuntu");
    try std.testing.expectEqualStrings("registry-1.docker.io", ref.host);
    try std.testing.expectEqualStrings("ubuntu", ref.repository);
    try std.testing.expectEqualStrings("latest", ref.reference);
}

test "parse image ref — with registry" {
    const ref = parseImageRef("ghcr.io/owner/repo:v1.2");
    try std.testing.expectEqualStrings("ghcr.io", ref.host);
    try std.testing.expectEqualStrings("owner/repo", ref.repository);
    try std.testing.expectEqualStrings("v1.2", ref.reference);
}

test "parse image ref — with port" {
    const ref = parseImageRef("localhost:5000/myimage:dev");
    try std.testing.expectEqualStrings("localhost:5000", ref.host);
    try std.testing.expectEqualStrings("myimage", ref.repository);
    try std.testing.expectEqualStrings("dev", ref.reference);
}

test "parse image ref — digest reference" {
    const ref = parseImageRef("nginx@sha256:abc123");
    try std.testing.expectEqualStrings("registry-1.docker.io", ref.host);
    try std.testing.expectEqualStrings("nginx", ref.repository);
    try std.testing.expectEqualStrings("sha256:abc123", ref.reference);
}

test "parse manifest" {
    const json =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        \\  "config": {
        \\    "mediaType": "application/vnd.docker.container.image.v1+json",
        \\    "digest": "sha256:aaaa",
        \\    "size": 1234
        \\  },
        \\  "layers": [
        \\    {
        \\      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
        \\      "digest": "sha256:bbbb",
        \\      "size": 5678
        \\    },
        \\    {
        \\      "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
        \\      "digest": "sha256:cccc",
        \\      "size": 91011
        \\    }
        \\  ]
        \\}
    ;

    const alloc = std.testing.allocator;
    var result = try parseManifest(alloc, json);
    defer result.deinit();

    try std.testing.expectEqual(@as(u32, 2), result.value.schemaVersion);
    try std.testing.expectEqualStrings("sha256:aaaa", result.value.config.digest);
    try std.testing.expectEqual(@as(usize, 2), result.value.layers.len);
    try std.testing.expectEqualStrings("sha256:bbbb", result.value.layers[0].digest);
    try std.testing.expectEqual(@as(u64, 5678), result.value.layers[0].size);
}

test "parse image config" {
    const json =
        \\{
        \\  "architecture": "amd64",
        \\  "os": "linux",
        \\  "config": {
        \\    "Cmd": ["/bin/sh"],
        \\    "Env": ["PATH=/usr/bin:/bin"],
        \\    "WorkingDir": "/app"
        \\  },
        \\  "rootfs": {
        \\    "type": "layers",
        \\    "diff_ids": ["sha256:aaa", "sha256:bbb"]
        \\  }
        \\}
    ;

    const alloc = std.testing.allocator;
    var result = try parseImageConfig(alloc, json);
    defer result.deinit();
    const config = result.value;

    try std.testing.expectEqualStrings("amd64", config.architecture.?);
    try std.testing.expectEqualStrings("linux", config.os.?);
    try std.testing.expectEqualStrings("/bin/sh", config.config.?.Cmd.?[0]);
    try std.testing.expectEqualStrings("/app", config.config.?.WorkingDir.?);
    try std.testing.expectEqual(@as(usize, 2), config.rootfs.?.diff_ids.len);
}

test "parse image index" {
    const json =
        \\{
        \\  "schemaVersion": 2,
        \\  "mediaType": "application/vnd.oci.image.index.v1+json",
        \\  "manifests": [
        \\    {
        \\      "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\      "digest": "sha256:amd64manifest",
        \\      "size": 500,
        \\      "platform": {
        \\        "architecture": "amd64",
        \\        "os": "linux"
        \\      }
        \\    },
        \\    {
        \\      "mediaType": "application/vnd.oci.image.manifest.v1+json",
        \\      "digest": "sha256:arm64manifest",
        \\      "size": 501,
        \\      "platform": {
        \\        "architecture": "arm64",
        \\        "os": "linux"
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    const alloc = std.testing.allocator;
    var result = try parseImageIndex(alloc, json);
    defer result.deinit();
    const index = result.value;

    try std.testing.expectEqual(@as(usize, 2), index.manifests.len);
    try std.testing.expectEqualStrings("amd64", index.manifests[0].platform.?.architecture);
    try std.testing.expectEqualStrings("arm64", index.manifests[1].platform.?.architecture);
}

test "media type detection" {
    try std.testing.expect(isIndexMediaType(media_type.manifest_list));
    try std.testing.expect(isIndexMediaType(media_type.oci_index));
    try std.testing.expect(!isIndexMediaType(media_type.manifest_v2));

    try std.testing.expect(isManifestMediaType(media_type.manifest_v2));
    try std.testing.expect(isManifestMediaType(media_type.oci_manifest));
    try std.testing.expect(!isManifestMediaType(media_type.oci_index));
}
