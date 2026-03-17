const std = @import("std");
const cli = @import("../../lib/cli.zig");
const spec = @import("../spec.zig");
const registry = @import("../registry.zig");
const oci = @import("../oci.zig");
const blob_store = @import("../store.zig");
const store = @import("../../state/store.zig");

const writeErr = cli.writeErr;

pub const ImageCommandsError = error{
    InvalidArgument,
    PullFailed,
    PushFailed,
    ImageNotFound,
    StoreFailed,
    OutOfMemory,
    InvalidDigest,
    PruneFailed,
};

pub const ImageBlobs = struct {
    manifest_bytes: []u8,
    config_bytes: []u8,
    manifest_digest: blob_store.Digest,
    config_digest: blob_store.Digest,

    pub fn deinit(self: ImageBlobs, alloc: std.mem.Allocator) void {
        alloc.free(self.manifest_bytes);
        alloc.free(self.config_bytes);
    }
};

pub fn loadImageBlobs(alloc: std.mem.Allocator, image: store.ImageRecord) ImageCommandsError!ImageBlobs {
    const manifest_digest = blob_store.Digest.parse(image.manifest_digest) orelse {
        writeErr("invalid manifest digest in image record\n", .{});
        return ImageCommandsError.InvalidDigest;
    };
    const manifest_bytes = blob_store.getBlob(alloc, manifest_digest) catch |err| {
        writeErr("failed to read manifest from blob store: {}\n", .{err});
        return ImageCommandsError.StoreFailed;
    };
    errdefer alloc.free(manifest_bytes);

    const config_digest = blob_store.Digest.parse(image.config_digest) orelse {
        writeErr("invalid config digest in image record\n", .{});
        return ImageCommandsError.InvalidDigest;
    };
    const config_bytes = blob_store.getBlob(alloc, config_digest) catch |err| {
        writeErr("failed to read config from blob store: {}\n", .{err});
        return ImageCommandsError.StoreFailed;
    };

    return .{
        .manifest_bytes = manifest_bytes,
        .config_bytes = config_bytes,
        .manifest_digest = manifest_digest,
        .config_digest = config_digest,
    };
}

pub fn saveImageRecord(ref: spec.ImageRef, pr: registry.PullResult) void {
    const cfg_computed = blob_store.computeDigest(pr.config_bytes);
    var cfg_digest_buf: [71]u8 = undefined;
    const cfg_digest_str = cfg_computed.string(&cfg_digest_buf);

    oci.saveImageFromPull(
        ref,
        pr.manifest_digest,
        pr.manifest_bytes,
        pr.config_bytes,
        cfg_digest_str,
        pr.total_size,
    ) catch |e| {
        writeErr("warning: failed to save image record: {}\n", .{e});
    };
}

pub fn writePullError(target: []const u8, err: anyerror) void {
    writeErr("failed to pull image: {s} ({})\n", .{ target, err });

    switch (err) {
        error.AuthFailed => writeErr("registry authentication failed\n", .{}),
        error.ManifestNotFound => writeErr("manifest not found for the requested image reference\n", .{}),
        error.BlobNotFound => writeErr("a required config or layer blob could not be downloaded\n", .{}),
        error.NetworkError => writeErr("network request to the registry failed\n", .{}),
        error.PlatformNotFound => writeErr("no linux/amd64 image was found in the manifest list\n", .{}),
        error.DigestMismatch => writeErr("the registry returned content with a mismatched digest\n", .{}),
        error.ResponseTooLarge => writeErr("the registry response exceeded the configured safety limit\n", .{}),
        error.ParseError => writeErr("the registry returned invalid manifest or config data\n", .{}),
        else => {},
    }
}

pub fn addDigestHex(set: *std.StringHashMap(void), digest_str: []const u8) void {
    const prefix = "sha256:";
    if (std.mem.startsWith(u8, digest_str, prefix)) {
        const hex = digest_str[prefix.len..];
        if (hex.len == 64) {
            set.put(hex, {}) catch {};
        }
    }
}
