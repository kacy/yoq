const std = @import("std");
const cli = @import("../../lib/cli.zig");
const spec = @import("../spec.zig");
const registry = @import("../registry.zig");
const layer = @import("../layer.zig");
const common = @import("common.zig");
const store = @import("../../state/store.zig");
const blob_store = @import("../store.zig");

pub const PullPolicy = enum { missing, always, never };

const writeErr = cli.writeErr;

pub const ImageResolution = struct {
    rootfs: []const u8,
    manifest_digest: []const u8 = "",
    stop_signal: ?[]const u8 = null,
    healthcheck: ?spec.Healthcheck = null,
    volumes: ?std.json.Value = null,
    entrypoint: []const []const u8 = &.{},
    default_cmd: []const []const u8 = &.{},
    image_env: []const []const u8 = &.{},
    working_dir: []const u8 = "/",
    user: ?[]const u8 = null,
    layer_paths: []const []const u8 = &.{},
    pull_result: ?registry.PullResult = null,
    config_parsed: ?spec.ParseResult(spec.ImageConfig) = null,
    alloc: ?std.mem.Allocator = null,

    pub fn deinit(self: *ImageResolution) void {
        if (self.alloc) |a| {
            for (self.layer_paths) |p| a.free(p);
            a.free(self.layer_paths);
        }
        if (self.config_parsed) |*c| c.deinit();
        if (self.pull_result) |*r| r.deinit();
    }
};

pub fn pullAndResolveImage(io: std.Io, alloc: std.mem.Allocator, target: []const u8) common.ImageCommandsError!ImageResolution {
    return resolveImage(io, alloc, target, .missing);
}

pub fn resolveImage(io: std.Io, alloc: std.mem.Allocator, target: []const u8, policy: PullPolicy) common.ImageCommandsError!ImageResolution {
    const ref = spec.parseImageRef(target);
    var result = ImageResolution{ .rootfs = target };
    errdefer result.deinit();

    if (policy != .always) result.pull_result = try loadLocalImage(alloc, target, ref);
    if (result.pull_result == null) {
        if (policy == .never) {
            writeErr("image not found locally: {s}\n", .{target});
            return error.ImageNotFound;
        }
        writeErr("pulling {s}...\n", .{target});
        result.pull_result = registry.pull(io, alloc, ref) catch |err| {
            common.writePullError(target, err);
            return error.PullFailed;
        };
        common.saveImageRecord(ref, result.pull_result.?);
    }
    result.manifest_digest = result.pull_result.?.manifest_digest;

    result.config_parsed = spec.parseImageConfig(alloc, result.pull_result.?.config_bytes) catch |err| {
        writeErr("failed to parse image config: {}\n", .{err});
        return common.ImageCommandsError.PullFailed;
    };

    if (result.config_parsed.?.value.config) |cc| {
        result.stop_signal = cc.StopSignal;
        result.healthcheck = cc.Healthcheck;
        result.volumes = cc.Volumes;
        if (cc.User) |user| {
            if (user.len > 0) result.user = user;
        }
        if (cc.Entrypoint) |ep| result.entrypoint = ep;
        if (cc.Cmd) |cmd| result.default_cmd = cmd;
        if (cc.Env) |env| result.image_env = env;
        if (cc.WorkingDir) |wd| {
            if (wd.len > 0) result.working_dir = wd;
        }
    }

    result.layer_paths = assembleLayers(alloc, result.pull_result.?.layers) catch |err| {
        writeErr("failed to extract image layers: {}\n", .{err});
        return common.ImageCommandsError.PullFailed;
    };
    result.alloc = alloc;

    if (result.layer_paths.len > 0) {
        result.rootfs = result.layer_paths[result.layer_paths.len - 1];
    }

    return result;
}

// Overlay mounts need a lower directory even for an image with no layers.
// Use a complete empty tar so its extraction shares the ordinary cache lifetime.
fn assembleLayers(alloc: std.mem.Allocator, descriptors: []const spec.Descriptor) ![]const []const u8 {
    if (descriptors.len > 0) return layer.assembleRootfsDescriptors(alloc, descriptors);
    const empty_tar = [_]u8{0} ** 1024;
    const digest = try blob_store.putBlob(&empty_tar);
    var digest_buf: [71]u8 = undefined;
    const empty_layer = spec.Descriptor{
        .mediaType = spec.media_type.oci_layer_tar,
        .digest = digest.string(&digest_buf),
        .size = empty_tar.len,
    };
    return layer.assembleRootfsDescriptors(alloc, &.{empty_layer});
}

// Keep the same owned blob and parsed-manifest lifetime for cached and pulled
// images so callers can use either without special cleanup.
fn loadLocalImage(alloc: std.mem.Allocator, target: []const u8, ref: spec.ImageRef) common.ImageCommandsError!?registry.PullResult {
    const record = (if (blob_store.Digest.parse(target) != null)
        store.loadImage(alloc, target)
    else if (ref.digest_reference)
        store.loadImage(alloc, ref.reference)
    else
        store.findImage(alloc, ref.host, ref.repository, ref.reference)) catch |err| switch (err) {
        error.NotFound => return null,
        else => return error.StoreFailed,
    };
    defer record.deinit(alloc);
    const blobs = try common.loadImageBlobs(alloc, record);
    errdefer blobs.deinit(alloc);
    var parsed = spec.parseManifest(alloc, blobs.manifest_bytes) catch return error.StoreFailed;
    errdefer parsed.deinit();
    const digest = try alloc.dupe(u8, record.manifest_digest);
    return .{
        .manifest_digest = digest,
        .manifest_bytes = blobs.manifest_bytes,
        .config_bytes = blobs.config_bytes,
        .layers = parsed.value.layers,
        .parsed_manifest = parsed,
        .layer_digests = &.{},
        .total_size = @intCast(@max(record.total_size, 0)),
        .alloc = alloc,
    };
}

test "local image resolution uses cached tags and rejects missing images without pulling" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    const config = "{\"config\":{\"Cmd\":[\"echo\",\"cached\"],\"StopSignal\":\"SIGTERM\"}}";
    const config_digest = try blob_store.putBlob(config);
    defer blob_store.removeBlob(config_digest);
    var config_buf: [71]u8 = undefined;
    const manifest = try std.fmt.allocPrint(alloc, "{{\"schemaVersion\":2,\"config\":{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[]}}", .{ spec.media_type.oci_config, config_digest.string(&config_buf), config.len });
    defer alloc.free(manifest);
    const digest = try blob_store.putBlob(manifest);
    defer blob_store.removeBlob(digest);
    var digest_buf: [71]u8 = undefined;
    try store.saveImage(.{ .id = digest.string(&digest_buf), .repository = "local-resolution-test", .tag = "latest", .manifest_digest = digest.string(&digest_buf), .config_digest = config_digest.string(&config_buf), .total_size = 0, .created_at = 0 });
    for ([_]PullPolicy{ .missing, .never }) |policy| {
        var result = try resolveImage(std.Options.debug_io, alloc, "local-resolution-test", policy);
        defer result.deinit();
        try std.testing.expectEqualStrings("cached", result.default_cmd[1]);
        try std.testing.expectEqual(@as(usize, 1), result.layer_paths.len);
        try std.testing.expect(std.mem.startsWith(u8, result.rootfs, "/"));
        try std.testing.expectEqualStrings(digest.string(&digest_buf), result.manifest_digest);
        try std.testing.expectEqualStrings("SIGTERM", result.stop_signal.?);
    }
    try std.testing.expectError(error.ImageNotFound, resolveImage(std.Options.debug_io, alloc, "not-cached", .never));
}
