const std = @import("std");
const spec = @import("../spec.zig");

pub const RegistryError = error{
    InvalidSizeLimit,
    AuthFailed,
    ManifestNotFound,
    BlobNotFound,
    NetworkError,
    ParseError,
    UnsupportedMediaType,
    PlatformNotFound,
    DigestMismatch,
    ResponseTooLarge,
    UploadFailed,
    UploadInitFailed,
};

pub const AuthError = error{
    AuthFailed,
    NetworkError,
    ParseError,
    ResponseTooLarge,
    OutOfMemory,
};

pub const ManifestError = error{
    ManifestNotFound,
    NetworkError,
    AuthFailed,
    ParseError,
    PlatformNotFound,
    DigestMismatch,
    ResponseTooLarge,
    OutOfMemory,
};

pub const manifest_accept = spec.media_type.oci_index ++ ", " ++
    spec.media_type.oci_manifest ++ ", " ++
    spec.media_type.manifest_list ++ ", " ++
    spec.media_type.manifest_v2;

pub const max_manifest_size: usize = 10 * 1024 * 1024;
pub const max_auth_response_size: usize = 64 * 1024;
pub const max_config_size: usize = 4 * 1024 * 1024;
pub const max_blob_size: usize = 512 * 1024 * 1024;
pub const max_parallel_downloads = 4;
pub const registry_timeout_sec = 30;

pub const PullOptions = struct {
    max_layer_bytes: u64 = max_blob_size,

    pub fn fromEnvironment() error{InvalidSizeLimit}!PullOptions {
        const value = std.c.getenv("YOQ_MAX_LAYER_BYTES") orelse return .{};
        return .{ .max_layer_bytes = try parseLayerLimit(std.mem.span(value)) };
    }
};

fn parseLayerLimit(value: []const u8) error{InvalidSizeLimit}!u64 {
    if (value.len == 0) return error.InvalidSizeLimit;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidSizeLimit;
    const limit = std.fmt.parseInt(u64, value, 10) catch return error.InvalidSizeLimit;
    if (limit == 0) return error.InvalidSizeLimit;
    return limit;
}

test "registry layer size policy accepts large explicit byte limits and rejects invalid configuration" {
    try std.testing.expectEqual(@as(u64, 8 * 1024 * 1024 * 1024), try parseLayerLimit("8589934592"));
    for ([_][]const u8{ "", "0", "-1", "+1", "8GiB", "18446744073709551616" }) |invalid|
        try std.testing.expectError(error.InvalidSizeLimit, parseLayerLimit(invalid));
}

pub const Token = struct {
    value: []const u8,
    kind: enum { bearer, basic } = .bearer,
};

pub const AuthChallenge = struct {
    realm: []const u8,
    service: []const u8,
};

pub const PullResult = struct {
    manifest_digest: []const u8,
    manifest_bytes: []const u8,
    config_bytes: []const u8,
    layer_digests: []const []const u8,
    total_size: u64,
    /// descriptors borrow the retained manifest and remain valid until deinit.
    layers: []const spec.Descriptor = &.{},
    parsed_manifest: ?spec.ParseResult(spec.Manifest) = null,

    alloc: std.mem.Allocator,

    pub fn deinit(self: *PullResult) void {
        if (self.parsed_manifest) |*parsed| parsed.deinit();
        self.alloc.free(self.manifest_bytes);
        self.alloc.free(self.config_bytes);
        for (self.layer_digests) |digest| self.alloc.free(digest);
        self.alloc.free(self.layer_digests);
        if (self.manifest_digest.len > 0) self.alloc.free(self.manifest_digest);
    }
};

pub const PushResult = struct {
    layers_uploaded: usize,
    layers_skipped: usize,
    manifest_digest: []const u8,

    alloc: std.mem.Allocator,

    pub fn deinit(self: *PushResult) void {
        if (self.manifest_digest.len > 0) self.alloc.free(self.manifest_digest);
    }
};

pub fn resolveRepository(ref: spec.ImageRef, buf: *[256]u8) []const u8 {
    if (std.mem.eql(u8, ref.host, "registry-1.docker.io") and
        std.mem.indexOfScalar(u8, ref.repository, '/') == null)
    {
        const result = std.fmt.bufPrint(buf, "library/{s}", .{ref.repository}) catch
            return ref.repository;
        return result;
    }
    return ref.repository;
}

pub fn contentTypeBase(value: []const u8) []const u8 {
    const semi_idx = std.mem.indexOfScalar(u8, value, ';') orelse return std.mem.trim(u8, value, " \t\r\n");
    return std.mem.trim(u8, value[0..semi_idx], " \t\r\n");
}

pub fn isRedirectStatus(status: std.http.Status) bool {
    const code = @intFromEnum(status);
    return code >= 300 and code < 400;
}

pub fn summarizeUrl(url: []const u8, buf: *[256]u8) []const u8 {
    const q_idx = std.mem.indexOfScalar(u8, url, '?') orelse url.len;
    const trimmed = url[0..q_idx];
    if (trimmed.len <= buf.len) {
        @memcpy(buf[0..trimmed.len], trimmed);
        return buf[0..trimmed.len];
    }

    const keep = buf.len - 3;
    @memcpy(buf[0..keep], trimmed[0..keep]);
    @memcpy(buf[keep..buf.len], "...");
    return buf[0..buf.len];
}

pub fn authHeaderValue(token: Token, buf: *[8192]u8) []const u8 {
    if (token.value.len == 0) return "";
    return std.fmt.bufPrint(buf, "{s} {s}", .{ if (token.kind == .bearer) "Bearer" else "Basic", token.value }) catch "";
}

test "registry pull result owns layer descriptors until deinit" {
    const alloc = std.testing.allocator;
    var result = result: {
        const bytes = try alloc.dupe(u8,
            \\{"schemaVersion":2,"config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:config","size":2},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+zstd","digest":"sha256:layer","size":4096}]}
        );
        errdefer alloc.free(bytes);
        var parsed = try spec.parseManifest(alloc, bytes);
        errdefer parsed.deinit();
        const config = try alloc.dupe(u8, "{}");
        break :result PullResult{
            .manifest_digest = "",
            .manifest_bytes = bytes,
            .config_bytes = config,
            .layer_digests = &.{},
            .total_size = 4096,
            .layers = parsed.value.layers,
            .parsed_manifest = parsed,
            .alloc = alloc,
        };
    };
    defer result.deinit();
    try std.testing.expectEqualStrings(spec.media_type.oci_layer_zstd, result.layers[0].mediaType);
    try std.testing.expectEqualStrings("sha256:layer", result.layers[0].digest);
    try std.testing.expectEqual(@as(u64, 4096), result.layers[0].size);
}
