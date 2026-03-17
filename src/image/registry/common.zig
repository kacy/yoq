const std = @import("std");
const spec = @import("../spec.zig");

pub const RegistryError = error{
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

pub const max_manifest_size: usize = 10 * 1024 * 1024;
pub const max_auth_response_size: usize = 64 * 1024;
pub const max_blob_size: usize = 512 * 1024 * 1024;
pub const max_parallel_downloads = 4;
pub const registry_timeout_sec = 30;

pub const Token = struct {
    value: []const u8,
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

    alloc: std.mem.Allocator,

    pub fn deinit(self: *PullResult) void {
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
    return std.fmt.bufPrint(buf, "Bearer {s}", .{token.value}) catch "";
}
