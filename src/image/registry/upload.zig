const std = @import("std");
const spec = @import("../spec.zig");
const blob_store = @import("../store.zig");
const common = @import("common.zig");
const http_helpers = @import("http.zig");

pub const UploadTarget = struct {
    /// borrows the location passed to resolveUploadTarget.
    url: []const u8,
    send_auth: bool,
};

pub fn checkBlobExists(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    token: common.Token,
) common.RegistryError!bool {
    var url_buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://{s}/v2/{s}/blobs/{s}",
        .{ host, repository, digest },
    ) catch return common.RegistryError.NetworkError;

    var auth_buf: [8192]u8 = undefined;
    const auth_value = common.authHeaderValue(token, &auth_buf);

    const uri = std.Uri.parse(url) catch return common.RegistryError.NetworkError;
    var req = http_helpers.requestWithTimeout(client, .HEAD, uri, .{
        .redirect_behavior = @enumFromInt(3),
        .keep_alive = false,
        .headers = .{
            .authorization = if (auth_value.len > 0) .{ .override = auth_value } else .default,
        },
    }) catch return common.RegistryError.NetworkError;
    defer req.deinit();

    req.sendBodiless() catch return common.RegistryError.NetworkError;

    _ = alloc;

    var redirect_buf: [4096]u8 = undefined;
    const response = req.receiveHead(&redirect_buf) catch return common.RegistryError.NetworkError;

    if (response.head.status == .ok) return true;
    if (response.head.status == .not_found) return false;
    return common.RegistryError.NetworkError;
}

pub fn uploadBlob(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    data: []const u8,
    token: common.Token,
) common.RegistryError!void {
    _ = alloc;

    return upload(client, host, repository, digest, .{ .bytes = data }, token);
}

pub fn uploadBlobFile(
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    blob: *blob_store.BlobHandle,
    token: common.Token,
) common.RegistryError!void {
    return upload(client, host, repository, digest, .{ .file = blob }, token);
}

const UploadBody = union(enum) {
    bytes: []const u8,
    file: *blob_store.BlobHandle,
};

fn upload(
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    body: UploadBody,
    token: common.Token,
) common.RegistryError!void {
    var location_buf: [8192]u8 = undefined;
    const target = try initiateUpload(client, host, repository, token, &location_buf);
    var put_url_buf: [2048]u8 = undefined;
    const put_url = buildUploadUrl(&put_url_buf, target.url, digest) catch
        return common.RegistryError.UploadFailed;
    const put_uri = std.Uri.parse(put_url) catch return common.RegistryError.UploadFailed;

    var auth_buf: [8192]u8 = undefined;
    const auth_value = common.authHeaderValue(token, &auth_buf);
    var req = http_helpers.requestWithTimeout(client, .PUT, put_uri, .{
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
        .headers = .{
            .authorization = if (target.send_auth and auth_value.len > 0) .{ .override = auth_value } else .default,
            .content_type = .{ .override = "application/octet-stream" },
        },
    }) catch return common.RegistryError.UploadFailed;
    defer req.deinit();

    switch (body) {
        .bytes => |data| req.sendBodyComplete(@constCast(data)) catch return common.RegistryError.UploadFailed,
        .file => |blob| try sendFile(&req, blob),
    }

    var response_buf: [8192]u8 = undefined;
    const response = req.receiveHead(&response_buf) catch return common.RegistryError.UploadFailed;
    if (response.head.status != .created) return common.RegistryError.UploadFailed;
}

fn sendFile(req: *std.http.Client.Request, blob: *blob_store.BlobHandle) common.RegistryError!void {
    req.transfer_encoding = .{ .content_length = blob.size };
    var body_buf: [8192]u8 = undefined;
    var body_writer = req.sendBody(&body_buf) catch return common.RegistryError.UploadFailed;
    var file_buf: [8192]u8 = undefined;
    var file_reader = blob.file.readerStreaming(std.Options.debug_io, &file_buf);

    // send the advertised size and reject files truncated since openBlob.
    file_reader.interface.streamExact64(&body_writer.writer, blob.size) catch return common.RegistryError.UploadFailed;
    body_writer.end() catch return common.RegistryError.UploadFailed;
    req.connection.?.flush() catch return common.RegistryError.UploadFailed;
}

pub fn uploadManifest(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    reference: []const u8,
    manifest_bytes: []const u8,
    token: common.Token,
) common.RegistryError!void {
    var url_buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://{s}/v2/{s}/manifests/{s}",
        .{ host, repository, reference },
    ) catch return common.RegistryError.UploadFailed;

    var auth_buf: [8192]u8 = undefined;
    const auth_value = common.authHeaderValue(token, &auth_buf);

    _ = alloc;

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .PUT,
        .payload = manifest_bytes,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = spec.media_type.oci_manifest },
            .{ .name = "Authorization", .value = auth_value },
        },
    }) catch return common.RegistryError.UploadFailed;

    if (result.status != .created) return common.RegistryError.UploadFailed;
}

pub fn resolveUploadTarget(registry_host: []const u8, location: []const u8) ?UploadTarget {
    const uri = std.Uri.parse(location) catch return null;
    const protocol = std.http.Client.Protocol.fromUri(uri) orelse return null;
    if (protocol != .tls) return null;

    var host_buf: [255]u8 = undefined;
    const upload_host = uri.getHost(&host_buf) catch return null;

    var registry_url_buf: [1024]u8 = undefined;
    const registry_url = std.fmt.bufPrint(&registry_url_buf, "https://{s}", .{registry_host}) catch return null;
    const registry_uri = std.Uri.parse(registry_url) catch return null;
    var registry_host_buf: [255]u8 = undefined;
    const registry_name = registry_uri.getHost(&registry_host_buf) catch return null;

    return .{
        .url = location,
        .send_auth = std.ascii.eqlIgnoreCase(upload_host.bytes, registry_name.bytes) and
            (uri.port orelse 443) == (registry_uri.port orelse 443),
    };
}

fn initiateUpload(
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    token: common.Token,
    location_buf: []u8,
) common.RegistryError!UploadTarget {
    var init_url_buf: [1024]u8 = undefined;
    const init_url = std.fmt.bufPrint(
        &init_url_buf,
        "https://{s}/v2/{s}/blobs/uploads/",
        .{ host, repository },
    ) catch return common.RegistryError.UploadInitFailed;

    var auth_buf: [8192]u8 = undefined;
    const auth_value = common.authHeaderValue(token, &auth_buf);

    const init_uri = std.Uri.parse(init_url) catch return common.RegistryError.UploadInitFailed;
    var init_req = http_helpers.requestWithTimeout(client, .POST, init_uri, .{
        .redirect_behavior = @enumFromInt(3),
        .keep_alive = false,
        .headers = .{
            .authorization = if (auth_value.len > 0) .{ .override = auth_value } else .default,
            .content_type = .{ .override = "application/octet-stream" },
        },
    }) catch return common.RegistryError.UploadInitFailed;
    defer init_req.deinit();

    init_req.sendBodiless() catch return common.RegistryError.UploadInitFailed;

    var redirect_buf: [8192]u8 = undefined;
    const init_response = init_req.receiveHead(&redirect_buf) catch
        return common.RegistryError.UploadInitFailed;
    if (init_response.head.status != .accepted) return common.RegistryError.UploadInitFailed;

    const location = http_helpers.parseLocationHeader(host, init_response.head, location_buf) orelse
        return common.RegistryError.UploadInitFailed;
    return resolveUploadTarget(host, location) orelse
        return common.RegistryError.UploadInitFailed;
}

fn buildUploadUrl(buf: *[2048]u8, location: []const u8, digest: []const u8) ![]const u8 {
    const separator: []const u8 = if (std.mem.indexOfScalar(u8, location, '?') != null) "&" else "?";
    return std.fmt.bufPrint(buf, "{s}{s}digest={s}", .{ location, separator, digest });
}

test "resolveUploadTarget rejects insecure absolute URLs" {
    try std.testing.expect(resolveUploadTarget(
        "registry.example.io",
        "http://registry.example.io/v2/myrepo/blobs/uploads/uuid-123",
    ) == null);
}

test "resolveUploadTarget omits auth for non-registry hosts" {
    const target = resolveUploadTarget(
        "registry.example.io",
        "https://storage.example.io/v2/myrepo/blobs/uploads/uuid-123",
    ).?;
    try std.testing.expectEqualStrings(
        "https://storage.example.io/v2/myrepo/blobs/uploads/uuid-123",
        target.url,
    );
    try std.testing.expect(!target.send_auth);
}

test "resolveUploadTarget keeps auth for registry host" {
    const target = resolveUploadTarget(
        "registry.example.io",
        "https://registry.example.io/v2/myrepo/blobs/uploads/uuid-123",
    ).?;
    try std.testing.expect(target.send_auth);
}

test "resolveUploadTarget forwards credentials only to the same https origin" {
    const Case = struct { registry: []const u8, location: []const u8, send_auth: bool };
    for ([_]Case{
        .{ .registry = "registry.example.io:5443", .location = "https://registry.example.io:5443/upload", .send_auth = true },
        .{ .registry = "registry.example.io:5443", .location = "https://registry.example.io:6443/upload", .send_auth = false },
        .{ .registry = "registry.example.io", .location = "https://registry.example.io:5443/upload", .send_auth = false },
        .{ .registry = "registry.example.io:5443", .location = "https://registry.example.io/upload", .send_auth = false },
        .{ .registry = "registry.example.io:443", .location = "https://registry.example.io/upload", .send_auth = true },
        .{ .registry = "registry.example.io", .location = "https://REGISTRY.EXAMPLE.IO:443/upload", .send_auth = true },
        .{ .registry = "[::1]:5443", .location = "https://[::1]:5443/upload", .send_auth = true },
    }) |case| {
        const target = resolveUploadTarget(case.registry, case.location).?;
        try std.testing.expectEqual(case.send_auth, target.send_auth);
    }
}
