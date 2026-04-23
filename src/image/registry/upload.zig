const std = @import("std");
const spec = @import("../spec.zig");
const blob_store = @import("../store.zig");
const common = @import("common.zig");
const http_helpers = @import("http.zig");

pub const UploadTarget = struct {
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
    var req = client.request(.HEAD, uri, .{
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

    const target = try initiateUpload(client, host, repository, token);
    var put_url_buf: [2048]u8 = undefined;
    const put_url = buildUploadUrl(&put_url_buf, target.url, digest) catch
        return common.RegistryError.UploadFailed;

    const put_uri = std.Uri.parse(put_url) catch return common.RegistryError.UploadFailed;
    const put_conn = http_helpers.connectWithTimeout(client, put_uri) catch return common.RegistryError.UploadFailed;

    var auth_buf: [8192]u8 = undefined;
    const auth_value = common.authHeaderValue(token, &auth_buf);

    var req = client.request(.PUT, put_uri, .{
        .connection = put_conn,
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
        .headers = .{
            .authorization = if (target.send_auth and auth_value.len > 0) .{ .override = auth_value } else .default,
            .content_type = .{ .override = "application/octet-stream" },
        },
    }) catch return common.RegistryError.UploadFailed;
    defer req.deinit();

    req.sendBodyComplete(@constCast(data)) catch return common.RegistryError.UploadFailed;

    var redirect_buf: [8192]u8 = undefined;
    const response = req.receiveHead(&redirect_buf) catch return common.RegistryError.UploadFailed;
    if (response.head.status != .created) return common.RegistryError.UploadFailed;
}

pub fn uploadBlobFile(
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    blob: *blob_store.BlobHandle,
    token: common.Token,
) common.RegistryError!void {
    const target = try initiateUpload(client, host, repository, token);
    var put_url_buf: [2048]u8 = undefined;
    const put_url = buildUploadUrl(&put_url_buf, target.url, digest) catch
        return common.RegistryError.UploadFailed;

    const put_uri = std.Uri.parse(put_url) catch return common.RegistryError.UploadFailed;
    const put_conn = http_helpers.connectWithTimeout(client, put_uri) catch return common.RegistryError.UploadFailed;

    var auth_buf: [8192]u8 = undefined;
    const auth_value = common.authHeaderValue(token, &auth_buf);

    var req = client.request(.PUT, put_uri, .{
        .connection = put_conn,
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
        .headers = .{
            .authorization = if (target.send_auth and auth_value.len > 0) .{ .override = auth_value } else .default,
            .content_type = .{ .override = "application/octet-stream" },
        },
    }) catch return common.RegistryError.UploadFailed;
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = blob.size };

    var body_buf: [8192]u8 = undefined;
    var body_writer = req.sendBody(&body_buf) catch return common.RegistryError.UploadFailed;

    var file_reader_buf: [8192]u8 = undefined;
    var sent: u64 = 0;
    while (sent < blob.size) {
        const bytes_read = blob.file.read(&file_reader_buf) catch return common.RegistryError.UploadFailed;
        if (bytes_read == 0) break;
        body_writer.writer.writeAll(file_reader_buf[0..bytes_read]) catch return common.RegistryError.UploadFailed;
        sent += bytes_read;
    }
    if (sent != blob.size) return common.RegistryError.UploadFailed;

    body_writer.end() catch return common.RegistryError.UploadFailed;
    req.connection.?.flush() catch return common.RegistryError.UploadFailed;

    var redirect_buf: [8192]u8 = undefined;
    const response = req.receiveHead(&redirect_buf) catch return common.RegistryError.UploadFailed;
    if (response.head.status != .created) return common.RegistryError.UploadFailed;
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

    return .{
        .url = location,
        .send_auth = std.mem.eql(u8, upload_host.bytes, registry_host),
    };
}

fn initiateUpload(
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    token: common.Token,
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
    const upload_conn = http_helpers.connectWithTimeout(client, init_uri) catch return common.RegistryError.UploadInitFailed;
    var init_req = client.request(.POST, init_uri, .{
        .connection = upload_conn,
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

    const location = http_helpers.parseLocationHeader(host, init_response.head) orelse
        return common.RegistryError.UploadInitFailed;
    return resolveUploadTarget(host, location) orelse
        return common.RegistryError.UploadInitFailed;
}

fn buildUploadUrl(buf: *[2048]u8, location: []const u8, digest: []const u8) ![]const u8 {
    const separator: []const u8 = if (std.mem.indexOfScalar(u8, location, '?') != null) "&" else "?";
    return std.fmt.bufPrint(buf, "{s}{s}digest={s}", .{ location, separator, digest });
}
