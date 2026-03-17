const std = @import("std");
const spec = @import("../spec.zig");
const blob_store = @import("../store.zig");
const log = @import("../../lib/log.zig");
const common = @import("common.zig");
const http_helpers = @import("http.zig");

pub const ManifestFetchResult = struct {
    body: []const u8,
    digest: []const u8,
};

pub fn fetchManifest(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    reference: []const u8,
    token: common.Token,
) common.ManifestError!ManifestFetchResult {
    var url_buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://{s}/v2/{s}/manifests/{s}",
        .{ host, repository, reference },
    ) catch return error.ManifestNotFound;

    const accept_header = std.http.Header{
        .name = "Accept",
        .value = spec.media_type.oci_index ++ ", " ++
            spec.media_type.oci_manifest ++ ", " ++
            spec.media_type.manifest_list ++ ", " ++
            spec.media_type.manifest_v2,
    };

    var auth_buf: [8192]u8 = undefined;
    const auth_value = common.authHeaderValue(token, &auth_buf);

    const uri = std.Uri.parse(url) catch return error.ManifestNotFound;
    var headers: [1]std.http.Header = .{accept_header};

    const manifest_conn = http_helpers.connectWithTimeout(client, uri) catch return error.NetworkError;
    var req = client.request(.GET, uri, .{
        .connection = manifest_conn,
        .redirect_behavior = @enumFromInt(3),
        .keep_alive = false,
        .headers = .{
            .authorization = if (auth_value.len > 0) .{ .override = auth_value } else .default,
        },
        .extra_headers = &headers,
    }) catch return error.NetworkError;
    defer req.deinit();

    req.sendBodiless() catch return error.NetworkError;

    var redirect_buf: [8192]u8 = undefined;
    var response = req.receiveHead(&redirect_buf) catch return error.NetworkError;
    if (response.head.status != .ok) return error.ManifestNotFound;

    if (response.head.content_length) |content_length| {
        if (content_length > common.max_manifest_size) return error.ResponseTooLarge;
    }

    const content_type = common.contentTypeBase(response.head.content_type orelse "");

    var expected_digest: ?blob_store.Digest = null;
    var header_it = response.head.iterateHeaders();
    while (header_it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "docker-content-digest")) continue;
        expected_digest = blob_store.Digest.parse(header.value);
        break;
    }

    var transfer_buf: [8192]u8 = undefined;
    const body_reader = response.reader(&transfer_buf);

    var aw_body: std.Io.Writer.Allocating = .init(alloc);
    defer aw_body.deinit();

    _ = body_reader.streamRemaining(&aw_body.writer) catch return error.NetworkError;

    const raw_body = aw_body.writer.buffer[0..aw_body.writer.end];
    if (raw_body.len > common.max_manifest_size) return error.ResponseTooLarge;

    const computed = blob_store.computeDigest(raw_body);
    var computed_str_buf: [71]u8 = undefined;
    const computed_str = computed.string(&computed_str_buf);

    if (expected_digest) |header_digest| {
        var header_digest_buf: [71]u8 = undefined;
        const header_digest_str = header_digest.string(&header_digest_buf);
        if (!computed.eql(header_digest)) {
            log.warn("manifest digest mismatch: computed {s}, header {s}", .{ computed_str, header_digest_str });
            return error.DigestMismatch;
        }
    }

    if (spec.isIndexMediaType(content_type)) {
        return resolveImageIndex(alloc, client, host, repository, raw_body, token);
    }

    var parsed_index = spec.parseImageIndex(alloc, raw_body) catch null;
    if (parsed_index) |*index| {
        defer index.deinit();
        if (index.value.manifests.len > 0) {
            return resolveImageIndex(alloc, client, host, repository, raw_body, token);
        }
    }

    const body = alloc.dupe(u8, raw_body) catch return error.NetworkError;
    const digest_str = alloc.dupe(u8, computed_str) catch {
        alloc.free(body);
        return error.NetworkError;
    };

    return .{
        .body = body,
        .digest = digest_str,
    };
}

fn resolveImageIndex(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    index_bytes: []const u8,
    token: common.Token,
) common.ManifestError!ManifestFetchResult {
    var parsed = spec.parseImageIndex(alloc, index_bytes) catch return error.ParseError;
    defer parsed.deinit();
    const index = parsed.value;

    var target_digest: ?[]const u8 = null;
    for (index.manifests) |manifest_entry| {
        if (manifest_entry.platform) |platform| {
            if (std.mem.eql(u8, platform.os, "linux") and std.mem.eql(u8, platform.architecture, "amd64")) {
                target_digest = manifest_entry.digest;
                break;
            }
        }
    }

    if (target_digest == null) {
        for (index.manifests) |manifest_entry| {
            if (manifest_entry.platform) |platform| {
                if (std.mem.eql(u8, platform.os, "linux")) {
                    target_digest = manifest_entry.digest;
                    break;
                }
            }
        }
    }

    const digest = target_digest orelse return error.PlatformNotFound;
    return fetchManifest(alloc, client, host, repository, digest, token);
}
