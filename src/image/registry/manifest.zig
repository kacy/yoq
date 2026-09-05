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
    return fetchManifestWithScheme(alloc, client, host, repository, reference, token, "https");
}

fn fetchManifestWithScheme(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    reference: []const u8,
    token: common.Token,
    comptime scheme: []const u8,
) common.ManifestError!ManifestFetchResult {
    // Colons are not legal in a tag. A digest-valued reference must parse
    // successfully, and its hash is authoritative even without a header.
    const requested_digest: ?blob_store.Digest = if (std.mem.indexOfScalar(u8, reference, ':') != null)
        blob_store.Digest.parse(reference) orelse return error.DigestMismatch
    else
        null;
    var url_buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "{s}://{s}/v2/{s}/manifests/{s}",
        .{ scheme, host, repository, reference },
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
        expected_digest = blob_store.Digest.parse(header.value) orelse return error.DigestMismatch;
        break;
    }

    var transfer_buf: [8192]u8 = undefined;
    const body_reader = response.reader(&transfer_buf);

    const raw_body = try http_helpers.readBody(alloc, body_reader, common.max_manifest_size);
    defer alloc.free(raw_body);

    const computed = blob_store.computeDigest(raw_body);
    var computed_str_buf: [71]u8 = undefined;
    const computed_str = computed.string(&computed_str_buf);

    if (requested_digest) |expected| {
        if (!computed.eql(expected)) return error.DigestMismatch;
    }

    if (expected_digest) |header_digest| {
        var header_digest_buf: [71]u8 = undefined;
        const header_digest_str = header_digest.string(&header_digest_buf);
        if (!computed.eql(header_digest)) {
            log.warn("manifest digest mismatch: computed {s}, header {s}", .{ computed_str, header_digest_str });
            return error.DigestMismatch;
        }
    }

    if (spec.isIndexMediaType(content_type)) {
        return resolveImageIndex(alloc, client, host, repository, raw_body, token, scheme);
    }

    var parsed_index = spec.parseImageIndex(alloc, raw_body) catch null;
    if (parsed_index) |*index| {
        defer index.deinit();
        if (index.value.manifests.len > 0) {
            return resolveImageIndex(alloc, client, host, repository, raw_body, token, scheme);
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
    comptime scheme: []const u8,
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
    _ = blob_store.Digest.parse(digest) orelse return error.DigestMismatch;
    return fetchManifestWithScheme(alloc, client, host, repository, digest, token, scheme);
}

test "registry transfer verifies pinned manifests with and without server digest headers" {
    const Server = @import("test_support.zig").Server;
    const alloc = std.testing.allocator;
    const body = "{\"schemaVersion\":2}";
    var digest_buf: [71]u8 = undefined;
    const digest = blob_store.computeDigest(body).string(&digest_buf);
    const wrong = "sha256:" ++ "0" ** 64;
    var headers_buf: [128]u8 = undefined;
    const headers = try std.fmt.bufPrint(&headers_buf, "Docker-Content-Digest: {s}\r\n", .{digest});
    for ([_]bool{ false, true }) |has_header| {
        for ([_]bool{ false, true }) |wrong_pin| {
            const replies = [_]Server.Reply{.{ .body = body, .headers = if (has_header) headers else "" }};
            var server = try Server.init(&replies);
            defer server.deinit();
            try server.start();
            var client: std.http.Client = .{ .io = std.testing.io, .allocator = alloc };
            defer client.deinit();
            var host_buf: [64]u8 = undefined;
            const result = fetchManifestWithScheme(alloc, &client, try server.host(&host_buf), "test", if (wrong_pin) wrong else digest, .{ .value = "" }, "http");
            if (wrong_pin) {
                try std.testing.expectError(error.DigestMismatch, result);
            } else {
                const fetched = try result;
                defer alloc.free(fetched.body);
                defer alloc.free(fetched.digest);
                try std.testing.expectEqualStrings(body, fetched.body);
                try std.testing.expectEqualStrings(digest, fetched.digest);
            }
        }
    }
}

test "registry transfer validates selected index descriptor syntax and content" {
    const Server = @import("test_support.zig").Server;
    const alloc = std.testing.allocator;
    const body = "{\"schemaVersion\":2}";
    var digest_buf: [71]u8 = undefined;
    const digest = blob_store.computeDigest(body).string(&digest_buf);
    const descriptors = [_][]const u8{ digest, "sha256:" ++ "0" ** 64, "latest" };
    for (descriptors, 0..) |descriptor, index| {
        const index_body = try std.fmt.allocPrint(
            alloc,
            "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{s}\",\"size\":19,\"platform\":{{\"os\":\"linux\",\"architecture\":\"amd64\"}}}}]}}",
            .{descriptor},
        );
        defer alloc.free(index_body);
        var headers_buf: [128]u8 = undefined;
        const child_headers = try std.fmt.bufPrint(&headers_buf, "Docker-Content-Digest: {s}\r\n", .{digest});
        const replies = [_]Server.Reply{
            .{ .body = index_body, .headers = "Content-Type: application/vnd.oci.image.index.v1+json\r\n" },
            .{ .body = body, .headers = child_headers },
        };
        var server = try Server.init(replies[0..if (index == 2) @as(usize, 1) else 2]);
        defer server.deinit();
        try server.start();
        var client: std.http.Client = .{ .io = std.testing.io, .allocator = alloc };
        defer client.deinit();
        var host_buf: [64]u8 = undefined;
        const result = fetchManifestWithScheme(alloc, &client, try server.host(&host_buf), "test", "latest", .{ .value = "" }, "http");
        if (index != 0) {
            try std.testing.expectError(error.DigestMismatch, result);
        } else {
            const fetched = try result;
            defer alloc.free(fetched.body);
            defer alloc.free(fetched.digest);
            try std.testing.expectEqualStrings(body, fetched.body);
        }
    }
}

test "registry transfer caps chunked and unknown length manifests before allocating the whole body" {
    const Server = @import("test_support.zig").Server;
    for ([_]Server.Reply{ .{ .framing = .chunked }, .{ .framing = .close } }) |framing| {
        const replies = [_]Server.Reply{.{ .framing = framing.framing, .repeated_bytes = common.max_manifest_size * 3 }};
        var server = try Server.init(&replies);
        defer server.deinit();
        try server.start();
        var client: std.http.Client = .{ .io = std.testing.io, .allocator = std.testing.allocator };
        defer client.deinit();
        const memory = try std.testing.allocator.alloc(u8, common.max_manifest_size * 2);
        defer std.testing.allocator.free(memory);
        var bounded = std.heap.FixedBufferAllocator.init(memory);
        var host_buf: [64]u8 = undefined;
        try std.testing.expectError(error.ResponseTooLarge, fetchManifestWithScheme(
            bounded.allocator(),
            &client,
            try server.host(&host_buf),
            "test",
            "latest",
            .{ .value = "" },
            "http",
        ));
    }
}
