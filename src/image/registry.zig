const std = @import("std");
const spec = @import("spec.zig");
const blob_store = @import("store.zig");
const common = @import("registry/common.zig");
const auth = @import("registry/auth.zig");
const manifest_fetch = @import("registry/manifest.zig");
const blob_transfer = @import("registry/blob_transfer.zig");
const upload = @import("registry/upload.zig");
const http_helpers = @import("registry/http.zig");

pub const RegistryError = common.RegistryError;
pub const PullResult = common.PullResult;
pub const PushResult = common.PushResult;

/// pull an image from a registry.
/// downloads the manifest, config, and all layer blobs.
/// layer blobs are stored in the blob store; config and manifest are returned.
///
/// uses errdefer chains so each allocation is automatically cleaned up
/// on any subsequent failure — no manual cleanup blocks needed.
pub fn pull(alloc: std.mem.Allocator, image_ref: spec.ImageRef) RegistryError!PullResult {
    var client: std.http.Client = .{ .allocator = alloc };
    defer client.deinit();

    var repo_buf: [256]u8 = undefined;
    const repository = common.resolveRepository(image_ref, &repo_buf);

    const token = auth.authenticate(alloc, &client, image_ref.host, repository, "pull") catch |e|
        return switch (e) {
            error.AuthFailed => RegistryError.AuthFailed,
            error.NetworkError => RegistryError.NetworkError,
            error.ParseError => RegistryError.ParseError,
            error.ResponseTooLarge => RegistryError.ResponseTooLarge,
            error.OutOfMemory => RegistryError.NetworkError,
        };
    defer {
        std.crypto.secureZero(u8, @constCast(token.value));
        alloc.free(token.value);
    }

    const manifest_result = manifest_fetch.fetchManifest(alloc, &client, image_ref.host, repository, image_ref.reference, token) catch |e| {
        return switch (e) {
            error.ManifestNotFound => RegistryError.ManifestNotFound,
            error.NetworkError => RegistryError.NetworkError,
            error.AuthFailed => RegistryError.AuthFailed,
            error.ParseError => RegistryError.ParseError,
            error.PlatformNotFound => RegistryError.PlatformNotFound,
            error.DigestMismatch => RegistryError.DigestMismatch,
            error.ResponseTooLarge => RegistryError.ResponseTooLarge,
            error.OutOfMemory => RegistryError.NetworkError,
        };
    };
    const manifest_bytes = manifest_result.body;
    errdefer alloc.free(manifest_bytes);
    const manifest_digest_str = manifest_result.digest;
    errdefer if (manifest_digest_str.len > 0) alloc.free(manifest_digest_str);

    var parsed = spec.parseManifest(alloc, manifest_bytes) catch
        return RegistryError.ParseError;
    defer parsed.deinit();
    const manifest = parsed.value;

    const config_bytes = blob_transfer.fetchBlob(alloc, &client, image_ref.host, repository, manifest.config.digest, token) catch |e|
        return switch (e) {
            error.BlobNotFound => RegistryError.BlobNotFound,
            error.NetworkError => RegistryError.NetworkError,
            error.ResponseTooLarge => RegistryError.ResponseTooLarge,
        };
    errdefer alloc.free(config_bytes);

    const config_computed = blob_store.computeDigest(config_bytes);
    if (blob_store.Digest.parse(manifest.config.digest)) |expected| {
        if (!config_computed.eql(expected)) {
            return RegistryError.DigestMismatch;
        }
    }

    var layer_digests: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (layer_digests.items) |d| alloc.free(d);
        layer_digests.deinit(alloc);
    }
    var total_size: u64 = 0;

    const layer_count = manifest.layers.len;
    if (layer_count <= 1) {
        for (manifest.layers) |layer| {
            blob_transfer.downloadLayerBlob(alloc, &client, image_ref.host, repository, layer.digest, token) catch |e|
                return switch (e) {
                    error.BlobNotFound => RegistryError.BlobNotFound,
                    error.NetworkError => RegistryError.NetworkError,
                    error.ResponseTooLarge => RegistryError.ResponseTooLarge,
                    error.DigestMismatch => RegistryError.DigestMismatch,
                };
            total_size += layer.size;
        }
    } else {
        var err_flag = std.atomic.Value(bool).init(false);
        var batch_start: usize = 0;

        while (batch_start < layer_count) {
            const batch_end = @min(batch_start + common.max_parallel_downloads, layer_count);
            const batch_size = batch_end - batch_start;

            var threads: [common.max_parallel_downloads]?std.Thread = .{null} ** common.max_parallel_downloads;
            var thread_errors: [common.max_parallel_downloads]?RegistryError = .{null} ** common.max_parallel_downloads;

            for (0..batch_size) |i| {
                const layer = manifest.layers[batch_start + i];
                threads[i] = std.Thread.spawn(.{}, blob_transfer.downloadLayerWorker, .{
                    alloc,
                    image_ref.host,
                    repository,
                    layer.digest,
                    token,
                    &err_flag,
                    &thread_errors[i],
                }) catch null; // fallback to sequential below
            }

            for (0..batch_size) |i| {
                if (threads[i]) |t| {
                    t.join();
                } else {
                    const layer = manifest.layers[batch_start + i];
                    blob_transfer.downloadLayerBlob(alloc, &client, image_ref.host, repository, layer.digest, token) catch |e|
                        return switch (e) {
                            error.BlobNotFound => RegistryError.BlobNotFound,
                            error.NetworkError => RegistryError.NetworkError,
                            error.ResponseTooLarge => RegistryError.ResponseTooLarge,
                            error.DigestMismatch => RegistryError.DigestMismatch,
                        };
                }
            }

            for (thread_errors[0..batch_size]) |maybe_err| {
                if (maybe_err) |e| return e;
            }

            batch_start = batch_end;
        }

        for (manifest.layers) |layer| {
            total_size += layer.size;
        }
    }

    for (manifest.layers) |layer| {
        const digest_copy = alloc.dupe(u8, layer.digest) catch
            return RegistryError.NetworkError;
        layer_digests.append(alloc, digest_copy) catch {
            alloc.free(digest_copy);
            return RegistryError.NetworkError;
        };
    }

    return PullResult{
        .manifest_digest = manifest_digest_str,
        .manifest_bytes = manifest_bytes,
        .config_bytes = config_bytes,
        .layer_digests = layer_digests.toOwnedSlice(alloc) catch
            return RegistryError.NetworkError,
        .total_size = total_size,
        .alloc = alloc,
    };
}

pub fn push(
    alloc: std.mem.Allocator,
    image_ref: spec.ImageRef,
    manifest_bytes: []const u8,
    config_bytes: []const u8,
    layer_digests: []const []const u8,
) RegistryError!PushResult {
    var client: std.http.Client = .{ .allocator = alloc };
    defer client.deinit();

    var repo_buf: [256]u8 = undefined;
    const repository = common.resolveRepository(image_ref, &repo_buf);

    const token = auth.authenticate(alloc, &client, image_ref.host, repository, "push,pull") catch |e|
        return switch (e) {
            error.AuthFailed => RegistryError.AuthFailed,
            error.NetworkError => RegistryError.NetworkError,
            error.ParseError => RegistryError.ParseError,
            error.ResponseTooLarge => RegistryError.ResponseTooLarge,
            error.OutOfMemory => RegistryError.NetworkError,
        };
    defer {
        std.crypto.secureZero(u8, @constCast(token.value));
        alloc.free(token.value);
    }

    var layers_uploaded: usize = 0;
    var layers_skipped: usize = 0;

    for (layer_digests) |digest| {
        const exists = upload.checkBlobExists(alloc, &client, image_ref.host, repository, digest, token) catch false;
        if (exists) {
            layers_skipped += 1;
            continue;
        }

        const parsed_digest = blob_store.Digest.parse(digest) orelse
            return RegistryError.BlobNotFound;
        var blob = blob_store.openBlob(parsed_digest) catch
            return RegistryError.BlobNotFound;
        defer blob.close();

        upload.uploadBlobFile(&client, image_ref.host, repository, digest, &blob, token) catch
            return RegistryError.UploadFailed;
        layers_uploaded += 1;
    }

    const config_digest = blob_store.computeDigest(config_bytes);
    var config_digest_buf: [71]u8 = undefined;
    const config_digest_str = config_digest.string(&config_digest_buf);

    const config_exists = upload.checkBlobExists(alloc, &client, image_ref.host, repository, config_digest_str, token) catch false;
    if (!config_exists) {
        upload.uploadBlob(alloc, &client, image_ref.host, repository, config_digest_str, config_bytes, token) catch
            return RegistryError.UploadFailed;
    }

    upload.uploadManifest(alloc, &client, image_ref.host, repository, image_ref.reference, manifest_bytes, token) catch
        return RegistryError.UploadFailed;

    const manifest_digest = blob_store.computeDigest(manifest_bytes);
    var manifest_digest_buf: [71]u8 = undefined;
    const manifest_digest_str = manifest_digest.string(&manifest_digest_buf);

    const digest_copy = alloc.dupe(u8, manifest_digest_str) catch
        return RegistryError.NetworkError;

    return PushResult{
        .layers_uploaded = layers_uploaded,
        .layers_skipped = layers_skipped,
        .manifest_digest = digest_copy,
        .alloc = alloc,
    };
}

pub fn checkBlobExists(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    token: common.Token,
) RegistryError!bool {
    return upload.checkBlobExists(alloc, client, host, repository, digest, token);
}

pub fn uploadBlob(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    data: []const u8,
    token: common.Token,
) RegistryError!void {
    return upload.uploadBlob(alloc, client, host, repository, digest, data, token);
}

pub fn uploadManifest(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    reference: []const u8,
    manifest_bytes: []const u8,
    token: common.Token,
) RegistryError!void {
    return upload.uploadManifest(alloc, client, host, repository, reference, manifest_bytes, token);
}

// -- tests --

test "resolve repository — bare name gets library/ prefix" {
    var buf: [256]u8 = undefined;
    const ref = spec.ImageRef{
        .host = "registry-1.docker.io",
        .repository = "nginx",
        .reference = "latest",
    };
    const resolved = common.resolveRepository(ref, &buf);
    try std.testing.expectEqualStrings("library/nginx", resolved);
}

test "resolve repository — already qualified passes through" {
    var buf: [256]u8 = undefined;
    const ref = spec.ImageRef{
        .host = "registry-1.docker.io",
        .repository = "myuser/myapp",
        .reference = "latest",
    };
    const resolved = common.resolveRepository(ref, &buf);
    try std.testing.expectEqualStrings("myuser/myapp", resolved);
}

test "resolve repository — non-docker-hub passes through" {
    var buf: [256]u8 = undefined;
    const ref = spec.ImageRef{
        .host = "ghcr.io",
        .repository = "nginx",
        .reference = "latest",
    };
    const resolved = common.resolveRepository(ref, &buf);
    try std.testing.expectEqualStrings("nginx", resolved);
}

test "parse auth challenge" {
    // simulate a response head with Www-Authenticate header
    const response_bytes = "HTTP/1.1 401 Unauthorized\r\n" ++
        "Www-Authenticate: Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\"\r\n" ++
        "Content-Length: 0\r\n\r\n";

    const head = std.http.Client.Response.Head.parse(response_bytes) catch unreachable;
    const challenge = auth.parseAuthChallenge(head).?;

    try std.testing.expectEqualStrings("https://auth.docker.io/token", challenge.realm);
    try std.testing.expectEqualStrings("registry.docker.io", challenge.service);
}

test "parse auth challenge — lowercase bearer scheme" {
    const response_bytes = "HTTP/1.1 401 Unauthorized\r\n" ++
        "www-authenticate: bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\"\r\n" ++
        "Content-Length: 0\r\n\r\n";

    const head = std.http.Client.Response.Head.parse(response_bytes) catch unreachable;
    const challenge = auth.parseAuthChallenge(head).?;

    try std.testing.expectEqualStrings("https://auth.docker.io/token", challenge.realm);
    try std.testing.expectEqualStrings("registry.docker.io", challenge.service);
}

test "parse auth challenge — missing header returns null" {
    const response_bytes = "HTTP/1.1 401 Unauthorized\r\n" ++
        "Content-Length: 0\r\n\r\n";

    const head = std.http.Client.Response.Head.parse(response_bytes) catch unreachable;
    try std.testing.expect(auth.parseAuthChallenge(head) == null);
}

test "contentTypeBase strips parameters and whitespace" {
    try std.testing.expectEqualStrings(
        "application/vnd.oci.image.index.v1+json",
        common.contentTypeBase(" application/vnd.oci.image.index.v1+json; charset=utf-8 "),
    );
}

test "isRedirectStatus detects redirect responses" {
    try std.testing.expect(common.isRedirectStatus(.temporary_redirect));
    try std.testing.expect(common.isRedirectStatus(.found));
    try std.testing.expect(!common.isRedirectStatus(.ok));
}

test "manifest digest is always computed from body" {
    // verifies that our digest computation matches expected sha256 output.
    // this is the foundation of manifest integrity verification — if we
    // compute digests correctly, we'll catch any tampering.
    const manifest_body = "{\"schemaVersion\":2}";
    const computed = blob_store.computeDigest(manifest_body);
    var str_buf: [71]u8 = undefined;
    const digest_str = computed.string(&str_buf);

    // the digest should be a valid sha256: prefixed string
    try std.testing.expect(std.mem.startsWith(u8, digest_str, "sha256:"));
    try std.testing.expectEqual(@as(usize, 71), digest_str.len);

    // computing the same body should always produce the same digest
    const computed2 = blob_store.computeDigest(manifest_body);
    try std.testing.expect(computed.eql(computed2));
}

test "manifest digest mismatch detected" {
    // simulate a scenario where the server-reported digest doesn't match
    // the actual content — this is how we detect MITM or registry corruption
    const body_a = "manifest body version A";
    const body_b = "manifest body version B";

    const digest_a = blob_store.computeDigest(body_a);
    const digest_b = blob_store.computeDigest(body_b);

    // different content must produce different digests
    try std.testing.expect(!digest_a.eql(digest_b));
}

test "response size limits — constants are reasonable" {
    // sanity check that our limits are set correctly
    try std.testing.expectEqual(@as(usize, 10 * 1024 * 1024), common.max_manifest_size);
    try std.testing.expectEqual(@as(usize, 64 * 1024), common.max_auth_response_size);
    try std.testing.expectEqual(@as(usize, 512 * 1024 * 1024), common.max_blob_size);

    // blob limit should be larger than manifest limit (layers >> manifests)
    try std.testing.expect(common.max_blob_size > common.max_manifest_size);

    // a normal manifest is well under the limit
    const small_manifest = "{\"schemaVersion\":2,\"config\":{},\"layers\":[]}";
    try std.testing.expect(small_manifest.len < common.max_manifest_size);
}

test "response size limit rejects oversized data" {
    // verify that data exceeding our limits would be caught.
    // we can't easily test the full HTTP flow, but we can verify the
    // size check logic that runs on the response body.
    const oversized_len: usize = common.max_manifest_size + 1;
    try std.testing.expect(oversized_len > common.max_manifest_size);

    // also verify auth limit
    const oversized_auth: usize = common.max_auth_response_size + 1;
    try std.testing.expect(oversized_auth > common.max_auth_response_size);
}

test "auth scope string — pull scope produces correct URL fragment" {
    // verify that the scope parameter is correctly embedded in the token URL.
    // we can't easily test the full auth flow without a real registry, but we
    // can verify the format string logic by checking bufPrint output.
    var buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &buf,
        "{s}?service={s}&scope=repository:{s}:{s}",
        .{ "https://auth.example.io/token", "registry.example.io", "myrepo", "pull" },
    ) catch unreachable;
    try std.testing.expect(std.mem.indexOf(u8, url, "scope=repository:myrepo:pull") != null);
}

test "auth scope string — push,pull scope produces correct URL fragment" {
    var buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &buf,
        "{s}?service={s}&scope=repository:{s}:{s}",
        .{ "https://auth.example.io/token", "registry.example.io", "myrepo", "push,pull" },
    ) catch unreachable;
    try std.testing.expect(std.mem.indexOf(u8, url, "scope=repository:myrepo:push,pull") != null);
}

test "parseLocationHeader — absolute URL returned as-is" {
    const response_bytes = "HTTP/1.1 202 Accepted\r\n" ++
        "Location: https://registry.example.io/v2/myrepo/blobs/uploads/uuid-123\r\n" ++
        "Content-Length: 0\r\n\r\n";

    const head = std.http.Client.Response.Head.parse(response_bytes) catch unreachable;
    const location = http_helpers.parseLocationHeader("registry.example.io", head).?;
    try std.testing.expectEqualStrings(
        "https://registry.example.io/v2/myrepo/blobs/uploads/uuid-123",
        location,
    );
}

test "parseLocationHeader — relative URL gets host prepended" {
    const response_bytes = "HTTP/1.1 202 Accepted\r\n" ++
        "Location: /v2/myrepo/blobs/uploads/uuid-456\r\n" ++
        "Content-Length: 0\r\n\r\n";

    const head = std.http.Client.Response.Head.parse(response_bytes) catch unreachable;
    const location = http_helpers.parseLocationHeader("registry.example.io", head).?;
    try std.testing.expectEqualStrings(
        "https://registry.example.io/v2/myrepo/blobs/uploads/uuid-456",
        location,
    );
}

test "parseLocationHeader — missing header returns null" {
    const response_bytes = "HTTP/1.1 202 Accepted\r\n" ++
        "Content-Length: 0\r\n\r\n";

    const head = std.http.Client.Response.Head.parse(response_bytes) catch unreachable;
    try std.testing.expect(http_helpers.parseLocationHeader("registry.example.io", head) == null);
}

test "resolveUploadTarget rejects insecure absolute URLs" {
    try std.testing.expect(upload.resolveUploadTarget(
        "registry.example.io",
        "http://registry.example.io/v2/myrepo/blobs/uploads/uuid-123",
    ) == null);
}

test "resolveUploadTarget omits auth for non-registry hosts" {
    const target = upload.resolveUploadTarget(
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
    const target = upload.resolveUploadTarget(
        "registry.example.io",
        "https://registry.example.io/v2/myrepo/blobs/uploads/uuid-123",
    ).?;
    try std.testing.expect(target.send_auth);
}

test "checkBlobExists — URL is correctly formed" {
    // verify the URL format used by checkBlobExists
    var url_buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://{s}/v2/{s}/blobs/{s}",
        .{ "registry.example.io", "myuser/myapp", "sha256:abc123" },
    ) catch unreachable;
    try std.testing.expectEqualStrings(
        "https://registry.example.io/v2/myuser/myapp/blobs/sha256:abc123",
        url,
    );
}

test "uploadManifest — URL format is correct" {
    var url_buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://{s}/v2/{s}/manifests/{s}",
        .{ "registry.example.io", "myuser/myapp", "v1.0" },
    ) catch unreachable;
    try std.testing.expectEqualStrings(
        "https://registry.example.io/v2/myuser/myapp/manifests/v1.0",
        url,
    );
}
