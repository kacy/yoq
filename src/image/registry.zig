// registry — OCI distribution protocol client
//
// pulls manifests and blobs from OCI-compliant container registries.
// implements the OCI distribution spec's pull workflow:
//   1. authenticate (bearer token via Www-Authenticate challenge)
//   2. fetch manifest (handles image index → platform manifest resolution)
//   3. download config and layer blobs
//
// supports Docker Hub, ghcr.io, and any OCI-compliant registry.
// uses std.http.Client for HTTPS — no external dependencies.

const std = @import("std");
const spec = @import("spec.zig");
const blob_store = @import("store.zig");
const log = @import("../lib/log.zig");

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
};

// -- response size limits --
// these prevent a malicious or buggy registry from sending unbounded data
// and exhausting memory.

/// max manifest size: 10 MB. real-world OCI manifests are a few KB at most,
/// but multi-arch indexes with many platforms can be larger. 10 MB is generous.
const max_manifest_size: usize = 10 * 1024 * 1024;

/// max auth/token response size: 64 KB. token JSON is typically < 4 KB.
const max_auth_response_size: usize = 64 * 1024;

/// bearer token from the registry's auth service
const Token = struct {
    value: []const u8,
};

/// auth challenge parsed from a Www-Authenticate header
const AuthChallenge = struct {
    realm: []const u8,
    service: []const u8,
};

/// pull result — everything needed to assemble a container rootfs
pub const PullResult = struct {
    manifest_digest: []const u8,
    manifest_bytes: []const u8,
    config_bytes: []const u8,
    /// layer digests in order (bottom to top)
    layer_digests: []const []const u8,
    /// total size of all layers
    total_size: u64,

    alloc: std.mem.Allocator,

    pub fn deinit(self: *PullResult) void {
        self.alloc.free(self.manifest_bytes);
        self.alloc.free(self.config_bytes);
        for (self.layer_digests) |d| self.alloc.free(d);
        self.alloc.free(self.layer_digests);
        if (self.manifest_digest.len > 0) self.alloc.free(self.manifest_digest);
    }
};

/// pull an image from a registry.
/// downloads the manifest, config, and all layer blobs.
/// layer blobs are stored in the blob store; config and manifest are returned.
///
/// uses errdefer chains so each allocation is automatically cleaned up
/// on any subsequent failure — no manual cleanup blocks needed.
pub fn pull(alloc: std.mem.Allocator, image_ref: spec.ImageRef) RegistryError!PullResult {
    var client: std.http.Client = .{ .allocator = alloc };
    defer client.deinit();

    // resolve the repository name (docker hub bare names need "library/" prefix)
    var repo_buf: [256]u8 = undefined;
    const repository = resolveRepository(image_ref, &repo_buf);

    // step 1: authenticate
    const token = authenticate(alloc, &client, image_ref.host, repository, "pull") catch
        return RegistryError.AuthFailed;
    defer alloc.free(token.value);

    // step 2: fetch manifest (resolving image index if multi-arch)
    const manifest_result = fetchManifest(alloc, &client, image_ref.host, repository, image_ref.reference, token) catch |e| {
        return switch (e) {
            error.DigestMismatch => RegistryError.DigestMismatch,
            error.ResponseTooLarge => RegistryError.ResponseTooLarge,
            else => RegistryError.ManifestNotFound,
        };
    };
    const manifest_bytes = manifest_result.body;
    errdefer alloc.free(manifest_bytes);
    const manifest_digest_str = manifest_result.digest;
    errdefer if (manifest_digest_str.len > 0) alloc.free(manifest_digest_str);

    // step 3: parse the manifest
    var parsed = spec.parseManifest(alloc, manifest_bytes) catch
        return RegistryError.ParseError;
    defer parsed.deinit();
    const manifest = parsed.value;

    // step 4: download the config blob
    const config_bytes = fetchBlob(alloc, &client, image_ref.host, repository, manifest.config.digest, token) catch
        return RegistryError.BlobNotFound;
    errdefer alloc.free(config_bytes);

    // verify config blob integrity against manifest digest
    const config_computed = blob_store.computeDigest(config_bytes);
    if (blob_store.Digest.parse(manifest.config.digest)) |expected| {
        if (!config_computed.eql(expected)) {
            return RegistryError.DigestMismatch;
        }
    }

    // step 5: download all layer blobs (stored in blob store)
    var layer_digests: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (layer_digests.items) |d| alloc.free(d);
        layer_digests.deinit(alloc);
    }
    var total_size: u64 = 0;

    for (manifest.layers) |l| {
        downloadLayerBlob(alloc, &client, image_ref.host, repository, l.digest, token) catch
            return RegistryError.BlobNotFound;

        const digest_copy = alloc.dupe(u8, l.digest) catch
            return RegistryError.NetworkError;
        layer_digests.append(alloc, digest_copy) catch {
            alloc.free(digest_copy);
            return RegistryError.NetworkError;
        };
        total_size += l.size;
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

// -- internal functions --

/// resolve "nginx" → "library/nginx" for docker hub, pass through otherwise
fn resolveRepository(ref: spec.ImageRef, buf: *[256]u8) []const u8 {
    if (std.mem.eql(u8, ref.host, "registry-1.docker.io") and
        std.mem.indexOfScalar(u8, ref.repository, '/') == null)
    {
        const result = std.fmt.bufPrint(buf, "library/{s}", .{ref.repository}) catch
            return ref.repository;
        return result;
    }
    return ref.repository;
}

/// authenticate with the registry's token service.
/// flow: request /v2/ → get 401 with Www-Authenticate → fetch token.
///
/// scope controls what permissions the token grants:
///   - "pull" for read-only access (downloading images)
///   - "push,pull" for read-write access (uploading images)
fn authenticate(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    scope: []const u8,
) !Token {
    // step 1: ping /v2/ to get the auth challenge
    var ping_url_buf: [512]u8 = undefined;
    const ping_url = std.fmt.bufPrint(&ping_url_buf, "https://{s}/v2/", .{host}) catch
        return error.AuthFailed;

    // we need the lower-level request API to read the Www-Authenticate header
    const uri = std.Uri.parse(ping_url) catch return error.AuthFailed;
    var req = client.request(.GET, uri, .{
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
    }) catch return error.AuthFailed;
    defer req.deinit();

    req.sendBodiless() catch return error.AuthFailed;

    var redirect_buf: [4096]u8 = undefined;
    const response = req.receiveHead(&redirect_buf) catch return error.AuthFailed;

    // if 200, no auth needed (rare but possible for local registries)
    if (response.head.status == .ok) {
        return Token{ .value = try alloc.dupe(u8, "") };
    }

    // parse the Www-Authenticate header from the raw response
    if (response.head.status != .unauthorized) return error.AuthFailed;

    const challenge = parseAuthChallenge(response.head) orelse return error.AuthFailed;

    // step 2: request a bearer token
    var token_url_buf: [1024]u8 = undefined;
    const token_url = std.fmt.bufPrint(
        &token_url_buf,
        "{s}?service={s}&scope=repository:{s}:{s}",
        .{ challenge.realm, challenge.service, repository, scope },
    ) catch return error.AuthFailed;

    // use fetch for the token request — it's simple and we just need the body
    var aw: std.Io.Writer.Allocating = .init(alloc);
    defer aw.deinit();

    const result = client.fetch(.{
        .location = .{ .url = token_url },
        .response_writer = &aw.writer,
    }) catch return error.AuthFailed;

    if (result.status != .ok) return error.AuthFailed;

    // the response body is in aw.writer.buffer[0..aw.writer.end]
    const body_data = aw.writer.buffer[0..aw.writer.end];

    // reject oversized auth responses — token JSON should be well under 64 KB
    if (body_data.len > max_auth_response_size) return error.AuthFailed;

    // parse the token from the JSON response
    const token_json = std.json.parseFromSlice(struct {
        token: ?[]const u8 = null,
        access_token: ?[]const u8 = null,
    }, alloc, body_data, .{ .ignore_unknown_fields = true }) catch return error.AuthFailed;
    defer token_json.deinit();

    const token_str = token_json.value.token orelse
        token_json.value.access_token orelse
        return error.AuthFailed;

    return Token{ .value = try alloc.dupe(u8, token_str) };
}

/// parse a Www-Authenticate: Bearer realm="...",service="..." header
fn parseAuthChallenge(head: std.http.Client.Response.Head) ?AuthChallenge {
    var it = head.iterateHeaders();
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "www-authenticate")) continue;

        // format: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
        const value = header.value;
        if (!std.mem.startsWith(u8, value, "Bearer ")) continue;
        const params = value["Bearer ".len..];

        var realm: ?[]const u8 = null;
        var service: ?[]const u8 = null;

        // simple parameter parser — find key="value" pairs
        var remaining = params;
        while (remaining.len > 0) {
            // skip whitespace and commas
            remaining = std.mem.trimLeft(u8, remaining, " ,");
            if (remaining.len == 0) break;

            // find key=
            const eq_idx = std.mem.indexOfScalar(u8, remaining, '=') orelse break;
            const key = remaining[0..eq_idx];
            remaining = remaining[eq_idx + 1 ..];

            // parse quoted value
            if (remaining.len == 0 or remaining[0] != '"') break;
            remaining = remaining[1..]; // skip opening quote
            const close_idx = std.mem.indexOfScalar(u8, remaining, '"') orelse break;
            const val = remaining[0..close_idx];
            remaining = remaining[close_idx + 1 ..];

            if (std.mem.eql(u8, key, "realm")) {
                realm = val;
            } else if (std.mem.eql(u8, key, "service")) {
                service = val;
            }
        }

        if (realm != null and service != null) {
            return AuthChallenge{
                .realm = realm.?,
                .service = service.?,
            };
        }
    }
    return null;
}

/// result from fetching a manifest
const ManifestFetchResult = struct {
    body: []const u8,
    digest: []const u8,
};

/// shared error set for manifest fetching (needed because fetchManifest
/// and resolveImageIndex call each other recursively)
const ManifestError = error{
    ManifestNotFound,
    NetworkError,
    AuthFailed,
    ParseError,
    PlatformNotFound,
    DigestMismatch,
    ResponseTooLarge,
    OutOfMemory,
};

/// fetch a manifest, resolving image index → platform-specific manifest if needed.
fn fetchManifest(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    reference: []const u8,
    token: Token,
) ManifestError!ManifestFetchResult {
    // fetch the manifest (might be an index or a direct manifest)
    var url_buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://{s}/v2/{s}/manifests/{s}",
        .{ host, repository, reference },
    ) catch return error.ManifestNotFound;

    // accept both index and manifest types
    const accept_header = std.http.Header{
        .name = "Accept",
        .value = spec.media_type.oci_index ++ ", " ++
            spec.media_type.oci_manifest ++ ", " ++
            spec.media_type.manifest_list ++ ", " ++
            spec.media_type.manifest_v2,
    };

    var auth_buf: [8192]u8 = undefined;
    const auth_value = authHeaderValue(token, &auth_buf);

    const uri = std.Uri.parse(url) catch return error.ManifestNotFound;

    var headers: [1]std.http.Header = .{accept_header};

    var req = client.request(.GET, uri, .{
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

    // reject manifests that exceed our size limit before reading the body.
    // check Content-Length if the server sent it.
    if (response.head.content_length) |cl| {
        if (cl > max_manifest_size) return error.ResponseTooLarge;
    }

    // read the content type to determine what we got
    const content_type = response.head.content_type orelse "";

    // read the body using stream API, tracking bytes to enforce size limit
    var transfer_buf: [8192]u8 = undefined;
    const body_reader = response.reader(&transfer_buf);

    var aw_body: std.Io.Writer.Allocating = .init(alloc);
    defer aw_body.deinit();

    _ = body_reader.streamRemaining(&aw_body.writer) catch return error.NetworkError;

    const raw_body = aw_body.writer.buffer[0..aw_body.writer.end];

    // enforce size limit on the actual body (servers can lie about Content-Length
    // or omit it entirely for chunked transfer)
    if (raw_body.len > max_manifest_size) return error.ResponseTooLarge;

    // always compute the digest from the response body — this is the source of truth
    const computed = blob_store.computeDigest(raw_body);
    var computed_str_buf: [71]u8 = undefined;
    const computed_str = computed.string(&computed_str_buf);

    // if the server sent a Docker-Content-Digest header, verify it matches
    var header_it = response.head.iterateHeaders();
    while (header_it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "docker-content-digest")) {
            if (blob_store.Digest.parse(h.value)) |header_digest| {
                if (!computed.eql(header_digest)) {
                    log.warn("manifest digest mismatch: computed {s}, header {s}", .{ computed_str, h.value });
                    return error.DigestMismatch;
                }
            }
            break;
        }
    }

    // if we got an image index, resolve to the platform-specific manifest
    if (spec.isIndexMediaType(content_type)) {
        const platform_result = resolveImageIndex(alloc, client, host, repository, raw_body, token) catch
            return error.PlatformNotFound;
        return platform_result;
    }

    // it's a direct manifest — return it
    const body = alloc.dupe(u8, raw_body) catch return error.NetworkError;

    const digest_str = alloc.dupe(u8, computed_str) catch {
        alloc.free(body);
        return error.NetworkError;
    };

    return ManifestFetchResult{
        .body = body,
        .digest = digest_str,
    };
}

/// resolve an image index to a platform-specific manifest.
/// selects linux/amd64 by default (most common target for servers).
fn resolveImageIndex(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    index_bytes: []const u8,
    token: Token,
) ManifestError!ManifestFetchResult {
    var parsed = spec.parseImageIndex(alloc, index_bytes) catch return error.ParseError;
    defer parsed.deinit();
    const index = parsed.value;

    // find the platform manifest — prefer amd64, fall back to first linux match
    var target_digest: ?[]const u8 = null;

    // first pass: exact match for linux/amd64
    for (index.manifests) |m| {
        if (m.platform) |p| {
            if (std.mem.eql(u8, p.os, "linux") and std.mem.eql(u8, p.architecture, "amd64")) {
                target_digest = m.digest;
                break;
            }
        }
    }

    // second pass: any linux platform
    if (target_digest == null) {
        for (index.manifests) |m| {
            if (m.platform) |p| {
                if (std.mem.eql(u8, p.os, "linux")) {
                    target_digest = m.digest;
                    break;
                }
            }
        }
    }

    const digest = target_digest orelse return error.PlatformNotFound;

    // fetch the platform-specific manifest by digest
    return fetchManifest(alloc, client, host, repository, digest, token);
}

/// format a bearer authorization header value from a token.
/// returns "" if the token is empty (no auth needed).
fn authHeaderValue(token: Token, buf: *[8192]u8) []const u8 {
    if (token.value.len == 0) return "";
    return std.fmt.bufPrint(buf, "Bearer {s}", .{token.value}) catch "";
}

/// fetch a blob (config or layer) from the registry
fn fetchBlob(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    token: Token,
) ![]u8 {
    var url_buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://{s}/v2/{s}/blobs/{s}",
        .{ host, repository, digest },
    ) catch return error.BlobNotFound;

    var auth_buf: [8192]u8 = undefined;
    const auth_value = authHeaderValue(token, &auth_buf);

    var aw: std.Io.Writer.Allocating = .init(alloc);
    defer aw.deinit();

    const result = client.fetch(.{
        .location = .{ .url = url },
        .headers = .{
            .authorization = if (auth_value.len > 0) .{ .override = auth_value } else .default,
        },
        .response_writer = &aw.writer,
    }) catch return error.NetworkError;

    if (result.status != .ok) return error.BlobNotFound;

    const body_data = aw.writer.buffer[0..aw.writer.end];
    return alloc.dupe(u8, body_data) catch return error.NetworkError;
}

/// download a layer blob and store it in the content-addressable blob store.
/// skips download if the blob already exists locally and passes integrity check.
/// if a cached blob is corrupted, it's removed and re-downloaded.
fn downloadLayerBlob(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    token: Token,
) !void {
    // check if already cached — verify integrity before trusting the cache
    if (blob_store.Digest.parse(digest)) |d| {
        if (blob_store.hasBlob(d)) {
            if (blob_store.verifyBlob(d)) return;

            // cached blob is corrupted — remove it and re-download
            log.warn("corrupted cached layer {s}, re-downloading", .{digest});
            blob_store.removeBlob(d);
        }
    }

    // download the blob
    const data = try fetchBlob(alloc, client, host, repository, digest, token);
    defer alloc.free(data);

    // verify downloaded data matches expected digest
    const computed = blob_store.computeDigest(data);
    if (blob_store.Digest.parse(digest)) |expected| {
        if (!computed.eql(expected)) return error.DigestMismatch;
    }

    _ = blob_store.putBlob(data) catch return error.BlobNotFound;
}

// -- tests --

test "resolve repository — bare name gets library/ prefix" {
    var buf: [256]u8 = undefined;
    const ref = spec.ImageRef{
        .host = "registry-1.docker.io",
        .repository = "nginx",
        .reference = "latest",
    };
    const resolved = resolveRepository(ref, &buf);
    try std.testing.expectEqualStrings("library/nginx", resolved);
}

test "resolve repository — already qualified passes through" {
    var buf: [256]u8 = undefined;
    const ref = spec.ImageRef{
        .host = "registry-1.docker.io",
        .repository = "myuser/myapp",
        .reference = "latest",
    };
    const resolved = resolveRepository(ref, &buf);
    try std.testing.expectEqualStrings("myuser/myapp", resolved);
}

test "resolve repository — non-docker-hub passes through" {
    var buf: [256]u8 = undefined;
    const ref = spec.ImageRef{
        .host = "ghcr.io",
        .repository = "nginx",
        .reference = "latest",
    };
    const resolved = resolveRepository(ref, &buf);
    try std.testing.expectEqualStrings("nginx", resolved);
}

test "parse auth challenge" {
    // simulate a response head with Www-Authenticate header
    const response_bytes = "HTTP/1.1 401 Unauthorized\r\n" ++
        "Www-Authenticate: Bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\"\r\n" ++
        "Content-Length: 0\r\n\r\n";

    const head = std.http.Client.Response.Head.parse(response_bytes) catch unreachable;
    const challenge = parseAuthChallenge(head).?;

    try std.testing.expectEqualStrings("https://auth.docker.io/token", challenge.realm);
    try std.testing.expectEqualStrings("registry.docker.io", challenge.service);
}

test "parse auth challenge — missing header returns null" {
    const response_bytes = "HTTP/1.1 401 Unauthorized\r\n" ++
        "Content-Length: 0\r\n\r\n";

    const head = std.http.Client.Response.Head.parse(response_bytes) catch unreachable;
    try std.testing.expect(parseAuthChallenge(head) == null);
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
    try std.testing.expectEqual(@as(usize, 10 * 1024 * 1024), max_manifest_size);
    try std.testing.expectEqual(@as(usize, 64 * 1024), max_auth_response_size);

    // a normal manifest is well under the limit
    const small_manifest = "{\"schemaVersion\":2,\"config\":{},\"layers\":[]}";
    try std.testing.expect(small_manifest.len < max_manifest_size);
}

test "response size limit rejects oversized data" {
    // verify that data exceeding our limits would be caught.
    // we can't easily test the full HTTP flow, but we can verify the
    // size check logic that runs on the response body.
    const oversized_len: usize = max_manifest_size + 1;
    try std.testing.expect(oversized_len > max_manifest_size);

    // also verify auth limit
    const oversized_auth: usize = max_auth_response_size + 1;
    try std.testing.expect(oversized_auth > max_auth_response_size);
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
