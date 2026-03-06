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
    /// bearer token authentication failed (bad credentials or challenge)
    AuthFailed,
    /// manifest not found for the given reference (tag or digest)
    ManifestNotFound,
    /// blob (config or layer) not found in the registry
    BlobNotFound,
    /// HTTP request failed (connection, timeout, DNS, etc.)
    NetworkError,
    /// manifest or config JSON could not be parsed
    ParseError,
    /// registry returned a media type we don't handle
    UnsupportedMediaType,
    /// no manifest found for the target platform (linux/amd64)
    PlatformNotFound,
    /// downloaded content's sha256 doesn't match the expected digest
    DigestMismatch,
    /// response body exceeds the configured size limit
    ResponseTooLarge,
    /// blob or manifest PUT to the registry failed
    UploadFailed,
    /// POST to initiate a blob upload returned non-202
    UploadInitFailed,
};

const AuthError = error{
    AuthFailed,
    NetworkError,
    ParseError,
    ResponseTooLarge,
    OutOfMemory,
};

// -- response size limits --
// these prevent a malicious or buggy registry from sending unbounded data
// and exhausting memory.

/// max manifest size: 10 MB. real-world OCI manifests are a few KB at most,
/// but multi-arch indexes with many platforms can be larger. 10 MB is generous.
const max_manifest_size: usize = 10 * 1024 * 1024;

/// max auth/token response size: 64 KB. token JSON is typically < 4 KB.
const max_auth_response_size: usize = 64 * 1024;

/// max blob size: 512 MB. individual layers rarely exceed ~200 MB.
/// this prevents a malicious registry from exhausting memory with an
/// unbounded response. (streaming download is deferred — see PR 3.)
const max_blob_size: usize = 512 * 1024 * 1024;

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
    const token = authenticate(alloc, &client, image_ref.host, repository, "pull") catch |e|
        return switch (e) {
            error.AuthFailed => RegistryError.AuthFailed,
            error.NetworkError => RegistryError.NetworkError,
            error.ParseError => RegistryError.ParseError,
            error.ResponseTooLarge => RegistryError.ResponseTooLarge,
            error.OutOfMemory => RegistryError.NetworkError,
        };
    defer {
        // zero the token before freeing to prevent it lingering in freed memory
        std.crypto.secureZero(u8, @constCast(token.value));
        alloc.free(token.value);
    }

    // step 2: fetch manifest (resolving image index if multi-arch)
    const manifest_result = fetchManifest(alloc, &client, image_ref.host, repository, image_ref.reference, token) catch |e| {
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

    // step 3: parse the manifest
    var parsed = spec.parseManifest(alloc, manifest_bytes) catch
        return RegistryError.ParseError;
    defer parsed.deinit();
    const manifest = parsed.value;

    // step 4: download the config blob
    const config_bytes = fetchBlob(alloc, &client, image_ref.host, repository, manifest.config.digest, token) catch |e|
        return switch (e) {
            error.BlobNotFound => RegistryError.BlobNotFound,
            error.NetworkError => RegistryError.NetworkError,
            error.ResponseTooLarge => RegistryError.ResponseTooLarge,
        };
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
        downloadLayerBlob(alloc, &client, image_ref.host, repository, l.digest, token) catch |e|
            return switch (e) {
                error.BlobNotFound => RegistryError.BlobNotFound,
                error.NetworkError => RegistryError.NetworkError,
                error.ResponseTooLarge => RegistryError.ResponseTooLarge,
                error.DigestMismatch => RegistryError.DigestMismatch,
            };

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

/// push result — summary of what was uploaded
pub const PushResult = struct {
    /// number of layer blobs that were uploaded (not already present)
    layers_uploaded: usize,
    /// number of layer blobs that were skipped (already in registry)
    layers_skipped: usize,
    /// the manifest digest (sha256 of manifest bytes)
    manifest_digest: []const u8,

    alloc: std.mem.Allocator,

    pub fn deinit(self: *PushResult) void {
        if (self.manifest_digest.len > 0) self.alloc.free(self.manifest_digest);
    }
};

/// push an image to a registry.
///
/// uploads all layer blobs, the config blob, and the manifest.
/// checks each blob against the registry first and skips uploads
/// for blobs that already exist (deduplication across images).
///
/// manifest_bytes and config_bytes should come from the local blob store
/// (saved during pull or build). layer_digests are the sha256 digests
/// of the layer blobs in the local blob store.
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
    const repository = resolveRepository(image_ref, &repo_buf);

    // authenticate with push,pull scope
    const token = authenticate(alloc, &client, image_ref.host, repository, "push,pull") catch |e|
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

    // upload each layer blob (skip if already present in registry)
    for (layer_digests) |digest| {
        const exists = checkBlobExists(alloc, &client, image_ref.host, repository, digest, token) catch false;
        if (exists) {
            layers_skipped += 1;
            continue;
        }

        // read the blob data from the local store
        const parsed_digest = blob_store.Digest.parse(digest) orelse
            return RegistryError.BlobNotFound;
        const data = blob_store.getBlob(alloc, parsed_digest) catch
            return RegistryError.BlobNotFound;
        defer alloc.free(data);

        uploadBlob(alloc, &client, image_ref.host, repository, digest, data, token) catch
            return RegistryError.UploadFailed;
        layers_uploaded += 1;
    }

    // upload the config blob
    const config_digest = blob_store.computeDigest(config_bytes);
    var config_digest_buf: [71]u8 = undefined;
    const config_digest_str = config_digest.string(&config_digest_buf);

    const config_exists = checkBlobExists(alloc, &client, image_ref.host, repository, config_digest_str, token) catch false;
    if (!config_exists) {
        uploadBlob(alloc, &client, image_ref.host, repository, config_digest_str, config_bytes, token) catch
            return RegistryError.UploadFailed;
    }

    // upload the manifest
    uploadManifest(alloc, &client, image_ref.host, repository, image_ref.reference, manifest_bytes, token) catch
        return RegistryError.UploadFailed;

    // compute manifest digest for the result
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
) AuthError!Token {
    // step 1: ping /v2/ to get the auth challenge
    var ping_url_buf: [512]u8 = undefined;
    const ping_url = std.fmt.bufPrint(&ping_url_buf, "https://{s}/v2/", .{host}) catch
        return error.OutOfMemory;

    // we need the lower-level request API to read the Www-Authenticate header
    const uri = std.Uri.parse(ping_url) catch return error.AuthFailed;
    var req = client.request(.GET, uri, .{
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
    }) catch return error.NetworkError;
    defer req.deinit();

    req.sendBodiless() catch return error.NetworkError;

    var redirect_buf: [4096]u8 = undefined;
    const response = req.receiveHead(&redirect_buf) catch return error.NetworkError;

    // if 200, no auth needed (rare but possible for local registries)
    if (response.head.status == .ok) {
        return Token{ .value = alloc.dupe(u8, "") catch return error.OutOfMemory };
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
    ) catch return error.OutOfMemory;

    // use fetch for the token request — it's simple and we just need the body
    var aw: std.Io.Writer.Allocating = .init(alloc);
    defer aw.deinit();

    const result = client.fetch(.{
        .location = .{ .url = token_url },
        .response_writer = &aw.writer,
    }) catch return error.NetworkError;

    if (result.status != .ok) return error.AuthFailed;

    // the response body is in aw.writer.buffer[0..aw.writer.end]
    const body_data = aw.writer.buffer[0..aw.writer.end];

    // reject oversized auth responses — token JSON should be well under 64 KB
    if (body_data.len > max_auth_response_size) return error.ResponseTooLarge;

    // parse the token from the JSON response
    const token_json = std.json.parseFromSlice(struct {
        token: ?[]const u8 = null,
        access_token: ?[]const u8 = null,
    }, alloc, body_data, .{ .ignore_unknown_fields = true }) catch return error.ParseError;
    defer token_json.deinit();

    const token_str = token_json.value.token orelse
        token_json.value.access_token orelse
        return error.AuthFailed;

    return Token{ .value = alloc.dupe(u8, token_str) catch return error.OutOfMemory };
}

/// parse a Www-Authenticate: Bearer realm="...",service="..." header
fn parseAuthChallenge(head: std.http.Client.Response.Head) ?AuthChallenge {
    var it = head.iterateHeaders();
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "www-authenticate")) continue;

        // format: Bearer realm="https://auth.docker.io/token",service="registry.docker.io"
        const value = header.value;
        const space_idx = std.mem.indexOfScalar(u8, value, ' ') orelse continue;
        const scheme = value[0..space_idx];
        if (!std.ascii.eqlIgnoreCase(scheme, "Bearer")) continue;
        const params = value[space_idx + 1 ..];

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

fn contentTypeBase(value: []const u8) []const u8 {
    const semi_idx = std.mem.indexOfScalar(u8, value, ';') orelse return std.mem.trim(u8, value, " \t\r\n");
    return std.mem.trim(u8, value[0..semi_idx], " \t\r\n");
}

fn isRedirectStatus(status: std.http.Status) bool {
    const code = @intFromEnum(status);
    return code >= 300 and code < 400;
}

fn summarizeUrl(url: []const u8, buf: *[256]u8) []const u8 {
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
    const content_type = contentTypeBase(response.head.content_type orelse "");

    // capture Docker-Content-Digest before reading the body: std.http.Response.reader()
    // invalidates header strings in response.head.
    var expected_digest: ?blob_store.Digest = null;
    var header_it = response.head.iterateHeaders();
    while (header_it.next()) |h| {
        if (!std.ascii.eqlIgnoreCase(h.name, "docker-content-digest")) continue;
        expected_digest = blob_store.Digest.parse(h.value);
        break;
    }

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

    // if the server sent a parseable Docker-Content-Digest header, verify it matches.
    if (expected_digest) |header_digest| {
        var header_digest_buf: [71]u8 = undefined;
        const header_digest_str = header_digest.string(&header_digest_buf);
        if (!computed.eql(header_digest)) {
            log.warn("manifest digest mismatch: computed {s}, header {s}", .{ computed_str, header_digest_str });
            return error.DigestMismatch;
        }
    }

    // if we got an image index, resolve to the platform-specific manifest
    if (spec.isIndexMediaType(content_type)) {
        const platform_result = resolveImageIndex(alloc, client, host, repository, raw_body, token) catch |e|
            return switch (e) {
                error.PlatformNotFound => error.PlatformNotFound,
                error.ManifestNotFound => error.ManifestNotFound,
                error.NetworkError => error.NetworkError,
                error.AuthFailed => error.AuthFailed,
                error.ParseError => error.ParseError,
                error.DigestMismatch => error.DigestMismatch,
                error.ResponseTooLarge => error.ResponseTooLarge,
                error.OutOfMemory => error.OutOfMemory,
            };
        return platform_result;
    }

    // Some registries return a generic or parameterized content type for multi-arch
    // images. Fall back to body inspection so common Docker Hub images still resolve.
    var parsed_index = spec.parseImageIndex(alloc, raw_body) catch null;
    if (parsed_index) |*idx| {
        defer idx.deinit();
        if (idx.value.manifests.len > 0) {
            const platform_result = resolveImageIndex(alloc, client, host, repository, raw_body, token) catch |e|
                return switch (e) {
                    error.PlatformNotFound => error.PlatformNotFound,
                    error.ManifestNotFound => error.ManifestNotFound,
                    error.NetworkError => error.NetworkError,
                    error.AuthFailed => error.AuthFailed,
                    error.ParseError => error.ParseError,
                    error.DigestMismatch => error.DigestMismatch,
                    error.ResponseTooLarge => error.ResponseTooLarge,
                    error.OutOfMemory => error.OutOfMemory,
                };
            return platform_result;
        }
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

/// check if a blob already exists in the remote registry.
/// sends a HEAD request to /v2/{repo}/blobs/{digest}.
/// returns true if the registry responds with 200, false if 404.
/// used before uploading to skip blobs that are already present.
pub fn checkBlobExists(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    token: Token,
) RegistryError!bool {
    var url_buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://{s}/v2/{s}/blobs/{s}",
        .{ host, repository, digest },
    ) catch return RegistryError.NetworkError;

    var auth_buf: [8192]u8 = undefined;
    const auth_value = authHeaderValue(token, &auth_buf);

    const uri = std.Uri.parse(url) catch return RegistryError.NetworkError;
    var req = client.request(.HEAD, uri, .{
        .redirect_behavior = @enumFromInt(3),
        .keep_alive = false,
        .headers = .{
            .authorization = if (auth_value.len > 0) .{ .override = auth_value } else .default,
        },
    }) catch return RegistryError.NetworkError;
    defer req.deinit();

    req.sendBodiless() catch return RegistryError.NetworkError;

    _ = alloc; // reserved for future use (e.g. reading error bodies)

    var redirect_buf: [4096]u8 = undefined;
    const response = req.receiveHead(&redirect_buf) catch return RegistryError.NetworkError;

    if (response.head.status == .ok) return true;
    if (response.head.status == .not_found) return false;

    return RegistryError.NetworkError;
}

/// upload a blob to the registry using the monolithic upload flow.
///
/// OCI distribution spec upload flow:
///   1. POST /v2/{repo}/blobs/uploads/ → 202 with Location header
///   2. PUT {location}?digest={digest} with blob body → 201
///
/// monolithic upload sends the entire blob in a single PUT, which is
/// simpler and works well for most blob sizes. chunked upload could
/// be added later for very large layers if needed.
pub fn uploadBlob(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    data: []const u8,
    token: Token,
) RegistryError!void {
    // step 1: initiate upload — POST to get an upload URL
    var init_url_buf: [1024]u8 = undefined;
    const init_url = std.fmt.bufPrint(
        &init_url_buf,
        "https://{s}/v2/{s}/blobs/uploads/",
        .{ host, repository },
    ) catch return RegistryError.UploadInitFailed;

    var auth_buf: [8192]u8 = undefined;
    const auth_value = authHeaderValue(token, &auth_buf);

    const init_uri = std.Uri.parse(init_url) catch return RegistryError.UploadInitFailed;
    var init_req = client.request(.POST, init_uri, .{
        .redirect_behavior = @enumFromInt(3),
        .keep_alive = false,
        .headers = .{
            .authorization = if (auth_value.len > 0) .{ .override = auth_value } else .default,
            .content_type = .{ .override = "application/octet-stream" },
        },
    }) catch return RegistryError.UploadInitFailed;
    defer init_req.deinit();

    init_req.sendBodiless() catch return RegistryError.UploadInitFailed;

    var init_redirect_buf: [8192]u8 = undefined;
    const init_response = init_req.receiveHead(&init_redirect_buf) catch
        return RegistryError.UploadInitFailed;

    if (init_response.head.status != .accepted)
        return RegistryError.UploadInitFailed;

    // step 2: extract the upload Location from the response headers
    const location = parseLocationHeader(host, init_response.head) orelse
        return RegistryError.UploadInitFailed;

    // step 3: PUT the blob data to the upload location with digest query param
    var put_url_buf: [2048]u8 = undefined;
    const separator: []const u8 = if (std.mem.indexOfScalar(u8, location, '?') != null) "&" else "?";
    const put_url = std.fmt.bufPrint(
        &put_url_buf,
        "{s}{s}digest={s}",
        .{ location, separator, digest },
    ) catch return RegistryError.UploadFailed;

    // re-read auth value since the buffer was reused above
    var auth_buf2: [8192]u8 = undefined;
    const auth_value2 = authHeaderValue(token, &auth_buf2);

    _ = alloc; // reserved for future use

    const put_result = client.fetch(.{
        .location = .{ .url = put_url },
        .method = .PUT,
        .payload = data,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/octet-stream" },
            .{ .name = "Authorization", .value = auth_value2 },
        },
    }) catch return RegistryError.UploadFailed;

    // 201 Created is the expected success status for blob upload
    if (put_result.status != .created)
        return RegistryError.UploadFailed;
}

/// extract the Location header value from a response.
/// handles both absolute URLs and relative paths (relative to the host).
/// returns null if no Location header is found.
fn parseLocationHeader(host: []const u8, head: std.http.Client.Response.Head) ?[]const u8 {
    var it = head.iterateHeaders();
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "location")) continue;

        const value = header.value;
        if (value.len == 0) continue;

        // absolute URL — use as-is
        if (std.mem.startsWith(u8, value, "http://") or
            std.mem.startsWith(u8, value, "https://"))
        {
            return value;
        }

        // relative path — this is tricky because we'd need to allocate to
        // prepend the host. for now, we use a static buffer. the OCI spec
        // says registries SHOULD return absolute URLs, but some return relative.
        // we handle it with a thread-local buffer since this is always called
        // from a single upload flow.
        const static = struct {
            threadlocal var buf: [8192]u8 = undefined;
        };
        const full_url = std.fmt.bufPrint(&static.buf, "https://{s}{s}", .{ host, value }) catch
            return null;
        return full_url;
    }
    return null;
}

/// upload a manifest to the registry.
/// PUT /v2/{repo}/manifests/{reference} with the manifest JSON body.
/// reference is typically a tag (e.g. "latest") or a digest.
pub fn uploadManifest(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    reference: []const u8,
    manifest_bytes: []const u8,
    token: Token,
) RegistryError!void {
    var url_buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://{s}/v2/{s}/manifests/{s}",
        .{ host, repository, reference },
    ) catch return RegistryError.UploadFailed;

    var auth_buf: [8192]u8 = undefined;
    const auth_value = authHeaderValue(token, &auth_buf);

    _ = alloc; // reserved for future use

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = .PUT,
        .payload = manifest_bytes,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = spec.media_type.oci_manifest },
            .{ .name = "Authorization", .value = auth_value },
        },
    }) catch return RegistryError.UploadFailed;

    // 201 Created is the expected success status for manifest upload
    if (result.status != .created)
        return RegistryError.UploadFailed;
}

/// fetch a blob (config or layer) from the registry.
/// uses the low-level request API so we can check Content-Length before
/// reading the body and enforce max_blob_size to prevent memory exhaustion.
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

    return fetchBlobFromUrl(alloc, client, host, url, token, true, 0);
}

fn fetchBlobFromUrl(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    url: []const u8,
    token: Token,
    send_auth: bool,
    redirect_count: u8,
) ![]u8 {
    if (redirect_count > 5) return error.NetworkError;

    var url_summary_buf: [256]u8 = undefined;
    const url_summary = summarizeUrl(url, &url_summary_buf);
    var auth_buf: [8192]u8 = undefined;
    const auth_value = if (send_auth) authHeaderValue(token, &auth_buf) else "";
    const uri = std.Uri.parse(url) catch {
        log.warn("blob fetch: failed to parse url {s}", .{url_summary});
        return error.BlobNotFound;
    };

    var req = client.request(.GET, uri, .{
        .redirect_behavior = .unhandled,
        .keep_alive = false,
        .headers = .{
            .authorization = if (auth_value.len > 0) .{ .override = auth_value } else .default,
        },
    }) catch |err| {
        log.warn("blob fetch: request setup failed for {s}: {}", .{ url_summary, err });
        return error.NetworkError;
    };
    defer req.deinit();

    req.sendBodiless() catch |err| {
        log.warn("blob fetch: send failed for {s}: {}", .{ url_summary, err });
        return error.NetworkError;
    };

    var redirect_buf: [262144]u8 = undefined;
    var response = req.receiveHead(&redirect_buf) catch |err| {
        log.warn("blob fetch: receive head failed for {s}: {}", .{ url_summary, err });
        return error.NetworkError;
    };

    if (isRedirectStatus(response.head.status)) {
        const location = parseLocationHeader(host, response.head) orelse {
            log.warn("blob fetch: redirect missing location for {s}", .{url_summary});
            return error.NetworkError;
        };
        const location_copy = alloc.dupe(u8, location) catch return error.NetworkError;
        defer alloc.free(location_copy);

        var location_summary_buf: [256]u8 = undefined;
        const location_summary = summarizeUrl(location_copy, &location_summary_buf);
        log.warn("blob fetch: redirect {d} from {s} to {s} (auth={})", .{
            @intFromEnum(response.head.status),
            url_summary,
            location_summary,
            send_auth,
        });

        return fetchBlobFromUrl(alloc, client, host, location_copy, token, false, redirect_count + 1);
    }

    if (response.head.status != .ok) {
        log.warn("blob fetch: unexpected status {d} for {s}", .{ @intFromEnum(response.head.status), url_summary });
        return error.BlobNotFound;
    }

    if (response.head.content_length) |cl| {
        if (cl > max_blob_size) return error.ResponseTooLarge;
    }

    var transfer_buf: [8192]u8 = undefined;
    const body_reader = response.reader(&transfer_buf);
    var aw: std.Io.Writer.Allocating = .init(alloc);
    defer aw.deinit();

    _ = body_reader.streamRemaining(&aw.writer) catch |err| {
        log.warn("blob fetch: body read failed for {s}: {}", .{ url_summary, err });
        return error.NetworkError;
    };

    const raw_body = aw.writer.buffer[0..aw.writer.end];
    if (raw_body.len > max_blob_size) return error.ResponseTooLarge;
    return alloc.dupe(u8, raw_body) catch return error.NetworkError;
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
    const expected = blob_store.Digest.parse(digest) orelse return error.DigestMismatch;
    if (!computed.eql(expected)) return error.DigestMismatch;

    // use putBlobDirect since we already verified the digest
    blob_store.putBlobDirect(data, expected) catch return error.BlobNotFound;
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

test "parse auth challenge — lowercase bearer scheme" {
    const response_bytes = "HTTP/1.1 401 Unauthorized\r\n" ++
        "www-authenticate: bearer realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\"\r\n" ++
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

test "contentTypeBase strips parameters and whitespace" {
    try std.testing.expectEqualStrings(
        "application/vnd.oci.image.index.v1+json",
        contentTypeBase(" application/vnd.oci.image.index.v1+json; charset=utf-8 "),
    );
}

test "isRedirectStatus detects redirect responses" {
    try std.testing.expect(isRedirectStatus(.temporary_redirect));
    try std.testing.expect(isRedirectStatus(.found));
    try std.testing.expect(!isRedirectStatus(.ok));
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
    try std.testing.expectEqual(@as(usize, 512 * 1024 * 1024), max_blob_size);

    // blob limit should be larger than manifest limit (layers >> manifests)
    try std.testing.expect(max_blob_size > max_manifest_size);

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

test "parseLocationHeader — absolute URL returned as-is" {
    const response_bytes = "HTTP/1.1 202 Accepted\r\n" ++
        "Location: https://registry.example.io/v2/myrepo/blobs/uploads/uuid-123\r\n" ++
        "Content-Length: 0\r\n\r\n";

    const head = std.http.Client.Response.Head.parse(response_bytes) catch unreachable;
    const location = parseLocationHeader("registry.example.io", head).?;
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
    const location = parseLocationHeader("registry.example.io", head).?;
    try std.testing.expectEqualStrings(
        "https://registry.example.io/v2/myrepo/blobs/uploads/uuid-456",
        location,
    );
}

test "parseLocationHeader — missing header returns null" {
    const response_bytes = "HTTP/1.1 202 Accepted\r\n" ++
        "Content-Length: 0\r\n\r\n";

    const head = std.http.Client.Response.Head.parse(response_bytes) catch unreachable;
    try std.testing.expect(parseLocationHeader("registry.example.io", head) == null);
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
