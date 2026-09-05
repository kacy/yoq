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

pub fn nativePlatform() spec.Platform {
    return .{
        .os = @tagName(@import("builtin").os.tag),
        .architecture = switch (@import("builtin").cpu.arch) {
            .x86_64 => "amd64",
            .aarch64 => "arm64",
            .riscv64 => "riscv64",
            else => @tagName(@import("builtin").cpu.arch),
        },
    };
}

pub fn fetchManifest(alloc: std.mem.Allocator, client: *std.http.Client, host: []const u8, repository: []const u8, reference: []const u8, token: common.Token) common.ManifestError!ManifestFetchResult {
    return fetchForPlatform(alloc, client, host, repository, reference, token, nativePlatform());
}

pub fn fetchForPlatform(alloc: std.mem.Allocator, client: *std.http.Client, host: []const u8, repository: []const u8, reference: []const u8, token: common.Token, platform: spec.Platform) common.ManifestError!ManifestFetchResult {
    return resolve(alloc, client, host, repository, reference, token, "https", platform, .{});
}

fn fetchManifestWithScheme(alloc: std.mem.Allocator, client: *std.http.Client, host: []const u8, repository: []const u8, reference: []const u8, token: common.Token, comptime scheme: []const u8) common.ManifestError!ManifestFetchResult {
    return resolve(alloc, client, host, repository, reference, token, scheme, nativePlatform(), .{});
}

const Limits = struct { requests: usize = 8, bytes: usize = 20 * 1024 * 1024 };
const SingleManifest = struct { result: ManifestFetchResult, is_index: bool };

const Pending = struct { digest: blob_store.Digest, depth: usize, require_index: bool };

fn resolve(alloc: std.mem.Allocator, client: *std.http.Client, host: []const u8, repository: []const u8, initial_reference: []const u8, token: common.Token, comptime scheme: []const u8, platform: spec.Platform, limits: Limits) common.ManifestError!ManifestFetchResult {
    var visited: [8]blob_store.Digest = undefined;
    var pending: [8]Pending = undefined;
    var queued: usize = 0;
    var count: usize = 0;
    var remaining = limits.bytes;
    var reference = initial_reference;
    var next_reference: [71]u8 = undefined;
    var depth: usize = 0;
    var require_index = false;
    while (count < @min(visited.len, limits.requests) and depth < visited.len) {
        if (blob_store.Digest.parse(reference)) |digest| {
            for (visited[0..count]) |prior| if (digest.eql(prior)) return error.ParseError;
        }
        {
            const fetched = try fetchSingle(alloc, client, host, repository, reference, token, scheme, @min(remaining, common.max_manifest_size));
            const result = fetched.result;
            remaining -= result.body.len;
            visited[count] = blob_store.computeDigest(result.body);
            count += 1;
            if (!fetched.is_index) {
                if (require_index) {
                    alloc.free(result.body);
                    alloc.free(result.digest);
                    return error.ParseError;
                }
                return result;
            }
            // Copy only descriptors into a bounded worklist. Parent HTTP and
            // JSON allocations are gone before any child request starts.
            defer alloc.free(result.body);
            defer alloc.free(result.digest);
            var parsed = spec.parseImageIndex(alloc, result.body) catch return error.ParseError;
            defer parsed.deinit();
            if (selectPlatform(parsed.value.manifests, platform)) |selected| {
                try enqueue(&pending, &queued, visited[0..count], selected, depth + 1, false);
            } else |_| {
                // OCI permits nested index descriptors without platform data.
                // Search those indices, never an unrelated platform's leaf.
                var i = parsed.value.manifests.len;
                while (i > 0) {
                    i -= 1;
                    const entry = parsed.value.manifests[i];
                    if (entry.platform == null and spec.isIndexMediaType(entry.mediaType))
                        try enqueue(&pending, &queued, visited[0..count], entry.digest, depth + 1, true);
                }
            }
        }
        if (queued == 0) return error.PlatformNotFound;
        queued -= 1;
        const next = pending[queued];
        reference = next.digest.string(&next_reference);
        depth = next.depth;
        require_index = next.require_index;
    }
    return error.ResponseTooLarge;
}

fn enqueue(pending: *[8]Pending, count: *usize, visited: []const blob_store.Digest, reference: []const u8, depth: usize, require_index: bool) common.ManifestError!void {
    const digest = blob_store.Digest.parse(reference) orelse return error.DigestMismatch;
    // A shared index may already have been searched through another branch.
    // Reusing that completed search must not discard the remaining siblings.
    for (visited) |prior| if (digest.eql(prior)) return;
    for (pending[0..count.*]) |prior| if (digest.eql(prior.digest)) return;
    if (count.* == pending.len) return error.ResponseTooLarge;
    pending[count.*] = .{ .digest = digest, .depth = depth, .require_index = require_index };
    count.* += 1;
}

fn variantMatches(candidate: spec.Platform, target: spec.Platform) bool {
    const wanted = target.variant orelse if (std.mem.eql(u8, target.architecture, "arm64")) "v8" else "";
    const actual = candidate.variant orelse if (std.mem.eql(u8, candidate.architecture, "arm64")) "v8" else "";
    return std.mem.eql(u8, actual, wanted);
}

fn selectPlatform(entries: []const spec.Descriptor, target: spec.Platform) common.ManifestError![]const u8 {
    for (entries) |entry| {
        const candidate = entry.platform orelse continue;
        if (std.mem.eql(u8, candidate.os, target.os) and std.mem.eql(u8, candidate.architecture, target.architecture) and variantMatches(candidate, target)) return entry.digest;
    }
    return error.PlatformNotFound;
}

fn fetchSingle(alloc: std.mem.Allocator, client: *std.http.Client, host: []const u8, repository: []const u8, reference: []const u8, token: common.Token, comptime scheme: []const u8, byte_limit: usize) common.ManifestError!SingleManifest {
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
        if (content_length > byte_limit) return error.ResponseTooLarge;
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

    const raw_body = try http_helpers.readBody(alloc, body_reader, byte_limit);
    errdefer alloc.free(raw_body);

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

    var is_index = spec.isIndexMediaType(content_type);
    if (!is_index) {
        if (spec.parseImageIndex(alloc, raw_body)) |value| {
            var parsed = value;
            defer parsed.deinit();
            is_index = true;
        } else |_| {}
    }
    const digest_str = alloc.dupe(u8, computed_str) catch return error.OutOfMemory;
    return .{ .result = .{ .body = raw_body, .digest = digest_str }, .is_index = is_index };
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
        const result = resolve(alloc, &client, try server.host(&host_buf), "test", "latest", .{ .value = "" }, "http", .{ .os = "linux", .architecture = "amd64" }, .{});
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

fn testIndex(alloc: std.mem.Allocator, child: []const u8, nested: bool) ![]u8 {
    var digest_buf: [71]u8 = undefined;
    return std.fmt.allocPrint(
        alloc,
        "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}{s}}}]}}",
        .{ if (nested) spec.media_type.oci_index else spec.media_type.oci_manifest, blob_store.computeDigest(child).string(&digest_buf), child.len, if (nested) "" else ",\"platform\":{\"os\":\"linux\",\"architecture\":\"amd64\"}" },
    );
}

test "image resolution selects requested architecture regardless of index order" {
    const Server = @import("test_support.zig").Server;
    const alloc = std.testing.allocator;
    const names = [_][]const u8{ "amd64", "arm64", "riscv64" };
    const bodies = [_][]const u8{ "{\"schemaVersion\":2,\"test\":\"amd64\"}", "{\"schemaVersion\":2,\"test\":\"arm64\"}", "{\"schemaVersion\":2,\"test\":\"riscv64\"}" };
    for ([_]bool{ false, true }) |reverse| {
        var index: std.Io.Writer.Allocating = .init(alloc);
        defer index.deinit();
        try index.writer.writeAll("{\"schemaVersion\":2,\"manifests\":[");
        for (0..names.len) |j| {
            const i = if (reverse) names.len - 1 - j else j;
            var digest_buf: [71]u8 = undefined;
            try index.writer.print("{s}{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d},\"platform\":{{\"os\":\"linux\",\"architecture\":\"{s}\"}}}}", .{ if (j == 0) "" else ",", spec.media_type.oci_manifest, blob_store.computeDigest(bodies[i]).string(&digest_buf), bodies[i].len, names[i] });
        }
        try index.writer.writeAll("]}");
        for (names, bodies) |name, body| {
            const replies = [_]Server.Reply{ .{ .body = index.written() }, .{ .body = body } };
            var server = try Server.init(&replies);
            defer server.deinit();
            try server.start();
            var client: std.http.Client = .{ .io = std.testing.io, .allocator = alloc };
            defer client.deinit();
            var host: [64]u8 = undefined;
            const result = try resolve(alloc, &client, try server.host(&host), "image", "latest", .{ .value = "" }, "http", .{ .os = "linux", .architecture = name }, .{});
            defer alloc.free(result.body);
            defer alloc.free(result.digest);
            try std.testing.expectEqualStrings(body, result.body);
        }
    }
}

test "image resolution variants are explicit and never select unrelated platforms" {
    const entries = [_]spec.Descriptor{
        .{ .mediaType = spec.media_type.oci_manifest, .digest = "v9", .size = 1, .platform = .{ .os = "linux", .architecture = "arm64", .variant = "v9" } },
        .{ .mediaType = spec.media_type.oci_manifest, .digest = "amd64", .size = 1, .platform = .{ .os = "linux", .architecture = "amd64" } },
        .{ .mediaType = spec.media_type.oci_manifest, .digest = "v8", .size = 1, .platform = .{ .os = "linux", .architecture = "arm64", .variant = "v8" } },
    };
    try std.testing.expectEqualStrings("v8", try selectPlatform(&entries, .{ .os = "linux", .architecture = "arm64" }));
    try std.testing.expectEqualStrings("v9", try selectPlatform(&entries, .{ .os = "linux", .architecture = "arm64", .variant = "v9" }));
    try std.testing.expectError(error.PlatformNotFound, selectPlatform(&entries, .{ .os = "linux", .architecture = "riscv64" }));
    try std.testing.expectError(error.PlatformNotFound, selectPlatform(&entries, .{ .os = "windows", .architecture = "amd64" }));
    try std.testing.expectError(error.PlatformNotFound, selectPlatform(&entries, .{ .os = "linux", .architecture = "arm64", .variant = "v7" }));
}

test "image resolution bounds nested HTTP graphs and aggregate bytes" {
    const Server = @import("test_support.zig").Server;
    const alloc = std.testing.allocator;
    const leaf = "{\"schemaVersion\":2}";
    const inner = try testIndex(alloc, leaf, false);
    defer alloc.free(inner);
    const outer = try testIndex(alloc, inner, true);
    defer alloc.free(outer);
    for ([_]Limits{ .{}, .{ .requests = 2 }, .{ .bytes = outer.len + inner.len - 1 } }, 0..) |limits, i| {
        const replies = [_]Server.Reply{ .{ .body = outer }, .{ .body = inner }, .{ .body = leaf } };
        var server = try Server.init(replies[0..if (i == 0) @as(usize, 3) else 2]);
        defer server.deinit();
        try server.start();
        var client: std.http.Client = .{ .io = std.testing.io, .allocator = alloc };
        defer client.deinit();
        var host: [64]u8 = undefined;
        const result = resolve(alloc, &client, try server.host(&host), "image", "latest", .{ .value = "" }, "http", .{ .os = "linux", .architecture = "amd64" }, limits);
        if (i == 0) {
            const fetched = try result;
            defer alloc.free(fetched.body);
            defer alloc.free(fetched.digest);
            try std.testing.expectEqualStrings(leaf, fetched.body);
        } else try std.testing.expectError(error.ResponseTooLarge, result);
        server.worker.?.join();
        server.worker = null;
        try std.testing.expectEqual(@as(usize, if (i == 0) 3 else 2), server.requests);
    }
}

test "image resolution bounds repeated descriptors before another request" {
    const digest = blob_store.computeDigest("index");
    var ref: [71]u8 = undefined;
    var pending: [8]Pending = undefined;
    var count: usize = 0;
    try enqueue(&pending, &count, &.{}, digest.string(&ref), 1, true);
    try enqueue(&pending, &count, &.{}, digest.string(&ref), 1, true);
    try std.testing.expectEqual(@as(usize, 1), count);
    count = 0; // The previously queued index has now been searched.
    try enqueue(&pending, &count, &.{digest}, digest.string(&ref), 2, true);
    try std.testing.expectEqual(@as(usize, 0), count);
}

test "image resolution deduplicates repeated nested descriptors over HTTP" {
    const Server = @import("test_support.zig").Server;
    const alloc = std.testing.allocator;
    const inner = "{\"schemaVersion\":2,\"manifests\":[]}";
    var digest_buf: [71]u8 = undefined;
    const descriptor = try std.fmt.allocPrint(alloc, "{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}", .{ spec.media_type.oci_index, blob_store.computeDigest(inner).string(&digest_buf), inner.len });
    defer alloc.free(descriptor);
    const outer = try std.fmt.allocPrint(alloc, "{{\"schemaVersion\":2,\"manifests\":[{s},{s}]}}", .{ descriptor, descriptor });
    defer alloc.free(outer);
    const replies = [_]Server.Reply{ .{ .body = outer }, .{ .body = inner } };
    var server = try Server.init(&replies);
    defer server.deinit();
    try server.start();
    var client: std.http.Client = .{ .io = std.testing.io, .allocator = alloc };
    defer client.deinit();
    var host: [64]u8 = undefined;
    try std.testing.expectError(error.PlatformNotFound, resolve(alloc, &client, try server.host(&host), "image", "latest", .{ .value = "" }, "http", .{ .os = "linux", .architecture = "amd64" }, .{}));
    server.worker.?.join();
    server.worker = null;
    try std.testing.expectEqual(@as(usize, 2), server.requests);
}

test "image resolution stops an overdeep HTTP index chain at the fixed request cap" {
    const Server = @import("test_support.zig").Server;
    const alloc = std.testing.allocator;
    var chain: [8][]u8 = undefined;
    var built: usize = 0;
    defer for (chain[chain.len - built ..]) |body| alloc.free(body);
    var child: []const u8 = "{\"schemaVersion\":2}";
    for (0..chain.len) |i| {
        const index = chain.len - 1 - i;
        chain[index] = try testIndex(alloc, child, i != 0);
        built += 1;
        child = chain[index];
    }
    var replies: [8]Server.Reply = undefined;
    for (&replies, chain) |*reply, body| reply.* = .{ .body = body };
    var server = try Server.init(&replies);
    defer server.deinit();
    try server.start();
    var client: std.http.Client = .{ .io = std.testing.io, .allocator = alloc };
    defer client.deinit();
    var host: [64]u8 = undefined;
    try std.testing.expectError(error.ResponseTooLarge, resolve(alloc, &client, try server.host(&host), "image", "latest", .{ .value = "" }, "http", .{ .os = "linux", .architecture = "amd64" }, .{}));
    server.worker.?.join();
    server.worker = null;
    try std.testing.expectEqual(@as(usize, 8), server.requests);
}

fn testNestedIndices(alloc: std.mem.Allocator, children: []const []const u8) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(alloc);
    defer output.deinit();
    try output.writer.writeAll("{\"schemaVersion\":2,\"manifests\":[");
    for (children, 0..) |child, i| {
        var digest_buf: [71]u8 = undefined;
        try output.writer.print("{s}{{\"mediaType\":\"{s}\",\"digest\":\"{s}\",\"size\":{d}}}", .{ if (i == 0) "" else ",", spec.media_type.oci_index, blob_store.computeDigest(child).string(&digest_buf), child.len });
    }
    try output.writer.writeAll("]}");
    return alloc.dupe(u8, output.written());
}

test "image resolution searches siblings after a shared nested index over HTTP" {
    const Server = @import("test_support.zig").Server;
    const alloc = std.testing.allocator;
    const leaf = "{\"schemaVersion\":2}";
    const shared = "{\"schemaVersion\":2,\"manifests\":[]}";
    const target = try testIndex(alloc, leaf, false);
    defer alloc.free(target);
    const left = try testNestedIndices(alloc, &.{shared});
    defer alloc.free(left);
    const right = try testNestedIndices(alloc, &.{ shared, target });
    defer alloc.free(right);
    const root = try testNestedIndices(alloc, &.{ left, right });
    defer alloc.free(root);
    // DFS visits root -> left -> shared -> right -> target -> leaf. The
    // second edge to shared consumes no request and cannot hide target.
    const replies = [_]Server.Reply{
        .{ .body = root },  .{ .body = left },   .{ .body = shared },
        .{ .body = right }, .{ .body = target }, .{ .body = leaf },
    };
    var server = try Server.init(&replies);
    defer server.deinit();
    try server.start();
    var client: std.http.Client = .{ .io = std.testing.io, .allocator = alloc };
    defer client.deinit();
    var host: [64]u8 = undefined;
    const result = try resolve(alloc, &client, try server.host(&host), "image", "latest", .{ .value = "" }, "http", .{ .os = "linux", .architecture = "amd64" }, .{});
    defer alloc.free(result.body);
    defer alloc.free(result.digest);
    try std.testing.expectEqualStrings(leaf, result.body);
    server.worker.?.join();
    server.worker = null;
    try std.testing.expectEqual(@as(usize, 6), server.requests);
}
