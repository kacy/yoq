const std = @import("std");
const paths = @import("../../lib/paths.zig");
const log = @import("../../lib/log.zig");
const blob_store = @import("../store.zig");
const common = @import("common.zig");
const http_helpers = @import("http.zig");

pub fn fetchBlob(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    token: common.Token,
) ![]u8 {
    var url_buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://{s}/v2/{s}/blobs/{s}",
        .{ host, repository, digest },
    ) catch return error.BlobNotFound;

    return fetchBlobFromUrl(alloc, client, host, url, token, true, 0);
}

pub fn downloadLayerWorker(
    io: std.Io,
    alloc: std.mem.Allocator,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    token: common.Token,
    err_flag: *std.atomic.Value(bool),
    thread_err: *?common.RegistryError,
) void {
    if (err_flag.load(.acquire)) return;

    var thread_client: std.http.Client = .{ .io = io, .allocator = alloc };
    defer thread_client.deinit();

    downloadLayerBlob(alloc, &thread_client, host, repository, digest, token) catch |err| {
        thread_err.* = switch (err) {
            error.BlobNotFound => common.RegistryError.BlobNotFound,
            error.NetworkError => common.RegistryError.NetworkError,
            error.ResponseTooLarge => common.RegistryError.ResponseTooLarge,
            error.DigestMismatch => common.RegistryError.DigestMismatch,
        };
        err_flag.store(true, .release);
    };
}

pub fn downloadLayerBlob(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    token: common.Token,
) !void {
    const expected = blob_store.Digest.parse(digest) orelse return error.DigestMismatch;

    if (blob_store.hasBlob(expected)) {
        if (blob_store.verifyBlob(expected)) return;
        log.warn("corrupted cached layer {s}, re-downloading", .{digest});
        blob_store.removeBlob(expected);
    }

    try downloadBlobToStore(alloc, client, host, repository, digest, expected, token);
}

fn fetchBlobFromUrl(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    url: []const u8,
    token: common.Token,
    send_auth: bool,
    redirect_count: u8,
) ![]u8 {
    if (redirect_count > 5) return error.NetworkError;

    var url_summary_buf: [256]u8 = undefined;
    const url_summary = common.summarizeUrl(url, &url_summary_buf);
    var auth_buf: [8192]u8 = undefined;
    const auth_value = if (send_auth) common.authHeaderValue(token, &auth_buf) else "";
    const uri = std.Uri.parse(url) catch {
        log.warn("blob fetch: failed to parse url {s}", .{url_summary});
        return error.BlobNotFound;
    };

    const blob_conn = http_helpers.connectWithTimeout(client, uri) catch {
        log.warn("blob fetch: connect failed for {s}", .{url_summary});
        return error.NetworkError;
    };
    var req = client.request(.GET, uri, .{
        .connection = blob_conn,
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

    if (common.isRedirectStatus(response.head.status)) {
        const location = http_helpers.parseLocationHeader(host, response.head) orelse {
            log.warn("blob fetch: redirect missing location for {s}", .{url_summary});
            return error.NetworkError;
        };
        const location_copy = alloc.dupe(u8, location) catch return error.NetworkError;
        defer alloc.free(location_copy);

        var location_summary_buf: [256]u8 = undefined;
        const location_summary = common.summarizeUrl(location_copy, &location_summary_buf);
        log.debug("blob fetch: redirect {d} from {s} to {s} (auth={})", .{
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

    if (response.head.content_length) |content_length| {
        if (content_length > common.max_blob_size) return error.ResponseTooLarge;
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
    if (raw_body.len > common.max_blob_size) return error.ResponseTooLarge;
    return alloc.dupe(u8, raw_body) catch return error.NetworkError;
}

fn downloadBlobToStore(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    digest: []const u8,
    expected: blob_store.Digest,
    token: common.Token,
) !void {
    var url_buf: [1024]u8 = undefined;
    const url = std.fmt.bufPrint(
        &url_buf,
        "https://{s}/v2/{s}/blobs/{s}",
        .{ host, repository, digest },
    ) catch return error.BlobNotFound;

    try downloadBlobUrlToStore(alloc, client, host, url, expected, token, true, 0);
}

fn downloadBlobUrlToStore(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    url: []const u8,
    expected: blob_store.Digest,
    token: common.Token,
    send_auth: bool,
    redirect_count: u8,
) !void {
    if (redirect_count > 5) return error.NetworkError;

    var url_summary_buf: [256]u8 = undefined;
    const url_summary = common.summarizeUrl(url, &url_summary_buf);
    var auth_buf: [8192]u8 = undefined;
    const auth_value = if (send_auth) common.authHeaderValue(token, &auth_buf) else "";
    const uri = std.Uri.parse(url) catch {
        log.warn("layer fetch: failed to parse url {s}", .{url_summary});
        return error.BlobNotFound;
    };

    const blob_conn = http_helpers.connectWithTimeout(client, uri) catch {
        log.warn("layer fetch: connect failed for {s}", .{url_summary});
        return error.NetworkError;
    };
    var req = client.request(.GET, uri, .{
        .connection = blob_conn,
        .redirect_behavior = .unhandled,
        .keep_alive = false,
        .headers = .{
            .authorization = if (auth_value.len > 0) .{ .override = auth_value } else .default,
        },
    }) catch |err| {
        log.warn("layer fetch: request setup failed for {s}: {}", .{ url_summary, err });
        return error.NetworkError;
    };
    defer req.deinit();

    req.sendBodiless() catch |err| {
        log.warn("layer fetch: send failed for {s}: {}", .{ url_summary, err });
        return error.NetworkError;
    };

    var redirect_buf: [262144]u8 = undefined;
    var response = req.receiveHead(&redirect_buf) catch |err| {
        log.warn("layer fetch: receive head failed for {s}: {}", .{ url_summary, err });
        return error.NetworkError;
    };

    if (common.isRedirectStatus(response.head.status)) {
        const location = http_helpers.parseLocationHeader(host, response.head) orelse {
            log.warn("layer fetch: redirect missing location for {s}", .{url_summary});
            return error.NetworkError;
        };
        const location_copy = alloc.dupe(u8, location) catch return error.NetworkError;
        defer alloc.free(location_copy);
        return downloadBlobUrlToStore(alloc, client, host, location_copy, expected, token, false, redirect_count + 1);
    }

    if (response.head.status != .ok) {
        log.warn("layer fetch: unexpected status {d} for {s}", .{ @intFromEnum(response.head.status), url_summary });
        return error.BlobNotFound;
    }

    if (response.head.content_length) |content_length| {
        if (content_length > common.max_blob_size) return error.ResponseTooLarge;
    }

    var tmp_path_buf: [paths.max_path]u8 = undefined;
    const tmp_path = blob_store.tempBlobPath(&tmp_path_buf) catch return error.NetworkError;
    var tmp_file = std.Io.Dir.cwd().createFile(std.Options.debug_io, tmp_path, .{}) catch return error.NetworkError;
    defer tmp_file.close(std.Options.debug_io);

    var committed = false;
    defer if (!committed) std.Io.Dir.cwd().deleteFile(std.Options.debug_io, tmp_path) catch {};

    var transfer_buf: [8192]u8 = undefined;
    const body_reader = response.reader(&transfer_buf);
    var chunk_buf: [8192]u8 = undefined;
    var bytes_read_total: usize = 0;

    while (true) {
        const bytes_read = body_reader.readSliceShort(&chunk_buf) catch |err| {
            log.warn("layer fetch: body read failed for {s}: {}", .{ url_summary, err });
            return error.NetworkError;
        };
        if (bytes_read == 0) break;

        bytes_read_total += bytes_read;
        if (bytes_read_total > common.max_blob_size) return error.ResponseTooLarge;

        tmp_file.writeStreamingAll(std.Options.debug_io, chunk_buf[0..bytes_read]) catch return error.NetworkError;
    }

    tmp_file.sync(std.Options.debug_io) catch {};
    try verifyFileDigest(tmp_path, expected);
    blob_store.commitTempBlob(tmp_path, expected) catch return error.NetworkError;
    committed = true;
}

fn verifyFileDigest(path: []const u8, expected: blob_store.Digest) !void {
    var file = std.Io.Dir.cwd().openFile(std.Options.debug_io, path, .{}) catch return error.NetworkError;
    defer file.close(std.Options.debug_io);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var reader_buf: [8192]u8 = undefined;
    var reader = file.readerStreaming(std.Options.debug_io, &reader_buf);
    var buffer: [8192]u8 = undefined;
    while (true) {
        const bytes_read = reader.interface.readSliceShort(&buffer) catch return error.NetworkError;
        if (bytes_read == 0) break;
        hasher.update(buffer[0..bytes_read]);
    }

    const computed = blob_store.Digest{ .hash = hasher.finalResult() };
    if (!computed.eql(expected)) return error.DigestMismatch;
}
