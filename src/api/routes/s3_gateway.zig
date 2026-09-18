// s3_gateway — HTTP route handler for S3-compatible API
//
// maps S3-style HTTP requests to the storage/s3.zig operations.
// mounted under /s3/ prefix in the API server.
//
// path format: /s3/{bucket}/{key...}
// auth: uses the same HMAC token as the rest of the API (not AWS SigV4).

const std = @import("std");
const http = @import("../http.zig");
const common = @import("common.zig");
const s3 = @import("../../storage/s3.zig");
const s3_xml = @import("../../storage/s3_xml.zig");
const s3_listing = @import("../../storage/s3_listing.zig");

const Response = common.Response;

/// try to route an S3 request. returns null if path doesn't match /s3/.
pub fn route(request: http.Request, alloc: std.mem.Allocator) ?Response {
    const prefix = "/s3";
    if (!std.mem.startsWith(u8, request.path_only, prefix)) return null;

    const rest = request.path_only[prefix.len..];

    // /s3 or /s3/ — service-level operations
    if (rest.len == 0 or std.mem.eql(u8, rest, "/")) {
        return serviceLevel(request, alloc);
    }

    // must start with /
    if (rest[0] != '/') return null;
    var path_buf: [4096]u8 = undefined;
    const path = decodeComponent(&path_buf, rest[1..], false) catch
        return s3Error(alloc, "InvalidArgument", "invalid encoded object path");

    // split into bucket and key
    if (std.mem.indexOfScalar(u8, path, '/')) |sep| {
        const bucket = path[0..sep];
        const key = path[sep + 1 ..];
        if (key.len == 0) {
            // /s3/bucket/ — bucket-level operations
            return bucketLevel(request, alloc, bucket);
        }
        // /s3/bucket/key... — object-level operations
        return objectLevel(request, alloc, bucket, key);
    }

    // /s3/bucket — bucket-level operations (no trailing slash)
    return bucketLevel(request, alloc, path);
}

/// handle service-level operations (GET /s3/ = ListBuckets)
fn serviceLevel(request: http.Request, alloc: std.mem.Allocator) Response {
    if (request.method != .GET) return common.methodNotAllowed();

    const result = s3.listBuckets(alloc) catch return s3Error(alloc, "InternalError", "failed to list buckets");
    defer {
        for (result.names) |n| alloc.free(n);
        alloc.free(result.names);
        alloc.free(result.timestamps);
    }

    var buf: [65536]u8 = undefined;
    const xml = s3_xml.listBucketsXml(&buf, result.names, result.timestamps) orelse
        return s3Error(alloc, "InternalError", "response too large");

    return xmlResponse(alloc, xml);
}

/// handle bucket-level operations
fn bucketLevel(request: http.Request, alloc: std.mem.Allocator, bucket: []const u8) Response {
    return switch (request.method) {
        .PUT => {
            // CreateBucket
            s3.createBucket(bucket) catch |e| return switch (e) {
                s3.S3Error.BucketAlreadyExists => s3Error(alloc, "BucketAlreadyOwnedByYou", "bucket already exists"),
                s3.S3Error.InvalidBucketName => s3Error(alloc, "InvalidBucketName", "invalid bucket name"),
                else => s3Error(alloc, "InternalError", "failed to create bucket"),
            };
            return .{ .status = .ok, .body = "", .allocated = false };
        },
        .DELETE => {
            // DeleteBucket
            s3.deleteBucket(bucket) catch |e| return switch (e) {
                s3.S3Error.BucketNotFound => s3ErrorStatus(alloc, .not_found, "NoSuchBucket", "bucket not found"),
                s3.S3Error.BucketNotEmpty => s3Error(alloc, "BucketNotEmpty", "bucket is not empty"),
                else => s3Error(alloc, "InternalError", "failed to delete bucket"),
            };
            return .{ .status = .no_content, .body = "", .allocated = false };
        },
        .GET => {
            // ListObjectsV2
            var prefix_buf: [1024]u8 = undefined;
            const prefix = decodeComponent(&prefix_buf, common.extractQueryValue(request.query, "prefix") orelse "", true) catch
                return s3Error(alloc, "InvalidArgument", "invalid encoded prefix");
            const max_keys_text = common.extractQueryValue(request.query, "max-keys") orelse "1000";
            const max_keys = std.fmt.parseInt(usize, max_keys_text, 10) catch
                return s3Error(alloc, "InvalidArgument", "invalid max-keys");
            if (max_keys > 1000) return s3Error(alloc, "InvalidArgument", "max-keys must not exceed 1000");
            var decoded_token: [1024]u8 = undefined;
            var after_buf: [1024]u8 = undefined;
            const after = if (common.extractQueryValue(request.query, "continuation-token")) |token|
                std.fmt.hexToBytes(&decoded_token, token) catch return s3Error(alloc, "InvalidArgument", "invalid continuation token")
            else
                decodeComponent(&after_buf, common.extractQueryValue(request.query, "start-after") orelse "", true) catch
                    return s3Error(alloc, "InvalidArgument", "invalid encoded start-after");
            const page = s3_listing.list(alloc, bucket, prefix, after, max_keys) catch |e| return switch (e) {
                s3.S3Error.BucketNotFound => s3ErrorStatus(alloc, .not_found, "NoSuchBucket", "bucket not found"),
                else => s3Error(alloc, "InternalError", "failed to list objects"),
            };
            defer page.deinit(alloc);
            var next_token_buf: [2048]u8 = undefined;
            const next_token = if (page.truncated)
                std.fmt.bufPrint(&next_token_buf, "{x}", .{page.objects[page.objects.len - 1].key}) catch
                    return common.internalError()
            else
                null;

            const buf = alloc.alloc(u8, 16384 + page.objects.len * 6400) catch return common.internalError();
            defer alloc.free(buf);
            const xml = s3_xml.listObjectsPageXml(buf, bucket, prefix, page.objects, max_keys, next_token) orelse
                return s3Error(alloc, "InternalError", "response too large");

            return xmlResponse(alloc, xml);
        },
        else => common.methodNotAllowed(),
    };
}

/// handle object-level operations
fn objectLevel(request: http.Request, alloc: std.mem.Allocator, bucket: []const u8, key: []const u8) Response {
    // check for multipart upload operations via query parameters
    if (request.query.len > 0) {
        if (common.extractQueryValue(request.query, "uploads") != null and request.method == .POST) {
            return initiateMultipart(alloc, bucket, key);
        }
        if (common.extractQueryValue(request.query, "uploadId")) |upload_id| {
            return multipartOp(request, alloc, bucket, key, upload_id);
        }
    }

    return switch (request.method) {
        .PUT => {
            // PutObject
            const etag = s3.putObject(bucket, key, request.body) catch |e| return switch (e) {
                s3.S3Error.BucketNotFound => s3ErrorStatus(alloc, .not_found, "NoSuchBucket", "bucket not found"),
                s3.S3Error.InvalidBucketName => s3Error(alloc, "InvalidBucketName", "invalid bucket name"),
                s3.S3Error.InvalidKey => s3Error(alloc, "InvalidKey", "invalid object key"),
                else => s3Error(alloc, "InternalError", "failed to put object"),
            };

            return etagJsonResponse(alloc, etag);
        },
        .GET => {
            // GetObject
            const data = s3.getObject(alloc, bucket, key) catch |e| return switch (e) {
                s3.S3Error.ObjectNotFound => s3ErrorStatus(alloc, .not_found, "NoSuchKey", "object not found"),
                s3.S3Error.InvalidKey => s3Error(alloc, "InvalidKey", "invalid object key"),
                else => s3Error(alloc, "InternalError", "failed to get object"),
            };

            return .{
                .status = .ok,
                .body = data,
                .allocated = true,
                .content_type = "application/octet-stream",
                .etag = s3.computeEtag(data),
            };
        },
        .HEAD => {
            // HeadObject — return metadata without body
            const meta = s3.headObject(bucket, key) catch |e| return switch (e) {
                s3.S3Error.ObjectNotFound => s3ErrorStatus(alloc, .not_found, "NoSuchKey", "object not found"),
                s3.S3Error.InvalidBucketName => s3Error(alloc, "InvalidBucketName", "invalid bucket name"),
                s3.S3Error.InvalidKey => s3Error(alloc, "InvalidKey", "invalid object key"),
                else => s3Error(alloc, "InternalError", "failed to head object"),
            };

            return headResponse(meta);
        },
        .DELETE => {
            // DeleteObject — S3 returns 204 even if object doesn't exist
            s3.deleteObject(bucket, key) catch |e| switch (e) {
                s3.S3Error.ObjectNotFound => {},
                s3.S3Error.InvalidBucketName => return s3Error(alloc, "InvalidBucketName", "invalid bucket name"),
                s3.S3Error.InvalidKey => return s3Error(alloc, "InvalidKey", "invalid object key"),
                else => return common.internalError(),
            };
            return .{ .status = .no_content, .body = "", .allocated = false };
        },
        .POST => common.methodNotAllowed(),
    };
}

/// initiate multipart upload
fn initiateMultipart(alloc: std.mem.Allocator, bucket: []const u8, key: []const u8) Response {
    const upload_id = s3.initiateMultipartUpload(bucket, key) catch |e| return switch (e) {
        s3.S3Error.BucketNotFound => s3ErrorStatus(alloc, .not_found, "NoSuchBucket", "bucket not found"),
        else => s3Error(alloc, "InternalError", "failed to initiate multipart upload"),
    };

    var buf: [4096]u8 = undefined;
    const xml = s3_xml.initiateMultipartXml(&buf, bucket, key, &upload_id) orelse
        return s3Error(alloc, "InternalError", "response too large");

    return xmlResponse(alloc, xml);
}

/// handle multipart upload part operations
fn multipartOp(request: http.Request, alloc: std.mem.Allocator, bucket: []const u8, key: []const u8, upload_id: []const u8) Response {
    return switch (request.method) {
        .PUT => {
            // UploadPart
            const part_num_str = common.extractQueryValue(request.query, "partNumber") orelse
                return s3Error(alloc, "InvalidArgument", "missing partNumber");

            const part_number = std.fmt.parseInt(u32, part_num_str, 10) catch
                return s3Error(alloc, "InvalidArgument", "invalid partNumber");

            const etag = s3.uploadPart(upload_id, bucket, key, part_number, request.body) catch |e| return switch (e) {
                s3.S3Error.UploadNotFound => s3ErrorStatus(alloc, .not_found, "NoSuchUpload", "upload not found"),
                s3.S3Error.InvalidPartNumber => s3Error(alloc, "InvalidPart", "invalid part number"),
                s3.S3Error.InvalidUploadId => s3Error(alloc, "InvalidArgument", "invalid uploadId"),
                else => s3Error(alloc, "InternalError", "failed to upload part"),
            };

            return etagJsonResponse(alloc, etag);
        },
        .POST => {
            // check existence first so an aborted upload still returns NoSuchUpload.
            s3.checkMultipartUpload(bucket, key, upload_id) catch |err| return switch (err) {
                error.UploadNotFound => s3ErrorStatus(alloc, .not_found, "NoSuchUpload", "upload not found"),
                error.InvalidUploadId => s3Error(alloc, "InvalidArgument", "invalid uploadId"),
                else => common.internalError(),
            };
            const parts = @import("../../storage/s3_multipart.zig").parse(alloc, request.body) catch |err| return switch (err) {
                error.InvalidPart => s3Error(alloc, "InvalidPart", "invalid or missing part"),
                error.InvalidPartOrder => s3Error(alloc, "InvalidPartOrder", "parts must be in ascending order"),
                error.MalformedXml => s3Error(alloc, "MalformedXML", "invalid multipart completion document"),
                error.OutOfMemory => common.internalError(),
            };
            defer alloc.free(parts);
            const etag = s3.completeSelectedParts(alloc, bucket, key, upload_id, parts) catch |e| return switch (e) {
                s3.S3Error.UploadNotFound => s3ErrorStatus(alloc, .not_found, "NoSuchUpload", "upload not found"),
                s3.S3Error.BucketNotFound => s3ErrorStatus(alloc, .not_found, "NoSuchBucket", "bucket not found"),
                s3.S3Error.InvalidUploadId => s3Error(alloc, "InvalidArgument", "invalid uploadId"),
                s3.S3Error.InvalidPart => s3Error(alloc, "InvalidPart", "part is missing or its etag does not match"),
                s3.S3Error.InvalidPartOrder => s3Error(alloc, "InvalidPartOrder", "parts must be in ascending order"),
                else => s3Error(alloc, "InternalError", "failed to complete multipart upload"),
            };

            var buf: [4096]u8 = undefined;
            const xml = s3_xml.completeMultipartXml(&buf, bucket, key, &etag) orelse
                return s3Error(alloc, "InternalError", "response too large");

            return xmlResponse(alloc, xml);
        },
        .DELETE => {
            // AbortMultipartUpload
            s3.abortMultipartUpload(upload_id) catch |e| return switch (e) {
                s3.S3Error.InvalidUploadId => s3Error(alloc, "InvalidArgument", "invalid uploadId"),
                else => .{ .status = .no_content, .body = "", .allocated = false },
            };
            return .{ .status = .no_content, .body = "", .allocated = false };
        },
        else => common.methodNotAllowed(),
    };
}

// -- helpers --

fn decodeComponent(buf: []u8, encoded: []const u8, plus_as_space: bool) ![]const u8 {
    var input: usize = 0;
    var output: usize = 0;
    while (input < encoded.len) : (input += 1) {
        if (output == buf.len) return error.TooLong;
        const byte = encoded[input];
        buf[output] = if (byte == '%') decoded: {
            if (input + 2 >= encoded.len) return error.InvalidEncoding;
            const high = std.fmt.charToDigit(encoded[input + 1], 16) catch return error.InvalidEncoding;
            const low = std.fmt.charToDigit(encoded[input + 2], 16) catch return error.InvalidEncoding;
            input += 2;
            break :decoded high * 16 + low;
        } else if (plus_as_space and byte == '+') ' ' else byte;
        output += 1;
    }
    return buf[0..output];
}

fn s3Error(alloc: std.mem.Allocator, code: []const u8, message: []const u8) Response {
    return s3ErrorStatus(alloc, if (std.mem.eql(u8, code, "InternalError")) .internal_server_error else .bad_request, code, message);
}

fn s3ErrorStatus(alloc: std.mem.Allocator, status: http.StatusCode, code: []const u8, message: []const u8) Response {
    var buf: [512]u8 = undefined;
    const xml = s3_xml.errorXml(&buf, code, message) orelse
        return .{ .status = status, .body = "<Error><Code>InternalError</Code></Error>", .allocated = false };

    const owned = alloc.dupe(u8, xml) catch
        return .{ .status = status, .body = "<Error><Code>InternalError</Code></Error>", .allocated = false };

    return .{ .status = status, .body = owned, .allocated = true, .content_type = "application/xml" };
}

fn headResponse(meta: s3.ObjectMeta) Response {
    return .{ .status = .ok, .body = "", .allocated = false, .content_type = "application/octet-stream", .content_length = @intCast(meta.size), .etag = meta.etag };
}

fn etagJsonResponse(alloc: std.mem.Allocator, etag: [32]u8) Response {
    var etag_buf: [64]u8 = undefined;
    const etag_json = std.fmt.bufPrint(&etag_buf, "{{\"ETag\":\"\\\"{s}\\\"\"}}", .{etag}) catch
        return .{ .status = .ok, .body = "{}", .allocated = false };

    const owned = alloc.dupe(u8, etag_json) catch return common.internalError();
    return .{ .status = .ok, .body = owned, .allocated = true, .etag = etag };
}

fn xmlResponse(alloc: std.mem.Allocator, xml: []const u8) Response {
    const owned = alloc.dupe(u8, xml) catch return common.internalError();
    return .{ .status = .ok, .body = owned, .allocated = true, .content_type = "application/xml" };
}

// -- tests --

test "route returns null for non-s3 paths" {
    const req = http.Request{
        .method = .GET,
        .path = "/health",
        .path_only = "/health",
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };
    const result = route(req, std.testing.allocator);
    try std.testing.expect(result == null);
}

test "route matches /s3 prefix" {
    const req = http.Request{
        .method = .GET,
        .path = "/s3/",
        .path_only = "/s3/",
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };
    const result = route(req, std.testing.allocator);
    // should return a response (not null) — whether it succeeds depends on storage
    try std.testing.expect(result != null);
    if (result) |resp| {
        if (resp.allocated) std.testing.allocator.free(resp.body);
    }
}

test "route matches /s3/bucket" {
    const req = http.Request{
        .method = .GET,
        .path = "/s3/mybucket",
        .path_only = "/s3/mybucket",
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };
    const result = route(req, std.testing.allocator);
    try std.testing.expect(result != null);
    if (result) |resp| {
        if (resp.allocated) std.testing.allocator.free(resp.body);
    }
}
