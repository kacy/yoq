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
    const path = rest[1..]; // strip leading /

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
            const prefix = common.extractQueryValue(request.query, "prefix") orelse "";

            const objects = s3.listObjects(alloc, bucket, prefix) catch |e| return switch (e) {
                s3.S3Error.BucketNotFound => s3ErrorStatus(alloc, .not_found, "NoSuchBucket", "bucket not found"),
                else => s3Error(alloc, "InternalError", "failed to list objects"),
            };
            defer {
                for (objects) |obj| alloc.free(obj.key);
                alloc.free(objects);
            }

            var buf: [65536]u8 = undefined;
            const xml = s3_xml.listObjectsV2Xml(&buf, bucket, prefix, objects) orelse
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
        if (std.mem.indexOf(u8, request.query, "uploads") != null and request.method == .POST) {
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

            return etagJsonResponse(alloc, &etag);
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

            return headResponse(alloc, meta);
        },
        .DELETE => {
            // DeleteObject — S3 returns 204 even if object doesn't exist
            s3.deleteObject(bucket, key) catch return common.internalError();
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

            return etagJsonResponse(alloc, &etag);
        },
        .POST => {
            // CompleteMultipartUpload
            const etag = s3.completeMultipartUpload(alloc, bucket, key, upload_id) catch |e| return switch (e) {
                s3.S3Error.UploadNotFound => s3ErrorStatus(alloc, .not_found, "NoSuchUpload", "upload not found"),
                s3.S3Error.BucketNotFound => s3ErrorStatus(alloc, .not_found, "NoSuchBucket", "bucket not found"),
                s3.S3Error.InvalidUploadId => s3Error(alloc, "InvalidArgument", "invalid uploadId"),
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

fn s3Error(alloc: std.mem.Allocator, code: []const u8, message: []const u8) Response {
    return s3ErrorStatus(alloc, .bad_request, code, message);
}

fn s3ErrorStatus(alloc: std.mem.Allocator, status: http.StatusCode, code: []const u8, message: []const u8) Response {
    var buf: [512]u8 = undefined;
    const xml = s3_xml.errorXml(&buf, code, message) orelse
        return .{ .status = status, .body = "<Error><Code>InternalError</Code></Error>", .allocated = false };

    const owned = alloc.dupe(u8, xml) catch
        return .{ .status = status, .body = "<Error><Code>InternalError</Code></Error>", .allocated = false };

    return .{ .status = status, .body = owned, .allocated = true, .content_type = "application/xml" };
}

fn headResponse(alloc: std.mem.Allocator, meta: s3.ObjectMeta) Response {
    var buf: [256]u8 = undefined;
    const json = std.fmt.bufPrint(&buf, "{{\"content_length\":{d},\"etag\":\"{s}\",\"last_modified\":{d}}}", .{
        meta.size,
        meta.etag[0..meta.etag_len],
        meta.last_modified,
    }) catch return common.internalError();

    const owned = alloc.dupe(u8, json) catch return common.internalError();
    return .{ .status = .ok, .body = owned, .allocated = true };
}

fn etagJsonResponse(alloc: std.mem.Allocator, etag: []const u8) Response {
    var etag_buf: [64]u8 = undefined;
    const etag_json = std.fmt.bufPrint(&etag_buf, "{{\"ETag\":\"\\\"{s}\\\"\"}}", .{etag}) catch
        return .{ .status = .ok, .body = "{}", .allocated = false };

    const owned = alloc.dupe(u8, etag_json) catch return common.internalError();
    return .{ .status = .ok, .body = owned, .allocated = true };
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
