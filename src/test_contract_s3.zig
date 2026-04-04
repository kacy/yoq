const std = @import("std");
const http = @import("api/http.zig");
const common = @import("api/routes/common.zig");
const s3_gateway = @import("api/routes/s3_gateway.zig");
const support = @import("test_contract_support.zig");

fn splitPath(path: []const u8) struct { path_only: []const u8, query: []const u8 } {
    const query_start = std.mem.indexOfScalar(u8, path, '?');
    return .{
        .path_only = if (query_start) |idx| path[0..idx] else path,
        .query = if (query_start) |idx| path[idx + 1 ..] else "",
    };
}

fn makeRequest(method: http.Method, path: []const u8, body: []const u8) http.Request {
    const parts = splitPath(path);
    return .{
        .method = method,
        .path = path,
        .path_only = parts.path_only,
        .query = parts.query,
        .headers_raw = "",
        .body = body,
        .content_length = body.len,
    };
}

fn routeRequest(method: http.Method, path: []const u8, body: []const u8) !common.Response {
    const req = makeRequest(method, path, body);
    const result = s3_gateway.route(req, std.testing.allocator);
    try std.testing.expect(result != null);
    return result.?;
}

fn freeResponse(resp: common.Response) void {
    if (resp.allocated) std.testing.allocator.free(resp.body);
}

fn expectXmlTag(body: []const u8, tag: []const u8) ![]const u8 {
    var open_buf: [64]u8 = undefined;
    var close_buf: [64]u8 = undefined;
    const open = try std.fmt.bufPrint(&open_buf, "<{s}>", .{tag});
    const close = try std.fmt.bufPrint(&close_buf, "</{s}>", .{tag});

    const start = std.mem.indexOf(u8, body, open) orelse return error.MissingTag;
    const value_start = start + open.len;
    const end = std.mem.indexOfPos(u8, body, value_start, close) orelse return error.MissingTag;
    return body[value_start..end];
}

test "contract: s3 bucket lifecycle returns exact codes and xml" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    try support.cleanupS3TestState();
    defer support.cleanupS3TestState() catch {};

    const create = try routeRequest(.PUT, "/s3/contract-bucket", "");
    defer freeResponse(create);
    try std.testing.expectEqual(http.StatusCode.ok, create.status);
    try std.testing.expectEqualStrings("", create.body);
    try std.testing.expect(create.content_type == null);

    const list = try routeRequest(.GET, "/s3/", "");
    defer freeResponse(list);
    try std.testing.expectEqual(http.StatusCode.ok, list.status);
    try std.testing.expectEqualStrings("application/xml", list.content_type.?);
    try std.testing.expect(std.mem.indexOf(u8, list.body, "<ListAllMyBucketsResult") != null);
    try std.testing.expect(std.mem.indexOf(u8, list.body, "<Name>contract-bucket</Name>") != null);

    const delete = try routeRequest(.DELETE, "/s3/contract-bucket", "");
    defer freeResponse(delete);
    try std.testing.expectEqual(http.StatusCode.no_content, delete.status);
    try std.testing.expectEqualStrings("", delete.body);
}

test "contract: s3 object lifecycle preserves bytes and metadata" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    try support.cleanupS3TestState();
    defer support.cleanupS3TestState() catch {};

    freeResponse(try routeRequest(.PUT, "/s3/object-bucket", ""));

    const object_body = "hello\x00world";
    const put = try routeRequest(.PUT, "/s3/object-bucket/nested/blob.bin", object_body);
    defer freeResponse(put);
    try std.testing.expectEqual(http.StatusCode.ok, put.status);
    try std.testing.expect(put.content_type == null);
    try std.testing.expect(std.mem.indexOf(u8, put.body, "\"ETag\":\"") != null);

    const get = try routeRequest(.GET, "/s3/object-bucket/nested/blob.bin", "");
    defer freeResponse(get);
    try std.testing.expectEqual(http.StatusCode.ok, get.status);
    try std.testing.expectEqualStrings("application/octet-stream", get.content_type.?);
    try std.testing.expectEqualSlices(u8, object_body, get.body);

    const head = try routeRequest(.HEAD, "/s3/object-bucket/nested/blob.bin", "");
    defer freeResponse(head);
    try std.testing.expectEqual(http.StatusCode.ok, head.status);
    try std.testing.expect(std.mem.indexOf(u8, head.body, "\"content_length\":11") != null);
    try std.testing.expect(std.mem.indexOf(u8, head.body, "\"etag\":\"") != null);

    const delete = try routeRequest(.DELETE, "/s3/object-bucket/nested/blob.bin", "");
    defer freeResponse(delete);
    try std.testing.expectEqual(http.StatusCode.no_content, delete.status);

    const missing = try routeRequest(.GET, "/s3/object-bucket/nested/blob.bin", "");
    defer freeResponse(missing);
    try std.testing.expectEqual(http.StatusCode.not_found, missing.status);
    try std.testing.expectEqualStrings("application/xml", missing.content_type.?);
    try std.testing.expect(std.mem.indexOf(u8, missing.body, "<Code>NoSuchKey</Code>") != null);
}

test "contract: s3 multipart completion assembles the final object" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    try support.cleanupS3TestState();
    defer support.cleanupS3TestState() catch {};

    freeResponse(try routeRequest(.PUT, "/s3/multipart-bucket", ""));

    const init = try routeRequest(.POST, "/s3/multipart-bucket/video.bin?uploads", "");
    defer freeResponse(init);
    try std.testing.expectEqual(http.StatusCode.ok, init.status);
    try std.testing.expectEqualStrings("application/xml", init.content_type.?);
    const upload_id = try expectXmlTag(init.body, "UploadId");
    try std.testing.expectEqual(@as(usize, 24), upload_id.len);

    var part1_path_buf: [128]u8 = undefined;
    const part1_path = try std.fmt.bufPrint(&part1_path_buf, "/s3/multipart-bucket/video.bin?partNumber=1&uploadId={s}", .{upload_id});
    const part1 = try routeRequest(.PUT, part1_path, "hello ");
    defer freeResponse(part1);
    try std.testing.expectEqual(http.StatusCode.ok, part1.status);

    var part2_path_buf: [128]u8 = undefined;
    const part2_path = try std.fmt.bufPrint(&part2_path_buf, "/s3/multipart-bucket/video.bin?partNumber=2&uploadId={s}", .{upload_id});
    const part2 = try routeRequest(.PUT, part2_path, "world");
    defer freeResponse(part2);
    try std.testing.expectEqual(http.StatusCode.ok, part2.status);

    var complete_path_buf: [128]u8 = undefined;
    const complete_path = try std.fmt.bufPrint(&complete_path_buf, "/s3/multipart-bucket/video.bin?uploadId={s}", .{upload_id});
    const complete = try routeRequest(.POST, complete_path, "");
    defer freeResponse(complete);
    try std.testing.expectEqual(http.StatusCode.ok, complete.status);
    try std.testing.expectEqualStrings("application/xml", complete.content_type.?);
    try std.testing.expect(std.mem.indexOf(u8, complete.body, "<CompleteMultipartUploadResult xmlns=") != null);

    const get = try routeRequest(.GET, "/s3/multipart-bucket/video.bin", "");
    defer freeResponse(get);
    try std.testing.expectEqualSlices(u8, "hello world", get.body);
}

test "contract: s3 multipart abort invalidates the upload id" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    try support.cleanupS3TestState();
    defer support.cleanupS3TestState() catch {};

    freeResponse(try routeRequest(.PUT, "/s3/multipart-bucket", ""));

    const abort_init = try routeRequest(.POST, "/s3/multipart-bucket/aborted.bin?uploads", "");
    defer freeResponse(abort_init);
    const aborted_upload_id = try expectXmlTag(abort_init.body, "UploadId");

    var abort_path_buf: [128]u8 = undefined;
    const abort_path = try std.fmt.bufPrint(&abort_path_buf, "/s3/multipart-bucket/aborted.bin?uploadId={s}", .{aborted_upload_id});
    const abort = try routeRequest(.DELETE, abort_path, "");
    defer freeResponse(abort);
    try std.testing.expectEqual(http.StatusCode.no_content, abort.status);

    var complete_aborted_path_buf: [128]u8 = undefined;
    const complete_aborted_path = try std.fmt.bufPrint(&complete_aborted_path_buf, "/s3/multipart-bucket/aborted.bin?uploadId={s}", .{aborted_upload_id});
    const complete_aborted = try routeRequest(.POST, complete_aborted_path, "");
    defer freeResponse(complete_aborted);
    try std.testing.expectEqual(http.StatusCode.not_found, complete_aborted.status);
    try std.testing.expectEqualStrings("application/xml", complete_aborted.content_type.?);
    try std.testing.expect(std.mem.indexOf(u8, complete_aborted.body, "<Code>NoSuchUpload</Code>") != null);
}

test "contract: s3 invalid bucket and key return exact client errors" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    try support.cleanupS3TestState();
    defer support.cleanupS3TestState() catch {};

    const invalid_bucket = try routeRequest(.PUT, "/s3/_bad", "");
    defer freeResponse(invalid_bucket);
    try std.testing.expectEqual(http.StatusCode.bad_request, invalid_bucket.status);
    try std.testing.expectEqualStrings("application/xml", invalid_bucket.content_type.?);
    try std.testing.expect(std.mem.indexOf(u8, invalid_bucket.body, "<Code>InvalidBucketName</Code>") != null);

    freeResponse(try routeRequest(.PUT, "/s3/good-bucket", ""));

    const invalid_key = try routeRequest(.PUT, "/s3/good-bucket/dir/../escape", "bad");
    defer freeResponse(invalid_key);
    try std.testing.expectEqual(http.StatusCode.bad_request, invalid_key.status);
    try std.testing.expectEqualStrings("application/xml", invalid_key.content_type.?);
    try std.testing.expect(std.mem.indexOf(u8, invalid_key.body, "<Code>InvalidKey</Code>") != null);
}
