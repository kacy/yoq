const std = @import("std");
const platform = @import("platform");
const http = @import("api/http.zig");
const common = @import("api/routes/common.zig");
const s3_gateway = @import("api/routes/s3_gateway.zig");
const paths = @import("lib/paths.zig");
const s3 = @import("storage/s3.zig");
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

fn expectMissingPath(path: []const u8) !void {
    std.Io.Dir.cwd().access(std.Options.debug_io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.PathShouldBeMissing;
}

test "contract: s3 route writes durable object bytes to storage" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    try support.cleanupS3TestState();
    defer support.cleanupS3TestState() catch {};

    freeResponse(try routeRequest(.PUT, "/s3/restart-bucket", ""));

    const put = try routeRequest(.PUT, "/s3/restart-bucket/config.json", "{\"version\":1}");
    defer freeResponse(put);
    try std.testing.expectEqual(http.StatusCode.ok, put.status);

    const stored = try s3.getObject(std.testing.allocator, "restart-bucket", "config.json");
    defer std.testing.allocator.free(stored);
    try std.testing.expectEqualStrings("{\"version\":1}", stored);

    var object_path_buf: [paths.max_path]u8 = undefined;
    const object_path = try paths.dataPathFmt(&object_path_buf, "s3/{s}/{s}", .{ "restart-bucket", "config.json" });
    const raw = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, object_path, std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(raw);
    try std.testing.expectEqualStrings("{\"version\":1}", raw);
}

test "contract: multipart staging persists on disk until completion and then cleans up" {
    support.contract_lock.lock();
    defer support.contract_lock.unlock();

    try support.cleanupS3TestState();
    defer support.cleanupS3TestState() catch {};

    freeResponse(try routeRequest(.PUT, "/s3/restart-multipart", ""));

    const init = try routeRequest(.POST, "/s3/restart-multipart/blob.bin?uploads", "");
    defer freeResponse(init);
    try std.testing.expectEqual(http.StatusCode.ok, init.status);
    const upload_id = try expectXmlTag(init.body, "UploadId");

    var part1_path_buf: [160]u8 = undefined;
    const part1_path = try std.fmt.bufPrint(
        &part1_path_buf,
        "/s3/restart-multipart/blob.bin?partNumber=1&uploadId={s}",
        .{upload_id},
    );
    freeResponse(try routeRequest(.PUT, part1_path, "hello "));

    var staging_dir_buf: [paths.max_path]u8 = undefined;
    const staging_dir = try paths.dataPathFmt(&staging_dir_buf, "s3-multipart/{s}", .{upload_id});

    var meta_path_buf: [paths.max_path]u8 = undefined;
    const meta_path = try paths.dataPathFmt(&meta_path_buf, "s3-multipart/{s}/.upload-meta", .{upload_id});
    const meta = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, meta_path, std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(meta);
    try std.testing.expectEqualStrings("restart-multipart\nblob.bin", meta);

    var part1_file_buf: [paths.max_path]u8 = undefined;
    const part1_file = try paths.dataPathFmt(&part1_file_buf, "s3-multipart/{s}/00001", .{upload_id});
    const part1_data = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, part1_file, std.testing.allocator, .limited(1024));
    defer std.testing.allocator.free(part1_data);
    try std.testing.expectEqualStrings("hello ", part1_data);

    var part2_path_buf: [160]u8 = undefined;
    const part2_path = try std.fmt.bufPrint(
        &part2_path_buf,
        "/s3/restart-multipart/blob.bin?partNumber=2&uploadId={s}",
        .{upload_id},
    );
    freeResponse(try routeRequest(.PUT, part2_path, "world"));

    var complete_path_buf: [160]u8 = undefined;
    const complete_path = try std.fmt.bufPrint(
        &complete_path_buf,
        "/s3/restart-multipart/blob.bin?uploadId={s}",
        .{upload_id},
    );
    const complete = try routeRequest(.POST, complete_path, "");
    defer freeResponse(complete);
    try std.testing.expectEqual(http.StatusCode.ok, complete.status);

    const stored = try s3.getObject(std.testing.allocator, "restart-multipart", "blob.bin");
    defer std.testing.allocator.free(stored);
    try std.testing.expectEqualStrings("hello world", stored);

    try expectMissingPath(staging_dir);
}
