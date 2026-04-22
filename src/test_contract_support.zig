const std = @import("std");
const platform = @import("platform");
const paths = @import("lib/paths.zig");

pub var contract_lock: platform.Mutex = .{};

pub fn cleanupS3TestState() !void {
    var path_buf: [paths.max_path]u8 = undefined;
    const object_root = try paths.dataPath(&path_buf, "s3");
    platform.cwd().deleteTree(object_root) catch {};

    const multipart_root = try paths.dataPath(&path_buf, "s3-multipart");
    platform.cwd().deleteTree(multipart_root) catch {};
}

pub const test_api_token =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
