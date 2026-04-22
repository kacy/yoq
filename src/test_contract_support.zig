const std = @import("std");
const paths = @import("lib/paths.zig");

pub var contract_lock: @import("compat").Mutex = .{};

pub fn cleanupS3TestState() !void {
    var path_buf: [paths.max_path]u8 = undefined;
    const object_root = try paths.dataPath(&path_buf, "s3");
    @import("compat").cwd().deleteTree(object_root) catch {};

    const multipart_root = try paths.dataPath(&path_buf, "s3-multipart");
    @import("compat").cwd().deleteTree(multipart_root) catch {};
}

pub const test_api_token =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
