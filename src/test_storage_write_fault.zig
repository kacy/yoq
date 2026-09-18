const std = @import("std");
const s3 = @import("storage/s3.zig");
const paths = @import("lib/paths.zig");

test "storage write fault preserves the previous object after a short write" {
    var limit: std.os.linux.rlimit = undefined;
    if (std.os.linux.errno(std.os.linux.getrlimit(.FSIZE, &limit)) != .SUCCESS or limit.cur != 8)
        return error.ExpectedEightByteFileLimit;
    const bucket = "short-write-regression";
    var path_buf: [paths.max_path]u8 = undefined;
    const path = try paths.dataPathFmt(&path_buf, "s3/{s}", .{bucket});
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, path) catch {};
    try s3.createBucket(bucket);
    _ = try s3.putObject(bucket, "object", "old");
    try std.testing.expectError(error.IoError, s3.putObject(bucket, "object", "0123456789abcdef"));
    const bytes = try s3.getObject(std.testing.allocator, bucket, "object");
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("old", bytes);
}
