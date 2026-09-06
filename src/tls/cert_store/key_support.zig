const master_key = @import("../../lib/master_key.zig");

pub const KeyError = master_key.KeyError;
pub const loadOrCreateKey = master_key.loadOrCreateKey;
pub const readKeyFile = master_key.readKeyFile;
pub const secureZero = master_key.secureZero;

test "shared key readers enforce the same owner-only permission policy" {
    const std = @import("std");
    const secrets = @import("../../state/secrets/key_support.zig");
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var file = try tmp.dir.createFile(io, "key", .{ .permissions = .fromMode(0o600) });
    defer file.close(io);
    const expected = [_]u8{0xa5} ** master_key.key_length;
    try file.writeStreamingAll(io, &expected);
    var base_buf: [std.fs.max_path_bytes]u8 = undefined;
    const base_len = try tmp.dir.realPath(io, &base_buf);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "{s}/key", .{base_buf[0..base_len]});
    inline for (.{ readKeyFile, secrets.readKeyFile }) |read| {
        // Set permissions explicitly so a restrictive test runner umask
        // cannot accidentally turn an insecure fixture into a secure one.
        for ([_]u32{ 0o600, 0o400 }) |mode| {
            try file.setPermissions(io, .fromMode(mode));
            var key = try read(path);
            defer secureZero(&key);
            try std.testing.expectEqualSlices(u8, &expected, &key);
        }
        for ([_]u32{ 0o644, 0o660, 0o601 }) |mode| {
            try file.setPermissions(io, .fromMode(mode));
            try std.testing.expectError(error.KeyLoadFailed, read(path));
        }
    }
    try file.setPermissions(io, .fromMode(0o600));
    try tmp.dir.symLink(io, "key", "link", .{});
    const link = try std.fmt.bufPrint(&path_buf, "{s}/link", .{base_buf[0..base_len]});
    inline for (.{ readKeyFile, secrets.readKeyFile }) |read| {
        try std.testing.expectError(error.KeyLoadFailed, read(link));
    }
}
