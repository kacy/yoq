const std = @import("std");
const linux = std.os.linux;

/// Numeric ownership, ordinary permissions, and the protective sticky bit. Privilege-granting bits
/// are intentionally excluded from both generated and extracted layers.
pub const Metadata = struct {
    uid: u32,
    gid: u32,
    mode: u32,
    mtime: u64 = 0,

    pub fn stat(dir: std.Io.Dir, path: []const u8) !Metadata {
        const name = try std.posix.toPosixPath(path);
        var result: linux.Statx = undefined;
        if (linux.errno(linux.statx(dir.handle, &name, linux.AT.SYMLINK_NOFOLLOW, .{ .UID = true, .GID = true, .MODE = true, .MTIME = true }, &result)) != .SUCCESS)
            return error.StatFailed;
        return .{ .uid = result.uid, .gid = result.gid, .mode = result.mode & 0o1777, .mtime = @intCast(@max(0, result.mtime.sec)) };
    }

    pub fn fromHeader(bytes: *const [512]u8, mode: u32) !Metadata {
        return .{
            .uid = try decodeId(bytes[108..116]),
            .gid = try decodeId(bytes[116..124]),
            .mode = mode & 0o1777,
        };
    }

    pub fn apply(self: Metadata, file: std.Io.File, ownership: bool) !void {
        if (ownership) try file.setOwner(std.Options.debug_io, self.uid, self.gid);
        try file.setPermissions(std.Options.debug_io, .fromMode(self.mode));
    }
};

pub fn encodeId(field: *[8]u8, value: u32) void {
    @memset(field, 0);
    // GNU base-256 encoding accommodates the full Linux UID/GID range.
    field[0] = 0x80;
    std.mem.writeInt(u32, field[4..8], value, .big);
}

fn decodeId(field: *const [8]u8) !u32 {
    if (field[0] & 0x80 != 0) {
        if (field[0] != 0x80 or field[1] != 0 or field[2] != 0 or field[3] != 0) return error.InvalidOwner;
        const value = std.mem.readInt(u32, field[4..8], .big);
        if (value == std.math.maxInt(u32)) return error.InvalidOwner;
        return value;
    }
    const digits = std.mem.trim(u8, field, " \x00");
    if (digits.len == 0) return 0;
    const value = std.fmt.parseInt(u32, digits, 8) catch return error.InvalidOwner;
    if (value == std.math.maxInt(u32)) return error.InvalidOwner;
    return value;
}

test "layer metadata numeric owners support octal and full Linux IDs" {
    try std.testing.expectEqual(@as(u32, 1000), try decodeId("0001750\x00"));
    var encoded: [8]u8 = undefined;
    encodeId(&encoded, 4000000000);
    try std.testing.expectEqual(@as(u32, 4000000000), try decodeId(&encoded));
    encodeId(&encoded, std.math.maxInt(u32));
    try std.testing.expectError(error.InvalidOwner, decodeId(&encoded));
}
