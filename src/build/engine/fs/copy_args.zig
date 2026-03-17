const std = @import("std");

const types = @import("../types.zig");

pub const ArchiveFormat = enum {
    tar,
    tar_gz,
    tar_xz,
    tar_bz2,
};

pub fn parseCopyArgs(args: []const u8) types.CopyArgs {
    var trimmed = std.mem.trim(u8, args, " \t");
    var from_stage: ?[]const u8 = null;

    if (std.mem.startsWith(u8, trimmed, "--from=")) {
        const rest = trimmed["--from=".len..];
        var end: usize = 0;
        while (end < rest.len and rest[end] != ' ' and rest[end] != '\t') end += 1;
        from_stage = rest[0..end];
        trimmed = if (end < rest.len)
            std.mem.trimLeft(u8, rest[end..], " \t")
        else
            "";
    }

    var i: usize = trimmed.len;
    while (i > 0) {
        i -= 1;
        if (trimmed[i] == ' ' or trimmed[i] == '\t') {
            return .{
                .src = std.mem.trim(u8, trimmed[0..i], " \t"),
                .dest = std.mem.trim(u8, trimmed[i + 1 ..], " \t"),
                .from_stage = from_stage,
            };
        }
    }

    return .{ .src = trimmed, .dest = trimmed, .from_stage = from_stage };
}

pub fn archiveFormat(path: []const u8) ?ArchiveFormat {
    if (std.mem.endsWith(u8, path, ".tar.gz") or std.mem.endsWith(u8, path, ".tgz")) return .tar_gz;
    if (std.mem.endsWith(u8, path, ".tar.xz")) return .tar_xz;
    if (std.mem.endsWith(u8, path, ".tar.bz2")) return .tar_bz2;
    if (std.mem.endsWith(u8, path, ".tar")) return .tar;
    return null;
}

pub fn isTarArchive(path: []const u8) bool {
    return archiveFormat(path) != null;
}
