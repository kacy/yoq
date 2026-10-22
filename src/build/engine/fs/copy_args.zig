const std = @import("std");

const types = @import("../types.zig");

pub const ArchiveFormat = enum {
    tar,
    tar_gz,
    tar_xz,
    tar_bz2,
};

pub const ParseError = error{
    /// fewer than one source and a destination, or a malformed JSON form
    InvalidCopyArgs,
    /// several sources need a directory destination ending in "/" or "."
    DestinationNotDirectory,
    /// --chown, --chmod and anything else yoq does not implement yet
    UnsupportedCopyFlag,
    TooManySources,
};

/// parse the arguments of COPY or ADD:
///
///   [--from=<stage>] [--link] <src>... <dest>
///   [--from=<stage>] [--link] ["<src>", ..., "<dest>"]
///
/// options may come in any order before the paths. --link is accepted and
/// ignored, since every COPY already produces its own layer. the returned
/// slices point into `args`.
pub fn parseCopyArgs(args: []const u8) ParseError!types.CopyArgs {
    var rest = std.mem.trim(u8, args, " \t");
    var result: types.CopyArgs = .{ .dest = "" };

    while (std.mem.startsWith(u8, rest, "--")) {
        const end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
        const flag = rest[0..end];
        rest = std.mem.trimStart(u8, rest[end..], " \t");
        if (std.mem.startsWith(u8, flag, "--from=") and flag.len > "--from=".len) {
            result.from_stage = flag["--from=".len..];
        } else if (!std.mem.eql(u8, flag, "--link")) {
            return error.UnsupportedCopyFlag;
        }
    }

    var paths: [types.max_copy_sources + 1][]const u8 = undefined;
    const count = if (std.mem.startsWith(u8, rest, "["))
        try splitJsonArray(rest, &paths)
    else
        try splitWords(rest, &paths);
    if (count < 2) return error.InvalidCopyArgs;

    result.dest = paths[count - 1];
    result.source_count = count - 1;
    @memcpy(result.sources_buf[0..result.source_count], paths[0..result.source_count]);
    if (result.source_count > 1 and !std.mem.endsWith(u8, result.dest, "/") and
        !std.mem.eql(u8, std.fs.path.basename(result.dest), "."))
        return error.DestinationNotDirectory;
    return result;
}

fn splitWords(text: []const u8, out: [][]const u8) ParseError!usize {
    var count: usize = 0;
    var words = std.mem.tokenizeAny(u8, text, " \t");
    while (words.next()) |word| {
        if (count == out.len) return error.TooManySources;
        out[count] = word;
        count += 1;
    }
    return count;
}

/// the exec form, `["a", "b", "/dest/"]`. escapes are rare in paths and are
/// rejected rather than decoded, so every result stays a slice of the input.
fn splitJsonArray(text: []const u8, out: [][]const u8) ParseError!usize {
    if (!std.mem.endsWith(u8, text, "]")) return error.InvalidCopyArgs;
    var rest = std.mem.trim(u8, text[1 .. text.len - 1], " \t");
    var count: usize = 0;
    while (rest.len > 0) {
        if (rest[0] != '"') return error.InvalidCopyArgs;
        const close = std.mem.indexOfScalarPos(u8, rest, 1, '"') orelse return error.InvalidCopyArgs;
        const value = rest[1..close];
        if (std.mem.indexOfScalar(u8, value, '\\') != null) return error.InvalidCopyArgs;
        if (count == out.len) return error.TooManySources;
        out[count] = value;
        count += 1;
        rest = std.mem.trimStart(u8, rest[close + 1 ..], " \t");
        if (rest.len == 0) break;
        if (rest[0] != ',') return error.InvalidCopyArgs;
        rest = std.mem.trimStart(u8, rest[1..], " \t");
        if (rest.len == 0) return error.InvalidCopyArgs;
    }
    return count;
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
