//! Names that end up as host path components: app, workload and volume
//! names. They come from api callers, so they must never carry a "/", a
//! "..", or anything else that changes where a path points.
const std = @import("std");

pub const max_len = 128;

/// An ascii letter or digit, then letters, digits, ".", "_" or "-", up to
/// max_len bytes. "." and ".." never pass because the first byte must be
/// alphanumeric.
pub fn isValid(name: []const u8) bool {
    if (name.len == 0 or name.len > max_len or !std.ascii.isAlphanumeric(name[0])) return false;
    for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.') return false;
    return true;
}

test "isValid accepts ordinary names and refuses anything path-like" {
    for ([_][]const u8{ "data-1", "pg.v2", "web_api", "A", "a" ** max_len }) |name|
        try std.testing.expect(isValid(name));
    for ([_][]const u8{ "", ".", "..", "../etc", "a/b", "-x", ".hidden", "a\x00b", "a b", "a\\b", "a" ** (max_len + 1) }) |name|
        try std.testing.expect(!isValid(name));
}
