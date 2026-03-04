// sql — SQL string escaping utilities
//
// provides escapeSqlString for safely encoding user-controlled values
// in dynamically-generated SQL strings. used by cluster modules that
// generate SQL for raft proposal (where parameterized queries aren't
// possible because raft entries are opaque bytes).
//
// defense-in-depth: API routes also validate inputs at the boundary,
// but we escape here too in case validation is bypassed or relaxed.

const std = @import("std");

/// escape a string for safe inclusion in a SQL string literal.
/// replaces single quotes with two single quotes (SQL standard).
/// returns a slice of buf containing the escaped string.
pub fn escapeSqlString(buf: []u8, input: []const u8) ![]const u8 {
    var pos: usize = 0;
    for (input) |c| {
        if (c == '\'') {
            if (pos + 2 > buf.len) return error.NoSpaceLeft;
            buf[pos] = '\'';
            buf[pos + 1] = '\'';
            pos += 2;
        } else {
            if (pos + 1 > buf.len) return error.NoSpaceLeft;
            buf[pos] = c;
            pos += 1;
        }
    }
    return buf[0..pos];
}

// -- tests --

test "basic string passes through" {
    var buf: [64]u8 = undefined;
    const result = try escapeSqlString(&buf, "hello world");
    try std.testing.expectEqualStrings("hello world", result);
}

test "single quote is doubled" {
    var buf: [64]u8 = undefined;
    const result = try escapeSqlString(&buf, "it's a test");
    try std.testing.expectEqualStrings("it''s a test", result);
}

test "multiple quotes are all doubled" {
    var buf: [64]u8 = undefined;
    const result = try escapeSqlString(&buf, "a'b'c");
    try std.testing.expectEqualStrings("a''b''c", result);
}

test "empty string" {
    var buf: [64]u8 = undefined;
    const result = try escapeSqlString(&buf, "");
    try std.testing.expectEqualStrings("", result);
}

test "buffer too small returns error" {
    var buf: [3]u8 = undefined;
    const result = escapeSqlString(&buf, "it's");
    try std.testing.expectError(error.NoSpaceLeft, result);
}
