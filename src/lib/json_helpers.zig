// json_helpers — shared JSON encoding utilities
//
// provides writeJsonEscaped for safely encoding strings in
// manually-built JSON output.

const std = @import("std");

/// write a string with JSON escaping (backslash, quotes, control chars).
/// handles all control characters below 0x20 with \u00XX encoding.
pub fn writeJsonEscaped(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    // other control characters — use \u00XX
                    try std.fmt.format(writer, "\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

// -- tests --

test "basic escaping" {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    try writeJsonEscaped(writer, "hello \"world\"");
    try std.testing.expectEqualStrings("hello \\\"world\\\"", stream.getWritten());
}

test "backslash and special chars" {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    try writeJsonEscaped(writer, "path\\to\nnew\tline");
    try std.testing.expectEqualStrings("path\\\\to\\nnew\\tline", stream.getWritten());
}

test "control characters use unicode escape" {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    // 0x01 (SOH) should become \u0001
    try writeJsonEscaped(writer, &[_]u8{0x01});
    try std.testing.expectEqualStrings("\\u0001", stream.getWritten());
}

test "plain ascii passthrough" {
    var buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    try writeJsonEscaped(writer, "abc123");
    try std.testing.expectEqualStrings("abc123", stream.getWritten());
}
