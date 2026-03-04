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

// -- JSON field extraction --
// minimal JSON field extraction for known request shapes.
// avoids pulling in a full parser for simple key-value lookups.

/// extract a string value from a JSON object: {"key":"value"}
pub fn extractJsonString(json: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [128]u8 = undefined;
    const needle = std.fmt.bufPrint(&search_buf, "\"{s}\":\"", .{key}) catch return null;

    const start_pos = std.mem.indexOf(u8, json, needle) orelse return null;
    const value_start = start_pos + needle.len;

    // find closing quote, skipping escaped characters
    var pos = value_start;
    while (pos < json.len) : (pos += 1) {
        if (json[pos] == '\\') {
            pos += 1; // skip escaped character
            continue;
        }
        if (json[pos] == '"') break;
    } else return null;
    const value_end = pos;

    return json[value_start..value_end];
}

/// extract an integer value from a JSON object: {"key":123}
pub fn extractJsonInt(json: []const u8, key: []const u8) ?i64 {
    var search_buf: [128]u8 = undefined;
    const needle = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;

    const start_pos = std.mem.indexOf(u8, json, needle) orelse return null;
    const value_start = start_pos + needle.len;

    // skip whitespace
    var pos = value_start;
    while (pos < json.len and json[pos] == ' ') : (pos += 1) {}

    // find end of number
    var end = pos;
    while (end < json.len and (json[end] >= '0' and json[end] <= '9')) : (end += 1) {}

    if (end == pos) return null;
    return std.fmt.parseInt(i64, json[pos..end], 10) catch return null;
}

// -- JSON array iteration --
// iterate over top-level objects in a JSON array like [{...},{...}].
// returns slices into the original buffer — no allocation needed.

pub const JsonObjectIterator = struct {
    json: []const u8,
    pos: usize,

    /// return the next top-level {...} object as a slice.
    pub fn next(self: *JsonObjectIterator) ?[]const u8 {
        // find the next opening brace
        while (self.pos < self.json.len and self.json[self.pos] != '{') {
            self.pos += 1;
        }
        if (self.pos >= self.json.len) return null;

        const start = self.pos;
        var depth: usize = 0;
        var in_string = false;
        var escape = false;

        while (self.pos < self.json.len) {
            const c = self.json[self.pos];

            if (escape) {
                escape = false;
                self.pos += 1;
                continue;
            }

            if (c == '\\' and in_string) {
                escape = true;
                self.pos += 1;
                continue;
            }

            if (c == '"') {
                in_string = !in_string;
            } else if (!in_string) {
                if (c == '{') {
                    depth += 1;
                } else if (c == '}') {
                    depth -= 1;
                    if (depth == 0) {
                        self.pos += 1;
                        return self.json[start..self.pos];
                    }
                }
            }
            self.pos += 1;
        }

        return null; // unterminated object
    }
};

/// iterate over top-level JSON objects in an array string.
/// example: `[{"a":1},{"b":2}]` yields `{"a":1}` then `{"b":2}`.
pub fn extractJsonObjects(json: []const u8) JsonObjectIterator {
    return .{ .json = json, .pos = 0 };
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

test "extractJsonString basic" {
    const json = "{\"token\":\"my-secret\",\"address\":\"10.0.0.5:7701\"}";
    try std.testing.expectEqualStrings("my-secret", extractJsonString(json, "token").?);
    try std.testing.expectEqualStrings("10.0.0.5:7701", extractJsonString(json, "address").?);
    try std.testing.expect(extractJsonString(json, "missing") == null);
}

test "extractJsonString handles escaped quotes" {
    const json = "{\"name\":\"hello \\\"world\\\"\",\"other\":\"val\"}";
    const result = extractJsonString(json, "name").?;
    try std.testing.expectEqualStrings("hello \\\"world\\\"", result);
    try std.testing.expectEqualStrings("val", extractJsonString(json, "other").?);
}

test "extractJsonInt basic" {
    const json = "{\"cpu_cores\":4,\"memory_mb\":8192}";
    try std.testing.expectEqual(@as(i64, 4), extractJsonInt(json, "cpu_cores").?);
    try std.testing.expectEqual(@as(i64, 8192), extractJsonInt(json, "memory_mb").?);
    try std.testing.expect(extractJsonInt(json, "missing") == null);
}

test "extractJsonObjects empty array" {
    var iter = extractJsonObjects("[]");
    try std.testing.expect(iter.next() == null);
}

test "extractJsonObjects single object" {
    var iter = extractJsonObjects("[{\"id\":\"abc\"}]");
    const obj = iter.next().?;
    try std.testing.expectEqualStrings("{\"id\":\"abc\"}", obj);
    try std.testing.expect(iter.next() == null);
}

test "extractJsonObjects multiple objects" {
    var iter = extractJsonObjects("[{\"id\":\"a\"},{\"id\":\"b\"}]");
    const first = iter.next().?;
    try std.testing.expectEqualStrings("{\"id\":\"a\"}", first);
    const second = iter.next().?;
    try std.testing.expectEqualStrings("{\"id\":\"b\"}", second);
    try std.testing.expect(iter.next() == null);
}

test "extractJsonObjects handles nested braces" {
    var iter = extractJsonObjects("[{\"data\":{\"nested\":1}},{\"id\":\"b\"}]");
    const first = iter.next().?;
    try std.testing.expectEqualStrings("{\"data\":{\"nested\":1}}", first);
    const second = iter.next().?;
    try std.testing.expectEqualStrings("{\"id\":\"b\"}", second);
    try std.testing.expect(iter.next() == null);
}

test "extractJsonObjects handles braces in strings" {
    var iter = extractJsonObjects("[{\"cmd\":\"echo {hi}\"}]");
    const obj = iter.next().?;
    try std.testing.expectEqualStrings("{\"cmd\":\"echo {hi}\"}", obj);
    try std.testing.expect(iter.next() == null);
}

test "extractJsonObjects empty string" {
    var iter = extractJsonObjects("");
    try std.testing.expect(iter.next() == null);
}
