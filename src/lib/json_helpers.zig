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
                    try @import("compat").format(writer, "\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

/// write a single JSON string field without a leading comma.
pub fn writeJsonStringField(writer: anytype, key: []const u8, value: []const u8) !void {
    try writer.writeByte('"');
    try writer.writeAll(key);
    try writer.writeAll("\":\"");
    try writeJsonEscaped(writer, value);
    try writer.writeByte('"');
}

/// write a single JSON string-or-null field without a leading comma.
pub fn writeNullableJsonStringField(writer: anytype, key: []const u8, value: ?[]const u8) !void {
    try writer.writeByte('"');
    try writer.writeAll(key);
    if (value) |text| {
        try writer.writeAll("\":\"");
        try writeJsonEscaped(writer, text);
        try writer.writeByte('"');
    } else {
        try writer.writeAll("\":null");
    }
}

pub fn writeNullableJsonRawField(writer: anytype, key: []const u8, value: ?[]const u8) !void {
    try writer.writeByte('"');
    try writer.writeAll(key);
    if (value) |raw| {
        try writer.writeAll("\":");
        try writer.writeAll(raw);
    } else {
        try writer.writeAll("\":null");
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
            if (pos >= json.len) return null; // Escape at end of string
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

    // check for optional leading minus sign
    var end = pos;
    if (end < json.len and json[end] == '-') end += 1;

    // find end of number
    while (end < json.len and (json[end] >= '0' and json[end] <= '9')) : (end += 1) {}

    if (end == pos) return null;
    return std.fmt.parseInt(i64, json[pos..end], 10) catch return null;
}

/// extract a float value from a JSON object: {"key":12.3}
pub fn extractJsonFloat(json: []const u8, key: []const u8) ?f64 {
    var search_buf: [128]u8 = undefined;
    const needle = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;

    const start_pos = std.mem.indexOf(u8, json, needle) orelse return null;
    const value_start = start_pos + needle.len;

    // skip whitespace
    var pos = value_start;
    while (pos < json.len and json[pos] == ' ') : (pos += 1) {}

    // find end of number (next , or })
    var end = pos;
    while (end < json.len) : (end += 1) {
        if (json[end] == ',' or json[end] == '}') break;
    }

    if (end == pos) return null;
    return std.fmt.parseFloat(f64, json[pos..end]) catch null;
}

/// extract a boolean value from a JSON object: {"key":true}
pub fn extractJsonBool(json: []const u8, key: []const u8) ?bool {
    var search_buf: [128]u8 = undefined;
    const needle = std.fmt.bufPrint(&search_buf, "\"{s}\":", .{key}) catch return null;

    const start_pos = std.mem.indexOf(u8, json, needle) orelse return null;
    var pos = start_pos + needle.len;
    while (pos < json.len and json[pos] == ' ') : (pos += 1) {}

    if (std.mem.startsWith(u8, json[pos..], "true")) return true;
    if (std.mem.startsWith(u8, json[pos..], "false")) return false;
    return null;
}

/// extract a top-level array value from a JSON object: {"key":[...]}
pub fn extractJsonArray(json: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [128]u8 = undefined;
    const needle = std.fmt.bufPrint(&search_buf, "\"{s}\":[", .{key}) catch return null;
    const start_pos = std.mem.indexOf(u8, json, needle) orelse return null;

    const array_start = start_pos + needle.len - 1;
    var pos = array_start;
    var depth: usize = 0;
    var in_string = false;
    var escape = false;

    while (pos < json.len) : (pos += 1) {
        const c = json[pos];

        if (escape) {
            escape = false;
            continue;
        }

        if (c == '\\' and in_string) {
            escape = true;
            continue;
        }

        if (c == '"') {
            in_string = !in_string;
            continue;
        }

        if (in_string) continue;

        if (c == '[') {
            depth += 1;
        } else if (c == ']') {
            depth -= 1;
            if (depth == 0) return json[array_start .. pos + 1];
        }
    }

    return null;
}

/// extract a top-level object value from a JSON object: {"key":{...}}
pub fn extractJsonObject(json: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [128]u8 = undefined;
    const needle = std.fmt.bufPrint(&search_buf, "\"{s}\":{{", .{key}) catch return null;
    const start_pos = std.mem.indexOf(u8, json, needle) orelse return null;

    const object_start = start_pos + needle.len - 1;
    var pos = object_start;
    var depth: usize = 0;
    var in_string = false;
    var escape = false;

    while (pos < json.len) : (pos += 1) {
        const c = json[pos];

        if (escape) {
            escape = false;
            continue;
        }

        if (c == '\\' and in_string) {
            escape = true;
            continue;
        }

        if (c == '"') {
            in_string = !in_string;
            continue;
        }

        if (in_string) continue;

        if (c == '{') {
            depth += 1;
        } else if (c == '}') {
            depth -= 1;
            if (depth == 0) return json[object_start .. pos + 1];
        }
    }

    return null;
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

pub fn summarizeFailureDetails(buf: []u8, failure_details_json: ?[]const u8) ?[]const u8 {
    const details = failure_details_json orelse return null;

    var written: usize = 0;
    var count: usize = 0;
    var iter = extractJsonObjects(details);
    while (iter.next()) |obj| {
        const workload_name = extractJsonString(obj, "workload_name") orelse continue;
        const reason = extractJsonString(obj, "reason") orelse continue;

        if (count < 2) {
            const prefix = if (count == 0) "" else "; ";
            const piece = std.fmt.bufPrint(buf[written..], "{s}{s}: {s}", .{
                prefix,
                workload_name,
                reason,
            }) catch break;
            written += piece.len;
        }
        count += 1;
    }

    if (count == 0) return null;
    if (count > 2) {
        const suffix = std.fmt.bufPrint(buf[written..], "; +{d} more", .{count - 2}) catch return buf[0..written];
        written += suffix.len;
    }
    return buf[0..written];
}

// -- tests --

test "basic escaping" {
    var buf: [256]u8 = undefined;
    var stream = @import("compat").fixedBufferStream(&buf);
    const writer = stream.writer();

    try writeJsonEscaped(writer, "hello \"world\"");
    try std.testing.expectEqualStrings("hello \\\"world\\\"", stream.getWritten());
}

test "backslash and special chars" {
    var buf: [256]u8 = undefined;
    var stream = @import("compat").fixedBufferStream(&buf);
    const writer = stream.writer();

    try writeJsonEscaped(writer, "path\\to\nnew\tline");
    try std.testing.expectEqualStrings("path\\\\to\\nnew\\tline", stream.getWritten());
}

test "control characters use unicode escape" {
    var buf: [256]u8 = undefined;
    var stream = @import("compat").fixedBufferStream(&buf);
    const writer = stream.writer();

    // 0x01 (SOH) should become \u0001
    try writeJsonEscaped(writer, &[_]u8{0x01});
    try std.testing.expectEqualStrings("\\u0001", stream.getWritten());
}

test "plain ascii passthrough" {
    var buf: [256]u8 = undefined;
    var stream = @import("compat").fixedBufferStream(&buf);
    const writer = stream.writer();

    try writeJsonEscaped(writer, "abc123");
    try std.testing.expectEqualStrings("abc123", stream.getWritten());
}

test "writeJsonStringField emits quoted field" {
    var buf: [256]u8 = undefined;
    var stream = @import("compat").fixedBufferStream(&buf);
    const writer = stream.writer();

    try writeJsonStringField(writer, "app_name", "demo-app");
    try std.testing.expectEqualStrings("\"app_name\":\"demo-app\"", stream.getWritten());
}

test "writeNullableJsonStringField emits null field" {
    var buf: [256]u8 = undefined;
    var stream = @import("compat").fixedBufferStream(&buf);
    const writer = stream.writer();

    try writeNullableJsonStringField(writer, "source_release_id", null);
    try std.testing.expectEqualStrings("\"source_release_id\":null", stream.getWritten());
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

test "summarizeFailureDetails condenses workload reasons" {
    var buf: [256]u8 = undefined;
    const summary = summarizeFailureDetails(&buf,
        \\[
        \\  {"workload_kind":"service","workload_name":"web","reason":"readiness_timeout"},
        \\  {"workload_kind":"service","workload_name":"db","reason":"placement_failed"},
        \\  {"workload_kind":"service","workload_name":"api","reason":"readiness_failed"}
        \\]
    ).?;

    try std.testing.expectEqualStrings("web: readiness_timeout; db: placement_failed; +1 more", summary);
}

test "extractJsonArray basic" {
    const json = "{\"services\":[{\"id\":\"a\"}],\"count\":1}";
    const array = extractJsonArray(json, "services").?;
    try std.testing.expectEqualStrings("[{\"id\":\"a\"}]", array);
}

test "extractJsonArray handles nested arrays and strings" {
    const json = "{\"services\":[{\"cmd\":\"echo [ok]\",\"ports\":[80,443]}]}";
    const array = extractJsonArray(json, "services").?;
    try std.testing.expectEqualStrings("[{\"cmd\":\"echo [ok]\",\"ports\":[80,443]}]", array);
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

test "writeJsonEscaped null byte" {
    var buf: [256]u8 = undefined;
    var stream = @import("compat").fixedBufferStream(&buf);
    const writer = stream.writer();

    try writeJsonEscaped(writer, &[_]u8{0x00});
    try std.testing.expectEqualStrings("\\u0000", stream.getWritten());
}

test "extractJsonInt with whitespace after colon" {
    const json = "{\"key\": 42}";
    try std.testing.expectEqual(@as(i64, 42), extractJsonInt(json, "key").?);
}

test "extractJsonInt returns null for non-numeric" {
    const json = "{\"key\":\"abc\"}";
    try std.testing.expect(extractJsonInt(json, "key") == null);
}

test "extractJsonInt returns null for missing key" {
    const json = "{\"other\":99}";
    try std.testing.expect(extractJsonInt(json, "missing") == null);
}

test "extractJsonString returns null for missing key" {
    const json = "{\"name\":\"alice\"}";
    try std.testing.expect(extractJsonString(json, "missing") == null);
}

test "extractJsonFloat basic" {
    const json = "{\"cpu_pct\":12.3,\"other\":99}";
    try std.testing.expectApproxEqAbs(@as(f64, 12.3), extractJsonFloat(json, "cpu_pct").?, 0.001);
    try std.testing.expect(extractJsonFloat(json, "missing") == null);
}

test "extractJsonFloat zero" {
    const json = "{\"value\":0.0}";
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), extractJsonFloat(json, "value").?, 0.001);
}

test "extractJsonString handles escape at end" {
    // Test that a string ending with an escape sequence is handled safely
    // Previously this could cause out-of-bounds read
    // Create JSON with backslash as last char before closing quote
    var json_buf: [32]u8 = undefined;
    const json = std.fmt.bufPrint(&json_buf, "{{\"key\":\"value{c}\"}}", .{'\\'}) catch unreachable;
    const result = extractJsonString(json, "key");
    // Should return null for malformed JSON (unterminated string due to escape)
    try std.testing.expect(result == null);
}

test "extractJsonString handles normal escapes" {
    const json = "{\"key\":\"hello\\nworld\"}";
    const result = extractJsonString(json, "key");
    try std.testing.expectEqualStrings("hello\\nworld", result.?);
}

test "extractJsonInt negative number" {
    const json = "{\"val\":-42}";
    try std.testing.expectEqual(@as(i64, -42), extractJsonInt(json, "val").?);
}

test "extractJsonFloat negative value" {
    const json = "{\"val\":-3.14}";
    const result = extractJsonFloat(json, "val").?;
    try std.testing.expectApproxEqAbs(@as(f64, -3.14), result, 0.001);
}

test "extractJsonFloat scientific notation" {
    const json = "{\"val\":1.5e3}";
    const result = extractJsonFloat(json, "val").?;
    try std.testing.expectApproxEqAbs(@as(f64, 1500.0), result, 0.001);
}

test "extractJsonString multiple consecutive escapes" {
    // JSON: {"s":"a\\\"b"} — value is a\"b (backslash, quote, b)
    // In Zig literal: each \ in the JSON needs to be \\ in Zig
    const json = "{\"s\":\"a\\\\\\\"b\"}";
    const result = extractJsonString(json, "s").?;
    // the raw bytes returned include the escape sequences as-is
    try std.testing.expectEqualStrings("a\\\\\\\"b", result);
}

test "writeJsonEscaped all control characters" {
    var buf: [1024]u8 = undefined;
    var stream = @import("compat").fixedBufferStream(&buf);
    const writer = stream.writer();

    // write all control chars 0x00-0x1F
    var input: [32]u8 = undefined;
    for (0..32) |i| {
        input[i] = @intCast(i);
    }
    try writeJsonEscaped(writer, &input);

    const output = stream.getWritten();

    // \n (0x0A), \r (0x0D), \t (0x09) use shorthand
    try std.testing.expect(std.mem.indexOf(u8, output, "\\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\\r") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\\t") != null);

    // 0x00 should be \u0000
    try std.testing.expect(std.mem.indexOf(u8, output, "\\u0000") != null);
    // 0x01 should be \u0001
    try std.testing.expect(std.mem.indexOf(u8, output, "\\u0001") != null);
    // 0x1F should be \u001f
    try std.testing.expect(std.mem.indexOf(u8, output, "\\u001f") != null);

    // no raw control characters should appear in the output
    for (output) |c| {
        try std.testing.expect(c >= 0x20);
    }
}
