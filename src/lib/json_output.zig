// json_output — structured JSON output for CLI commands
//
// provides a JsonWriter that builds compact JSON output to stdout.
// used by commands that support --json to emit machine-readable output.
//
// conventions:
//   - bare arrays/objects (no envelope)
//   - snake_case field names
//   - sizes in bytes, timestamps as unix seconds
//   - null for missing values
//   - compact single-line output

const std = @import("std");
const json_helpers = @import("json_helpers.zig");

pub const JsonWriter = struct {
    buf: [8192]u8 = undefined,
    pos: usize = 0,
    /// tracks nesting to know whether to insert commas.
    /// each bit: 0 = first element (no comma needed), 1 = subsequent (comma needed).
    needs_comma: u32 = 0,
    depth: u5 = 0,
    /// tracks if the last flush operation failed
    flush_failed: bool = false,
    /// tracks if any data was dropped due to buffer overflow.
    /// when true, the JSON output is incomplete and should not be trusted.
    truncated: bool = false,

    // -- structure --

    pub fn beginArray(self: *JsonWriter) void {
        self.maybeComma();
        self.put('[');
        self.pushNesting();
    }

    pub fn endArray(self: *JsonWriter) void {
        self.popNesting();
        self.put(']');
    }

    pub fn beginObject(self: *JsonWriter) void {
        self.maybeComma();
        self.put('{');
        self.pushNesting();
    }

    pub fn endObject(self: *JsonWriter) void {
        self.popNesting();
        self.put('}');
    }

    // -- fields (inside objects) --

    pub fn stringField(self: *JsonWriter, key: []const u8, value: []const u8) void {
        self.maybeComma();
        self.put('"');
        self.putSlice(key);
        self.putSlice("\":\"");
        self.putEscaped(value);
        self.put('"');
    }

    pub fn intField(self: *JsonWriter, key: []const u8, value: i64) void {
        self.maybeComma();
        self.put('"');
        self.putSlice(key);
        self.putSlice("\":");
        var num_buf: [24]u8 = undefined;
        const formatted = std.fmt.bufPrint(&num_buf, "{d}", .{value}) catch return;
        self.putSlice(formatted);
    }

    pub fn uintField(self: *JsonWriter, key: []const u8, value: u64) void {
        self.maybeComma();
        self.put('"');
        self.putSlice(key);
        self.putSlice("\":");
        var num_buf: [24]u8 = undefined;
        const formatted = std.fmt.bufPrint(&num_buf, "{d}", .{value}) catch return;
        self.putSlice(formatted);
    }

    pub fn boolField(self: *JsonWriter, key: []const u8, value: bool) void {
        self.maybeComma();
        self.put('"');
        self.putSlice(key);
        self.putSlice("\":");
        self.putSlice(if (value) "true" else "false");
    }

    pub fn nullField(self: *JsonWriter, key: []const u8) void {
        self.maybeComma();
        self.put('"');
        self.putSlice(key);
        self.putSlice("\":null");
    }

    pub fn floatField(self: *JsonWriter, key: []const u8, value: f64) void {
        self.maybeComma();
        self.put('"');
        self.putSlice(key);
        self.putSlice("\":");
        var num_buf: [32]u8 = undefined;
        const formatted = std.fmt.bufPrint(&num_buf, "{d:.2}", .{value}) catch return;
        self.putSlice(formatted);
    }

    // -- nested structure fields --

    /// begin a nested object as a field value: "key":{
    pub fn beginObjectField(self: *JsonWriter, key: []const u8) void {
        self.maybeComma();
        self.put('"');
        self.putSlice(key);
        self.putSlice("\":");
        self.put('{');
        self.pushNesting();
    }

    /// begin a nested array as a field value: "key":[
    pub fn beginArrayField(self: *JsonWriter, key: []const u8) void {
        self.maybeComma();
        self.put('"');
        self.putSlice(key);
        self.putSlice("\":");
        self.put('[');
        self.pushNesting();
    }

    // -- bare values (inside arrays) --

    pub fn stringValue(self: *JsonWriter, value: []const u8) void {
        self.maybeComma();
        self.put('"');
        self.putEscaped(value);
        self.put('"');
    }

    // -- output --

    /// flush the buffer to stdout with a trailing newline.
    /// tracks if flush failed in flush_failed field.
    /// if the output was truncated, emits a warning to stderr.
    pub fn flush(self: *JsonWriter) void {
        if (self.truncated) {
            var err_buf: [128]u8 = undefined;
            var err_w = std.fs.File.stderr().writer(&err_buf);
            err_w.interface.writeAll("warning: JSON output truncated (exceeded 8192 byte buffer)\n") catch {};
            err_w.interface.flush() catch {};
        }

        const data = self.buf[0..self.pos];
        var buf: [4096]u8 = undefined;
        var w = std.fs.File.stdout().writer(&buf);
        const out = &w.interface;

        out.writeAll(data) catch {
            self.flush_failed = true;
            return;
        };
        out.writeAll("\n") catch {
            self.flush_failed = true;
            return;
        };
        out.flush() catch {
            self.flush_failed = true;
            return;
        };
        self.pos = 0;
    }

    /// return the current buffer contents as a slice (for testing).
    pub fn getWritten(self: *const JsonWriter) []const u8 {
        return self.buf[0..self.pos];
    }

    // -- internal helpers --

    fn maybeComma(self: *JsonWriter) void {
        if (self.depth > 31) return; // Guard against shift overflow
        const mask = @as(u32, 1) << @intCast(self.depth);
        if (self.needs_comma & mask != 0) {
            self.put(',');
        } else {
            self.needs_comma |= mask;
        }
    }

    fn pushNesting(self: *JsonWriter) void {
        if (self.depth >= 31) return; // Guard against shift overflow
        self.depth += 1;
        // clear the comma bit for this new level (depth is now 1-31, shift is safe)
        const mask = @as(u32, 1) << @intCast(self.depth);
        self.needs_comma &= ~mask;
    }

    fn popNesting(self: *JsonWriter) void {
        if (self.depth > 0) self.depth -= 1;
    }

    fn put(self: *JsonWriter, c: u8) void {
        if (self.pos < self.buf.len) {
            self.buf[self.pos] = c;
            self.pos += 1;
        } else {
            self.truncated = true;
        }
    }

    fn putSlice(self: *JsonWriter, s: []const u8) void {
        const remaining = self.buf.len - self.pos;
        const copy_len = @min(s.len, remaining);
        if (copy_len < s.len) self.truncated = true;
        @memcpy(self.buf[self.pos..][0..copy_len], s[0..copy_len]);
        self.pos += copy_len;
    }

    fn putEscaped(self: *JsonWriter, s: []const u8) void {
        for (s) |c| {
            switch (c) {
                '"' => self.putSlice("\\\""),
                '\\' => self.putSlice("\\\\"),
                '\n' => self.putSlice("\\n"),
                '\r' => self.putSlice("\\r"),
                '\t' => self.putSlice("\\t"),
                else => {
                    if (c < 0x20) {
                        var esc_buf: [6]u8 = undefined;
                        const esc = std.fmt.bufPrint(&esc_buf, "\\u{x:0>4}", .{c}) catch continue;
                        self.putSlice(esc);
                    } else {
                        self.put(c);
                    }
                },
            }
        }
    }
};

// -- tests --

test "empty object" {
    var w = JsonWriter{};
    w.beginObject();
    w.endObject();
    try std.testing.expectEqualStrings("{}", w.getWritten());
}

test "empty array" {
    var w = JsonWriter{};
    w.beginArray();
    w.endArray();
    try std.testing.expectEqualStrings("[]", w.getWritten());
}

test "object with fields" {
    var w = JsonWriter{};
    w.beginObject();
    w.stringField("name", "web");
    w.intField("pid", 1234);
    w.boolField("running", true);
    w.endObject();
    try std.testing.expectEqualStrings(
        "{\"name\":\"web\",\"pid\":1234,\"running\":true}",
        w.getWritten(),
    );
}

test "array of objects" {
    var w = JsonWriter{};
    w.beginArray();
    w.beginObject();
    w.stringField("id", "abc");
    w.endObject();
    w.beginObject();
    w.stringField("id", "def");
    w.endObject();
    w.endArray();
    try std.testing.expectEqualStrings(
        "[{\"id\":\"abc\"},{\"id\":\"def\"}]",
        w.getWritten(),
    );
}

test "null and float fields" {
    var w = JsonWriter{};
    w.beginObject();
    w.nullField("error");
    w.floatField("cpu_pct", 42.50);
    w.endObject();
    try std.testing.expectEqualStrings(
        "{\"error\":null,\"cpu_pct\":42.50}",
        w.getWritten(),
    );
}

test "string escaping" {
    var w = JsonWriter{};
    w.beginObject();
    w.stringField("msg", "hello \"world\"\nnewline");
    w.endObject();
    try std.testing.expectEqualStrings(
        "{\"msg\":\"hello \\\"world\\\"\\nnewline\"}",
        w.getWritten(),
    );
}

test "nested objects" {
    var w = JsonWriter{};
    w.beginObject();
    w.stringField("name", "test");
    w.beginObjectField("resources");
    w.intField("cpu", 100);
    w.intField("memory", 256);
    w.endObject(); // close resources
    w.endObject(); // close root
    try std.testing.expectEqualStrings(
        "{\"name\":\"test\",\"resources\":{\"cpu\":100,\"memory\":256}}",
        w.getWritten(),
    );
}

test "nested array field" {
    var w = JsonWriter{};
    w.beginObject();
    w.stringField("name", "test");
    w.beginArrayField("ports");
    w.stringValue("8080");
    w.stringValue("443");
    w.endArray();
    w.endObject();
    try std.testing.expectEqualStrings(
        "{\"name\":\"test\",\"ports\":[\"8080\",\"443\"]}",
        w.getWritten(),
    );
}

test "uint field" {
    var w = JsonWriter{};
    w.beginObject();
    w.uintField("size_bytes", 1048576);
    w.endObject();
    try std.testing.expectEqualStrings(
        "{\"size_bytes\":1048576}",
        w.getWritten(),
    );
}

test "array of strings" {
    var w = JsonWriter{};
    w.beginArray();
    w.stringValue("one");
    w.stringValue("two");
    w.stringValue("three");
    w.endArray();
    try std.testing.expectEqualStrings(
        "[\"one\",\"two\",\"three\"]",
        w.getWritten(),
    );
}

test "control character escaping" {
    var w = JsonWriter{};
    w.beginObject();
    w.stringField("data", &[_]u8{ 0x01, 0x02 });
    w.endObject();
    try std.testing.expectEqualStrings(
        "{\"data\":\"\\u0001\\u0002\"}",
        w.getWritten(),
    );
}

test "depth overflow protection" {
    // Test that depth is capped at 31 to prevent bit shift overflow
    var w = JsonWriter{};

    // Push nesting 40 times (exceeds the 31 limit)
    for (0..40) |_| {
        w.beginObject();
    }

    // Depth should be capped at 31
    try std.testing.expect(w.depth <= 31);

    // Should still be able to write fields without crashing
    w.stringField("key", "value");

    // Pop all nesting
    for (0..40) |_| {
        w.endObject();
    }

    // Verify we can flush without error
    w.flush();
    try std.testing.expect(!w.flush_failed);
}

test "flush failure tracking" {
    var w = JsonWriter{};
    w.beginObject();
    w.stringField("key", "value");
    w.endObject();
    w.flush();

    // In normal operation, flush should succeed
    try std.testing.expect(!w.flush_failed);
}

test "truncation tracking" {
    var w = JsonWriter{};
    try std.testing.expect(!w.truncated);

    // fill the buffer with a large string value
    w.beginObject();
    var big: [8200]u8 = undefined;
    @memset(&big, 'a');
    w.stringField("data", &big);
    w.endObject();

    // buffer should have been exceeded
    try std.testing.expect(w.truncated);
}

test "no truncation on small output" {
    var w = JsonWriter{};
    w.beginObject();
    w.stringField("key", "value");
    w.endObject();
    try std.testing.expect(!w.truncated);
}
