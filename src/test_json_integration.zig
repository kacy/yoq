// integration tests — JSON output
//
// tests the JSON writer used by the --json flag across all commands.
// runs without sqlite or root.

const std = @import("std");
const json_out = @import("lib/json_output.zig");

test "json empty object" {
    var w = json_out.JsonWriter{};
    w.beginObject();
    w.endObject();
    try std.testing.expectEqualStrings("{}", w.getWritten());
}

test "json empty array" {
    var w = json_out.JsonWriter{};
    w.beginArray();
    w.endArray();
    try std.testing.expectEqualStrings("[]", w.getWritten());
}

test "json array of objects" {
    var w = json_out.JsonWriter{};
    w.beginArray();
    w.beginObject();
    w.stringField("name", "test");
    w.intField("value", 42);
    w.endObject();
    w.endArray();
    try std.testing.expectEqualStrings("[{\"name\":\"test\",\"value\":42}]", w.getWritten());
}

test "json null and bool fields" {
    var w = json_out.JsonWriter{};
    w.beginObject();
    w.nullField("missing");
    w.boolField("enabled", true);
    w.boolField("disabled", false);
    w.endObject();
    try std.testing.expectEqualStrings("{\"missing\":null,\"enabled\":true,\"disabled\":false}", w.getWritten());
}

test "json string escaping" {
    var w = json_out.JsonWriter{};
    w.beginObject();
    w.stringField("msg", "hello \"world\"\nline2");
    w.endObject();
    try std.testing.expectEqualStrings("{\"msg\":\"hello \\\"world\\\"\\nline2\"}", w.getWritten());
}

test "json uint field" {
    var w = json_out.JsonWriter{};
    w.beginObject();
    w.uintField("size", 1024);
    w.endObject();
    try std.testing.expectEqualStrings("{\"size\":1024}", w.getWritten());
}

test "json nested objects" {
    var w = json_out.JsonWriter{};
    w.beginObject();
    w.stringField("name", "outer");
    w.beginObjectField("inner");
    w.stringField("key", "val");
    w.endObject();
    w.endObject();
    try std.testing.expectEqualStrings("{\"name\":\"outer\",\"inner\":{\"key\":\"val\"}}", w.getWritten());
}

test "json array of strings" {
    var w = json_out.JsonWriter{};
    w.beginArray();
    w.stringValue("one");
    w.stringValue("two");
    w.stringValue("three");
    w.endArray();
    try std.testing.expectEqualStrings("[\"one\",\"two\",\"three\"]", w.getWritten());
}

test "json float field" {
    var w = json_out.JsonWriter{};
    w.beginObject();
    w.floatField("pct", 42.5);
    w.endObject();
    const output = w.getWritten();
    try std.testing.expect(std.mem.startsWith(u8, output, "{\"pct\":"));
    try std.testing.expect(std.mem.endsWith(u8, output, "}"));
}

test "json multiple objects in array" {
    var w = json_out.JsonWriter{};
    w.beginArray();
    w.beginObject();
    w.stringField("id", "a");
    w.endObject();
    w.beginObject();
    w.stringField("id", "b");
    w.endObject();
    w.endArray();
    try std.testing.expectEqualStrings("[{\"id\":\"a\"},{\"id\":\"b\"}]", w.getWritten());
}

test "json nested array field" {
    var w = json_out.JsonWriter{};
    w.beginObject();
    w.beginArrayField("items");
    w.stringValue("x");
    w.stringValue("y");
    w.endArray();
    w.endObject();
    try std.testing.expectEqualStrings("{\"items\":[\"x\",\"y\"]}", w.getWritten());
}

test "json control character escaping" {
    var w = json_out.JsonWriter{};
    w.beginObject();
    w.stringField("tab", "a\tb");
    w.endObject();
    try std.testing.expectEqualStrings("{\"tab\":\"a\\tb\"}", w.getWritten());
}
