// toml — TOML parser
//
// minimal TOML parser for yoq manifest files. line-by-line parser that
// handles what the manifest format needs: tables, dotted tables, strings,
// integers, booleans, and string arrays. no inline tables, literal strings,
// multiline strings, dates, or floats.

const std = @import("std");
const log = @import("log.zig");
const table_path = @import("toml/table_path.zig");
const types = @import("toml/types.zig");
const value_support = @import("toml/value_support.zig");

pub const ParseError = types.ParseError;
pub const Value = types.Value;
pub const Table = types.Table;
pub const ParseResult = types.ParseResult;
const max_table_depth = types.max_table_depth;

/// parse a TOML string into a table structure.
/// caller must call result.deinit() when done.
pub fn parse(alloc: std.mem.Allocator, input: []const u8) ParseError!ParseResult {
    var root = Table{ .entries = .{} };
    errdefer root.deinit(alloc);

    var current = &root;
    var line_num: usize = 0;

    var line_iter = std.mem.splitScalar(u8, input, '\n');
    while (line_iter.next()) |raw_line| {
        line_num += 1;

        // strip \r for windows line endings
        const no_cr = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r')
            raw_line[0 .. raw_line.len - 1]
        else
            raw_line;

        const line = std.mem.trim(u8, no_cr, " \t");

        // skip empty lines and comments
        if (line.len == 0) continue;
        if (line[0] == '#') continue;

        // table header
        if (line[0] == '[') {
            current = table_path.resolveTablePath(&root, alloc, line, line_num) catch |e| return e;
            continue;
        }

        // key = value
        const eq_pos = std.mem.indexOfScalar(u8, line, '=') orelse {
            log.err("toml: line {d}: expected '=' in key-value pair", .{line_num});
            return ParseError.UnexpectedCharacter;
        };

        const raw_key = std.mem.trim(u8, line[0..eq_pos], " \t");
        if (raw_key.len == 0) {
            log.err("toml: line {d}: empty key", .{line_num});
            return ParseError.EmptyKey;
        }

        var raw_value = std.mem.trim(u8, line[eq_pos + 1 ..], " \t");

        // handle multiline arrays: if value starts with '[' but doesn't
        // contain ']', accumulate subsequent lines until the array closes
        var multiline_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer multiline_buf.deinit(alloc);

        if (raw_value.len > 0 and raw_value[0] == '[' and
            std.mem.indexOfScalar(u8, raw_value, ']') == null)
        {
            multiline_buf.appendSlice(alloc, raw_value) catch return ParseError.OutOfMemory;

            while (line_iter.next()) |cont_raw| {
                line_num += 1;
                const cont_no_cr = if (cont_raw.len > 0 and cont_raw[cont_raw.len - 1] == '\r')
                    cont_raw[0 .. cont_raw.len - 1]
                else
                    cont_raw;
                const cont = std.mem.trim(u8, cont_no_cr, " \t");

                // skip empty lines and comments inside multiline arrays
                if (cont.len == 0) continue;
                if (cont[0] == '#') continue;

                multiline_buf.appendSlice(alloc, cont) catch return ParseError.OutOfMemory;

                if (std.mem.indexOfScalar(u8, cont, ']') != null) break;
            }

            // check if we actually found the closing bracket
            if (std.mem.indexOfScalar(u8, multiline_buf.items, ']') == null) {
                log.err("toml: line {d}: unterminated array", .{line_num});
                return ParseError.UnterminatedArray;
            }

            raw_value = multiline_buf.items;
        }

        const value = value_support.parseValue(alloc, raw_value, line_num) catch |e| return e;

        // check for duplicates before allocating the key
        if (current.entries.contains(raw_key)) {
            log.err("toml: line {d}: duplicate key '{s}'", .{ line_num, raw_key });
            value_support.freeValue(alloc, value);
            return ParseError.DuplicateKey;
        }

        const key = alloc.dupe(u8, raw_key) catch return ParseError.OutOfMemory;
        current.entries.put(alloc, key, value) catch {
            alloc.free(key);
            value_support.freeValue(alloc, value);
            return ParseError.OutOfMemory;
        };
    }

    return ParseResult{ .root = root, .alloc = alloc };
}

// -- tests --

test "parse empty input" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "");
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.root.entries.count());
}

test "parse comments only" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "# just a comment\n# another one\n");
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 0), result.root.entries.count());
}

test "parse string value" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "name = \"hello\"");
    defer result.deinit();

    try std.testing.expectEqualStrings("hello", result.root.getString("name").?);
}

test "parse integer value" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "port = 8080");
    defer result.deinit();

    try std.testing.expectEqual(@as(i64, 8080), result.root.getInt("port").?);
}

test "parse negative integer" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "offset = -42");
    defer result.deinit();

    try std.testing.expectEqual(@as(i64, -42), result.root.getInt("offset").?);
}

test "parse boolean values" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc,
        \\debug = true
        \\verbose = false
    );
    defer result.deinit();

    try std.testing.expectEqual(true, result.root.getBool("debug").?);
    try std.testing.expectEqual(false, result.root.getBool("verbose").?);
}

test "parse string with escapes" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "path = \"foo\\\\bar\"");
    defer result.deinit();
    try std.testing.expectEqualStrings("foo\\bar", result.root.getString("path").?);
}

test "parse string with newline escape" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "msg = \"line1\\nline2\"");
    defer result.deinit();
    try std.testing.expectEqualStrings("line1\nline2", result.root.getString("msg").?);
}

test "parse string with escaped quote" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "val = \"say \\\"hi\\\"\"");
    defer result.deinit();
    try std.testing.expectEqualStrings("say \"hi\"", result.root.getString("val").?);
}

test "whitespace around equals" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "key   =   \"value\"");
    defer result.deinit();
    try std.testing.expectEqualStrings("value", result.root.getString("key").?);
}

test "multiple key-value pairs" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc,
        \\name = "yoq"
        \\version = 1
        \\debug = false
    );
    defer result.deinit();

    try std.testing.expectEqualStrings("yoq", result.root.getString("name").?);
    try std.testing.expectEqual(@as(i64, 1), result.root.getInt("version").?);
    try std.testing.expectEqual(false, result.root.getBool("debug").?);
}

test "duplicate key error" {
    const alloc = std.testing.allocator;
    const result = parse(alloc, "name = \"first\"\nname = \"second\"");
    try std.testing.expectError(ParseError.DuplicateKey, result);
}

test "unterminated string error" {
    const alloc = std.testing.allocator;
    const result = parse(alloc, "name = \"missing end");
    try std.testing.expectError(ParseError.UnterminatedString, result);
}

test "empty key error" {
    const alloc = std.testing.allocator;
    const result = parse(alloc, " = \"value\"");
    try std.testing.expectError(ParseError.EmptyKey, result);
}

test "missing value error" {
    const alloc = std.testing.allocator;
    const result = parse(alloc, "key =");
    try std.testing.expectError(ParseError.InvalidValue, result);
}

test "windows line endings" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "a = \"one\"\r\nb = \"two\"\r\n");
    defer result.deinit();
    try std.testing.expectEqualStrings("one", result.root.getString("a").?);
    try std.testing.expectEqualStrings("two", result.root.getString("b").?);
}

test "accessor returns null for wrong type" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "name = \"hello\"");
    defer result.deinit();

    try std.testing.expect(result.root.getInt("name") == null);
    try std.testing.expect(result.root.getBool("name") == null);
    try std.testing.expect(result.root.getString("missing") == null);
}

test "simple table" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc,
        \\[server]
        \\host = "localhost"
        \\port = 8080
    );
    defer result.deinit();

    const server = result.root.getTable("server").?;
    try std.testing.expectEqualStrings("localhost", server.getString("host").?);
    try std.testing.expectEqual(@as(i64, 8080), server.getInt("port").?);
}

test "dotted table path" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.db]
        \\image = "postgres:15"
    );
    defer result.deinit();

    const service = result.root.getTable("service").?;
    const web = service.getTable("web").?;
    const db = service.getTable("db").?;
    try std.testing.expectEqualStrings("nginx:latest", web.getString("image").?);
    try std.testing.expectEqualStrings("postgres:15", db.getString("image").?);
}

test "shared table prefix" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc,
        \\[a.b]
        \\x = 1
        \\
        \\[a.c]
        \\y = 2
        \\
        \\[a]
        \\z = 3
    );
    defer result.deinit();

    const a = result.root.getTable("a").?;
    try std.testing.expectEqual(@as(i64, 3), a.getInt("z").?);
    try std.testing.expectEqual(@as(i64, 1), a.getTable("b").?.getInt("x").?);
    try std.testing.expectEqual(@as(i64, 2), a.getTable("c").?.getInt("y").?);
}

test "multiple tables" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc,
        \\name = "root"
        \\
        \\[alpha]
        \\val = 1
        \\
        \\[beta]
        \\val = 2
    );
    defer result.deinit();

    try std.testing.expectEqualStrings("root", result.root.getString("name").?);
    try std.testing.expectEqual(@as(i64, 1), result.root.getTable("alpha").?.getInt("val").?);
    try std.testing.expectEqual(@as(i64, 2), result.root.getTable("beta").?.getInt("val").?);
}

test "empty table header error" {
    const alloc = std.testing.allocator;
    const result = parse(alloc, "[]");
    try std.testing.expectError(ParseError.InvalidTableHeader, result);
}

test "table path with empty segment error" {
    const alloc = std.testing.allocator;
    const result = parse(alloc, "[a..b]");
    try std.testing.expectError(ParseError.InvalidTableHeader, result);
}

test "table path conflicts with existing value" {
    const alloc = std.testing.allocator;
    const result = parse(alloc, "name = \"hello\"\n[name.sub]\nval = 1");
    try std.testing.expectError(ParseError.DuplicateKey, result);
}

test "inline string array" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "ports = [\"80:8080\", \"443:8443\"]");
    defer result.deinit();

    const arr = result.root.getArray("ports").?;
    try std.testing.expectEqual(@as(usize, 2), arr.len);
    try std.testing.expectEqualStrings("80:8080", arr[0]);
    try std.testing.expectEqualStrings("443:8443", arr[1]);
}

test "single element array" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "tags = [\"latest\"]");
    defer result.deinit();

    const arr = result.root.getArray("tags").?;
    try std.testing.expectEqual(@as(usize, 1), arr.len);
    try std.testing.expectEqualStrings("latest", arr[0]);
}

test "empty array" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "items = []");
    defer result.deinit();

    const arr = result.root.getArray("items").?;
    try std.testing.expectEqual(@as(usize, 0), arr.len);
}

test "multiline array" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc,
        \\ports = [
        \\  "80:8080",
        \\  "443:8443"
        \\]
    );
    defer result.deinit();

    const arr = result.root.getArray("ports").?;
    try std.testing.expectEqual(@as(usize, 2), arr.len);
    try std.testing.expectEqualStrings("80:8080", arr[0]);
    try std.testing.expectEqualStrings("443:8443", arr[1]);
}

test "multiline array with comments" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc,
        \\env = [
        \\  # database settings
        \\  "DB_HOST=localhost",
        \\  "DB_PORT=5432"
        \\]
    );
    defer result.deinit();

    const arr = result.root.getArray("env").?;
    try std.testing.expectEqual(@as(usize, 2), arr.len);
    try std.testing.expectEqualStrings("DB_HOST=localhost", arr[0]);
    try std.testing.expectEqualStrings("DB_PORT=5432", arr[1]);
}

test "unterminated array error" {
    const alloc = std.testing.allocator;
    const result = parse(alloc, "items = [\"a\", \"b\"");
    try std.testing.expectError(ParseError.UnterminatedArray, result);
}

test "array with escapes" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc, "cmds = [\"/bin/sh\", \"-c\", \"echo \\\"hello\\\"\"]");
    defer result.deinit();

    const arr = result.root.getArray("cmds").?;
    try std.testing.expectEqual(@as(usize, 3), arr.len);
    try std.testing.expectEqualStrings("/bin/sh", arr[0]);
    try std.testing.expectEqualStrings("-c", arr[1]);
    try std.testing.expectEqualStrings("echo \"hello\"", arr[2]);
}

test "full manifest format" {
    const alloc = std.testing.allocator;
    var result = try parse(alloc,
        \\# yoq manifest
        \\
        \\[service.web]
        \\image = "nginx:latest"
        \\command = ["/bin/sh", "-c", "echo hello"]
        \\ports = ["80:8080", "443:8443"]
        \\env = ["DEBUG=true", "PORT=8080"]
        \\depends_on = ["db"]
        \\working_dir = "/app"
        \\
        \\[service.db]
        \\image = "postgres:15"
        \\env = ["POSTGRES_PASSWORD=secret"]
        \\
        \\[volume.data]
        \\driver = "local"
    );
    defer result.deinit();

    // verify top-level structure
    const service = result.root.getTable("service").?;
    const volume = result.root.getTable("volume").?;

    // verify web service
    const web = service.getTable("web").?;
    try std.testing.expectEqualStrings("nginx:latest", web.getString("image").?);
    try std.testing.expectEqualStrings("/app", web.getString("working_dir").?);

    const cmd = web.getArray("command").?;
    try std.testing.expectEqual(@as(usize, 3), cmd.len);
    try std.testing.expectEqualStrings("/bin/sh", cmd[0]);
    try std.testing.expectEqualStrings("-c", cmd[1]);
    try std.testing.expectEqualStrings("echo hello", cmd[2]);

    const ports = web.getArray("ports").?;
    try std.testing.expectEqual(@as(usize, 2), ports.len);
    try std.testing.expectEqualStrings("80:8080", ports[0]);

    const env = web.getArray("env").?;
    try std.testing.expectEqual(@as(usize, 2), env.len);
    try std.testing.expectEqualStrings("DEBUG=true", env[0]);

    const deps = web.getArray("depends_on").?;
    try std.testing.expectEqual(@as(usize, 1), deps.len);
    try std.testing.expectEqualStrings("db", deps[0]);

    // verify db service
    const db = service.getTable("db").?;
    try std.testing.expectEqualStrings("postgres:15", db.getString("image").?);
    const db_env = db.getArray("env").?;
    try std.testing.expectEqual(@as(usize, 1), db_env.len);
    try std.testing.expectEqualStrings("POSTGRES_PASSWORD=secret", db_env[0]);

    // verify volume
    const data = volume.getTable("data").?;
    try std.testing.expectEqualStrings("local", data.getString("driver").?);
}

test "deeply nested table path rejected" {
    const alloc = std.testing.allocator;
    // build a table path with 65 levels of nesting (exceeds max_table_depth=64)
    var path_buf: [65 * 2 + 2]u8 = undefined;
    path_buf[0] = '[';
    var pos: usize = 1;
    for (0..65) |i| {
        if (i > 0) {
            path_buf[pos] = '.';
            pos += 1;
        }
        path_buf[pos] = 'a';
        pos += 1;
    }
    path_buf[pos] = ']';
    pos += 1;

    const input = path_buf[0..pos];
    const result = parse(alloc, input);
    try std.testing.expectError(ParseError.InvalidTableHeader, result);
}

test "table nesting at max depth succeeds" {
    const alloc = std.testing.allocator;
    // build a table path with exactly 64 levels (at the limit)
    var path_buf: [64 * 2 + 2]u8 = undefined;
    path_buf[0] = '[';
    var pos: usize = 1;
    for (0..64) |i| {
        if (i > 0) {
            path_buf[pos] = '.';
            pos += 1;
        }
        path_buf[pos] = 'a';
        pos += 1;
    }
    path_buf[pos] = ']';
    pos += 1;

    const input = path_buf[0..pos];
    var result = parse(alloc, input) catch |e| {
        // should not fail with InvalidTableHeader
        try std.testing.expect(e != ParseError.InvalidTableHeader);
        return;
    };
    result.deinit();
}
