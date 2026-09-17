const std = @import("std");

const log = @import("../log.zig");
const types = @import("types.zig");

const ParseError = types.ParseError;
const Table = types.Table;
const Value = types.Value;
const max_table_depth = types.max_table_depth;

pub fn resolveTablePath(root: *Table, alloc: std.mem.Allocator, line: []const u8, line_num: usize) ParseError!*Table {
    if (line.len < 3 or line[line.len - 1] != ']') {
        log.err("toml: line {d}: invalid table header", .{line_num});
        return ParseError.InvalidTableHeader;
    }

    const path = std.mem.trim(u8, line[1 .. line.len - 1], " \t");
    if (path.len == 0) {
        log.err("toml: line {d}: empty table header", .{line_num});
        return ParseError.InvalidTableHeader;
    }

    const depth = std.mem.count(u8, path, ".") + 1;
    if (depth > max_table_depth) {
        log.err("toml: line {d}: table nesting too deep ({d} levels, max {d})", .{ line_num, depth, max_table_depth });
        return ParseError.InvalidTableHeader;
    }

    var current = root;
    var parts = std.mem.splitScalar(u8, path, '.');
    while (parts.next()) |raw_part| {
        const part = std.mem.trim(u8, raw_part, " \t");
        if (part.len == 0) {
            log.err("toml: line {d}: empty segment in table path", .{line_num});
            return ParseError.InvalidTableHeader;
        }

        current = try resolveSegment(current, alloc, part, line_num);
    }

    return current;
}

fn resolveSegment(parent: *Table, alloc: std.mem.Allocator, name: []const u8, line_num: usize) ParseError!*Table {
    if (parent.entries.get(name)) |existing| {
        return switch (existing) {
            .table => |table| table,
            else => {
                log.err("toml: line {d}: '{s}' is not a table", .{ line_num, name });
                return ParseError.DuplicateKey;
            },
        };
    }

    const subtable = alloc.create(Table) catch return ParseError.OutOfMemory;
    subtable.* = Table{ .entries = .{} };
    errdefer {
        subtable.deinit(alloc);
        alloc.destroy(subtable);
    }

    const key = alloc.dupe(u8, name) catch return ParseError.OutOfMemory;
    errdefer alloc.free(key);
    parent.entries.put(alloc, key, Value{ .table = subtable }) catch return ParseError.OutOfMemory;
    // the parent owns the key and subtable once insertion succeeds.
    return subtable;
}
