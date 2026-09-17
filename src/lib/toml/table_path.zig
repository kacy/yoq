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

test "toml table paths reuse existing tables and trim segment whitespace" {
    const alloc = std.testing.allocator;
    var root = Table{ .entries = .{} };
    defer root.deinit(alloc);

    const web = try resolveTablePath(&root, alloc, "[ services . web ]", 1);
    const reopened = try resolveTablePath(&root, alloc, "[services.web]", 2);
    const worker = try resolveTablePath(&root, alloc, "[services.worker]", 3);
    try std.testing.expect(web == reopened);
    try std.testing.expect(web != worker);
    try std.testing.expectEqual(@as(usize, 1), root.entries.count());
    try std.testing.expectEqual(@as(usize, 2), root.getTable("services").?.entries.count());
}

test "toml table paths retain completed segments when a later segment is invalid" {
    const alloc = std.testing.allocator;
    var root = Table{ .entries = .{} };
    defer root.deinit(alloc);

    try std.testing.expectError(ParseError.InvalidTableHeader, resolveTablePath(&root, alloc, "[services..web]", 1));
    const services = root.getTable("services") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), services.entries.count());
}

test "toml table paths release allocations when table creation fails" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkTablePathAllocations, .{});
}

fn checkTablePathAllocations(alloc: std.mem.Allocator) !void {
    var root = Table{ .entries = .{} };
    defer root.deinit(alloc);
    _ = try resolveTablePath(&root, alloc, "[services.web]", 1);
    _ = try resolveTablePath(&root, alloc, "[services.worker]", 2);
}
