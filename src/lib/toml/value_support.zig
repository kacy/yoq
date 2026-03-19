const std = @import("std");

const log = @import("../log.zig");
const types = @import("types.zig");

const ParseError = types.ParseError;
const Value = types.Value;

pub fn freeValue(alloc: std.mem.Allocator, value: Value) void {
    switch (value) {
        .string => |s| alloc.free(s),
        .array => |arr| {
            for (arr) |item| alloc.free(item);
            alloc.free(arr);
        },
        .table => |table| {
            table.deinit(alloc);
            alloc.destroy(table);
        },
        .integer, .boolean => {},
    }
}

pub fn parseValue(alloc: std.mem.Allocator, raw: []const u8, line_num: usize) ParseError!Value {
    if (raw.len == 0) {
        log.err("toml: line {d}: missing value", .{line_num});
        return ParseError.InvalidValue;
    }

    if (raw[0] == '"') return parseString(alloc, raw, line_num);
    if (raw[0] == '[') return parseStringArray(alloc, raw, line_num);
    if (std.mem.eql(u8, raw, "true")) return Value{ .boolean = true };
    if (std.mem.eql(u8, raw, "false")) return Value{ .boolean = false };
    if (raw[0] == '-' or std.ascii.isDigit(raw[0])) return parseInt(raw, line_num);

    log.err("toml: line {d}: unrecognized value: {s}", .{ line_num, raw });
    return ParseError.InvalidValue;
}

fn parseString(alloc: std.mem.Allocator, raw: []const u8, line_num: usize) ParseError!Value {
    if (raw.len < 2 or raw[0] != '"') {
        log.err("toml: line {d}: invalid string", .{line_num});
        return ParseError.UnexpectedCharacter;
    }

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(alloc);

    var i: usize = 1;
    while (i < raw.len) {
        const c = raw[i];
        if (c == '"') {
            const result = alloc.dupe(u8, buf.items) catch return ParseError.OutOfMemory;
            buf.deinit(alloc);
            return Value{ .string = result };
        }
        if (c == '\\') {
            i += 1;
            if (i >= raw.len) {
                log.err("toml: line {d}: unterminated escape sequence", .{line_num});
                return ParseError.UnterminatedString;
            }
            const escaped: u8 = switch (raw[i]) {
                '\\' => '\\',
                '"' => '"',
                'n' => '\n',
                't' => '\t',
                else => {
                    log.err("toml: line {d}: unknown escape '\\{c}'", .{ line_num, raw[i] });
                    return ParseError.UnexpectedCharacter;
                },
            };
            buf.append(alloc, escaped) catch return ParseError.OutOfMemory;
        } else {
            buf.append(alloc, c) catch return ParseError.OutOfMemory;
        }
        i += 1;
    }

    log.err("toml: line {d}: unterminated string", .{line_num});
    return ParseError.UnterminatedString;
}

fn parseInt(raw: []const u8, line_num: usize) ParseError!Value {
    const value = std.fmt.parseInt(i64, raw, 10) catch {
        log.err("toml: line {d}: invalid integer: {s}", .{ line_num, raw });
        return ParseError.InvalidValue;
    };
    return Value{ .integer = value };
}

fn parseStringArray(alloc: std.mem.Allocator, raw: []const u8, line_num: usize) ParseError!Value {
    if (raw.len < 2 or raw[0] != '[') {
        log.err("toml: line {d}: invalid array", .{line_num});
        return ParseError.UnexpectedCharacter;
    }

    const close = std.mem.indexOfScalar(u8, raw, ']') orelse {
        log.err("toml: line {d}: unterminated array", .{line_num});
        return ParseError.UnterminatedArray;
    };

    const inner = std.mem.trim(u8, raw[1..close], " \t");
    if (inner.len == 0) {
        const empty = alloc.alloc([]const u8, 0) catch return ParseError.OutOfMemory;
        return Value{ .array = empty };
    }

    var items: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (items.items) |item| alloc.free(item);
        items.deinit(alloc);
    }

    var pos: usize = 0;
    while (pos < inner.len) {
        while (pos < inner.len and (inner[pos] == ' ' or inner[pos] == '\t' or inner[pos] == ',')) {
            pos += 1;
        }
        if (pos >= inner.len) break;

        if (inner[pos] != '"') {
            log.err("toml: line {d}: expected '\"' in array element", .{line_num});
            return ParseError.UnexpectedCharacter;
        }

        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(alloc);

        pos += 1;
        while (pos < inner.len) {
            const c = inner[pos];
            if (c == '"') {
                pos += 1;
                const duped = alloc.dupe(u8, buf.items) catch return ParseError.OutOfMemory;
                buf.deinit(alloc);
                items.append(alloc, duped) catch {
                    alloc.free(duped);
                    return ParseError.OutOfMemory;
                };
                break;
            }
            if (c == '\\') {
                pos += 1;
                if (pos >= inner.len) {
                    log.err("toml: line {d}: unterminated escape in array string", .{line_num});
                    return ParseError.UnterminatedString;
                }
                const escaped: u8 = switch (inner[pos]) {
                    '\\' => '\\',
                    '"' => '"',
                    'n' => '\n',
                    't' => '\t',
                    else => {
                        log.err("toml: line {d}: unknown escape in array string", .{line_num});
                        return ParseError.UnexpectedCharacter;
                    },
                };
                buf.append(alloc, escaped) catch return ParseError.OutOfMemory;
            } else {
                buf.append(alloc, c) catch return ParseError.OutOfMemory;
            }
            pos += 1;
        } else {
            log.err("toml: line {d}: unterminated string in array", .{line_num});
            return ParseError.UnterminatedString;
        }
    }

    const result = items.toOwnedSlice(alloc) catch return ParseError.OutOfMemory;
    return Value{ .array = result };
}
