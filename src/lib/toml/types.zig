const std = @import("std");

pub const ParseError = error{
    UnexpectedCharacter,
    UnterminatedString,
    UnterminatedArray,
    InvalidValue,
    DuplicateKey,
    InvalidTableHeader,
    EmptyKey,
    OutOfMemory,
};

pub const max_table_depth = 64;

pub const Value = union(enum) {
    string: []const u8,
    integer: i64,
    boolean: bool,
    array: []const []const u8,
    table: *Table,
};

pub const Table = struct {
    entries: std.StringArrayHashMapUnmanaged(Value),

    pub fn getString(self: *const Table, key: []const u8) ?[]const u8 {
        const val = self.entries.get(key) orelse return null;
        return switch (val) {
            .string => |s| s,
            else => null,
        };
    }

    pub fn getInt(self: *const Table, key: []const u8) ?i64 {
        const val = self.entries.get(key) orelse return null;
        return switch (val) {
            .integer => |i| i,
            else => null,
        };
    }

    pub fn getBool(self: *const Table, key: []const u8) ?bool {
        const val = self.entries.get(key) orelse return null;
        return switch (val) {
            .boolean => |b| b,
            else => null,
        };
    }

    pub fn getArray(self: *const Table, key: []const u8) ?[]const []const u8 {
        const val = self.entries.get(key) orelse return null;
        return switch (val) {
            .array => |arr| arr,
            else => null,
        };
    }

    pub fn getTable(self: *const Table, key: []const u8) ?*Table {
        const val = self.entries.get(key) orelse return null;
        return switch (val) {
            .table => |table| table,
            else => null,
        };
    }

    pub fn deinit(self: *Table, alloc: std.mem.Allocator) void {
        for (self.entries.keys(), self.entries.values()) |key, val| {
            switch (val) {
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
            alloc.free(key);
        }
        self.entries.deinit(alloc);
    }
};

pub const ParseResult = struct {
    root: Table,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *ParseResult) void {
        self.root.deinit(self.alloc);
    }
};
