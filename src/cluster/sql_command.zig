// Encode typed values into the existing replicated SQL wire format. Templates
// are compile-time SQL; values are always literals, never SQL fragments.
const std = @import("std");

pub fn render(alloc: std.mem.Allocator, comptime template: []const u8, values: anytype) ![]u8 {
    var out = std.Io.Writer.Allocating.init(alloc);
    defer out.deinit();
    try write(&out.writer, template, values);
    return out.toOwnedSlice();
}

pub fn write(out: *std.Io.Writer, comptime template: []const u8, values: anytype) !void {
    comptime var start: usize = 0;
    inline for (values) |value| {
        const end = comptime std.mem.indexOfScalarPos(u8, template, start, '?') orelse @compileError("missing SQL parameter");
        try out.writeAll(template[start..end]);
        try literal(out, value);
        start = end + 1;
    }
    comptime if (std.mem.indexOfScalarPos(u8, template, start, '?') != null) @compileError("unbound SQL parameter");
    try out.writeAll(template[start..]);
}

fn literal(out: *std.Io.Writer, value: anytype) !void {
    switch (@typeInfo(@TypeOf(value))) {
        .null => try out.writeAll("NULL"),
        .optional => if (value) |inner| try literal(out, inner) else try out.writeAll("NULL"),
        .int, .comptime_int => {
            const signed = std.math.cast(i64, value) orelse return error.InvalidInteger;
            try out.print("{d}", .{signed});
        },
        .pointer => {
            const text: []const u8 = value;
            if (std.mem.indexOfScalar(u8, text, 0) != null) return error.InvalidString;
            try out.writeByte('\'');
            for (text) |c| {
                try out.writeByte(c);
                if (c == '\'') try out.writeByte(c);
            }
            try out.writeByte('\'');
        },
        else => @compileError("unsupported replicated SQL parameter"),
    }
}

test "replicated SQL values preserve quotes and reject unrepresentable inputs" {
    const encoded = try render(std.testing.allocator, "UPDATE deployments SET message = ?, failed_targets = ? WHERE id = ?;", .{ "it's; quoted", @as(u64, 2), @as(?[]const u8, null) });
    defer std.testing.allocator.free(encoded);
    try std.testing.expectEqualStrings("UPDATE deployments SET message = 'it''s; quoted', failed_targets = 2 WHERE id = NULL;", encoded);
    try std.testing.expectError(error.InvalidString, render(std.testing.allocator, "SELECT ?;", .{"bad\x00value"}));
    try std.testing.expectError(error.InvalidInteger, render(std.testing.allocator, "SELECT ?;", .{std.math.maxInt(u64)}));
}
