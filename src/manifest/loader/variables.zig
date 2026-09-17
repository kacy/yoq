const std = @import("std");
const common = @import("common.zig");

pub fn expandVariables(alloc: std.mem.Allocator, input: []const u8) common.LoadError![]const u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(alloc);

    var cursor: usize = 0;
    while (cursor < input.len) {
        if (input[cursor] != '$' or cursor + 1 == input.len) {
            result.append(alloc, input[cursor]) catch return common.LoadError.OutOfMemory;
            cursor += 1;
            continue;
        }

        if (input[cursor + 1] == '$') {
            result.append(alloc, '$') catch return common.LoadError.OutOfMemory;
            cursor += 2;
            continue;
        }

        if (input[cursor + 1] != '{') {
            result.append(alloc, '$') catch return common.LoadError.OutOfMemory;
            cursor += 1;
            continue;
        }

        const expression_start = cursor + 2;
        const closing_brace = std.mem.indexOfScalarPos(u8, input, expression_start, '}') orelse {
            result.append(alloc, '$') catch return common.LoadError.OutOfMemory;
            cursor += 1;
            continue;
        };

        const expression = input[expression_start..closing_brace];
        var variable_name = expression;
        var fallback: ?[]const u8 = null;
        if (std.mem.indexOf(u8, expression, ":-")) |separator| {
            variable_name = expression[0..separator];
            fallback = expression[separator + 2 ..];
        }

        const value = if (variable_name.len > 0)
            getEnvVarOwned(alloc, variable_name) catch return common.LoadError.OutOfMemory
        else
            null;
        defer if (value) |owned| alloc.free(owned);

        // an empty environment value takes precedence over the fallback.
        const expanded = value orelse (fallback orelse "");
        result.appendSlice(alloc, expanded) catch return common.LoadError.OutOfMemory;
        cursor = closing_brace + 1;
    }

    return result.toOwnedSlice(alloc) catch return common.LoadError.OutOfMemory;
}

fn getEnvVarOwned(alloc: std.mem.Allocator, name: []const u8) error{OutOfMemory}!?[]u8 {
    const name_z = try alloc.dupeZ(u8, name);
    defer alloc.free(name_z);

    const value = std.c.getenv(name_z.ptr) orelse return null;
    return try alloc.dupe(u8, std.mem.span(value));
}
