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

test "variable expansion keeps escapes and fallback text literal" {
    const alloc = std.testing.allocator;
    const cases = [_]struct { input: []const u8, expected: []const u8 }{
        .{ .input = "$${:-fallback}", .expected = "${:-fallback}" },
        .{ .input = "$$${:-fallback}", .expected = "$fallback" },
        .{ .input = "${:-$$}", .expected = "$$" },
        .{ .input = "${:-first:-second}", .expected = "first:-second" },
        .{ .input = "${unclosed $$ tail$", .expected = "${unclosed $ tail$" },
        .{ .input = "${:-left}${:-right}", .expected = "leftright" },
    };

    for (cases) |case| {
        const expanded = try expandVariables(alloc, case.input);
        defer alloc.free(expanded);
        try std.testing.expectEqualStrings(case.expected, expanded);
    }
}

test "variable expansion uses fallback only when the environment value is absent" {
    const env = struct {
        extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
        extern "c" fn unsetenv(name: [*:0]const u8) c_int;
    };
    const alloc = std.testing.allocator;
    const name = "YOQ_TEST_VARIABLE_EXPANSION_EMPTY_VALUE";
    const original = if (std.c.getenv(name)) |value|
        try alloc.dupeZ(u8, std.mem.span(value))
    else
        null;
    defer if (original) |value| alloc.free(value);
    defer {
        if (original) |value| {
            _ = env.setenv(name, value.ptr, 1);
        } else {
            _ = env.unsetenv(name);
        }
    }

    try std.testing.expectEqual(@as(c_int, 0), env.setenv(name, "", 1));
    const empty = try expandVariables(alloc, "${" ++ name ++ ":-fallback}");
    defer alloc.free(empty);
    try std.testing.expectEqualStrings("", empty);

    try std.testing.expectEqual(@as(c_int, 0), env.unsetenv(name));
    const absent = try expandVariables(alloc, "${" ++ name ++ ":-fallback}");
    defer alloc.free(absent);
    try std.testing.expectEqualStrings("fallback", absent);
}

test "variable expansion releases allocations on failure" {
    const check = struct {
        fn expand(alloc: std.mem.Allocator) !void {
            const expanded = try expandVariables(alloc, "before ${PATH:-} $$ ${:-fallback} after");
            defer alloc.free(expanded);

            const prefix = "before ";
            const suffix = " $ fallback after";
            const path = if (std.c.getenv("PATH")) |value| std.mem.span(value) else "";
            try std.testing.expect(std.mem.startsWith(u8, expanded, prefix));
            try std.testing.expect(std.mem.endsWith(u8, expanded, suffix));
            try std.testing.expectEqualStrings(path, expanded[prefix.len .. expanded.len - suffix.len]);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, check.expand, .{});
}
