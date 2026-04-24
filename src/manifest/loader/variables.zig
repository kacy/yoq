const std = @import("std");
const common = @import("common.zig");

pub fn expandVariables(alloc: std.mem.Allocator, input: []const u8) common.LoadError![]const u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(alloc);

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '$') {
            if (i + 1 < input.len and input[i + 1] == '$') {
                result.append(alloc, '$') catch return common.LoadError.OutOfMemory;
                i += 2;
                continue;
            }

            if (i + 1 < input.len and input[i + 1] == '{') {
                const start = i + 2;
                const close = std.mem.indexOfScalarPos(u8, input, start, '}') orelse {
                    result.append(alloc, '$') catch return common.LoadError.OutOfMemory;
                    i += 1;
                    continue;
                };

                const content = input[start..close];
                var var_name: []const u8 = content;
                var default_value: ?[]const u8 = null;

                if (std.mem.indexOf(u8, content, ":-")) |sep| {
                    var_name = content[0..sep];
                    default_value = content[sep + 2 ..];
                }

                const value = if (var_name.len > 0)
                    getEnvVarOwned(alloc, var_name) catch return common.LoadError.OutOfMemory
                else
                    null;
                defer if (value) |owned| alloc.free(owned);

                const expanded = value orelse (default_value orelse "");
                result.appendSlice(alloc, expanded) catch return common.LoadError.OutOfMemory;
                i = close + 1;
                continue;
            }

            result.append(alloc, '$') catch return common.LoadError.OutOfMemory;
            i += 1;
        } else {
            result.append(alloc, input[i]) catch return common.LoadError.OutOfMemory;
            i += 1;
        }
    }

    return result.toOwnedSlice(alloc) catch return common.LoadError.OutOfMemory;
}

fn getEnvVarOwned(alloc: std.mem.Allocator, name: []const u8) error{OutOfMemory}!?[]u8 {
    const name_z = try alloc.dupeZ(u8, name);
    defer alloc.free(name_z);

    const value = std.c.getenv(name_z.ptr) orelse return null;
    return try alloc.dupe(u8, std.mem.span(value));
}
