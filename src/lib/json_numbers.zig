const std = @import("std");

pub const Error = error{InvalidRequest};

/// Numeric fields default only when absent. Explicit null, strings, fractions,
/// exponent notation, and values outside the destination range are rejected.
pub fn optional(comptime T: type, object: std.json.Value, key: []const u8, min: T, max: T) Error!?T {
    if (object != .object) return error.InvalidRequest;
    const value = object.object.get(key) orelse return null;
    const number = switch (value) {
        .integer => |n| std.math.cast(T, n) orelse return error.InvalidRequest,
        .number_string => |n| std.fmt.parseInt(T, n, 10) catch return error.InvalidRequest,
        else => return error.InvalidRequest,
    };
    if (number < min or number > max) return error.InvalidRequest;
    return number;
}

pub fn field(comptime T: type, object: std.json.Value, key: []const u8, min: T, max: T, default: T) Error!T {
    return (try optional(T, object, key, min, max)) orelse default;
}

pub fn parse(alloc: std.mem.Allocator, json: []const u8) !std.json.Parsed(std.json.Value) {
    // Keep the original numeric token so fractions cannot be rounded to an integer.
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, json, .{ .parse_numbers = false });
    errdefer parsed.deinit();
    if (parsed.value != .object) return error.InvalidRequest;
    return parsed;
}
