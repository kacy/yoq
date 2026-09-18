const std = @import("std");
const spec = @import("../../image/spec.zig");
const types = @import("types.zig");
const command_config = @import("command_config.zig");

/// Store the image's healthcheck object, including its execution form and timing.
pub fn parse(alloc: std.mem.Allocator, input: []const u8) types.BuildError![]const u8 {
    var remaining = std.mem.trim(u8, input, " \t");
    var config: spec.Healthcheck = .{};
    while (std.mem.startsWith(u8, remaining, "--")) {
        const end = std.mem.indexOfAny(u8, remaining, " \t") orelse return error.MetadataFailed;
        const option = remaining[0..end];
        const eq = std.mem.indexOfScalar(u8, option, '=') orelse return error.MetadataFailed;
        const key = option[0..eq];
        const value = option[eq + 1 ..];
        if (std.mem.eql(u8, key, "--retries")) {
            const retries = std.fmt.parseInt(i64, value, 10) catch return error.MetadataFailed;
            if (retries <= 0) return error.MetadataFailed;
            config.Retries = retries;
        } else {
            const ns = try duration(value);
            if (std.mem.eql(u8, key, "--interval")) config.Interval = ns else if (std.mem.eql(u8, key, "--timeout")) config.Timeout = ns else if (std.mem.eql(u8, key, "--start-period")) config.StartPeriod = ns else if (std.mem.eql(u8, key, "--start-interval")) config.StartInterval = ns else return error.MetadataFailed;
        }
        remaining = std.mem.trimStart(u8, remaining[end..], " \t");
    }
    if (std.mem.eql(u8, remaining, "NONE")) {
        config.Test = &.{"NONE"};
        return std.json.Stringify.valueAlloc(alloc, config, .{ .emit_null_optional_fields = false });
    }
    if (!std.mem.startsWith(u8, remaining, "CMD ") and !std.mem.startsWith(u8, remaining, "CMD\t")) return error.MetadataFailed;
    remaining = std.mem.trimStart(u8, remaining[3..], " \t");
    if (remaining.len == 0) return error.MetadataFailed;
    if (remaining[0] != '[') {
        config.Test = &.{ "CMD-SHELL", remaining };
        return std.json.Stringify.valueAlloc(alloc, config, .{ .emit_null_optional_fields = false });
    }
    const argv = try command_config.parse(alloc, remaining, null);
    defer command_config.free(alloc, argv);
    if (argv.len == 0) return error.MetadataFailed;
    const test_args = try alloc.alloc([]const u8, argv.len + 1);
    defer alloc.free(test_args);
    test_args[0] = "CMD";
    @memcpy(test_args[1..], argv);
    config.Test = test_args;
    return std.json.Stringify.valueAlloc(alloc, config, .{ .emit_null_optional_fields = false });
}

fn duration(value: []const u8) types.BuildError!i64 {
    var offset: usize = 0;
    var total: f64 = 0;
    while (offset < value.len) {
        const start = offset;
        while (offset < value.len and (std.ascii.isDigit(value[offset]) or value[offset] == '.')) : (offset += 1) {}
        if (offset == start) return error.MetadataFailed;
        const number = std.fmt.parseFloat(f64, value[start..offset]) catch return error.MetadataFailed;
        const unit_start = offset;
        while (offset < value.len and std.ascii.isAlphabetic(value[offset])) : (offset += 1) {}
        const unit = value[unit_start..offset];
        const multiplier: f64 = if (std.mem.eql(u8, unit, "ns")) 1 else if (std.mem.eql(u8, unit, "us")) 1_000 else if (std.mem.eql(u8, unit, "ms")) 1_000_000 else if (std.mem.eql(u8, unit, "s")) 1_000_000_000 else if (std.mem.eql(u8, unit, "m")) 60_000_000_000 else if (std.mem.eql(u8, unit, "h")) 3_600_000_000_000 else return error.MetadataFailed;
        total += number * multiplier;
    }
    if (!std.math.isFinite(total) or total < 1 or total >= 9223372036854775808.0) return error.MetadataFailed;
    return @intFromFloat(total);
}
