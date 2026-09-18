const std = @import("std");

pub fn nanoseconds(value: []const u8) error{InvalidDuration}!i64 {
    var offset: usize = 0;
    var total: f64 = 0;
    while (offset < value.len) {
        const start = offset;
        while (offset < value.len and (std.ascii.isDigit(value[offset]) or value[offset] == '.')) : (offset += 1) {}
        if (offset == start) return error.InvalidDuration;
        const number = std.fmt.parseFloat(f64, value[start..offset]) catch return error.InvalidDuration;
        const unit_start = offset;
        while (offset < value.len and std.ascii.isAlphabetic(value[offset])) : (offset += 1) {}
        const unit = value[unit_start..offset];
        const multiplier: f64 = if (std.mem.eql(u8, unit, "ns")) 1 else if (std.mem.eql(u8, unit, "us")) 1_000 else if (std.mem.eql(u8, unit, "ms")) 1_000_000 else if (std.mem.eql(u8, unit, "s")) 1_000_000_000 else if (std.mem.eql(u8, unit, "m")) 60_000_000_000 else if (std.mem.eql(u8, unit, "h")) 3_600_000_000_000 else return error.InvalidDuration;
        total += number * multiplier;
    }
    if (!std.math.isFinite(total) or total < 1 or total >= 9223372036854775808.0) return error.InvalidDuration;
    return @intFromFloat(total);
}
