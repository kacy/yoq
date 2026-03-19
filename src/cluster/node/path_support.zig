const std = @import("std");

pub fn bufPrintZ(buf: []u8, comptime fmt: []const u8, args: anytype) ?[:0]const u8 {
    const slice = std.fmt.bufPrint(buf, fmt, args) catch return null;
    if (slice.len >= buf.len) return null;
    buf[slice.len] = 0;
    return buf[0..slice.len :0];
}
