const std = @import("std");

pub const forwarded = [_]std.os.linux.SIG{ .HUP, .INT, .QUIT, .TERM, .USR1, .USR2, .PIPE, .ALRM, .WINCH, .CONT, .TSTP, .TTIN, .TTOU };

pub fn parse(value: []const u8) ?u8 {
    const text = if (std.mem.startsWith(u8, value, "SIG")) value[3..] else value;
    for (forwarded) |signal| {
        if (std.ascii.eqlIgnoreCase(text, @tagName(signal))) return @intCast(@intFromEnum(signal));
    }
    if (std.ascii.eqlIgnoreCase(text, "KILL")) return 9;
    if (std.fmt.parseInt(u8, text, 10)) |number| {
        if (number == 9) return number;
        for (forwarded) |signal| if (number == @intFromEnum(signal)) return number;
    } else |_| {}
    return null;
}

test "container signals accept names and supported numbers" {
    try std.testing.expectEqual(@as(?u8, 15), parse("SIGTERM"));
    try std.testing.expectEqual(@as(?u8, 10), parse("USR1"));
    try std.testing.expectEqual(@as(?u8, 9), parse("9"));
    try std.testing.expectEqual(@as(?u8, null), parse("0"));
    try std.testing.expectEqual(@as(?u8, null), parse("invalid"));
}
