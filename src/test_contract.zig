const std = @import("std");

pub const std_options: std.Options = .{
    .logFn = contractLogFn,
};

fn contractLogFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (scope == .sqlite and level == .err) return;
    std.log.defaultLog(level, scope, format, args);
}

test "contract smoke test" {
    try std.testing.expect(true);
}

comptime {
    _ = @import("test_contract_http.zig");
    _ = @import("test_contract_restart.zig");
    _ = @import("test_contract_s3.zig");
}
