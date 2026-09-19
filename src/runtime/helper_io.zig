const std = @import("std");

// Keep the runtime import path stable for existing health and volume helpers.
pub const init = @import("../lib/helper_io.zig").init;

test "runtime helper subprocess io allocates arguments and inherits environment" {
    var instance = init();
    defer instance.deinit();
    var child = try std.process.spawn(instance.io(), .{
        .argv = &.{ "/bin/sh", "-c", "test -n \"$PATH\"" },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer child.kill(instance.io());
    const result = try child.wait(instance.io());
    try std.testing.expectEqual(std.process.Child.Term{ .exited = 0 }, result);
}
