const std = @import("std");

// The debug I/O singleton deliberately uses a failing allocator. Reexec helpers
// need allocation for argv and the inherited environment, but no worker pool.
// Keep each instance local to its calling thread and leave signal handlers alone.
pub fn init() std.Io.Threaded {
    var result = std.Io.Threaded.init_single_threaded;
    result.allocator = std.heap.page_allocator;
    result.environ = .{ .process_environ = .{ .block = .{ .slice = std.mem.span(std.c.environ) } } };
    result.environ_initialized = false;
    return result;
}

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
