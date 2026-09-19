const std = @import("std");

// The debug I/O singleton deliberately uses a failing allocator. Subprocesses
// need allocation for argv and the inherited environment, but no worker pool.
// Keep each instance local to its calling thread and leave signal handlers alone.
pub fn init() std.Io.Threaded {
    var result = std.Io.Threaded.init_single_threaded;
    result.allocator = std.heap.page_allocator;
    result.environ = .{ .process_environ = .{ .block = .{ .slice = std.mem.span(std.c.environ) } } };
    result.environ_initialized = false;
    return result;
}
