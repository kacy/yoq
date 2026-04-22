const std = @import("std");

pub const AppContext = struct {
    alloc: std.mem.Allocator,
    io: std.Io,
};
