const std = @import("std");
const log = @import("log.zig");

pub const Error = error{SleepInterrupted};

pub fn sleep(duration: std.Io.Duration, comptime context: []const u8) bool {
    return sleepWithIo(std.Options.debug_io, duration, context);
}

pub fn sleepWithIo(io: std.Io, duration: std.Io.Duration, comptime context: []const u8) bool {
    std.Io.sleep(io, duration, .awake) catch |err| {
        log.warn("{s}: sleep interrupted: {}", .{ context, err });
        return false;
    };
    return true;
}

pub fn sleepOrError(duration: std.Io.Duration, comptime context: []const u8) Error!void {
    if (!sleep(duration, context)) return error.SleepInterrupted;
}

pub fn sleepWithIoOrError(io: std.Io, duration: std.Io.Duration, comptime context: []const u8) Error!void {
    if (!sleepWithIo(io, duration, context)) return error.SleepInterrupted;
}
