const std = @import("std");
pub const LogError = error{
    CreateFailed,
    ReadFailed,
    WriteFailed,
    NotFound,
    PathTooLong,
    InvalidId,
};

pub const logs_subdir = "logs";
pub const max_log_size: u64 = 50 * 1024 * 1024;

pub fn writeToStdout(data: []const u8) LogError!void {
    const io = std.Options.debug_io;
    const prev = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(prev);

    var buf: [4096]u8 = undefined;
    var writer = std.Io.File.stdout().writer(io, &buf);
    writer.interface.writeAll(data) catch return LogError.WriteFailed;
    writer.interface.flush() catch return LogError.WriteFailed;
}
