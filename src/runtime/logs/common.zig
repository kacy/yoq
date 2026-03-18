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
    std.fs.File.stdout().writeAll(data) catch return LogError.WriteFailed;
}
