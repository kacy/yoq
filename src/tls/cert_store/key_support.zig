const std = @import("std");
const platform = @import("platform");
const paths = @import("../../lib/paths.zig");
const common = @import("common.zig");

pub const KeyError = error{
    HomeDirNotFound,
    PathTooLong,
    KeyCreateFailed,
    KeyLoadFailed,
};

const ReadKeyError = error{
    NotFound,
    KeyLoadFailed,
};

pub fn secureZero(buf: []u8) void {
    std.crypto.secureZero(u8, buf);
}

pub fn loadOrCreateKey() KeyError![common.key_length]u8 {
    var path_buf: [paths.max_path]u8 = undefined;
    const key_path = paths.dataPath(&path_buf, "secrets.key") catch |err| return switch (err) {
        error.HomeDirNotFound => KeyError.HomeDirNotFound,
        error.PathTooLong => KeyError.PathTooLong,
    };

    paths.ensureDataDirStrict("") catch |err| return switch (err) {
        error.HomeDirNotFound => KeyError.HomeDirNotFound,
        error.PathTooLong => KeyError.PathTooLong,
        error.CreateFailed => KeyError.KeyCreateFailed,
    };

    if (readKeyFile(key_path)) |key| {
        return key;
    } else |err| switch (err) {
        error.NotFound => {},
        error.KeyLoadFailed => return KeyError.KeyLoadFailed,
    }

    var key: [common.key_length]u8 = undefined;
    platform.randomBytes(&key);

    saveKeyFile(key_path, &key) catch return KeyError.KeyCreateFailed;
    return key;
}

pub fn readKeyFile(path: []const u8) ReadKeyError![common.key_length]u8 {
    const file = platform.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return ReadKeyError.NotFound,
        else => return ReadKeyError.KeyLoadFailed,
    };
    defer file.close();

    var key: [common.key_length]u8 = undefined;
    const bytes_read = file.readAll(&key) catch return ReadKeyError.KeyLoadFailed;
    if (bytes_read != common.key_length) return ReadKeyError.KeyLoadFailed;

    return key;
}

pub fn saveKeyFile(path: []const u8, key: *const [common.key_length]u8) !void {
    const file = platform.cwd().createFile(path, .{ .mode = 0o600 }) catch
        return error.KeyCreateFailed;
    defer file.close();

    file.writeAll(key) catch return error.KeyCreateFailed;
}
