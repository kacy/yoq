const std = @import("std");
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

    if (keyFileExists(key_path)) {
        if (!keyFileHasOwnerOnlyPermissions(key_path)) return KeyError.KeyLoadFailed;
        return readKeyFile(key_path) catch |err| switch (err) {
            error.NotFound => KeyError.KeyLoadFailed,
            error.KeyLoadFailed => KeyError.KeyLoadFailed,
        };
    }

    var key: [common.key_length]u8 = undefined;
    std.crypto.random.bytes(&key);

    saveKeyFile(key_path, &key) catch return KeyError.KeyCreateFailed;
    return key;
}

pub fn readKeyFile(path: []const u8) ReadKeyError![common.key_length]u8 {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return ReadKeyError.NotFound,
        else => return ReadKeyError.KeyLoadFailed,
    };
    defer file.close();

    const stat = file.stat() catch return ReadKeyError.KeyLoadFailed;
    if ((stat.mode & 0o077) != 0) return ReadKeyError.KeyLoadFailed;

    var key: [common.key_length]u8 = undefined;
    const bytes_read = file.readAll(&key) catch return ReadKeyError.KeyLoadFailed;
    if (bytes_read != common.key_length) return ReadKeyError.KeyLoadFailed;

    return key;
}

pub fn keyFileExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

pub fn keyFileHasOwnerOnlyPermissions(path: []const u8) bool {
    const file = std.fs.cwd().openFile(path, .{}) catch return false;
    defer file.close();

    const stat = file.stat() catch return false;
    return (stat.mode & 0o077) == 0;
}

pub fn saveKeyFile(path: []const u8, key: *const [common.key_length]u8) !void {
    const file = std.fs.cwd().createFile(path, .{ .mode = 0o600 }) catch
        return error.KeyCreateFailed;
    defer file.close();

    file.writeAll(key) catch return error.KeyCreateFailed;
    file.sync() catch return error.KeyCreateFailed;
}

pub fn secureZero(buf: []u8) void {
    std.crypto.secureZero(u8, buf);
}
