const std = @import("std");
const linux_platform = @import("linux_platform");
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
    linux_platform.randomBytes(&key);

    saveKeyFile(key_path, &key) catch return KeyError.KeyCreateFailed;
    return key;
}

pub fn readKeyFile(path: []const u8) ReadKeyError![common.key_length]u8 {
    var file = std.Io.Dir.cwd().openFile(std.Options.debug_io, path, .{}) catch |err| switch (err) {
        error.FileNotFound => return ReadKeyError.NotFound,
        else => return ReadKeyError.KeyLoadFailed,
    };
    defer file.close(std.Options.debug_io);

    const stat = file.stat(std.Options.debug_io) catch return ReadKeyError.KeyLoadFailed;
    if ((stat.permissions.toMode() & 0o077) != 0) return ReadKeyError.KeyLoadFailed;

    var key: [common.key_length]u8 = undefined;
    var reader = file.reader(std.Options.debug_io, &.{});
    reader.interface.readSliceAll(&key) catch return ReadKeyError.KeyLoadFailed;

    return key;
}

pub fn keyFileExists(path: []const u8) bool {
    std.Io.Dir.cwd().access(std.Options.debug_io, path, .{}) catch return false;
    return true;
}

pub fn keyFileHasOwnerOnlyPermissions(path: []const u8) bool {
    var file = std.Io.Dir.cwd().openFile(std.Options.debug_io, path, .{}) catch return false;
    defer file.close(std.Options.debug_io);

    const stat = file.stat(std.Options.debug_io) catch return false;
    return (stat.permissions.toMode() & 0o077) == 0;
}

pub fn saveKeyFile(path: []const u8, key: *const [common.key_length]u8) !void {
    var file = std.Io.Dir.cwd().createFile(std.Options.debug_io, path, .{
        .permissions = std.Io.File.Permissions.fromMode(0o600),
        .truncate = true,
    }) catch
        return error.KeyCreateFailed;
    defer file.close(std.Options.debug_io);

    file.writeStreamingAll(std.Options.debug_io, key) catch return error.KeyCreateFailed;
    file.sync(std.Options.debug_io) catch return error.KeyCreateFailed;
}

pub fn secureZero(buf: []u8) void {
    std.crypto.secureZero(u8, buf);
}
