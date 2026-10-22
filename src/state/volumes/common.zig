const std = @import("std");
const paths = @import("../../lib/paths.zig");
const spec = @import("../../manifest/spec.zig");
const names = @import("../../manifest/names.zig");

pub const VolumeError = error{
    DbError,
    OutOfMemory,
    PathTooLong,
    HomeDirNotFound,
    IoError,
    MountFailed,
    UnmountFailed,
    InvalidName,
};

pub const VolumeRecord = struct {
    name: []const u8,
    app_name: []const u8,
    driver: []const u8,
    path: []const u8,
    status: []const u8,

    pub fn deinit(self: VolumeRecord, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.app_name);
        alloc.free(self.driver);
        alloc.free(self.path);
        alloc.free(self.status);
    }
};

pub const VolumeConstraint = struct {
    driver: []const u8,
    node_id: ?[]const u8,
};

pub const VolumeLookupRow = struct {
    driver: @import("sqlite").Text,
    path: @import("sqlite").Text,
};

pub const PreparedVolume = struct {
    path_created: bool = false,
    nfs_mounted: bool = false,
};

pub fn resolveVolumePath(
    buf: *[paths.max_path]u8,
    app_name: []const u8,
    vol_name: []const u8,
    driver: spec.VolumeDriver,
) VolumeError![]const u8 {
    // managed volumes live under the data root; a traversing name would put
    // them, and later their deleteTree, anywhere on the host
    switch (driver) {
        .local, .nfs => {
            const app_ok = names.isValid(app_name) or std.mem.eql(u8, app_name, names.standalone_app);
            if (!app_ok or !names.isValid(vol_name)) return VolumeError.InvalidName;
        },
        .host, .parallel => {},
    }
    return switch (driver) {
        .local => paths.dataPathFmt(buf, "volumes/{s}/{s}", .{ app_name, vol_name }) catch |err| switch (err) {
            error.HomeDirNotFound => VolumeError.HomeDirNotFound,
            error.PathTooLong => VolumeError.PathTooLong,
        },
        .nfs => paths.dataPathFmt(buf, "mounts/nfs/{s}/{s}", .{ app_name, vol_name }) catch |err| switch (err) {
            error.HomeDirNotFound => VolumeError.HomeDirNotFound,
            error.PathTooLong => VolumeError.PathTooLong,
        },
        .host => |h| h.path,
        .parallel => |p| p.mount_path,
    };
}
