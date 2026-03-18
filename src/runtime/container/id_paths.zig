const std = @import("std");
const paths = @import("../../lib/paths.zig");

pub const ContainerId = [12]u8;

pub const OverlayDirs = struct {
    upper: [paths.max_path]u8,
    upper_len: usize,
    work: [paths.max_path]u8,
    work_len: usize,
    merged: [paths.max_path]u8,
    merged_len: usize,

    pub fn upperPath(self: *const OverlayDirs) []const u8 {
        return self.upper[0..self.upper_len];
    }

    pub fn workPath(self: *const OverlayDirs) []const u8 {
        return self.work[0..self.work_len];
    }

    pub fn mergedPath(self: *const OverlayDirs) []const u8 {
        return self.merged[0..self.merged_len];
    }
};

pub fn isValidContainerId(id: []const u8) bool {
    if (id.len != 12) return false;
    for (id) |c| {
        switch (c) {
            '0'...'9', 'a'...'f' => {},
            else => return false,
        }
    }
    return true;
}

pub fn validateContainerId(id: []const u8) error{InvalidId}!ContainerId {
    if (!isValidContainerId(id)) return error.InvalidId;
    var result: ContainerId = undefined;
    @memcpy(&result, id);
    return result;
}

pub fn createContainerDirs(containers_subdir: []const u8, container_id: []const u8) error{ CreateFailed, InvalidId }!OverlayDirs {
    if (!isValidContainerId(container_id)) return error.InvalidId;

    var dirs: OverlayDirs = .{
        .upper = undefined,
        .upper_len = 0,
        .work = undefined,
        .work_len = 0,
        .merged = undefined,
        .merged_len = 0,
    };

    const upper_slice = paths.dataPathFmt(&dirs.upper, "{s}/{s}/upper", .{
        containers_subdir, container_id,
    }) catch return error.CreateFailed;
    dirs.upper_len = upper_slice.len;

    const work_slice = paths.dataPathFmt(&dirs.work, "{s}/{s}/work", .{
        containers_subdir, container_id,
    }) catch return error.CreateFailed;
    dirs.work_len = work_slice.len;

    const merged_slice = paths.dataPathFmt(&dirs.merged, "{s}/{s}/rootfs", .{
        containers_subdir, container_id,
    }) catch return error.CreateFailed;
    dirs.merged_len = merged_slice.len;

    std.fs.cwd().makePath(dirs.upperPath()) catch return error.CreateFailed;
    std.fs.cwd().makePath(dirs.workPath()) catch return error.CreateFailed;
    std.fs.cwd().makePath(dirs.mergedPath()) catch return error.CreateFailed;

    return dirs;
}

pub fn cleanupContainerDirs(containers_subdir: []const u8, container_id: []const u8) void {
    if (!isValidContainerId(container_id)) return;

    var path_buf: [paths.max_path]u8 = undefined;
    const dir_path = paths.dataPathFmt(&path_buf, "{s}/{s}", .{
        containers_subdir, container_id,
    }) catch return;

    std.fs.cwd().deleteTree(dir_path) catch {};
}

pub fn generateId(containers_subdir: []const u8, buf: *ContainerId) error{IdGenerationFailed}!void {
    const chars = "0123456789abcdef";
    const max_collision_attempts: u32 = 10;

    var collision_count: u32 = 0;
    while (collision_count < max_collision_attempts) : (collision_count += 1) {
        var bytes: [6]u8 = undefined;
        std.crypto.random.bytes(&bytes);

        for (bytes, 0..) |b, i| {
            buf[i * 2] = chars[b >> 4];
            buf[i * 2 + 1] = chars[b & 0x0f];
        }

        var path_buf: [paths.max_path]u8 = undefined;
        const dir_path = paths.dataPathFmt(&path_buf, "{s}/{s}", .{
            containers_subdir, buf,
        }) catch continue;

        std.fs.cwd().access(dir_path, .{}) catch return;
    }

    const now = std.time.timestamp();
    var counter: u16 = 0;
    while (counter < 1000) : (counter += 1) {
        const unique_val: u64 = @as(u64, @intCast(now)) << 16 | counter;
        var bytes: [6]u8 = undefined;
        bytes[0] = @intCast((unique_val >> 40) & 0xFF);
        bytes[1] = @intCast((unique_val >> 32) & 0xFF);
        bytes[2] = @intCast((unique_val >> 24) & 0xFF);
        bytes[3] = @intCast((unique_val >> 16) & 0xFF);
        bytes[4] = @intCast((unique_val >> 8) & 0xFF);
        bytes[5] = @intCast(unique_val & 0xFF);

        for (bytes, 0..) |b, i| {
            buf[i * 2] = chars[b >> 4];
            buf[i * 2 + 1] = chars[b & 0x0f];
        }

        var path_buf: [paths.max_path]u8 = undefined;
        const dir_path = paths.dataPathFmt(&path_buf, "{s}/{s}", .{
            containers_subdir, buf,
        }) catch continue;

        std.fs.cwd().access(dir_path, .{}) catch return;
    }

    return error.IdGenerationFailed;
}
