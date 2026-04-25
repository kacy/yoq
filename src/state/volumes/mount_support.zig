const std = @import("std");
const sqlite = @import("sqlite");
const linux = std.os.linux;
const paths = @import("../../lib/paths.zig");
const log = @import("../../lib/log.zig");
const spec = @import("../../manifest/spec.zig");
const syscall_util = @import("../../lib/syscall.zig");
const common = @import("common.zig");

const ENOENT = 2;
const EBUSY = 16;
const EINVAL = 22;

pub fn prepareVolumePath(vol_path: []const u8, driver: spec.VolumeDriver) common.VolumeError!common.PreparedVolume {
    var prepared: common.PreparedVolume = .{};
    switch (driver) {
        .local => prepared.path_created = try ensurePath(vol_path, "directory"),
        .nfs => |nfs| {
            prepared.path_created = try ensurePath(vol_path, "NFS mountpoint");
            const was_mounted = isMounted(vol_path);
            mountNfs(vol_path, nfs.server, nfs.path, nfs.options) catch |err| {
                log.err("volumes: NFS mount failed for {s}: {}", .{ vol_path, err });
                if (prepared.path_created) std.Io.Dir.cwd().deleteTree(std.Options.debug_io, vol_path) catch {};
                return err;
            };
            prepared.nfs_mounted = !was_mounted;
        },
        .host => {},
        .parallel => |parallel| {
            validateParallelFs(parallel.mount_path) catch |err| {
                log.err("volumes: parallel FS validation failed for {s}: {}", .{ parallel.mount_path, err });
                return err;
            };
        },
    }
    return prepared;
}

pub fn rollbackPreparedVolume(path: []const u8, driver: spec.VolumeDriver, prepared: common.PreparedVolume) void {
    switch (driver) {
        .local => {
            if (prepared.path_created) std.Io.Dir.cwd().deleteTree(std.Options.debug_io, path) catch {};
        },
        .nfs => {
            if (prepared.nfs_mounted) unmountNfs(path) catch {};
            if (prepared.path_created) std.Io.Dir.cwd().deleteTree(std.Options.debug_io, path) catch {};
        },
        .host, .parallel => {},
    }
}

pub fn cleanupManagedVolume(driver: []const u8, path: []const u8) common.VolumeError!void {
    if (std.mem.eql(u8, driver, "nfs")) {
        unmountNfs(path) catch |err| {
            log.err("volumes: NFS unmount failed for {s}: {}", .{ path, err });
            return err;
        };
    }

    if (std.mem.eql(u8, driver, "local") or std.mem.eql(u8, driver, "nfs")) {
        std.Io.Dir.cwd().deleteTree(std.Options.debug_io, path) catch |err| {
            log.err("volumes: failed to remove directory {s}: {}", .{ path, err });
            return common.VolumeError.IoError;
        };
    }
}

pub fn pathExists(path: []const u8) bool {
    std.Io.Dir.cwd().access(std.Options.debug_io, path, .{}) catch return false;
    return true;
}

pub fn isMounted(path: []const u8) bool {
    var file = std.Io.Dir.cwd().openFile(std.Options.debug_io, "/proc/mounts", .{}) catch return false;
    defer file.close(std.Options.debug_io);

    var buf: [8192]u8 = undefined;
    var leftover_len: usize = 0;
    var reader = file.reader(std.Options.debug_io, &.{});

    while (true) {
        const bytes_read = reader.interface.readSliceShort(buf[leftover_len..]) catch return false;
        if (bytes_read == 0) {
            if (leftover_len > 0) {
                if (checkMountLine(buf[0..leftover_len], path)) return true;
            }
            break;
        }
        const total = leftover_len + bytes_read;

        var content = buf[0..total];
        while (std.mem.indexOf(u8, content, "\n")) |nl| {
            const line = content[0..nl];
            if (checkMountLine(line, path)) return true;
            content = content[nl + 1 ..];
        }

        leftover_len = content.len;
        if (leftover_len > 0) {
            std.mem.copyForwards(u8, &buf, content);
        }
    }
    return false;
}

fn checkMountLine(line: []const u8, path: []const u8) bool {
    const first_space = std.mem.indexOf(u8, line, " ") orelse return false;
    const after_device = line[first_space + 1 ..];
    const mountpoint = if (std.mem.indexOf(u8, after_device, " ")) |second_space|
        after_device[0..second_space]
    else
        after_device;
    return std.mem.eql(u8, mountpoint, path);
}

fn ensurePath(path: []const u8, label: []const u8) common.VolumeError!bool {
    const existed = pathExists(path);
    std.Io.Dir.cwd().createDirPath(std.Options.debug_io, path) catch |err| {
        log.err("volumes: failed to create {s} {s}: {}", .{ label, path, err });
        return common.VolumeError.IoError;
    };
    return !existed;
}

fn mountNfs(
    mountpoint: []const u8,
    server: []const u8,
    export_path: []const u8,
    options: ?[]const u8,
) common.VolumeError!void {
    var source_buf: [paths.max_path]u8 = undefined;
    const source_z = std.fmt.bufPrint(&source_buf, "{s}:{s}\x00", .{ server, export_path }) catch
        return common.VolumeError.PathTooLong;

    var mp_buf: [paths.max_path]u8 = undefined;
    const mp_z = std.fmt.bufPrint(&mp_buf, "{s}\x00", .{mountpoint}) catch
        return common.VolumeError.PathTooLong;

    const default_opts = "vers=4.1";
    const opts = options orelse default_opts;
    var opts_buf: [1024]u8 = undefined;
    const opts_z = std.fmt.bufPrint(&opts_buf, "{s}\x00", .{opts}) catch
        return common.VolumeError.PathTooLong;

    const fstype = "nfs4\x00";

    const rc = linux.syscall5(
        .mount,
        @intFromPtr(source_z.ptr),
        @intFromPtr(mp_z.ptr),
        @intFromPtr(fstype.ptr),
        0,
        @intFromPtr(opts_z.ptr),
    );

    if (syscall_util.isError(rc)) {
        const errno = syscall_util.getErrno(rc);
        if (errno == EBUSY) return;
        log.err("volumes: mount(2) failed for NFS {s}:{s} on {s}: errno={}", .{
            server, export_path, mountpoint, errno,
        });
        return common.VolumeError.MountFailed;
    }
}

fn unmountNfs(mountpoint: []const u8) common.VolumeError!void {
    var mp_buf: [paths.max_path]u8 = undefined;
    const mp_z = std.fmt.bufPrint(&mp_buf, "{s}\x00", .{mountpoint}) catch
        return common.VolumeError.PathTooLong;

    const MNT_DETACH = 0x00000002;
    const rc = linux.syscall2(.umount2, @intFromPtr(mp_z.ptr), MNT_DETACH);

    if (syscall_util.isError(rc)) {
        const errno = syscall_util.getErrno(rc);
        if (errno == EINVAL or errno == ENOENT) return;
        log.err("volumes: umount2 failed for {s}: errno={}", .{ mountpoint, errno });
        return common.VolumeError.UnmountFailed;
    }
}

const LUSTRE_MAGIC: u32 = 0x0BD00BD0;
const GPFS_MAGIC: u32 = 0x47504653;
const BEEGFS_MAGIC: u32 = 0x19830326;

const StatfsBuf = extern struct {
    f_type: isize,
    _pad: [120]u8 = undefined,
};

pub fn validateParallelFs(mount_path: []const u8) common.VolumeError!void {
    var path_buf: [paths.max_path]u8 = undefined;
    if (mount_path.len >= path_buf.len) return common.VolumeError.PathTooLong;
    @memcpy(path_buf[0..mount_path.len], mount_path);
    path_buf[mount_path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_buf);

    var statfs_buf: StatfsBuf = .{ .f_type = 0 };
    const rc = linux.syscall2(.statfs, @intFromPtr(path_z), @intFromPtr(&statfs_buf));

    if (syscall_util.isError(rc)) {
        log.err("volumes: statfs failed for parallel FS path {s}: errno={}", .{
            mount_path, syscall_util.getErrno(rc),
        });
        return common.VolumeError.IoError;
    }

    if (!isParallelFsMagic(statfs_buf.f_type)) {
        log.err("volumes: {s} is not a recognized parallel filesystem (f_type=0x{X})", .{
            mount_path, statfs_buf.f_type,
        });
        return common.VolumeError.MountFailed;
    }
}

pub fn isParallelFsMagic(f_type: anytype) bool {
    const magic: u32 = if (@TypeOf(f_type) == u32)
        f_type
    else
        @intCast(@as(i64, @intCast(f_type)) & 0xFFFFFFFF);
    return magic == LUSTRE_MAGIC or magic == GPFS_MAGIC or magic == BEEGFS_MAGIC;
}

pub fn driverNodeId(driver: spec.VolumeDriver, node_id: ?[]const u8) ?sqlite.Text {
    return switch (driver) {
        .local, .parallel => if (node_id) |nid| sqlite.Text{ .data = nid } else null,
        .nfs, .host => null,
    };
}
