// hold selected devices until every owning container exits. lock files stay
// in place so concurrent processes always contend on the same inode.
const std = @import("std");
const platform = @import("linux_platform");
const detect = @import("detect.zig");
const paths = @import("../lib/paths.zig");
const linux = std.os.linux;

pub const Lease = struct {
    indices: [detect.max_gpus]u32 = undefined,
    files: [detect.max_gpus]std.posix.fd_t = undefined,
    count: usize = 0,

    pub fn acquire(count: u32, model: ?[]const u8) !Lease {
        return acquireWithMinimum(count, model, null);
    }

    pub fn acquireWithMinimum(count: u32, model: ?[]const u8, vram_min_mb: ?u64) !Lease {
        if (count == 0) return .{};
        var detected = detect.detect();
        defer detected.deinit();
        try paths.ensureDataDirStrict("gpu-leases");
        var path_buf: [paths.max_path]u8 = undefined;
        const path = try paths.dataPath(&path_buf, "gpu-leases");
        var dir = try std.Io.Dir.cwd().openDir(std.Options.debug_io, path, .{});
        defer dir.close(std.Options.debug_io);
        return acquireInDirWithMinimum(dir, detected.gpus[0..detected.count], count, model, vram_min_mb);
    }

    pub fn acquireInDir(dir: std.Io.Dir, gpus: []const detect.GpuInfo, count: u32, model: ?[]const u8) !Lease {
        return acquireInDirWithMinimum(dir, gpus, count, model, null);
    }

    pub fn acquireInDirWithMinimum(dir: std.Io.Dir, gpus: []const detect.GpuInfo, count: u32, model: ?[]const u8, vram_min_mb: ?u64) !Lease {
        if (count > detect.max_gpus) return error.InsufficientGpus;
        var lease: Lease = .{};
        errdefer lease.deinit();
        for (gpus) |gpu| {
            if (lease.count == count) break;
            if (vram_min_mb) |minimum| if (gpu.vram_mb < minimum) continue;
            if (model) |wanted| if (std.mem.indexOf(u8, gpu.getName(), wanted) == null) continue;
            var buf: [40]u8 = undefined;
            const name = try std.fmt.bufPrintZ(&buf, "gpu-{d}.lock", .{gpu.index});
            const opened = linux.openat(dir.handle, name, .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o600);
            if (linux.errno(opened) != .SUCCESS) return error.LockFailed;
            const fd: std.posix.fd_t = @intCast(opened);
            switch (linux.errno(linux.flock(fd, 2 | 4))) {
                .SUCCESS => {},
                .AGAIN => {
                    platform.posix.close(fd);
                    continue;
                },
                else => {
                    platform.posix.close(fd);
                    return error.LockFailed;
                },
            }
            lease.files[lease.count] = fd;
            lease.indices[lease.count] = gpu.index;
            lease.count += 1;
        }
        if (lease.count != count) return error.InsufficientGpus;
        return lease;
    }

    pub fn deinit(self: *Lease) void {
        for (self.files[0..self.count]) |fd| platform.posix.close(fd);
        self.count = 0;
    }
};

test "training gpu leases select distinct devices and release partial reservations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const devices = [_]detect.GpuInfo{ .{ .index = 3 }, .{ .index = 7 } };
    var first = try Lease.acquireInDir(tmp.dir, &devices, 1, null);
    defer first.deinit();
    try std.testing.expectEqual(@as(u32, 3), first.indices[0]);
    try std.testing.expectError(error.InsufficientGpus, Lease.acquireInDir(tmp.dir, &devices, 2, null));
    var second = try Lease.acquireInDir(tmp.dir, &devices, 1, null);
    defer second.deinit();
    try std.testing.expectEqual(@as(u32, 7), second.indices[0]);
    try std.testing.expectError(error.InsufficientGpus, Lease.acquireInDir(tmp.dir, &devices, 1, null));
    first.deinit();
    var reused = try Lease.acquireInDir(tmp.dir, &devices, 1, null);
    defer reused.deinit();
    try std.testing.expectEqual(@as(u32, 3), reused.indices[0]);
}

test "training gpu leases enforce per-device memory requirements" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const devices = [_]detect.GpuInfo{ .{ .index = 2, .vram_mb = 8192 }, .{ .index = 5, .vram_mb = 40960 } };
    var lease = try Lease.acquireInDirWithMinimum(tmp.dir, &devices, 1, null, 32768);
    defer lease.deinit();
    try std.testing.expectEqual(@as(u32, 5), lease.indices[0]);
    try std.testing.expectError(error.InsufficientGpus, Lease.acquireInDirWithMinimum(tmp.dir, &devices, 1, null, 32768));
}
