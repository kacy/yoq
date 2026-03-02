// cgroups — cgroups v2 management for container resource limits
//
// cgroups v2 uses a unified hierarchy mounted at /sys/fs/cgroup.
// each container gets its own cgroup under /sys/fs/cgroup/yoq/<container-id>/
// where we set cpu, memory, and pid limits by writing to control files.
//
// this module also reads PSI (pressure stall information) metrics
// for resource monitoring.

const std = @import("std");
const linux = std.os.linux;

pub const CgroupError = error{
    CreateFailed,
    WriteFailed,
    ReadFailed,
    DeleteFailed,
    NotSupported,
    InvalidLimit,
};

/// resource limits for a container's cgroup
pub const ResourceLimits = struct {
    /// cpu weight (1-10000, default 100). relative to other cgroups.
    cpu_weight: ?u16 = null,

    /// max cpu bandwidth as microseconds per period.
    /// e.g. 50000/100000 = 50% of one core.
    cpu_max_usec: ?u64 = null,
    cpu_max_period: u64 = 100_000,

    /// memory limit in bytes. container gets OOM killed if exceeded.
    memory_max: ?u64 = null,

    /// memory high watermark in bytes. triggers reclaim pressure.
    memory_high: ?u64 = null,

    /// max number of processes/threads.
    pids_max: ?u32 = null,
};

/// PSI (pressure stall information) metrics
pub const PsiMetrics = struct {
    /// percentage of time at least some tasks are stalled (avg10)
    some_avg10: f64,
    /// percentage of time all tasks are stalled (avg10)
    full_avg10: f64,
};

const cgroup_root = "/sys/fs/cgroup";
const yoq_prefix = "yoq";

/// a handle to a container's cgroup
pub const Cgroup = struct {
    path_buf: [256]u8,
    path_len: usize,

    /// create a new cgroup for the given container id.
    /// creates the directory under /sys/fs/cgroup/yoq/<id>/
    pub fn create(container_id: []const u8) CgroupError!Cgroup {
        var cg: Cgroup = .{ .path_buf = undefined, .path_len = 0 };

        const formatted = std.fmt.bufPrint(&cg.path_buf, cgroup_root ++ "/" ++ yoq_prefix ++ "/{s}", .{container_id}) catch
            return CgroupError.CreateFailed;
        cg.path_len = formatted.len;

        // create yoq parent dir if needed
        std.fs.cwd().makeDir(cgroup_root ++ "/" ++ yoq_prefix) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return CgroupError.CreateFailed,
        };

        // create container cgroup dir
        std.fs.cwd().makeDir(formatted) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return CgroupError.CreateFailed,
        };

        return cg;
    }

    /// apply resource limits to this cgroup
    pub fn setLimits(self: *const Cgroup, limits: ResourceLimits) CgroupError!void {
        if (limits.cpu_weight) |weight| {
            if (weight < 1 or weight > 10000) return CgroupError.InvalidLimit;
            self.writeFile("cpu.weight", &intToStr(weight)) catch return CgroupError.WriteFailed;
        }

        if (limits.cpu_max_usec) |max_usec| {
            var buf: [64]u8 = undefined;
            const val = std.fmt.bufPrint(&buf, "{d} {d}", .{ max_usec, limits.cpu_max_period }) catch
                return CgroupError.WriteFailed;
            self.writeFile("cpu.max", val) catch return CgroupError.WriteFailed;
        }

        if (limits.memory_max) |max| {
            self.writeFile("memory.max", &intToStr(max)) catch return CgroupError.WriteFailed;
        }

        if (limits.memory_high) |high| {
            self.writeFile("memory.high", &intToStr(high)) catch return CgroupError.WriteFailed;
        }

        if (limits.pids_max) |max| {
            self.writeFile("pids.max", &intToStr(max)) catch return CgroupError.WriteFailed;
        }
    }

    /// add a process to this cgroup
    pub fn addProcess(self: *const Cgroup, pid: std.posix.pid_t) CgroupError!void {
        self.writeFile("cgroup.procs", &intToStr(pid)) catch return CgroupError.WriteFailed;
    }

    /// read memory usage in bytes
    pub fn memoryUsage(self: *const Cgroup) CgroupError!u64 {
        return self.readU64("memory.current");
    }

    /// read cpu usage in microseconds
    pub fn cpuUsage(self: *const Cgroup) CgroupError!u64 {
        // cpu.stat contains "usage_usec <value>\n..."
        var buf: [512]u8 = undefined;
        const content = self.readFile("cpu.stat", &buf) catch return CgroupError.ReadFailed;

        // parse "usage_usec <value>"
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "usage_usec ")) {
                const val_str = line["usage_usec ".len..];
                return std.fmt.parseInt(u64, val_str, 10) catch return CgroupError.ReadFailed;
            }
        }
        return CgroupError.ReadFailed;
    }

    /// read PSI memory pressure metrics
    pub fn memoryPressure(self: *const Cgroup) CgroupError!PsiMetrics {
        return self.readPsi("memory.pressure");
    }

    /// read PSI cpu pressure metrics
    pub fn cpuPressure(self: *const Cgroup) CgroupError!PsiMetrics {
        return self.readPsi("cpu.pressure");
    }

    /// remove this cgroup. the cgroup must have no processes.
    pub fn destroy(self: *const Cgroup) CgroupError!void {
        std.fs.cwd().deleteDir(self.path()) catch return CgroupError.DeleteFailed;
    }

    /// get the cgroup path as a string
    pub fn path(self: *const Cgroup) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    // -- internal helpers --

    fn writeFile(self: *const Cgroup, filename: []const u8, value: []const u8) !void {
        var path_buf: [512]u8 = undefined;
        const file_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ self.path(), filename }) catch return error.WriteFailed;

        const file = std.fs.cwd().openFile(file_path, .{ .mode = .write_only }) catch return error.WriteFailed;
        defer file.close();

        file.writeAll(value) catch return error.WriteFailed;
    }

    fn readFile(self: *const Cgroup, filename: []const u8, buf: []u8) ![]const u8 {
        var path_buf: [512]u8 = undefined;
        const file_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ self.path(), filename }) catch return error.ReadFailed;

        const file = std.fs.cwd().openFile(file_path, .{}) catch return error.ReadFailed;
        defer file.close();

        const n = file.readAll(buf) catch return error.ReadFailed;
        return std.mem.trimRight(u8, buf[0..n], "\n ");
    }

    fn readU64(self: *const Cgroup, filename: []const u8) CgroupError!u64 {
        var buf: [64]u8 = undefined;
        const content = self.readFile(filename, &buf) catch return CgroupError.ReadFailed;
        return std.fmt.parseInt(u64, content, 10) catch return CgroupError.ReadFailed;
    }

    fn readPsi(self: *const Cgroup, filename: []const u8) CgroupError!PsiMetrics {
        var buf: [512]u8 = undefined;
        const content = self.readFile(filename, &buf) catch return CgroupError.ReadFailed;

        var metrics: PsiMetrics = .{ .some_avg10 = 0.0, .full_avg10 = 0.0 };
        var lines = std.mem.splitScalar(u8, content, '\n');

        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "some ")) {
                metrics.some_avg10 = parsePsiAvg10(line) catch return CgroupError.ReadFailed;
            } else if (std.mem.startsWith(u8, line, "full ")) {
                metrics.full_avg10 = parsePsiAvg10(line) catch return CgroupError.ReadFailed;
            }
        }

        return metrics;
    }
};

/// parse the avg10 value from a PSI line like "some avg10=0.00 avg60=0.00 avg300=0.00 total=0"
fn parsePsiAvg10(line: []const u8) !f64 {
    const prefix = "avg10=";
    const start = std.mem.indexOf(u8, line, prefix) orelse return error.ParseError;
    const val_start = start + prefix.len;
    const val_end = std.mem.indexOfScalarPos(u8, line, val_start, ' ') orelse line.len;
    return std.fmt.parseFloat(f64, line[val_start..val_end]) catch return error.ParseError;
}

/// format a number into a decimal string.
/// returns a slice into the provided buffer.
fn intToStr(value: anytype) [20]u8 {
    var buf: [20]u8 = .{0} ** 20;
    _ = std.fmt.bufPrint(&buf, "{d}", .{value}) catch {};
    return buf;
}

// -- tests --

test "resource limits defaults" {
    const limits: ResourceLimits = .{};
    try std.testing.expect(limits.cpu_weight == null);
    try std.testing.expect(limits.memory_max == null);
    try std.testing.expect(limits.pids_max == null);
    try std.testing.expectEqual(@as(u64, 100_000), limits.cpu_max_period);
}

test "resource limits validation" {
    var cg: Cgroup = .{ .path_buf = undefined, .path_len = 0 };
    const written = std.fmt.bufPrint(&cg.path_buf, "/tmp/test-cg", .{}) catch unreachable;
    cg.path_len = written.len;

    // weight out of range
    const result = cg.setLimits(.{ .cpu_weight = 0 });
    try std.testing.expectError(CgroupError.InvalidLimit, result);

    const result2 = cg.setLimits(.{ .cpu_weight = 10001 });
    try std.testing.expectError(CgroupError.InvalidLimit, result2);
}

test "intToStr" {
    const buf = intToStr(@as(u64, 12345));
    const str = std.mem.sliceTo(&buf, 0);
    try std.testing.expectEqualStrings("12345", str);
}

test "parsePsiAvg10" {
    const val = try parsePsiAvg10("some avg10=1.50 avg60=0.00 avg300=0.00 total=0");
    try std.testing.expectApproxEqAbs(@as(f64, 1.50), val, 0.001);
}
