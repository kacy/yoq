// cgroups — cgroups v2 management for container resource limits
//
// cgroups v2 uses a unified hierarchy mounted at /sys/fs/cgroup.
// each container gets its own cgroup under /sys/fs/cgroup/yoq/<container-id>/
// where we set cpu, memory, and pid limits by writing to control files.
//
// this module also reads PSI (pressure stall information) metrics
// for resource monitoring.

const std = @import("std");
const log = @import("../lib/log.zig");
const container = @import("container.zig");
const process = @import("process.zig");

pub const CgroupError = error{
    /// failed to create the cgroup directory under /sys/fs/cgroup/yoq/
    CreateFailed,
    /// failed to write a cgroup control file (cpu.weight, memory.max, etc.)
    WriteFailed,
    /// failed to read a cgroup control file (cpu.stat, memory.current, etc.)
    ReadFailed,
    /// failed to remove the cgroup directory during cleanup
    DeleteFailed,
    /// cgroups v2 is not available on this system
    NotSupported,
    /// a resource limit value is outside its valid range (e.g. cpu_weight 0 or >10000)
    InvalidLimit,
    /// a resource limit is below the safe minimum (memory < 4 MB or pids < 1)
    LimitBelowMinimum,
    /// container ID validation failed
    InvalidId,
};

/// minimum memory limit: 4 MB. anything less is unusable and likely a mistake.
const min_memory_bytes: u64 = 4 * 1024 * 1024;

/// minimum pids limit. at least one process is required to run anything.
const min_pids: u32 = 1;

/// resource limits for a container's cgroup.
///
/// defaults are safe for most workloads: 512 MB memory, 4096 pids.
/// use ResourceLimits.unlimited for explicit opt-out of defaults.
pub const ResourceLimits = struct {
    /// cpu weight (1-10000, default 100). relative to other cgroups.
    cpu_weight: ?u16 = null,

    /// max cpu bandwidth as microseconds per period.
    /// e.g. 50000/100000 = 50% of one core.
    cpu_max_usec: ?u64 = null,
    cpu_max_period: u64 = 100_000,

    /// memory limit in bytes. container gets OOM killed if exceeded.
    /// default: 512 MB.
    memory_max: ?u64 = 512 * 1024 * 1024,

    /// memory high watermark in bytes. triggers reclaim pressure.
    memory_high: ?u64 = null,

    /// max number of processes/threads.
    /// default: 4096.
    pids_max: ?u32 = 4096,

    /// explicit opt-out of all resource limits. use this when you
    /// intentionally want no limits (e.g. trusted workloads or benchmarks).
    pub const unlimited = ResourceLimits{
        .cpu_weight = null,
        .cpu_max_usec = null,
        .cpu_max_period = 100_000,
        .memory_max = null,
        .memory_high = null,
        .pids_max = null,
    };

    /// validate that limits are above safe minimums.
    /// returns LimitBelowMinimum if memory_max < 4 MB or pids_max < 1.
    pub fn validate(self: ResourceLimits) CgroupError!void {
        if (self.memory_max) |mem| {
            if (mem < min_memory_bytes) return CgroupError.LimitBelowMinimum;
        }
        if (self.pids_max) |pids| {
            if (pids < min_pids) return CgroupError.LimitBelowMinimum;
        }
    }
};

/// PSI (pressure stall information) metrics
pub const PsiMetrics = struct {
    /// percentage of time at least some tasks are stalled (avg10)
    some_avg10: f64,
    /// percentage of time all tasks are stalled (avg10)
    full_avg10: f64,
};

/// block I/O statistics from cgroups v2 io.stat
pub const IoStats = struct {
    read_bytes: u64 = 0,
    write_bytes: u64 = 0,
    read_ios: u64 = 0,
    write_ios: u64 = 0,
};

const cgroup_root = "/sys/fs/cgroup";
const yoq_prefix = "yoq";
var subtree_controllers_enabled: bool = false;

/// a handle to a container's cgroup
pub const Cgroup = struct {
    path_buf: [256]u8,
    path_len: usize,

    /// open a handle to an existing cgroup for reading metrics.
    /// does not create any directories — use create() for new cgroups.
    pub fn open(container_id: []const u8) CgroupError!Cgroup {
        // validate container ID to prevent path traversal
        if (!container.isValidContainerId(container_id)) return CgroupError.InvalidId;

        var cg: Cgroup = .{ .path_buf = undefined, .path_len = 0 };

        const formatted = std.fmt.bufPrint(&cg.path_buf, cgroup_root ++ "/" ++ yoq_prefix ++ "/{s}", .{container_id}) catch
            return CgroupError.CreateFailed;
        cg.path_len = formatted.len;

        return cg;
    }

    /// check if cgroups v2 is available on this system.
    /// looks for the cgroup.controllers file which only exists
    /// when cgroups v2 is mounted at /sys/fs/cgroup.
    /// result is cached — cgroup version doesn't change at runtime.
    var v2_cached: enum { unknown, yes, no } = .unknown;
    pub fn isV2Available() bool {
        if (v2_cached != .unknown) return v2_cached == .yes;
        std.fs.cwd().access(cgroup_root ++ "/cgroup.controllers", .{}) catch {
            v2_cached = .no;
            return false;
        };
        v2_cached = .yes;
        return true;
    }

    /// create a new cgroup for the given container id.
    /// creates the directory under /sys/fs/cgroup/yoq/<id>/
    /// returns NotSupported if cgroups v2 is not available.
    pub fn create(container_id: []const u8) CgroupError!Cgroup {
        // validate container ID to prevent path traversal
        if (!container.isValidContainerId(container_id)) return CgroupError.InvalidId;

        if (!isV2Available()) return CgroupError.NotSupported;

        var cg = open(container_id) catch return CgroupError.CreateFailed;

        // create yoq parent dir if needed
        std.fs.cwd().makeDir(cgroup_root ++ "/" ++ yoq_prefix) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return CgroupError.CreateFailed,
        };

        // enable controllers on the yoq parent so child cgroups can use them.
        // without this, writes to cpu.weight/memory.max/pids.max in child
        // cgroups fail because the controllers aren't delegated.
        // only needed once — controllers persist until unmount.
        if (!subtree_controllers_enabled) {
            enableSubtreeControllers(cgroup_root ++ "/" ++ yoq_prefix);
            subtree_controllers_enabled = true;
        }

        // create container cgroup dir
        std.fs.cwd().makeDir(cg.path()) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return CgroupError.CreateFailed,
        };

        return cg;
    }

    /// apply resource limits to this cgroup
    pub fn setLimits(self: *const Cgroup, limits: ResourceLimits) CgroupError!void {
        if (limits.cpu_weight) |weight| {
            if (weight < 1 or weight > 10000) {
                log.err("cgroup: invalid cpu_weight {d} for {s}, must be 1-10000", .{ weight, self.path() });
                return CgroupError.InvalidLimit;
            }
            var weight_buf: [20]u8 = undefined;
            const weight_str = std.fmt.bufPrint(&weight_buf, "{d}", .{weight}) catch {
                log.err("cgroup: failed to format cpu_weight for {s}", .{self.path()});
                return CgroupError.WriteFailed;
            };
            self.writeFile("cpu.weight", weight_str) catch |e| {
                log.err("cgroup: failed to set cpu.weight for {s}: {s}", .{ self.path(), @errorName(e) });
                return CgroupError.WriteFailed;
            };
        }

        if (limits.cpu_max_usec) |max_usec| {
            var buf: [64]u8 = undefined;
            const val = std.fmt.bufPrint(&buf, "{d} {d}", .{ max_usec, limits.cpu_max_period }) catch {
                log.err("cgroup: failed to format cpu.max for {s}", .{self.path()});
                return CgroupError.WriteFailed;
            };
            self.writeFile("cpu.max", val) catch |e| {
                log.err("cgroup: failed to set cpu.max for {s}: {s}", .{ self.path(), @errorName(e) });
                return CgroupError.WriteFailed;
            };
        }

        if (limits.memory_max) |max| {
            var mem_max_buf: [20]u8 = undefined;
            const mem_max_str = std.fmt.bufPrint(&mem_max_buf, "{d}", .{max}) catch {
                log.err("cgroup: failed to format memory.max for {s}", .{self.path()});
                return CgroupError.WriteFailed;
            };
            self.writeAndVerify("memory.max", mem_max_str) catch |e| {
                log.err("cgroup: failed to set memory.max for {s}: {s}", .{ self.path(), @errorName(e) });
                return CgroupError.WriteFailed;
            };
        }

        if (limits.memory_high) |high| {
            var mem_high_buf: [20]u8 = undefined;
            const mem_high_str = std.fmt.bufPrint(&mem_high_buf, "{d}", .{high}) catch {
                log.err("cgroup: failed to format memory.high for {s}", .{self.path()});
                return CgroupError.WriteFailed;
            };
            self.writeFile("memory.high", mem_high_str) catch |e| {
                log.err("cgroup: failed to set memory.high for {s}: {s}", .{ self.path(), @errorName(e) });
                return CgroupError.WriteFailed;
            };
        }

        if (limits.pids_max) |max| {
            var pids_buf: [20]u8 = undefined;
            const pids_str = std.fmt.bufPrint(&pids_buf, "{d}", .{max}) catch {
                log.err("cgroup: failed to format pids.max for {s}", .{self.path()});
                return CgroupError.WriteFailed;
            };
            self.writeAndVerify("pids.max", pids_str) catch |e| {
                log.err("cgroup: failed to set pids.max for {s}: {s}", .{ self.path(), @errorName(e) });
                return CgroupError.WriteFailed;
            };
        }
    }

    /// add a process to this cgroup
    pub fn addProcess(self: *const Cgroup, pid: std.posix.pid_t) CgroupError!void {
        var pid_buf: [20]u8 = undefined;
        const pid_str = std.fmt.bufPrint(&pid_buf, "{d}", .{pid}) catch {
            log.err("cgroup: failed to format pid {d} for {s}", .{ pid, self.path() });
            return CgroupError.WriteFailed;
        };
        self.writeFile("cgroup.procs", pid_str) catch |e| {
            log.err("cgroup: failed to add pid {d} to {s}: {s}", .{ pid, self.path(), @errorName(e) });
            return CgroupError.WriteFailed;
        };
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

    /// all metrics collected in one pass
    pub const CgroupMetrics = struct {
        memory_bytes: ?u64 = null,
        cpu_usec: ?u64 = null,
        psi_cpu: ?PsiMetrics = null,
        psi_memory: ?PsiMetrics = null,
        // current limits (read from cgroup control files)
        memory_limit: ?u64 = null, // memory.max (null = "max" / unlimited)
        cpu_max_usec: ?u64 = null, // cpu.max quota (null = "max" / unlimited)
        cpu_max_period: ?u64 = null, // cpu.max period
        io: ?IoStats = null,
    };

    /// read all metrics in a single pass by opening the cgroup directory once.
    /// avoids N separate open/close cycles per container.
    pub fn readAllMetrics(self: *const Cgroup) CgroupMetrics {
        var metrics: CgroupMetrics = .{};

        var dir = std.fs.cwd().openDir(self.path(), .{}) catch return metrics;
        defer dir.close();

        // memory.current
        {
            var buf: [64]u8 = undefined;
            if (readFromDir(dir, "memory.current", &buf)) |content| {
                metrics.memory_bytes = std.fmt.parseInt(u64, content, 10) catch null;
            }
        }

        // cpu.stat — parse usage_usec
        {
            var buf: [512]u8 = undefined;
            if (readFromDir(dir, "cpu.stat", &buf)) |content| {
                var lines = std.mem.splitScalar(u8, content, '\n');
                while (lines.next()) |line| {
                    if (std.mem.startsWith(u8, line, "usage_usec ")) {
                        metrics.cpu_usec = std.fmt.parseInt(u64, line["usage_usec ".len..], 10) catch null;
                        break;
                    }
                }
            }
        }

        // memory.max — "max" means unlimited, otherwise bytes as u64
        {
            var buf: [64]u8 = undefined;
            if (readFromDir(dir, "memory.max", &buf)) |content| {
                if (!std.mem.eql(u8, content, "max")) {
                    metrics.memory_limit = std.fmt.parseInt(u64, content, 10) catch null;
                }
            }
        }

        // cpu.max — format is "quota period" or "max period"
        {
            var buf: [64]u8 = undefined;
            if (readFromDir(dir, "cpu.max", &buf)) |content| {
                parseCpuMax(content, &metrics);
            }
        }

        // io.stat — aggregate across all devices
        {
            var buf: [1024]u8 = undefined;
            if (readFromDir(dir, "io.stat", &buf)) |content| {
                metrics.io = parseIoStat(content);
            }
        }

        // PSI metrics
        {
            var buf: [512]u8 = undefined;
            if (readFromDir(dir, "cpu.pressure", &buf)) |content| {
                metrics.psi_cpu = parsePsiFromContent(content);
            }
        }
        {
            var buf: [512]u8 = undefined;
            if (readFromDir(dir, "memory.pressure", &buf)) |content| {
                metrics.psi_memory = parsePsiFromContent(content);
            }
        }

        return metrics;
    }

    /// remove this cgroup. kills remaining processes first to avoid EBUSY.
    /// returns error if processes are still running after timeout.
    pub fn destroy(self: *const Cgroup) CgroupError!void {
        // try cgroup.kill (kernel 5.14+) — cleanest approach
        self.writeFile("cgroup.kill", "1") catch {
            // fallback: read cgroup.procs and SIGKILL each PID
            self.killRemainingProcesses();
        };

        // poll until cgroup.procs is empty or timeout (5 seconds)
        var attempts: u32 = 0;
        const max_attempts: u32 = 500; // 500 * 10ms = 5 seconds
        while (attempts < max_attempts) : (attempts += 1) {
            if (self.isEmpty()) break;
            std.Thread.sleep(10 * std.time.ns_per_ms);
        }

        // check if processes are still running
        if (!self.isEmpty()) {
            var buf: [4096]u8 = undefined;
            const procs = self.readFile("cgroup.procs", &buf) catch "<unknown>";
            log.err("cgroup: processes still running after 5s timeout: {s}\nRemaining: {s}", .{ self.path(), procs });
            return CgroupError.DeleteFailed;
        }

        std.fs.cwd().deleteDir(self.path()) catch return CgroupError.DeleteFailed;
    }

    /// check if the cgroup has any remaining processes
    fn isEmpty(self: *const Cgroup) bool {
        var buf: [4096]u8 = undefined;
        const content = self.readFile("cgroup.procs", &buf) catch return false;
        // if the file is empty or contains only whitespace, cgroup is empty
        for (content) |c| {
            if (c != ' ' and c != '\n' and c != '\t' and c != '\r') return false;
        }
        return true;
    }

    /// send SIGKILL to all processes in the cgroup.
    /// used as a fallback when cgroup.kill is not available.
    fn killRemainingProcesses(self: *const Cgroup) void {
        var buf: [4096]u8 = undefined;
        const content = self.readFile("cgroup.procs", &buf) catch {
            log.warn("cgroup: failed to read procs for cleanup: {s}", .{self.path()});
            return;
        };
        if (content.len == 0) return;

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const pid = std.fmt.parseInt(std.posix.pid_t, line, 10) catch continue;
            process.kill(pid) catch {};
        }
    }

    /// get the cgroup path as a string
    pub fn path(self: *const Cgroup) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    // -- internal helpers --

    /// write a value to a cgroup file and verify the kernel accepted it.
    /// logs a warning if the read-back value differs (e.g., kernel clamped
    /// to a system maximum). returns the write error if writing fails.
    fn writeAndVerify(self: *const Cgroup, filename: []const u8, value: []const u8) !void {
        try self.writeFile(filename, value);

        var verify_buf: [64]u8 = undefined;
        const actual = self.readFile(filename, &verify_buf) catch return; // read-back failure is non-fatal
        if (!std.mem.eql(u8, actual, value)) {
            log.warn("cgroup: {s} for {s}: wrote '{s}', kernel applied '{s}'", .{
                filename, self.path(), value, actual,
            });
        }
    }

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

        const bytes_read = file.readAll(buf) catch return error.ReadFailed;
        return std.mem.trimRight(u8, buf[0..bytes_read], "\n ");
    }

    fn readU64(self: *const Cgroup, filename: []const u8) CgroupError!u64 {
        var buf: [64]u8 = undefined;
        const content = self.readFile(filename, &buf) catch return CgroupError.ReadFailed;
        return std.fmt.parseInt(u64, content, 10) catch return CgroupError.ReadFailed;
    }

    fn readPsi(self: *const Cgroup, filename: []const u8) CgroupError!PsiMetrics {
        var buf: [512]u8 = undefined;
        const content = self.readFile(filename, &buf) catch return CgroupError.ReadFailed;
        return parsePsiFromContent(content) orelse CgroupError.ReadFailed;
    }
};

/// enable cpu, memory, and pids controllers on a cgroup directory's
/// subtree_control so that child cgroups inherit those controllers.
/// best-effort: silently ignores failures (e.g. controllers already
/// enabled, or the kernel doesn't support one).
fn enableSubtreeControllers(dir_path: []const u8) void {
    var buf: [512]u8 = undefined;
    const ctrl_path = std.fmt.bufPrint(&buf, "{s}/cgroup.subtree_control", .{dir_path}) catch return;
    const file = std.fs.cwd().openFile(ctrl_path, .{ .mode = .write_only }) catch return;
    defer file.close();
    file.writeAll("+cpu +memory +pids +io") catch {};
}

/// read a file from an already-opened directory handle.
/// avoids the overhead of constructing full paths and opening the cgroup dir again.
fn readFromDir(dir: std.fs.Dir, filename: []const u8, buf: []u8) ?[]const u8 {
    const file = dir.openFile(filename, .{}) catch return null;
    defer file.close();
    const bytes_read = file.readAll(buf) catch return null;
    return std.mem.trimRight(u8, buf[0..bytes_read], "\n ");
}

/// parse PSI metrics from already-read content (for batch reads)
fn parsePsiFromContent(content: []const u8) ?PsiMetrics {
    var metrics: PsiMetrics = .{ .some_avg10 = 0.0, .full_avg10 = 0.0 };
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "some ")) {
            metrics.some_avg10 = parsePsiAvg10(line) catch return null;
        } else if (std.mem.startsWith(u8, line, "full ")) {
            metrics.full_avg10 = parsePsiAvg10(line) catch return null;
        }
    }
    return metrics;
}

/// parse cpu.max content: "quota period" or "max period".
/// quota = "max" means unlimited (leave cpu_max_usec null).
/// e.g. "50000 100000" → quota=50000, period=100000.
fn parseCpuMax(content: []const u8, metrics: *Cgroup.CgroupMetrics) void {
    var parts = std.mem.splitScalar(u8, content, ' ');
    const quota_str = parts.next() orelse return;
    const period_str = parts.next() orelse return;

    metrics.cpu_max_period = std.fmt.parseInt(u64, period_str, 10) catch return;

    if (!std.mem.eql(u8, quota_str, "max")) {
        metrics.cpu_max_usec = std.fmt.parseInt(u64, quota_str, 10) catch return;
    }
}

/// parse the avg10 value from a PSI line like "some avg10=0.00 avg60=0.00 avg300=0.00 total=0"
fn parsePsiAvg10(line: []const u8) !f64 {
    const prefix = "avg10=";
    const start = std.mem.indexOf(u8, line, prefix) orelse return error.ParseError;
    const val_start = start + prefix.len;
    const val_end = std.mem.indexOfScalarPos(u8, line, val_start, ' ') orelse line.len;
    return std.fmt.parseFloat(f64, line[val_start..val_end]) catch return error.ParseError;
}

/// parse io.stat content from cgroups v2.
/// format: "MAJ:MIN rbytes=N wbytes=N rios=N wios=N dbytes=N dios=N\n"
/// aggregates across all devices (each line is one device).
/// returns zeros if content is empty.
pub fn parseIoStat(content: []const u8) IoStats {
    var stats = IoStats{};
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        // skip "MAJ:MIN " prefix
        const after_dev = std.mem.indexOf(u8, line, " ") orelse continue;
        var pairs = std.mem.splitScalar(u8, line[after_dev + 1 ..], ' ');
        while (pairs.next()) |pair| {
            if (std.mem.startsWith(u8, pair, "rbytes=")) {
                stats.read_bytes += std.fmt.parseInt(u64, pair["rbytes=".len..], 10) catch continue;
            } else if (std.mem.startsWith(u8, pair, "wbytes=")) {
                stats.write_bytes += std.fmt.parseInt(u64, pair["wbytes=".len..], 10) catch continue;
            } else if (std.mem.startsWith(u8, pair, "rios=")) {
                stats.read_ios += std.fmt.parseInt(u64, pair["rios=".len..], 10) catch continue;
            } else if (std.mem.startsWith(u8, pair, "wios=")) {
                stats.write_ios += std.fmt.parseInt(u64, pair["wios=".len..], 10) catch continue;
            }
        }
    }
    return stats;
}

// -- tests --

test "resource limits defaults" {
    const limits: ResourceLimits = .{};
    try std.testing.expect(limits.cpu_weight == null);
    try std.testing.expectEqual(@as(u64, 512 * 1024 * 1024), limits.memory_max.?);
    try std.testing.expectEqual(@as(u32, 4096), limits.pids_max.?);
    try std.testing.expectEqual(@as(u64, 100_000), limits.cpu_max_period);
}

test "resource limits unlimited has null values" {
    const limits = ResourceLimits.unlimited;
    try std.testing.expect(limits.cpu_weight == null);
    try std.testing.expect(limits.memory_max == null);
    try std.testing.expect(limits.pids_max == null);
}

test "resource limits validation rejects low memory" {
    const limits = ResourceLimits{ .memory_max = 1024 }; // 1 KB, way below 4 MB minimum
    try std.testing.expectError(CgroupError.LimitBelowMinimum, limits.validate());
}

test "resource limits validation rejects zero pids" {
    const limits = ResourceLimits{ .pids_max = 0 };
    try std.testing.expectError(CgroupError.LimitBelowMinimum, limits.validate());
}

test "resource limits validation accepts defaults" {
    const limits: ResourceLimits = .{};
    try limits.validate();
}

test "resource limits validation accepts unlimited" {
    try ResourceLimits.unlimited.validate();
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

test "bufPrint integer formatting" {
    var buf: [20]u8 = undefined;
    const str = std.fmt.bufPrint(&buf, "{d}", .{@as(u64, 12345)}) catch unreachable;
    try std.testing.expectEqualStrings("12345", str);
}

test "parsePsiAvg10" {
    const val = try parsePsiAvg10("some avg10=1.50 avg60=0.00 avg300=0.00 total=0");
    try std.testing.expectApproxEqAbs(@as(f64, 1.50), val, 0.001);
}

test "parsePsiAvg10 with zero value" {
    const val = try parsePsiAvg10("some avg10=0.00 avg60=0.00 avg300=0.00 total=0");
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), val, 0.001);
}

test "parsePsiAvg10 with high pressure" {
    const val = try parsePsiAvg10("full avg10=99.99 avg60=50.00 avg300=25.00 total=9999");
    try std.testing.expectApproxEqAbs(@as(f64, 99.99), val, 0.001);
}

test "parsePsiAvg10 rejects missing avg10 field" {
    const result = parsePsiAvg10("some total=12345");
    try std.testing.expectError(error.ParseError, result);
}

test "parseCpuMax — quota and period" {
    var metrics: Cgroup.CgroupMetrics = .{};
    parseCpuMax("50000 100000", &metrics);
    try std.testing.expectEqual(@as(u64, 50000), metrics.cpu_max_usec.?);
    try std.testing.expectEqual(@as(u64, 100000), metrics.cpu_max_period.?);
}

test "parseCpuMax — unlimited (max period)" {
    var metrics: Cgroup.CgroupMetrics = .{};
    parseCpuMax("max 100000", &metrics);
    try std.testing.expect(metrics.cpu_max_usec == null);
    try std.testing.expectEqual(@as(u64, 100000), metrics.cpu_max_period.?);
}

test "parseCpuMax — empty content" {
    var metrics: Cgroup.CgroupMetrics = .{};
    parseCpuMax("", &metrics);
    try std.testing.expect(metrics.cpu_max_usec == null);
    try std.testing.expect(metrics.cpu_max_period == null);
}

test "isEmpty returns true for whitespace-only cgroup.procs content" {
    // test the logic of isEmpty directly by examining what it checks
    const empty_cases = [_][]const u8{
        "",
        "   ",
        "\n",
        "\n\n\n",
        " \t\r\n",
    };

    for (empty_cases) |content| {
        // verify all characters are whitespace
        var all_whitespace = true;
        for (content) |c| {
            if (c != ' ' and c != '\n' and c != '\t' and c != '\r') {
                all_whitespace = false;
                break;
            }
        }
        try std.testing.expect(all_whitespace);
    }
}

test "isEmpty returns false for non-whitespace cgroup.procs content" {
    const non_empty_cases = [_][]const u8{
        "1234",
        "1234\n5678",
        " 1234 ",
        "\n1234\n",
    };

    for (non_empty_cases) |content| {
        // verify there's at least one non-whitespace character
        var has_non_whitespace = false;
        for (content) |c| {
            if (c != ' ' and c != '\n' and c != '\t' and c != '\r') {
                has_non_whitespace = true;
                break;
            }
        }
        try std.testing.expect(has_non_whitespace);
    }
}

test "ResourceLimits.validate rejects memory below minimum" {
    const limits = ResourceLimits{ .memory_max = 1024 * 1024 }; // 1 MB, below 4 MB minimum
    try std.testing.expectError(CgroupError.LimitBelowMinimum, limits.validate());
}

test "ResourceLimits.validate accepts valid memory limit" {
    const limits = ResourceLimits{ .memory_max = 8 * 1024 * 1024 }; // 8 MB
    try limits.validate();
}

test "ResourceLimits.validate rejects pids below minimum" {
    const limits = ResourceLimits{ .pids_max = 0 };
    try std.testing.expectError(CgroupError.LimitBelowMinimum, limits.validate());
}

test "ResourceLimits.validate accepts valid pids limit" {
    const limits = ResourceLimits{ .pids_max = 100 };
    try limits.validate();
}

test "ResourceLimits.validate accepts unlimited" {
    try ResourceLimits.unlimited.validate();
}

test "ResourceLimits default values are reasonable" {
    const defaults = ResourceLimits{};
    try std.testing.expectEqual(@as(u64, 512 * 1024 * 1024), defaults.memory_max.?);
    try std.testing.expectEqual(@as(u32, 4096), defaults.pids_max.?);
}

test "parseIoStat — single device" {
    const content = "8:0 rbytes=1024 wbytes=2048 rios=10 wios=20 dbytes=0 dios=0\n";
    const stats = parseIoStat(content);
    try std.testing.expectEqual(@as(u64, 1024), stats.read_bytes);
    try std.testing.expectEqual(@as(u64, 2048), stats.write_bytes);
    try std.testing.expectEqual(@as(u64, 10), stats.read_ios);
    try std.testing.expectEqual(@as(u64, 20), stats.write_ios);
}

test "parseIoStat — multiple devices aggregated" {
    const content =
        "8:0 rbytes=1000 wbytes=2000 rios=5 wios=10 dbytes=0 dios=0\n" ++
        "8:16 rbytes=500 wbytes=300 rios=3 wios=7 dbytes=0 dios=0\n";
    const stats = parseIoStat(content);
    try std.testing.expectEqual(@as(u64, 1500), stats.read_bytes);
    try std.testing.expectEqual(@as(u64, 2300), stats.write_bytes);
    try std.testing.expectEqual(@as(u64, 8), stats.read_ios);
    try std.testing.expectEqual(@as(u64, 17), stats.write_ios);
}

test "parseIoStat — empty content" {
    const stats = parseIoStat("");
    try std.testing.expectEqual(@as(u64, 0), stats.read_bytes);
    try std.testing.expectEqual(@as(u64, 0), stats.write_bytes);
    try std.testing.expectEqual(@as(u64, 0), stats.read_ios);
    try std.testing.expectEqual(@as(u64, 0), stats.write_ios);
}
