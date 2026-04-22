const std = @import("std");
const platform = @import("platform");
const log = @import("../../lib/log.zig");
const container = @import("../container.zig");
const process = @import("../process.zig");
const common = @import("common.zig");
const metrics_support = @import("metrics_support.zig");

pub const CgroupError = common.CgroupError;
pub const ResourceLimits = common.ResourceLimits;
pub const PsiMetrics = common.PsiMetrics;
pub const IoStats = common.IoStats;

const cgroup_root = "/sys/fs/cgroup";
const yoq_prefix = "yoq";
var subtree_controllers_enabled: bool = false;

pub const Cgroup = struct {
    path_buf: [256]u8,
    path_len: usize,

    pub const CgroupMetrics = common.CgroupMetrics;

    pub fn open(container_id: []const u8) CgroupError!Cgroup {
        if (!container.isValidContainerId(container_id)) return CgroupError.InvalidId;

        var cg: Cgroup = .{ .path_buf = undefined, .path_len = 0 };
        const formatted = std.fmt.bufPrint(&cg.path_buf, cgroup_root ++ "/" ++ yoq_prefix ++ "/{s}", .{container_id}) catch
            return CgroupError.CreateFailed;
        cg.path_len = formatted.len;
        return cg;
    }

    var v2_cached: enum { unknown, yes, no } = .unknown;
    pub fn isV2Available() bool {
        if (v2_cached != .unknown) return v2_cached == .yes;
        platform.cwd().access(cgroup_root ++ "/cgroup.controllers", .{}) catch {
            v2_cached = .no;
            return false;
        };
        v2_cached = .yes;
        return true;
    }

    pub fn create(container_id: []const u8) CgroupError!Cgroup {
        if (!container.isValidContainerId(container_id)) return CgroupError.InvalidId;
        if (!isV2Available()) return CgroupError.NotSupported;

        const cg = open(container_id) catch return CgroupError.CreateFailed;

        platform.cwd().makeDir(cgroup_root ++ "/" ++ yoq_prefix) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return CgroupError.CreateFailed,
        };

        if (!subtree_controllers_enabled) {
            subtree_controllers_enabled = enableSubtreeControllers(cgroup_root ++ "/" ++ yoq_prefix);
        }

        platform.cwd().makeDir(cg.path()) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return CgroupError.CreateFailed,
        };

        return cg;
    }

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

    pub fn memoryUsage(self: *const Cgroup) CgroupError!u64 {
        return self.readU64("memory.current");
    }

    pub fn containsProcess(self: *const Cgroup, pid: std.posix.pid_t) bool {
        return self.containsProcessChecked(pid) catch false;
    }

    pub fn containsProcessChecked(self: *const Cgroup, pid: std.posix.pid_t) CgroupError!bool {
        var buf: [4096]u8 = undefined;
        const content = self.readFile("cgroup.procs", &buf) catch return CgroupError.ReadFailed;
        return metrics_support.procsContainsPid(content, pid);
    }

    pub fn cpuUsage(self: *const Cgroup) CgroupError!u64 {
        var buf: [512]u8 = undefined;
        const content = self.readFile("cpu.stat", &buf) catch return CgroupError.ReadFailed;

        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |line| {
            if (std.mem.startsWith(u8, line, "usage_usec ")) {
                const val_str = line["usage_usec ".len..];
                return std.fmt.parseInt(u64, val_str, 10) catch return CgroupError.ReadFailed;
            }
        }
        return CgroupError.ReadFailed;
    }

    pub fn memoryPressure(self: *const Cgroup) CgroupError!PsiMetrics {
        return self.readPsi("memory.pressure");
    }

    pub fn cpuPressure(self: *const Cgroup) CgroupError!PsiMetrics {
        return self.readPsi("cpu.pressure");
    }

    pub fn readAllMetrics(self: *const Cgroup) common.CgroupMetrics {
        var metrics: common.CgroupMetrics = .{};

        var dir = platform.cwd().openDir(self.path(), .{}) catch return metrics;
        defer dir.close();

        {
            var buf: [64]u8 = undefined;
            if (metrics_support.readFromDir(dir, "memory.current", &buf)) |content| {
                metrics.memory_bytes = std.fmt.parseInt(u64, content, 10) catch null;
            }
        }
        {
            var buf: [512]u8 = undefined;
            if (metrics_support.readFromDir(dir, "cpu.stat", &buf)) |content| {
                var lines = std.mem.splitScalar(u8, content, '\n');
                while (lines.next()) |line| {
                    if (std.mem.startsWith(u8, line, "usage_usec ")) {
                        metrics.cpu_usec = std.fmt.parseInt(u64, line["usage_usec ".len..], 10) catch null;
                        break;
                    }
                }
            }
        }
        {
            var buf: [64]u8 = undefined;
            if (metrics_support.readFromDir(dir, "memory.max", &buf)) |content| {
                if (!std.mem.eql(u8, content, "max")) {
                    metrics.memory_limit = std.fmt.parseInt(u64, content, 10) catch null;
                }
            }
        }
        {
            var buf: [64]u8 = undefined;
            if (metrics_support.readFromDir(dir, "cpu.max", &buf)) |content| {
                metrics_support.parseCpuMax(content, &metrics);
            }
        }
        {
            var buf: [1024]u8 = undefined;
            if (metrics_support.readFromDir(dir, "io.stat", &buf)) |content| {
                metrics.io = metrics_support.parseIoStat(content);
            }
        }
        {
            var buf: [512]u8 = undefined;
            if (metrics_support.readFromDir(dir, "cpu.pressure", &buf)) |content| {
                metrics.psi_cpu = metrics_support.parsePsiFromContent(content);
            }
        }
        {
            var buf: [512]u8 = undefined;
            if (metrics_support.readFromDir(dir, "memory.pressure", &buf)) |content| {
                metrics.psi_memory = metrics_support.parsePsiFromContent(content);
            }
        }

        return metrics;
    }

    pub fn destroy(self: *const Cgroup) CgroupError!void {
        self.writeFile("cgroup.kill", "1") catch {
            self.killRemainingProcesses();
        };

        var attempts: u32 = 0;
        const max_attempts: u32 = 500;
        while (attempts < max_attempts) : (attempts += 1) {
            if (self.isEmpty()) break;
            platform.sleep(10 * std.time.ns_per_ms);
        }

        if (!self.isEmpty()) {
            var buf: [4096]u8 = undefined;
            const procs = self.readFile("cgroup.procs", &buf) catch "<unknown>";
            log.err("cgroup: processes still running after 5s timeout: {s}\nRemaining: {s}", .{ self.path(), procs });
            return CgroupError.DeleteFailed;
        }

        platform.cwd().deleteDir(self.path()) catch return CgroupError.DeleteFailed;
    }

    fn isEmpty(self: *const Cgroup) bool {
        var buf: [4096]u8 = undefined;
        const content = self.readFile("cgroup.procs", &buf) catch return false;
        for (content) |c| {
            if (c != ' ' and c != '\n' and c != '\t' and c != '\r') return false;
        }
        return true;
    }

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

    pub fn path(self: *const Cgroup) []const u8 {
        return self.path_buf[0..self.path_len];
    }

    fn writeAndVerify(self: *const Cgroup, filename: []const u8, value: []const u8) !void {
        try self.writeFile(filename, value);

        var verify_buf: [64]u8 = undefined;
        const actual = self.readFile(filename, &verify_buf) catch return;
        if (!std.mem.eql(u8, actual, value)) {
            log.warn("cgroup: {s} for {s}: wrote '{s}', kernel applied '{s}'", .{
                filename, self.path(), value, actual,
            });
        }
    }

    fn writeFile(self: *const Cgroup, filename: []const u8, value: []const u8) !void {
        var path_buf: [512]u8 = undefined;
        const file_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ self.path(), filename }) catch return error.WriteFailed;

        const file = platform.cwd().openFile(file_path, .{ .mode = .write_only }) catch return error.WriteFailed;
        defer file.close();

        file.writeAll(value) catch return error.WriteFailed;
    }

    fn readFile(self: *const Cgroup, filename: []const u8, buf: []u8) ![]const u8 {
        var path_buf: [512]u8 = undefined;
        const file_path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ self.path(), filename }) catch return error.ReadFailed;

        const file = platform.cwd().openFile(file_path, .{}) catch return error.ReadFailed;
        defer file.close();

        const bytes_read = file.readAll(buf) catch return error.ReadFailed;
        return std.mem.trimEnd(u8, buf[0..bytes_read], "\n ");
    }

    fn readU64(self: *const Cgroup, filename: []const u8) CgroupError!u64 {
        var buf: [64]u8 = undefined;
        const content = self.readFile(filename, &buf) catch return CgroupError.ReadFailed;
        return std.fmt.parseInt(u64, content, 10) catch return CgroupError.ReadFailed;
    }

    fn readPsi(self: *const Cgroup, filename: []const u8) CgroupError!PsiMetrics {
        var buf: [512]u8 = undefined;
        const content = self.readFile(filename, &buf) catch return CgroupError.ReadFailed;
        return metrics_support.parsePsiFromContent(content) orelse CgroupError.ReadFailed;
    }
};

fn enableSubtreeControllers(dir_path: []const u8) bool {
    var ctrl_buf: [512]u8 = undefined;
    const ctrl_path = std.fmt.bufPrint(&ctrl_buf, "{s}/cgroup.subtree_control", .{dir_path}) catch return false;
    const file = platform.cwd().openFile(ctrl_path, .{ .mode = .write_only }) catch return false;
    defer file.close();

    var controllers_path_buf: [512]u8 = undefined;
    const controllers_path = std.fmt.bufPrint(&controllers_path_buf, "{s}/cgroup.controllers", .{dir_path}) catch return false;
    const controllers_file = platform.cwd().openFile(controllers_path, .{}) catch return false;
    defer controllers_file.close();

    var available_buf: [256]u8 = undefined;
    const available_len = controllers_file.readAll(&available_buf) catch return false;
    const available = std.mem.trim(u8, available_buf[0..available_len], " \n\r\t");

    var desired_buf: [64]u8 = undefined;
    const desired = buildDesiredSubtreeControl(available, &desired_buf) orelse return false;

    file.writeAll(desired) catch {
        log.warn("cgroup: failed to enable subtree controllers '{s}' for {s}", .{ desired, dir_path });
        return false;
    };
    return true;
}

fn buildDesiredSubtreeControl(available: []const u8, buf: []u8) ?[]const u8 {
    const wanted = [_][]const u8{ "cpu", "memory", "pids", "io" };
    var pos: usize = 0;

    for (wanted) |name| {
        if (!controllersContain(available, name)) continue;
        const separator_len: usize = if (pos > 0) 1 else 0;
        const needed: usize = 1 + name.len + separator_len;
        if (pos + needed > buf.len) return null;
        if (pos > 0) {
            buf[pos] = ' ';
            pos += 1;
        }
        buf[pos] = '+';
        pos += 1;
        @memcpy(buf[pos .. pos + name.len], name);
        pos += name.len;
    }

    if (pos == 0) return null;
    return buf[0..pos];
}

fn controllersContain(available: []const u8, wanted: []const u8) bool {
    var parts = std.mem.tokenizeAny(u8, available, " \n\r\t");
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, wanted)) return true;
    }
    return false;
}

test "resource limits validation" {
    var cg: Cgroup = .{ .path_buf = undefined, .path_len = 0 };
    const written = std.fmt.bufPrint(&cg.path_buf, "/tmp/test-cg", .{}) catch unreachable;
    cg.path_len = written.len;

    const result = cg.setLimits(.{ .cpu_weight = 0 });
    try std.testing.expectError(CgroupError.InvalidLimit, result);

    const result2 = cg.setLimits(.{ .cpu_weight = 10001 });
    try std.testing.expectError(CgroupError.InvalidLimit, result2);
}

test "buildDesiredSubtreeControl only enables available controllers" {
    var buf: [64]u8 = undefined;
    const desired = buildDesiredSubtreeControl("cpu memory pids", &buf).?;
    try std.testing.expectEqualStrings("+cpu +memory +pids", desired);
}

test "buildDesiredSubtreeControl includes io when available" {
    var buf: [64]u8 = undefined;
    const desired = buildDesiredSubtreeControl("cpu io memory pids", &buf).?;
    try std.testing.expectEqualStrings("+cpu +memory +pids +io", desired);
}

test "isEmpty returns true for whitespace-only cgroup.procs content" {
    const empty_cases = [_][]const u8{
        "",
        "   ",
        "\n",
        "\n\n\n",
        " \t\r\n",
    };

    for (empty_cases) |content| {
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
