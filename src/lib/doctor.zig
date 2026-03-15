// doctor — pre-flight system readiness checks
//
// runs a series of checks to verify that the host environment
// meets yoq's requirements: kernel version, cgroups v2, eBPF,
// GPU drivers, WireGuard, InfiniBand, disk space.
//
// each check returns pass/warn/fail with a diagnostic message.

const std = @import("std");
const mesh = @import("../gpu/mesh.zig");

pub const CheckStatus = enum {
    pass,
    warn,
    fail,
};

pub const Check = struct {
    name: [32]u8 = .{0} ** 32,
    name_len: u8 = 0,
    status: CheckStatus = .fail,
    message: [128]u8 = .{0} ** 128,
    message_len: u8 = 0,

    pub fn getName(self: *const Check) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn getMessage(self: *const Check) []const u8 {
        return self.message[0..self.message_len];
    }

    pub fn statusLabel(self: *const Check) []const u8 {
        return switch (self.status) {
            .pass => "PASS",
            .warn => "WARN",
            .fail => "FAIL",
        };
    }
};

pub const max_checks = 8;

pub const CheckResult = struct {
    checks: [max_checks]Check,
    count: u8,
};

fn makeCheck(name: []const u8, status: CheckStatus, message: []const u8) Check {
    var c = Check{};
    const nlen: u8 = @intCast(@min(name.len, 32));
    @memcpy(c.name[0..nlen], name[0..nlen]);
    c.name_len = nlen;
    c.status = status;
    const mlen: u8 = @intCast(@min(message.len, 128));
    @memcpy(c.message[0..mlen], message[0..mlen]);
    c.message_len = mlen;
    return c;
}

pub fn runAllChecks() CheckResult {
    var result = CheckResult{
        .checks = undefined,
        .count = 0,
    };

    result.checks[result.count] = checkKernel();
    result.count += 1;

    result.checks[result.count] = checkCgroupV2();
    result.count += 1;

    result.checks[result.count] = checkEbpf();
    result.count += 1;

    result.checks[result.count] = checkGpu();
    result.count += 1;

    result.checks[result.count] = checkWireguard();
    result.count += 1;

    result.checks[result.count] = checkInfiniband();
    result.count += 1;

    result.checks[result.count] = checkDiskSpace();
    result.count += 1;

    return result;
}

pub fn checkKernel() Check {
    var uts: std.posix.utsname = undefined;
    const rc = std.os.linux.uname(&uts);
    if (rc != 0) {
        return makeCheck("kernel", .fail, "could not read kernel version");
    }

    const release: [*:0]const u8 = @ptrCast(&uts.release);
    const release_str = std.mem.span(release);

    // parse major.minor
    var iter = std.mem.splitScalar(u8, release_str, '.');
    const major_str = iter.next() orelse return makeCheck("kernel", .fail, "could not parse kernel version");
    const minor_str = iter.next() orelse return makeCheck("kernel", .fail, "could not parse kernel version");

    const major = std.fmt.parseInt(u32, major_str, 10) catch return makeCheck("kernel", .fail, "could not parse kernel major version");
    const minor = std.fmt.parseInt(u32, minor_str, 10) catch return makeCheck("kernel", .fail, "could not parse kernel minor version");

    if (major > 6 or (major == 6 and minor >= 1)) {
        var msg_buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "kernel {d}.{d} >= 6.1", .{ major, minor }) catch "ok";
        return makeCheck("kernel", .pass, msg);
    } else if (major == 5 and minor >= 15) {
        var msg_buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "kernel {d}.{d} (>= 6.1 recommended)", .{ major, minor }) catch "degraded";
        return makeCheck("kernel", .warn, msg);
    } else {
        return makeCheck("kernel", .fail, "kernel < 5.15 (>= 6.1 required)");
    }
}

pub fn checkCgroupV2() Check {
    const file = std.fs.openFileAbsolute("/sys/fs/cgroup/cgroup.controllers", .{}) catch {
        return makeCheck("cgroup-v2", .fail, "/sys/fs/cgroup/cgroup.controllers not found");
    };
    file.close();
    return makeCheck("cgroup-v2", .pass, "cgroups v2 unified hierarchy available");
}

pub fn checkEbpf() Check {
    std.fs.accessAbsolute("/sys/fs/bpf", .{}) catch {
        return makeCheck("ebpf", .fail, "/sys/fs/bpf not mounted");
    };
    return makeCheck("ebpf", .pass, "bpf filesystem available");
}

pub fn checkGpu() Check {
    var lib = std.DynLib.open("libnvidia-ml.so.1") catch {
        return makeCheck("gpu", .warn, "libnvidia-ml.so.1 not found (no NVIDIA GPU support)");
    };
    lib.close();
    return makeCheck("gpu", .pass, "NVIDIA driver available");
}

pub fn checkWireguard() Check {
    std.fs.accessAbsolute("/sys/module/wireguard", .{}) catch {
        return makeCheck("wireguard", .warn, "wireguard module not loaded (cluster networking unavailable)");
    };
    return makeCheck("wireguard", .pass, "wireguard module loaded");
}

pub fn checkInfiniband() Check {
    const ib_result = mesh.detectInfiniband();
    if (ib_result.count == 0) {
        return makeCheck("infiniband", .warn, "no InfiniBand devices (GPU mesh will use TCP)");
    }

    var msg_buf: [128]u8 = undefined;
    const gdr_str: []const u8 = if (ib_result.gdr_available) ", GDR available" else "";
    const msg = std.fmt.bufPrint(&msg_buf, "{d} IB device(s) found{s}", .{ ib_result.count, gdr_str }) catch "found";
    return makeCheck("infiniband", .pass, msg);
}

/// statfs result buffer for disk space checks (x86_64 Linux ABI)
const StatfsBuf = extern struct {
    f_type: isize,
    f_bsize: isize,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    _pad: [64]u8 = undefined,
};

pub fn checkDiskSpace() Check {
    const path = "/\x00";
    const path_z: [*:0]const u8 = @ptrCast(path);
    var stat: StatfsBuf = undefined;
    const rc = std.os.linux.syscall2(.statfs, @intFromPtr(path_z), @intFromPtr(&stat));
    if (rc > std.math.maxInt(usize) - 4096) {
        return makeCheck("disk-space", .warn, "could not check disk space");
    }

    const avail_bytes = stat.f_bavail * @as(u64, @bitCast(stat.f_bsize));
    const avail_gb = avail_bytes / (1024 * 1024 * 1024);

    if (avail_gb >= 10) {
        var msg_buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "{d} GB available", .{avail_gb}) catch "ok";
        return makeCheck("disk-space", .pass, msg);
    } else if (avail_gb >= 2) {
        var msg_buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "{d} GB available (< 10 GB)", .{avail_gb}) catch "low";
        return makeCheck("disk-space", .warn, msg);
    } else {
        return makeCheck("disk-space", .fail, "less than 2 GB disk space available");
    }
}

// -- tests --

test "makeCheck sets fields correctly" {
    const c = makeCheck("test-check", .pass, "all good");
    try std.testing.expectEqualStrings("test-check", c.getName());
    try std.testing.expectEqual(CheckStatus.pass, c.status);
    try std.testing.expectEqualStrings("all good", c.getMessage());
    try std.testing.expectEqualStrings("PASS", c.statusLabel());
}

test "makeCheck truncates long name" {
    const long_name = "this-is-a-very-long-check-name-that-exceeds-32-characters";
    const c = makeCheck(long_name, .fail, "msg");
    try std.testing.expectEqual(@as(u8, 32), c.name_len);
}

test "checkKernel returns pass or warn on linux" {
    const c = checkKernel();
    // on any modern linux, kernel should be at least 5.15
    try std.testing.expect(c.status == .pass or c.status == .warn);
}

test "checkCgroupV2 runs without crash" {
    const c = checkCgroupV2();
    // might pass or fail depending on host — just verify it runs
    try std.testing.expect(c.status == .pass or c.status == .fail);
}

test "checkEbpf runs without crash" {
    const c = checkEbpf();
    try std.testing.expect(c.status == .pass or c.status == .fail);
}

test "checkGpu runs without crash" {
    const c = checkGpu();
    try std.testing.expect(c.status == .pass or c.status == .warn);
}

test "checkWireguard runs without crash" {
    const c = checkWireguard();
    try std.testing.expect(c.status == .pass or c.status == .warn);
}

test "checkInfiniband runs without crash" {
    const c = checkInfiniband();
    try std.testing.expect(c.status == .pass or c.status == .warn);
}

test "checkDiskSpace runs without crash" {
    const c = checkDiskSpace();
    try std.testing.expect(c.status == .pass or c.status == .warn or c.status == .fail);
}

test "runAllChecks returns all checks" {
    const result = runAllChecks();
    try std.testing.expectEqual(@as(u8, 7), result.count);
}

test "statusLabel returns correct strings" {
    var c = makeCheck("x", .pass, "");
    try std.testing.expectEqualStrings("PASS", c.statusLabel());
    c.status = .warn;
    try std.testing.expectEqualStrings("WARN", c.statusLabel());
    c.status = .fail;
    try std.testing.expectEqualStrings("FAIL", c.statusLabel());
}
