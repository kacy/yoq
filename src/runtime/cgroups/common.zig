const std = @import("std");

pub const CgroupError = error{
    CreateFailed,
    WriteFailed,
    ReadFailed,
    DeleteFailed,
    NotSupported,
    InvalidLimit,
    LimitBelowMinimum,
    InvalidId,
};

const min_memory_bytes: u64 = 4 * 1024 * 1024;
const min_pids: u32 = 1;

pub const ResourceLimits = struct {
    cpu_weight: ?u16 = null,
    cpu_max_usec: ?u64 = null,
    cpu_max_period: u64 = 100_000,
    memory_max: ?u64 = 512 * 1024 * 1024,
    memory_high: ?u64 = null,
    pids_max: ?u32 = 4096,

    pub const unlimited = ResourceLimits{
        .cpu_weight = null,
        .cpu_max_usec = null,
        .cpu_max_period = 100_000,
        .memory_max = null,
        .memory_high = null,
        .pids_max = null,
    };

    pub fn validate(self: ResourceLimits) CgroupError!void {
        if (self.memory_max) |mem| {
            if (mem < min_memory_bytes) return CgroupError.LimitBelowMinimum;
        }
        if (self.pids_max) |pids| {
            if (pids < min_pids) return CgroupError.LimitBelowMinimum;
        }
    }
};

pub const PsiMetrics = struct {
    some_avg10: f64,
    full_avg10: f64,
};

pub const IoStats = struct {
    read_bytes: u64 = 0,
    write_bytes: u64 = 0,
    read_ios: u64 = 0,
    write_ios: u64 = 0,
};

pub const CgroupMetrics = struct {
    memory_bytes: ?u64 = null,
    cpu_usec: ?u64 = null,
    psi_cpu: ?PsiMetrics = null,
    psi_memory: ?PsiMetrics = null,
    memory_limit: ?u64 = null,
    cpu_max_usec: ?u64 = null,
    cpu_max_period: ?u64 = null,
    io: ?IoStats = null,
};

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
    const limits = ResourceLimits{ .memory_max = 1024 };
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

test "ResourceLimits.validate rejects memory below minimum" {
    const limits = ResourceLimits{ .memory_max = 1024 * 1024 };
    try std.testing.expectError(CgroupError.LimitBelowMinimum, limits.validate());
}

test "ResourceLimits.validate accepts valid memory limit" {
    const limits = ResourceLimits{ .memory_max = 8 * 1024 * 1024 };
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

test "ResourceLimits default values are reasonable" {
    const limits: ResourceLimits = .{};
    try std.testing.expect(limits.memory_max.? >= 128 * 1024 * 1024);
    try std.testing.expect(limits.pids_max.? >= 256);
}
