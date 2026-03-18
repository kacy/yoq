const health = @import("../../manifest/health.zig");
const cgroups = @import("../cgroups.zig");

pub const ServiceSnapshot = struct {
    name: []const u8,
    status: ServiceStatus,
    health_status: ?health.HealthStatus,
    cpu_pct: f64,
    memory_bytes: u64,
    psi_cpu: ?cgroups.PsiMetrics,
    psi_memory: ?cgroups.PsiMetrics,
    io_read_bytes: u64 = 0,
    io_write_bytes: u64 = 0,
    running_count: u32,
    desired_count: u32,
    uptime_secs: i64,
    memory_limit: ?u64 = null,
    cpu_quota_pct: ?f64 = null,
};

pub const ServiceStatus = enum {
    running,
    stopped,
    mixed,
};
