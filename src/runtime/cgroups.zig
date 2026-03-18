// cgroups — runtime cgroups facade
//
// keep the public cgroup API stable while the implementation lives in
// runtime/cgroups/.

const common = @import("cgroups/common.zig");
const lifecycle_support = @import("cgroups/lifecycle_support.zig");
const metrics_support = @import("cgroups/metrics_support.zig");

pub const CgroupError = common.CgroupError;
pub const ResourceLimits = common.ResourceLimits;
pub const PsiMetrics = common.PsiMetrics;
pub const IoStats = common.IoStats;
pub const Cgroup = lifecycle_support.Cgroup;

pub fn parseIoStat(content: []const u8) IoStats {
    return metrics_support.parseIoStat(content);
}
