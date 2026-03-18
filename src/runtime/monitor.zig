// monitor — runtime monitor facade
//
// keep the public monitor API stable while the collection, formatting,
// and tuning logic lives in runtime/monitor/.

const std = @import("std");
const store = @import("../state/store.zig");
const common = @import("monitor/common.zig");
const snapshot_collect = @import("monitor/snapshot_collect.zig");
const formatting = @import("monitor/formatting.zig");
const tuning = @import("monitor/tuning.zig");

pub const ServiceSnapshot = common.ServiceSnapshot;
pub const ServiceStatus = common.ServiceStatus;

pub fn collectSnapshots(
    alloc: std.mem.Allocator,
    container_records: *std.ArrayList(store.ContainerRecord),
) !std.ArrayList(ServiceSnapshot) {
    return snapshot_collect.collectSnapshots(alloc, container_records);
}

pub fn formatUptime(buf: []u8, secs: i64) []const u8 {
    return formatting.formatUptime(buf, secs);
}

pub fn formatBytes(buf: []u8, bytes: u64) []const u8 {
    return formatting.formatBytes(buf, bytes);
}

pub fn formatHealth(status: ?@import("../manifest/health.zig").HealthStatus) []const u8 {
    return formatting.formatHealth(status);
}

pub fn formatStatus(status: ServiceStatus) []const u8 {
    return formatting.formatStatus(status);
}

pub fn suggestTuning(buf: []u8, snap: ServiceSnapshot) ?[]const u8 {
    return tuning.suggestTuning(buf, snap);
}
