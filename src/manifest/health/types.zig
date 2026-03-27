const std = @import("std");
const spec = @import("../spec.zig");

pub const HealthStatus = enum {
    starting,
    healthy,
    unhealthy,
};

pub const ServiceHealth = struct {
    status: HealthStatus,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_check: ?i64,
    last_error: ?[]const u8,
    started_at: ?i64,
    name_buf: [64]u8 = undefined,
    name_len: u8 = 0,
    endpoint_id_buf: [96]u8 = undefined,
    endpoint_id_len: u8 = 0,
    container_id: [12]u8,
    container_ip: [4]u8,
    config: spec.HealthCheck,
    generation: i64,
    registration_epoch: u64 = 0,
    next_check_at: i64 = 0,
    in_flight: bool = false,
    flap_count: u32 = 0,

    pub fn serviceName(self: *const ServiceHealth) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn endpointId(self: *const ServiceHealth) []const u8 {
        return self.endpoint_id_buf[0..self.endpoint_id_len];
    }
};

pub const HealthError = error{
    OutOfMemory,
};

pub const max_worker_threads = 4;
pub const max_queued_checks = 64;
pub const scheduler_interval_ms: u64 = 250;

pub const CheckItem = struct {
    container_ip: [4]u8,
    container_id: [12]u8,
    config: spec.HealthCheck,
    service_name_buf: [64]u8 = [_]u8{0} ** 64,
    service_name_len: u8 = 0,
    endpoint_id_buf: [96]u8 = [_]u8{0} ** 96,
    endpoint_id_len: u8 = 0,
    generation: i64,
    registration_epoch: u64,

    pub fn serviceName(self: *const CheckItem) []const u8 {
        return self.service_name_buf[0..self.service_name_len];
    }

    pub fn endpointId(self: *const CheckItem) []const u8 {
        return self.endpoint_id_buf[0..self.endpoint_id_len];
    }
};

pub const CheckerSnapshot = struct {
    running: bool,
    tracked_endpoints: usize,
    in_flight_checks: usize,
    queued_checks: usize,
    worker_threads: usize,
    scheduled_total: u64,
    completed_total: u64,
    stale_results_total: u64,
    dropped_queue_full_total: u64,
    last_scheduled_at: ?i64,
    last_completed_at: ?i64,
};
