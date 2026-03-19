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
    container_id: [12]u8,
    container_ip: [4]u8,
    config: spec.HealthCheck,

    pub fn serviceName(self: *const ServiceHealth) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub const HealthError = error{
    RegistryFull,
};

pub const max_services = 64;

pub const CheckItem = struct {
    index: usize,
    container_ip: [4]u8,
    container_id: [12]u8,
    config: spec.HealthCheck,
    service_name: []const u8,
};
