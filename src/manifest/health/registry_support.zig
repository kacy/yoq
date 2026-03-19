const std = @import("std");
const log = @import("../../lib/log.zig");
const types = @import("types.zig");

pub var health_states: [types.max_services]?types.ServiceHealth = [_]?types.ServiceHealth{null} ** types.max_services;
pub var health_mutex: std.Thread.Mutex = .{};
pub var checker_thread: ?std.Thread = null;
pub var checker_running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

pub fn registerService(
    service_name: []const u8,
    container_id: [12]u8,
    container_ip: [4]u8,
    config: anytype,
) types.HealthError!void {
    health_mutex.lock();
    defer health_mutex.unlock();

    const len = @min(service_name.len, 64);
    for (&health_states) |*slot| {
        if (slot.* == null) {
            var entry = types.ServiceHealth{
                .status = .starting,
                .consecutive_failures = 0,
                .consecutive_successes = 0,
                .last_check = null,
                .last_error = null,
                .started_at = std.time.timestamp(),
                .container_id = container_id,
                .container_ip = container_ip,
                .config = config,
                .name_len = @intCast(len),
            };
            @memcpy(entry.name_buf[0..len], service_name[0..len]);
            slot.* = entry;
            return;
        }
    }

    log.err("health: registry full (max {d}), cannot track {s}", .{ types.max_services, service_name });
    return types.HealthError.RegistryFull;
}

pub fn unregisterService(service_name: []const u8) void {
    health_mutex.lock();
    defer health_mutex.unlock();

    for (&health_states) |*slot| {
        if (slot.*) |entry| {
            if (std.mem.eql(u8, entry.serviceName(), service_name)) {
                slot.* = null;
                return;
            }
        }
    }
}

pub fn getStatus(service_name: []const u8) ?types.HealthStatus {
    health_mutex.lock();
    defer health_mutex.unlock();

    for (health_states) |slot| {
        if (slot) |entry| {
            if (std.mem.eql(u8, entry.serviceName(), service_name)) return entry.status;
        }
    }
    return null;
}

pub fn getServiceHealth(service_name: []const u8) ?types.ServiceHealth {
    health_mutex.lock();
    defer health_mutex.unlock();

    for (health_states) |slot| {
        if (slot) |entry| {
            if (std.mem.eql(u8, entry.serviceName(), service_name)) return entry;
        }
    }
    return null;
}

pub fn resetForTest() void {
    health_mutex.lock();
    defer health_mutex.unlock();
    for (&health_states) |*slot| slot.* = null;
}
