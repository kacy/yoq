const std = @import("std");
const dns = @import("../../network/dns.zig");
const log = @import("../../lib/log.zig");
const types = @import("types.zig");
const checks = @import("check_runtime.zig");
const registry = @import("registry_support.zig");
const service_reconciler = @import("../../network/service_reconciler.zig");

pub fn startChecker() void {
    if (registry.checker_running.load(.acquire)) return;

    registry.checker_running.store(true, .release);
    registry.checker_thread = std.Thread.spawn(.{}, checkerLoop, .{}) catch |err| {
        log.warn("health: failed to spawn checker thread: {}", .{err});
        registry.checker_running.store(false, .release);
        return;
    };

    log.info("health checker started", .{});
}

pub fn stopChecker() void {
    if (!registry.checker_running.load(.acquire)) return;

    registry.checker_running.store(false, .release);

    if (registry.checker_thread) |thread| {
        thread.join();
        registry.checker_thread = null;
    }
}

fn checkerLoop() void {
    while (registry.checker_running.load(.acquire)) {
        const now = std.time.timestamp();

        var to_check: [types.max_services]?types.CheckItem = [_]?types.CheckItem{null} ** types.max_services;
        var check_count: usize = 0;

        {
            registry.health_mutex.lock();
            defer registry.health_mutex.unlock();

            for (registry.health_states, 0..) |slot, i| {
                const entry = slot orelse continue;

                if (entry.started_at) |started| {
                    if (now - started < entry.config.start_period) continue;
                }

                if (entry.last_check) |last| {
                    if (now - last < entry.config.interval) continue;
                }

                to_check[check_count] = .{
                    .index = i,
                    .container_ip = entry.container_ip,
                    .container_id = entry.container_id,
                    .config = entry.config,
                    .service_name = entry.serviceName(),
                };
                check_count += 1;
            }
        }

        for (to_check[0..check_count]) |maybe_item| {
            const item = maybe_item orelse continue;
            const success = checks.runCheck(item.container_ip, item.config);

            registry.health_mutex.lock();
            defer registry.health_mutex.unlock();

            if (registry.health_states[item.index]) |*entry| {
                if (!std.mem.eql(u8, &entry.container_id, &item.container_id)) continue;
                entry.last_check = now;
                updateState(entry, success);
            }
        }

        std.Thread.sleep(1 * std.time.ns_per_s);
    }
}

pub fn updateState(entry: *types.ServiceHealth, success: bool) void {
    if (success) {
        entry.consecutive_successes += 1;
        entry.consecutive_failures = 0;
        entry.last_error = null;

        switch (entry.status) {
            .starting => {
                entry.status = .healthy;
                log.info("health: {s} is now healthy", .{entry.serviceName()});
                dnsRegister(entry);
            },
            .unhealthy => {
                entry.status = .healthy;
                log.info("health: {s} recovered, now healthy", .{entry.serviceName()});
                dnsRegister(entry);
            },
            .healthy => {},
        }
    } else {
        entry.consecutive_failures += 1;
        entry.consecutive_successes = 0;

        switch (entry.status) {
            .starting => {
                if (entry.consecutive_failures >= entry.config.retries) {
                    entry.status = .unhealthy;
                    log.warn("health: {s} failed to start (after {d} retries)", .{
                        entry.serviceName(),
                        entry.config.retries,
                    });
                }
            },
            .healthy => {
                if (entry.consecutive_failures >= entry.config.retries) {
                    entry.status = .unhealthy;
                    log.warn("health: {s} is now unhealthy (after {d} consecutive failures)", .{
                        entry.serviceName(),
                        entry.config.retries,
                    });
                    dnsUnregister(entry);
                }
            },
            .unhealthy => {},
        }
    }
}

fn dnsRegister(entry: *const types.ServiceHealth) void {
    dns.registerService(entry.serviceName(), &entry.container_id, entry.container_ip);
    service_reconciler.noteEndpointHealthy(entry.serviceName(), &entry.container_id, entry.container_ip);
    log.info("health: registered {s} in DNS", .{entry.serviceName()});
}

fn dnsUnregister(entry: *const types.ServiceHealth) void {
    dns.unregisterService(&entry.container_id);
    service_reconciler.noteEndpointUnhealthy(entry.serviceName(), &entry.container_id, entry.container_ip);
    log.info("health: unregistered {s} from DNS", .{entry.serviceName()});
}
