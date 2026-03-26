const std = @import("std");
const log = @import("../lib/log.zig");
const rollout = @import("service_rollout.zig");

pub const EventKind = enum {
    container_registered,
    container_unregistered,
    endpoint_healthy,
    endpoint_unhealthy,

    pub fn label(self: EventKind) []const u8 {
        return switch (self) {
            .container_registered => "container_registered",
            .container_unregistered => "container_unregistered",
            .endpoint_healthy => "endpoint_healthy",
            .endpoint_unhealthy => "endpoint_unhealthy",
        };
    }
};

pub const Event = struct {
    kind: EventKind,
    service_name_buf: [64]u8 = [_]u8{0} ** 64,
    service_name_len: u8 = 0,
    container_id_buf: [64]u8 = [_]u8{0} ** 64,
    container_id_len: u8 = 0,
    ip: ?[4]u8 = null,
    recorded_at: i64,

    pub fn serviceName(self: *const Event) []const u8 {
        return self.service_name_buf[0..self.service_name_len];
    }

    pub fn containerId(self: *const Event) []const u8 {
        return self.container_id_buf[0..self.container_id_len];
    }
};

pub const max_recent_events = 32;

var mutex: std.Thread.Mutex = .{};
var recent_events: [max_recent_events]Event = undefined;
var recent_start: usize = 0;
var recent_len: usize = 0;
var event_counts: [@typeInfo(EventKind).@"enum".fields.len]u64 = [_]u64{0} ** @typeInfo(EventKind).@"enum".fields.len;
var logged_authoritative_flag_notice: bool = false;

pub fn noteContainerRegistered(service_name: []const u8, container_id: []const u8, ip: [4]u8) void {
    noteEvent(buildEvent(.container_registered, service_name, container_id, ip));
}

pub fn noteContainerUnregistered(container_id: []const u8) void {
    noteEvent(buildEvent(.container_unregistered, "", container_id, null));
}

pub fn noteEndpointHealthy(service_name: []const u8, container_id: []const u8, ip: [4]u8) void {
    noteEvent(buildEvent(.endpoint_healthy, service_name, container_id, ip));
}

pub fn noteEndpointUnhealthy(service_name: []const u8, container_id: []const u8, ip: [4]u8) void {
    noteEvent(buildEvent(.endpoint_unhealthy, service_name, container_id, ip));
}

pub fn eventCount(kind: EventKind) u64 {
    mutex.lock();
    defer mutex.unlock();
    return event_counts[@intFromEnum(kind)];
}

pub fn snapshotRecentEvents(out: []Event) usize {
    mutex.lock();
    defer mutex.unlock();

    const count = @min(out.len, recent_len);
    const start = recent_len - count;
    for (0..count) |i| {
        const idx = (recent_start + start + i) % max_recent_events;
        out[i] = recent_events[idx];
    }
    return count;
}

pub fn resetForTest() void {
    mutex.lock();
    defer mutex.unlock();
    recent_start = 0;
    recent_len = 0;
    event_counts = [_]u64{0} ** event_counts.len;
    logged_authoritative_flag_notice = false;
}

fn noteEvent(event: Event) void {
    if (rollout.mode() == .legacy) return;

    const current_flags = rollout.current();

    mutex.lock();
    defer mutex.unlock();

    if (current_flags.service_registry_reconciler and !logged_authoritative_flag_notice) {
        logged_authoritative_flag_notice = true;
        log.info("service reconciler flag enabled; phase 0 remains shadow-only and keeps legacy writers active", .{});
    }

    const write_idx = (recent_start + recent_len) % max_recent_events;
    recent_events[write_idx] = event;
    if (recent_len < max_recent_events) {
        recent_len += 1;
    } else {
        recent_start = (recent_start + 1) % max_recent_events;
    }

    event_counts[@intFromEnum(event.kind)] += 1;

    log.debug(
        "service reconciler: shadow event kind={s} service={s} container={s}",
        .{ event.kind.label(), event.serviceName(), event.containerId() },
    );
}

fn buildEvent(kind: EventKind, service_name: []const u8, container_id: []const u8, ip: ?[4]u8) Event {
    var event = Event{
        .kind = kind,
        .recorded_at = std.time.timestamp(),
        .ip = ip,
    };

    const service_len = @min(service_name.len, event.service_name_buf.len);
    event.service_name_len = @intCast(service_len);
    @memcpy(event.service_name_buf[0..service_len], service_name[0..service_len]);

    const container_len = @min(container_id.len, event.container_id_buf.len);
    event.container_id_len = @intCast(container_len);
    @memcpy(event.container_id_buf[0..container_len], container_id[0..container_len]);

    return event;
}

test "legacy mode does not record events" {
    rollout.setForTest(.{});
    defer rollout.resetForTest();
    resetForTest();

    noteContainerRegistered("api", "abc123", .{ 10, 42, 0, 9 });

    try std.testing.expectEqual(@as(u64, 0), eventCount(.container_registered));
}

test "shadow mode records container and health events" {
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    resetForTest();

    noteContainerRegistered("api", "abc123", .{ 10, 42, 0, 9 });
    noteEndpointHealthy("api", "abc123", .{ 10, 42, 0, 9 });

    try std.testing.expectEqual(@as(u64, 1), eventCount(.container_registered));
    try std.testing.expectEqual(@as(u64, 1), eventCount(.endpoint_healthy));

    var events: [4]Event = undefined;
    const count = snapshotRecentEvents(&events);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqualStrings("api", events[0].serviceName());
    try std.testing.expectEqualStrings("abc123", events[0].containerId());
    try std.testing.expectEqual(EventKind.container_registered, events[0].kind);
    try std.testing.expectEqual(EventKind.endpoint_healthy, events[1].kind);
}

test "recent event buffer keeps only the newest events" {
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();
    resetForTest();

    var idx: usize = 0;
    while (idx < max_recent_events + 4) : (idx += 1) {
        var name_buf: [16]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "svc{d}", .{idx}) catch unreachable;
        noteContainerRegistered(name, "abc123", .{ 10, 42, 0, 9 });
    }

    try std.testing.expectEqual(@as(u64, max_recent_events + 4), eventCount(.container_registered));

    var events: [max_recent_events]Event = undefined;
    const count = snapshotRecentEvents(&events);
    try std.testing.expectEqual(@as(usize, max_recent_events), count);
    try std.testing.expectEqualStrings("svc4", events[0].serviceName());
}
