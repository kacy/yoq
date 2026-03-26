const std = @import("std");
const store = @import("../../../state/store.zig");
const monitor = @import("../../../runtime/monitor.zig");
const common = @import("../common.zig");
const writers = @import("writers.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const service_rollout = @import("../../../network/service_rollout.zig");
const service_reconciler = @import("../../../network/service_reconciler.zig");

const Response = common.Response;

pub fn handleStatus(alloc: std.mem.Allocator) Response {
    var records = store.listAll(alloc) catch return common.internalError();

    var snapshots = monitor.collectSnapshots(alloc, &records) catch {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
        return common.internalError();
    };
    defer {
        for (records.items) |rec| rec.deinit(alloc);
        records.deinit(alloc);
        snapshots.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    var writer = json_buf.writer(alloc);
    writer.writeByte('[') catch return common.internalError();

    for (snapshots.items, 0..) |snap, idx| {
        if (idx > 0) writer.writeByte(',') catch return common.internalError();
        writers.writeSnapshotJson(writer, snap) catch return common.internalError();
    }

    writer.writeByte(']') catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

pub fn handleServiceRolloutStatus(alloc: std.mem.Allocator) Response {
    const flags = service_rollout.current();

    var events: [service_reconciler.max_recent_events]service_reconciler.Event = undefined;
    const event_count = service_reconciler.snapshotRecentEvents(&events);

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    var writer = json_buf.writer(alloc);

    writer.writeAll("{\"mode\":\"") catch return common.internalError();
    writer.writeAll(switch (service_rollout.mode()) {
        .legacy => "legacy",
        .shadow => "shadow",
    }) catch return common.internalError();
    writer.writeAll("\",\"flags\":{") catch return common.internalError();
    writer.print(
        "\"service_registry_v2\":{},\"service_registry_reconciler\":{},\"dns_returns_vip\":{},\"l7_proxy_http\":{}",
        .{
            flags.service_registry_v2,
            flags.service_registry_reconciler,
            flags.dns_returns_vip,
            flags.l7_proxy_http,
        },
    ) catch return common.internalError();
    writer.writeAll("},\"events\":{\"counts\":{") catch return common.internalError();
    writer.print(
        "\"container_registered\":{d},\"container_unregistered\":{d},\"endpoint_healthy\":{d},\"endpoint_unhealthy\":{d}",
        .{
            service_reconciler.eventCount(.container_registered),
            service_reconciler.eventCount(.container_unregistered),
            service_reconciler.eventCount(.endpoint_healthy),
            service_reconciler.eventCount(.endpoint_unhealthy),
        },
    ) catch return common.internalError();
    writer.writeAll("},\"recent\":[") catch return common.internalError();

    for (events[0..event_count], 0..) |event, idx| {
        if (idx > 0) writer.writeByte(',') catch return common.internalError();

        writer.writeAll("{\"kind\":\"") catch return common.internalError();
        writer.writeAll(event.kind.label()) catch return common.internalError();
        writer.writeAll("\",\"service\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, event.serviceName()) catch return common.internalError();
        writer.writeAll("\",\"container\":\"") catch return common.internalError();
        json_helpers.writeJsonEscaped(writer, event.containerId()) catch return common.internalError();
        writer.writeAll("\",\"recorded_at\":") catch return common.internalError();
        writer.print("{d}", .{event.recorded_at}) catch return common.internalError();
        if (event.ip) |ip| {
            writer.writeAll(",\"ip\":\"") catch return common.internalError();
            writer.print("{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch return common.internalError();
            writer.writeByte('"') catch return common.internalError();
        }
        writer.writeByte('}') catch return common.internalError();
    }

    writer.writeAll("]}}") catch return common.internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}
