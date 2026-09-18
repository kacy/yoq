const std = @import("std");
const spec = @import("../spec.zig");

/// primary instances retain their service index; additional replicas follow them.
/// the manifest remains a list of logical services throughout apply and rollback.
pub fn count(services: []const spec.Service) error{Overflow}!usize {
    var total: usize = 0;
    for (services) |service| total = try std.math.add(usize, total, service.replicas);
    return total;
}

pub fn serviceIndex(services: []const spec.Service, instance: usize) usize {
    if (instance < services.len) return instance;
    var offset = services.len;
    for (services, 0..) |service, index| {
        const end = offset + service.replicas - 1;
        if (instance < end) return index;
        offset = end;
    }
    unreachable;
}

pub fn instanceIndex(services: []const spec.Service, service_index: usize, replica: usize) usize {
    std.debug.assert(replica < services[service_index].replicas);
    if (replica == 0) return service_index;
    var offset = services.len;
    for (services[0..service_index]) |service| offset += service.replicas - 1;
    return offset + replica - 1;
}

test "replica state indexes preserve logical service identity" {
    const services = [_]spec.Service{
        .{ .name = "web", .image = "nginx", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{}, .replicas = 3 },
        .{ .name = "db", .image = "postgres", .command = &.{}, .ports = &.{}, .env = &.{}, .depends_on = &.{}, .working_dir = null, .volumes = &.{}, .replicas = 2 },
    };
    try std.testing.expectEqual(@as(usize, 5), try count(&services));
    try std.testing.expectEqual(@as(usize, 0), instanceIndex(&services, 0, 0));
    try std.testing.expectEqual(@as(usize, 1), instanceIndex(&services, 1, 0));
    for (services, 0..) |service, logical| {
        for (0..service.replicas) |replica| try std.testing.expectEqual(logical, serviceIndex(&services, instanceIndex(&services, logical, replica)));
    }
}
