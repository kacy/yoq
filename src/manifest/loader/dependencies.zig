const std = @import("std");
const spec = @import("../spec.zig");
const log = @import("../../lib/log.zig");
const common = @import("common.zig");

pub fn validateDependencies(services: []const spec.Service, workers: []const spec.Worker) common.LoadError!void {
    for (services) |service| {
        for (service.depends_on) |dep| {
            if (std.mem.eql(u8, service.name, dep)) {
                log.err("manifest: service '{s}' depends on itself", .{service.name});
                return common.LoadError.CircularDependency;
            }

            var found = false;
            for (services) |other| {
                if (std.mem.eql(u8, other.name, dep)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                for (workers) |worker| {
                    if (std.mem.eql(u8, worker.name, dep)) {
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                log.err("manifest: service '{s}' depends on unknown service or worker '{s}'", .{ service.name, dep });
                return common.LoadError.UnknownDependency;
            }
        }
    }
}

pub fn sortByDependency(alloc: std.mem.Allocator, services: []const spec.Service) common.LoadError![]const spec.Service {
    const service_count = services.len;

    var name_to_idx: std.StringHashMapUnmanaged(usize) = .empty;
    defer name_to_idx.deinit(alloc);

    for (services, 0..) |service, i| {
        name_to_idx.put(alloc, service.name, i) catch return common.LoadError.OutOfMemory;
    }

    const in_degree = alloc.alloc(usize, service_count) catch return common.LoadError.OutOfMemory;
    defer alloc.free(in_degree);
    @memset(in_degree, 0);

    for (services) |service| {
        const idx = name_to_idx.get(service.name).?;
        var service_dep_count: usize = 0;
        for (service.depends_on) |dep| {
            if (name_to_idx.contains(dep)) service_dep_count += 1;
        }
        in_degree[idx] = service_dep_count;
    }

    var queue: std.ArrayListUnmanaged(usize) = .empty;
    defer queue.deinit(alloc);

    for (in_degree, 0..) |degree, i| {
        if (degree == 0) {
            queue.append(alloc, i) catch return common.LoadError.OutOfMemory;
        }
    }

    var sorted: std.ArrayListUnmanaged(spec.Service) = .empty;
    defer sorted.deinit(alloc);

    var queue_pos: usize = 0;
    while (queue_pos < queue.items.len) {
        const idx = queue.items[queue_pos];
        queue_pos += 1;
        sorted.append(alloc, services[idx]) catch return common.LoadError.OutOfMemory;

        for (services, 0..) |service, i| {
            for (service.depends_on) |dep| {
                if (std.mem.eql(u8, dep, services[idx].name)) {
                    in_degree[i] -= 1;
                    if (in_degree[i] == 0) {
                        queue.append(alloc, i) catch return common.LoadError.OutOfMemory;
                    }
                }
            }
        }
    }

    if (sorted.items.len != service_count) {
        log.err("manifest: circular dependency detected among services", .{});
        return common.LoadError.CircularDependency;
    }

    return sorted.toOwnedSlice(alloc) catch return common.LoadError.OutOfMemory;
}
