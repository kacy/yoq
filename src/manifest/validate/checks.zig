const std = @import("std");
const spec = @import("../spec.zig");
const validate = @import("../validate.zig");
const mount_support = @import("mount_support.zig");

pub fn checkHostPortConflicts(
    alloc: std.mem.Allocator,
    manifest: *const spec.Manifest,
    diagnostics: *std.ArrayList(validate.Diagnostic),
) !void {
    for (manifest.services, 0..) |svc_a, i| {
        for (svc_a.ports) |port_a| {
            for (manifest.services[i + 1 ..]) |svc_b| {
                for (svc_b.ports) |port_b| {
                    if (port_a.host_port == port_b.host_port) {
                        const msg = std.fmt.allocPrint(alloc, "host port {d} is mapped by both '{s}' and '{s}'", .{
                            port_a.host_port,
                            svc_a.name,
                            svc_b.name,
                        }) catch return error.OutOfMemory;
                        diagnostics.append(alloc, .{ .severity = .@"error", .message = msg }) catch {
                            alloc.free(msg);
                            return error.OutOfMemory;
                        };
                    }
                }
            }
        }
    }
}

pub fn checkVolumeReferences(
    alloc: std.mem.Allocator,
    manifest: *const spec.Manifest,
    diagnostics: *std.ArrayList(validate.Diagnostic),
) !void {
    const collection = mount_support.collectAllMounts(manifest);

    if (collection.truncated) {
        const msg = std.fmt.allocPrint(
            alloc,
            "manifest has more than 128 services/workers/crons — volume validation may be incomplete",
            .{},
        ) catch return error.OutOfMemory;
        diagnostics.append(alloc, .{ .severity = .warning, .message = msg }) catch {
            alloc.free(msg);
            return error.OutOfMemory;
        };
    }

    for (collection.entries) |entry| {
        for (entry.volumes) |vol| {
            if (vol.kind != .named) continue;

            var found = false;
            for (manifest.volumes) |declared| {
                if (std.mem.eql(u8, vol.source, declared.name)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                const msg = std.fmt.allocPrint(alloc, "service '{s}' uses volume '{s}' which is not declared in [volume.*]", .{
                    entry.name,
                    vol.source,
                }) catch return error.OutOfMemory;
                diagnostics.append(alloc, .{ .severity = .warning, .message = msg }) catch {
                    alloc.free(msg);
                    return error.OutOfMemory;
                };
            }
        }
    }
}

pub fn checkHealthCheckTiming(
    alloc: std.mem.Allocator,
    manifest: *const spec.Manifest,
    diagnostics: *std.ArrayList(validate.Diagnostic),
) !void {
    for (manifest.services) |svc| {
        const hc = svc.health_check orelse continue;
        if (hc.timeout >= hc.interval) {
            const msg = std.fmt.allocPrint(alloc, "service '{s}' health check timeout ({d}s) >= interval ({d}s)", .{
                svc.name,
                hc.timeout,
                hc.interval,
            }) catch return error.OutOfMemory;
            diagnostics.append(alloc, .{ .severity = .warning, .message = msg }) catch {
                alloc.free(msg);
                return error.OutOfMemory;
            };
        }
    }
}

pub fn checkTrainingJobs(
    alloc: std.mem.Allocator,
    manifest: *const spec.Manifest,
    diagnostics: *std.ArrayList(validate.Diagnostic),
) !void {
    for (manifest.training_jobs) |tj| {
        if (tj.checkpoint) |ckpt| {
            if (ckpt.path.len == 0 or ckpt.path[0] != '/') {
                const msg = std.fmt.allocPrint(alloc, "training '{s}' checkpoint path must be absolute (start with /)", .{
                    tj.name,
                }) catch return error.OutOfMemory;
                diagnostics.append(alloc, .{ .severity = .@"error", .message = msg }) catch {
                    alloc.free(msg);
                    return error.OutOfMemory;
                };
            }
        }
    }
}
