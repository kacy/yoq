const std = @import("std");
const spec = @import("../spec.zig");
const validate = @import("../validate.zig");

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
    inline for (.{ manifest.services, manifest.workers, manifest.crons, manifest.training_jobs }, .{ "service", "worker", "cron", "training" }) |workloads, kind| {
        for (workloads) |workload| {
            for (workload.volumes) |mount| {
                if (mount.kind != .named) continue;
                for (manifest.volumes) |declared| {
                    if (std.mem.eql(u8, mount.source, declared.name)) break;
                } else {
                    const message = try std.fmt.allocPrint(alloc, "{s}.{s}.volumes references undeclared volume '{s}'; add [volume.{s}]", .{ kind, workload.name, mount.source, mount.source });
                    errdefer alloc.free(message);
                    try diagnostics.append(alloc, .{ .severity = .@"error", .message = message });
                }
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
