// validate — semantic checks on a parsed manifest
//
// runs after the loader succeeds. the loader already validates syntax,
// required fields, port/env/volume formats, health check configs, and
// dependency graphs. this module adds cross-cutting checks that only
// make sense on a fully-parsed manifest:
//
//   - host port conflicts (two services mapping the same host port)
//   - undeclared named volumes (volume mount references a name not in [volume.*])
//   - health check timing (timeout >= interval means checks overlap)

const std = @import("std");
const spec = @import("spec.zig");

pub const Severity = enum {
    @"error",
    warning,
};

pub const Diagnostic = struct {
    severity: Severity,
    message: []const u8,
};

pub const Result = struct {
    diagnostics: []const Diagnostic,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *Result) void {
        for (self.diagnostics) |d| self.alloc.free(d.message);
        self.alloc.free(self.diagnostics);
    }

    pub fn hasErrors(self: *const Result) bool {
        for (self.diagnostics) |d| {
            if (d.severity == .@"error") return true;
        }
        return false;
    }
};

/// run all semantic checks against a parsed manifest.
/// returns diagnostics the caller must free via result.deinit().
pub fn check(alloc: std.mem.Allocator, manifest: *const spec.Manifest) !Result {
    var diagnostics: std.ArrayList(Diagnostic) = .empty;

    try checkHostPortConflicts(alloc, manifest, &diagnostics);
    try checkVolumeReferences(alloc, manifest, &diagnostics);
    try checkHealthCheckTiming(alloc, manifest, &diagnostics);
    try checkTrainingJobs(alloc, manifest, &diagnostics);

    return .{
        .diagnostics = diagnostics.toOwnedSlice(alloc) catch return error.OutOfMemory,
        .alloc = alloc,
    };
}

/// flag duplicate host_port values across services.
/// two services binding the same host port will fail at runtime,
/// so catch it early.
fn checkHostPortConflicts(
    alloc: std.mem.Allocator,
    manifest: *const spec.Manifest,
    diagnostics: *std.ArrayList(Diagnostic),
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

/// warn when a named volume mount references a volume not declared
/// in [volume.*]. bind mounts are skipped — they reference host paths,
/// not named volumes.
fn checkVolumeReferences(
    alloc: std.mem.Allocator,
    manifest: *const spec.Manifest,
    diagnostics: *std.ArrayList(Diagnostic),
) !void {
    // collect all service + worker + cron volume mounts
    const collection = collectAllMounts(manifest);

    if (collection.truncated) {
        const msg = std.fmt.allocPrint(alloc, "manifest has more than 128 services/workers/crons — volume validation may be incomplete", .{}) catch return error.OutOfMemory;
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

/// warn when a health check's timeout >= interval. if the check can't
/// finish before the next one starts, you'll get overlapping checks
/// and confusing behavior.
fn checkHealthCheckTiming(
    alloc: std.mem.Allocator,
    manifest: *const spec.Manifest,
    diagnostics: *std.ArrayList(Diagnostic),
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

const MountEntry = struct {
    name: []const u8,
    volumes: []const spec.VolumeMount,
};

/// gather volume mounts from services, workers, and crons into a
/// unified view for the volume reference check.
const MountCollection = struct {
    entries: []const MountEntry,
    truncated: bool,
};

fn collectAllMounts(manifest: *const spec.Manifest) MountCollection {
    // use a comptime-sized buffer — manifests won't have thousands of entries.
    const max_entries = 128;
    const S = struct {
        var buf: [max_entries]MountEntry = undefined;
    };
    var count: usize = 0;
    var truncated = false;

    for (manifest.services) |svc| {
        if (count >= max_entries) {
            truncated = true;
            break;
        }
        S.buf[count] = .{ .name = svc.name, .volumes = svc.volumes };
        count += 1;
    }
    for (manifest.workers) |w| {
        if (count >= max_entries) {
            truncated = true;
            break;
        }
        S.buf[count] = .{ .name = w.name, .volumes = w.volumes };
        count += 1;
    }
    for (manifest.crons) |c| {
        if (count >= max_entries) {
            truncated = true;
            break;
        }
        S.buf[count] = .{ .name = c.name, .volumes = c.volumes };
        count += 1;
    }
    for (manifest.training_jobs) |tj| {
        if (count >= max_entries) {
            truncated = true;
            break;
        }
        S.buf[count] = .{ .name = tj.name, .volumes = tj.volumes };
        count += 1;
    }

    return .{ .entries = S.buf[0..count], .truncated = truncated };
}

/// validate training job configurations.
/// checks that checkpoint paths are absolute when specified.
fn checkTrainingJobs(
    alloc: std.mem.Allocator,
    manifest: *const spec.Manifest,
    diagnostics: *std.ArrayList(Diagnostic),
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

// -- tests --

fn testService(alloc: std.mem.Allocator, name: []const u8, ports: []const spec.PortMapping, volumes: []const spec.VolumeMount, health_check: ?spec.HealthCheck) !spec.Service {
    return .{
        .name = try alloc.dupe(u8, name),
        .image = try alloc.dupe(u8, "scratch"),
        .command = try alloc.alloc([]const u8, 0),
        .ports = ports,
        .env = try alloc.alloc([]const u8, 0),
        .depends_on = try alloc.alloc([]const u8, 0),
        .working_dir = null,
        .volumes = volumes,
        .health_check = health_check,
    };
}

fn testManifest(alloc: std.mem.Allocator, services: []const spec.Service, volumes: []const spec.Volume) spec.Manifest {
    _ = alloc;
    return .{
        .services = services,
        .workers = &.{},
        .crons = &.{},
        .training_jobs = &.{},
        .volumes = volumes,
        .alloc = std.testing.allocator,
    };
}

test "valid manifest produces zero diagnostics" {
    const alloc = std.testing.allocator;

    const ports_a = try alloc.alloc(spec.PortMapping, 1);
    ports_a[0] = .{ .host_port = 80, .container_port = 8080 };

    const ports_b = try alloc.alloc(spec.PortMapping, 1);
    ports_b[0] = .{ .host_port = 443, .container_port = 8443 };

    const vol_mount = try alloc.alloc(spec.VolumeMount, 1);
    vol_mount[0] = .{
        .source = try alloc.dupe(u8, "data"),
        .target = try alloc.dupe(u8, "/data"),
        .kind = .named,
    };

    const empty_vols = try alloc.alloc(spec.VolumeMount, 0);

    const services = try alloc.alloc(spec.Service, 2);
    services[0] = try testService(alloc, "web", ports_a, empty_vols, null);
    services[1] = try testService(alloc, "api", ports_b, vol_mount, .{
        .check_type = .{ .tcp = .{ .port = 8443 } },
        .interval = 10,
        .timeout = 5,
    });

    const declared_vols = try alloc.alloc(spec.Volume, 1);
    declared_vols[0] = .{
        .name = try alloc.dupe(u8, "data"),
        .driver = .{ .local = .{} },
    };

    var manifest = testManifest(alloc, services, declared_vols);
    defer manifest.deinit();

    var result = try check(alloc, &manifest);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.diagnostics.len);
    try std.testing.expect(!result.hasErrors());
}

test "port conflict produces error diagnostic" {
    const alloc = std.testing.allocator;

    const ports_a = try alloc.alloc(spec.PortMapping, 1);
    ports_a[0] = .{ .host_port = 80, .container_port = 8080 };

    const ports_b = try alloc.alloc(spec.PortMapping, 1);
    ports_b[0] = .{ .host_port = 80, .container_port = 3000 };

    const empty_a = try alloc.alloc(spec.VolumeMount, 0);
    const empty_b = try alloc.alloc(spec.VolumeMount, 0);

    const services = try alloc.alloc(spec.Service, 2);
    services[0] = try testService(alloc, "web", ports_a, empty_a, null);
    services[1] = try testService(alloc, "proxy", ports_b, empty_b, null);

    const volumes = try alloc.alloc(spec.Volume, 0);

    var manifest = testManifest(alloc, services, volumes);
    defer manifest.deinit();

    var result = try check(alloc, &manifest);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.diagnostics.len);
    try std.testing.expectEqual(Severity.@"error", result.diagnostics[0].severity);
    try std.testing.expect(std.mem.indexOf(u8, result.diagnostics[0].message, "host port 80") != null);
    try std.testing.expect(result.hasErrors());
}

test "undeclared named volume produces warning diagnostic" {
    const alloc = std.testing.allocator;

    const vol_mount = try alloc.alloc(spec.VolumeMount, 1);
    vol_mount[0] = .{
        .source = try alloc.dupe(u8, "cache"),
        .target = try alloc.dupe(u8, "/cache"),
        .kind = .named,
    };

    const empty_ports = try alloc.alloc(spec.PortMapping, 0);

    const services = try alloc.alloc(spec.Service, 1);
    services[0] = try testService(alloc, "api", empty_ports, vol_mount, null);

    const volumes = try alloc.alloc(spec.Volume, 0);

    var manifest = testManifest(alloc, services, volumes);
    defer manifest.deinit();

    var result = try check(alloc, &manifest);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.diagnostics.len);
    try std.testing.expectEqual(Severity.warning, result.diagnostics[0].severity);
    try std.testing.expect(std.mem.indexOf(u8, result.diagnostics[0].message, "cache") != null);
    try std.testing.expect(!result.hasErrors());
}

test "health check timeout >= interval produces warning" {
    const alloc = std.testing.allocator;

    const empty_ports = try alloc.alloc(spec.PortMapping, 0);
    const empty_vols = try alloc.alloc(spec.VolumeMount, 0);

    const services = try alloc.alloc(spec.Service, 1);
    services[0] = try testService(alloc, "web", empty_ports, empty_vols, .{
        .check_type = .{ .tcp = .{ .port = 8080 } },
        .interval = 5,
        .timeout = 10,
    });

    const volumes = try alloc.alloc(spec.Volume, 0);

    var manifest = testManifest(alloc, services, volumes);
    defer manifest.deinit();

    var result = try check(alloc, &manifest);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 1), result.diagnostics.len);
    try std.testing.expectEqual(Severity.warning, result.diagnostics[0].severity);
    try std.testing.expect(std.mem.indexOf(u8, result.diagnostics[0].message, "timeout") != null);
    try std.testing.expect(!result.hasErrors());
}

test "bind mounts are skipped by volume reference check" {
    const alloc = std.testing.allocator;

    const vol_mount = try alloc.alloc(spec.VolumeMount, 1);
    vol_mount[0] = .{
        .source = try alloc.dupe(u8, "./src"),
        .target = try alloc.dupe(u8, "/app"),
        .kind = .bind,
    };

    const empty_ports = try alloc.alloc(spec.PortMapping, 0);

    const services = try alloc.alloc(spec.Service, 1);
    services[0] = try testService(alloc, "dev", empty_ports, vol_mount, null);

    const volumes = try alloc.alloc(spec.Volume, 0);

    var manifest = testManifest(alloc, services, volumes);
    defer manifest.deinit();

    var result = try check(alloc, &manifest);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.diagnostics.len);
}

test "multiple port conflicts produce multiple errors" {
    const alloc = std.testing.allocator;

    // service A: ports 80, 443
    const ports_a = try alloc.alloc(spec.PortMapping, 2);
    ports_a[0] = .{ .host_port = 80, .container_port = 8080 };
    ports_a[1] = .{ .host_port = 443, .container_port = 8443 };

    // service B: port 80 (conflicts with A)
    const ports_b = try alloc.alloc(spec.PortMapping, 1);
    ports_b[0] = .{ .host_port = 80, .container_port = 3000 };

    // service C: port 443 (conflicts with A)
    const ports_c = try alloc.alloc(spec.PortMapping, 1);
    ports_c[0] = .{ .host_port = 443, .container_port = 4000 };

    const empty_a = try alloc.alloc(spec.VolumeMount, 0);
    const empty_b = try alloc.alloc(spec.VolumeMount, 0);
    const empty_c = try alloc.alloc(spec.VolumeMount, 0);

    const services = try alloc.alloc(spec.Service, 3);
    services[0] = try testService(alloc, "web", ports_a, empty_a, null);
    services[1] = try testService(alloc, "api", ports_b, empty_b, null);
    services[2] = try testService(alloc, "proxy", ports_c, empty_c, null);

    const volumes = try alloc.alloc(spec.Volume, 0);

    var manifest = testManifest(alloc, services, volumes);
    defer manifest.deinit();

    var result = try check(alloc, &manifest);
    defer result.deinit();

    // should produce 2 error diagnostics (80 conflict + 443 conflict)
    try std.testing.expectEqual(@as(usize, 2), result.diagnostics.len);
    try std.testing.expect(result.hasErrors());
}

test "three-way port conflict" {
    const alloc = std.testing.allocator;

    const ports_a = try alloc.alloc(spec.PortMapping, 1);
    ports_a[0] = .{ .host_port = 8080, .container_port = 80 };

    const ports_b = try alloc.alloc(spec.PortMapping, 1);
    ports_b[0] = .{ .host_port = 8080, .container_port = 3000 };

    const ports_c = try alloc.alloc(spec.PortMapping, 1);
    ports_c[0] = .{ .host_port = 8080, .container_port = 4000 };

    const empty_a = try alloc.alloc(spec.VolumeMount, 0);
    const empty_b = try alloc.alloc(spec.VolumeMount, 0);
    const empty_c = try alloc.alloc(spec.VolumeMount, 0);

    const services = try alloc.alloc(spec.Service, 3);
    services[0] = try testService(alloc, "svc-a", ports_a, empty_a, null);
    services[1] = try testService(alloc, "svc-b", ports_b, empty_b, null);
    services[2] = try testService(alloc, "svc-c", ports_c, empty_c, null);

    const volumes = try alloc.alloc(spec.Volume, 0);

    var manifest = testManifest(alloc, services, volumes);
    defer manifest.deinit();

    var result = try check(alloc, &manifest);
    defer result.deinit();

    // 3 pairwise conflicts: A-B, A-C, B-C
    try std.testing.expectEqual(@as(usize, 3), result.diagnostics.len);
    for (result.diagnostics) |d| {
        try std.testing.expectEqual(Severity.@"error", d.severity);
    }
}

test "health check timeout less than interval produces no warning" {
    const alloc = std.testing.allocator;

    const empty_ports = try alloc.alloc(spec.PortMapping, 0);
    const empty_vols = try alloc.alloc(spec.VolumeMount, 0);

    const services = try alloc.alloc(spec.Service, 1);
    services[0] = try testService(alloc, "web", empty_ports, empty_vols, .{
        .check_type = .{ .tcp = .{ .port = 8080 } },
        .interval = 10,
        .timeout = 5,
    });

    const volumes = try alloc.alloc(spec.Volume, 0);

    var manifest = testManifest(alloc, services, volumes);
    defer manifest.deinit();

    var result = try check(alloc, &manifest);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.diagnostics.len);
}

test "empty manifest produces zero diagnostics" {
    const alloc = std.testing.allocator;

    const services = try alloc.alloc(spec.Service, 0);
    const volumes = try alloc.alloc(spec.Volume, 0);

    var manifest = testManifest(alloc, services, volumes);
    defer manifest.deinit();

    var result = try check(alloc, &manifest);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.diagnostics.len);
    try std.testing.expect(!result.hasErrors());
}

test "volume used by worker and cron is validated" {
    const alloc = std.testing.allocator;

    // worker with an undeclared named volume
    const worker_vols = try alloc.alloc(spec.VolumeMount, 1);
    worker_vols[0] = .{
        .source = try alloc.dupe(u8, "shared-data"),
        .target = try alloc.dupe(u8, "/data"),
        .kind = .named,
    };

    const workers = try alloc.alloc(spec.Worker, 1);
    workers[0] = .{
        .name = try alloc.dupe(u8, "processor"),
        .image = try alloc.dupe(u8, "worker:latest"),
        .command = try alloc.alloc([]const u8, 0),
        .env = try alloc.alloc([]const u8, 0),
        .depends_on = try alloc.alloc([]const u8, 0),
        .working_dir = null,
        .volumes = worker_vols,
    };

    // cron with a different undeclared named volume
    const cron_vols = try alloc.alloc(spec.VolumeMount, 1);
    cron_vols[0] = .{
        .source = try alloc.dupe(u8, "logs"),
        .target = try alloc.dupe(u8, "/var/log"),
        .kind = .named,
    };

    const crons = try alloc.alloc(spec.Cron, 1);
    crons[0] = .{
        .name = try alloc.dupe(u8, "cleanup"),
        .image = try alloc.dupe(u8, "cron:latest"),
        .command = try alloc.alloc([]const u8, 0),
        .env = try alloc.alloc([]const u8, 0),
        .working_dir = null,
        .volumes = cron_vols,
        .every = 3600,
    };

    const services = try alloc.alloc(spec.Service, 0);
    const volumes = try alloc.alloc(spec.Volume, 0);

    var manifest: spec.Manifest = .{
        .services = services,
        .workers = workers,
        .crons = crons,
        .training_jobs = &.{},
        .volumes = volumes,
        .alloc = alloc,
    };
    defer manifest.deinit();

    var result = try check(alloc, &manifest);
    defer result.deinit();

    // should produce 2 warnings (one for "shared-data", one for "logs")
    try std.testing.expectEqual(@as(usize, 2), result.diagnostics.len);
    for (result.diagnostics) |d| {
        try std.testing.expectEqual(Severity.warning, d.severity);
    }
    try std.testing.expect(!result.hasErrors());
}
