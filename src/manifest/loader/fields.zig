const std = @import("std");
const spec = @import("../spec.zig");
const toml = @import("../../lib/toml.zig");
const log = @import("../../lib/log.zig");
const common = @import("common.zig");

pub fn parseStringArray(alloc: std.mem.Allocator, raw: ?[]const []const u8) common.LoadError![]const []const u8 {
    const items = raw orelse {
        return alloc.alloc([]const u8, 0) catch return common.LoadError.OutOfMemory;
    };

    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (result.items) |item| alloc.free(item);
        result.deinit(alloc);
    }

    for (items) |item| {
        const duped = alloc.dupe(u8, item) catch return common.LoadError.OutOfMemory;
        result.append(alloc, duped) catch {
            alloc.free(duped);
            return common.LoadError.OutOfMemory;
        };
    }

    return result.toOwnedSlice(alloc) catch return common.LoadError.OutOfMemory;
}

pub fn parsePortMappings(alloc: std.mem.Allocator, raw: ?[]const []const u8) common.LoadError![]const spec.PortMapping {
    const items = raw orelse {
        return alloc.alloc(spec.PortMapping, 0) catch return common.LoadError.OutOfMemory;
    };

    var result: std.ArrayListUnmanaged(spec.PortMapping) = .empty;
    errdefer result.deinit(alloc);

    for (items) |item| {
        const mapping = parseOnePort(item) orelse {
            log.err("manifest: invalid port mapping: '{s}'", .{item});
            return common.LoadError.InvalidPortMapping;
        };
        result.append(alloc, mapping) catch return common.LoadError.OutOfMemory;
    }

    return result.toOwnedSlice(alloc) catch return common.LoadError.OutOfMemory;
}

pub fn parseOnePort(s: []const u8) ?spec.PortMapping {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return null;
    if (colon == 0 or colon >= s.len - 1) return null;

    const host_port = std.fmt.parseInt(u16, s[0..colon], 10) catch return null;
    const container_port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return null;
    return .{ .host_port = host_port, .container_port = container_port };
}

pub fn parseEnvVars(alloc: std.mem.Allocator, raw: ?[]const []const u8) common.LoadError![]const []const u8 {
    const items = raw orelse {
        return alloc.alloc([]const u8, 0) catch return common.LoadError.OutOfMemory;
    };

    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (result.items) |item| alloc.free(item);
        result.deinit(alloc);
    }

    for (items) |item| {
        if (!validateEnvVar(item)) {
            log.err("manifest: invalid env var: '{s}'", .{item});
            return common.LoadError.InvalidEnvVar;
        }
        const duped = alloc.dupe(u8, item) catch return common.LoadError.OutOfMemory;
        result.append(alloc, duped) catch {
            alloc.free(duped);
            return common.LoadError.OutOfMemory;
        };
    }

    return result.toOwnedSlice(alloc) catch return common.LoadError.OutOfMemory;
}

pub fn validateEnvVar(s: []const u8) bool {
    const eq = std.mem.indexOfScalar(u8, s, '=') orelse return false;
    return eq > 0;
}

pub fn parseVolumeMounts(alloc: std.mem.Allocator, raw: ?[]const []const u8) common.LoadError![]const spec.VolumeMount {
    const items = raw orelse {
        return alloc.alloc(spec.VolumeMount, 0) catch return common.LoadError.OutOfMemory;
    };

    var result: std.ArrayListUnmanaged(spec.VolumeMount) = .empty;
    errdefer {
        for (result.items) |mount| mount.deinit(alloc);
        result.deinit(alloc);
    }

    for (items) |item| {
        const mount = try parseOneVolumeMount(alloc, item);
        result.append(alloc, mount) catch {
            mount.deinit(alloc);
            return common.LoadError.OutOfMemory;
        };
    }

    return result.toOwnedSlice(alloc) catch return common.LoadError.OutOfMemory;
}

pub fn parseOneVolumeMount(alloc: std.mem.Allocator, s: []const u8) common.LoadError!spec.VolumeMount {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse {
        log.err("manifest: invalid volume mount (missing ':'): '{s}'", .{s});
        return common.LoadError.InvalidVolumeMount;
    };
    if (colon == 0 or colon >= s.len - 1) {
        log.err("manifest: invalid volume mount: '{s}'", .{s});
        return common.LoadError.InvalidVolumeMount;
    }

    const source = s[0..colon];
    const target = s[colon + 1 ..];
    const kind: spec.VolumeMount.Kind = if (std.mem.startsWith(u8, source, "/") or
        std.mem.startsWith(u8, source, "./") or
        std.mem.startsWith(u8, source, "../"))
        .bind
    else
        .named;

    return .{
        .source = alloc.dupe(u8, source) catch return common.LoadError.OutOfMemory,
        .target = alloc.dupe(u8, target) catch return common.LoadError.OutOfMemory,
        .kind = kind,
    };
}

pub fn parseRestartPolicy(service_name: []const u8, raw: ?[]const u8) common.LoadError!spec.RestartPolicy {
    const value = raw orelse return .none;

    if (std.mem.eql(u8, value, "none")) return .none;
    if (std.mem.eql(u8, value, "always")) return .always;
    if (std.mem.eql(u8, value, "on_failure")) return .on_failure;

    log.err("manifest: service '{s}' has invalid restart policy '{s}' (expected none, always, or on_failure)", .{ service_name, value });
    return common.LoadError.InvalidRestartPolicy;
}

pub fn parseTlsConfig(
    alloc: std.mem.Allocator,
    service_name: []const u8,
    table: ?*const toml.Table,
) common.LoadError!?spec.TlsConfig {
    const tls_table = table orelse return null;

    const domain = tls_table.getString("domain") orelse {
        log.err("manifest: service '{s}' tls is missing required field 'domain'", .{service_name});
        return common.LoadError.InvalidTlsConfig;
    };
    if (domain.len == 0) {
        log.err("manifest: service '{s}' tls domain cannot be empty", .{service_name});
        return common.LoadError.InvalidTlsConfig;
    }

    const acme = tls_table.getBool("acme") orelse false;
    const email_raw = tls_table.getString("email");
    if (acme and email_raw == null) {
        log.err("manifest: service '{s}' tls has acme = true but no email", .{service_name});
        return common.LoadError.InvalidTlsConfig;
    }

    const email: ?[]const u8 = if (email_raw) |e|
        alloc.dupe(u8, e) catch return common.LoadError.OutOfMemory
    else
        null;

    return .{
        .domain = alloc.dupe(u8, domain) catch return common.LoadError.OutOfMemory,
        .acme = acme,
        .email = email,
    };
}

pub fn parseHttpProxyRoute(
    alloc: std.mem.Allocator,
    service_name: []const u8,
    route_name: []const u8,
    field_name: []const u8,
    table: ?*const toml.Table,
) common.LoadError!?spec.HttpProxyRoute {
    const proxy_table = table orelse return null;

    const host = proxy_table.getString("host") orelse {
        log.err("manifest: service '{s}' {s} route '{s}' is missing required field 'host'", .{ service_name, field_name, route_name });
        return common.LoadError.InvalidHttpProxyConfig;
    };
    if (host.len == 0) {
        log.err("manifest: service '{s}' {s} route '{s}' host cannot be empty", .{ service_name, field_name, route_name });
        return common.LoadError.InvalidHttpProxyConfig;
    }

    const path_prefix = proxy_table.getString("path_prefix") orelse "/";
    if (path_prefix.len == 0 or path_prefix[0] != '/') {
        log.err("manifest: service '{s}' {s} route '{s}' path_prefix must start with '/'", .{ service_name, field_name, route_name });
        return common.LoadError.InvalidHttpProxyConfig;
    }

    const retries_raw = proxy_table.getInt("retries") orelse 0;
    if (retries_raw < 0 or retries_raw > 5) {
        log.err("manifest: service '{s}' {s} route '{s}' retries must be between 0 and 5", .{ service_name, field_name, route_name });
        return common.LoadError.InvalidHttpProxyConfig;
    }

    const connect_timeout_raw = proxy_table.getInt("connect_timeout_ms") orelse 1000;
    if (connect_timeout_raw < 1 or connect_timeout_raw > std.math.maxInt(u32)) {
        log.err("manifest: service '{s}' {s} route '{s}' connect_timeout_ms must be between 1 and {d}", .{
            service_name,
            field_name,
            route_name,
            std.math.maxInt(u32),
        });
        return common.LoadError.InvalidHttpProxyConfig;
    }

    const request_timeout_raw = proxy_table.getInt("request_timeout_ms") orelse 5000;
    if (request_timeout_raw < 1 or request_timeout_raw > std.math.maxInt(u32)) {
        log.err("manifest: service '{s}' {s} route '{s}' request_timeout_ms must be between 1 and {d}", .{
            service_name,
            field_name,
            route_name,
            std.math.maxInt(u32),
        });
        return common.LoadError.InvalidHttpProxyConfig;
    }

    const preserve_host = proxy_table.getBool("preserve_host") orelse true;

    return .{
        .name = alloc.dupe(u8, route_name) catch return common.LoadError.OutOfMemory,
        .host = alloc.dupe(u8, host) catch return common.LoadError.OutOfMemory,
        .path_prefix = alloc.dupe(u8, path_prefix) catch return common.LoadError.OutOfMemory,
        .retries = @intCast(retries_raw),
        .connect_timeout_ms = @intCast(connect_timeout_raw),
        .request_timeout_ms = @intCast(request_timeout_raw),
        .preserve_host = preserve_host,
    };
}

pub fn parseHttpProxyRoutes(
    alloc: std.mem.Allocator,
    service_name: []const u8,
    http_proxy_table: ?*const toml.Table,
    http_routes_table: ?*const toml.Table,
) common.LoadError![]const spec.HttpProxyRoute {
    if (http_proxy_table != null and http_routes_table != null) {
        log.err("manifest: service '{s}' cannot define both http_proxy and http_routes", .{service_name});
        return common.LoadError.InvalidHttpProxyConfig;
    }

    if (http_proxy_table) |table| {
        const route = (try parseHttpProxyRoute(alloc, service_name, "default", "http_proxy", table)).?;
        errdefer route.deinit(alloc);
        const routes = try alloc.alloc(spec.HttpProxyRoute, 1);
        routes[0] = route;
        return routes;
    }

    const routes_table = http_routes_table orelse return alloc.alloc(spec.HttpProxyRoute, 0) catch return common.LoadError.OutOfMemory;

    var routes: std.ArrayListUnmanaged(spec.HttpProxyRoute) = .empty;
    errdefer {
        for (routes.items) |route| route.deinit(alloc);
        routes.deinit(alloc);
    }

    for (routes_table.entries.keys(), routes_table.entries.values()) |route_name, value| {
        const route_table = switch (value) {
            .table => |child| child,
            else => {
                log.err("manifest: service '{s}' http_routes entry '{s}' must be a table", .{ service_name, route_name });
                return common.LoadError.InvalidHttpProxyConfig;
            },
        };
        const route = (try parseHttpProxyRoute(alloc, service_name, route_name, "http_routes", route_table)).?;
        errdefer route.deinit(alloc);
        try validateHttpProxyRouteConflict(service_name, routes.items, route);
        routes.append(alloc, route) catch {
            route.deinit(alloc);
            return common.LoadError.OutOfMemory;
        };
    }

    if (routes.items.len == 0) {
        log.err("manifest: service '{s}' http_routes must define at least one named route table", .{service_name});
        return common.LoadError.InvalidHttpProxyConfig;
    }

    return routes.toOwnedSlice(alloc) catch return common.LoadError.OutOfMemory;
}

fn validateHttpProxyRouteConflict(
    service_name: []const u8,
    existing: []const spec.HttpProxyRoute,
    candidate: spec.HttpProxyRoute,
) common.LoadError!void {
    for (existing) |route| {
        if (!std.ascii.eqlIgnoreCase(route.host, candidate.host)) continue;
        if (!std.mem.eql(u8, route.path_prefix, candidate.path_prefix)) continue;

        log.err(
            "manifest: service '{s}' defines duplicate http route match host='{s}' path_prefix='{s}'",
            .{ service_name, candidate.host, candidate.path_prefix },
        );
        return common.LoadError.InvalidHttpProxyConfig;
    }
}

pub fn parseGpuSpec(
    alloc: std.mem.Allocator,
    table: ?*const toml.Table,
) common.LoadError!?spec.GpuSpec {
    const gpu_table = table orelse return null;

    const count_raw = gpu_table.getInt("count") orelse return null;
    if (count_raw < 1) return null;

    const model_raw = gpu_table.getString("model");
    const model: ?[]const u8 = if (model_raw) |model_name|
        alloc.dupe(u8, model_name) catch return common.LoadError.OutOfMemory
    else
        null;

    const vram_raw = gpu_table.getInt("vram_min_mb");
    const vram_min_mb: ?u64 = if (vram_raw) |vram| @intCast(@max(0, vram)) else null;

    return .{
        .count = @intCast(count_raw),
        .model = model,
        .vram_min_mb = vram_min_mb,
    };
}

pub fn parseGpuMeshSpec(table: ?*const toml.Table) common.LoadError!?spec.GpuMeshSpec {
    const mesh_table = table orelse return null;

    const world_size_raw = mesh_table.getInt("world_size") orelse return null;
    if (world_size_raw < 1) return null;

    const gpus_per_rank_raw = mesh_table.getInt("gpus_per_rank");
    const gpus_per_rank: u32 = if (gpus_per_rank_raw) |gpus| @intCast(@max(1, gpus)) else 1;

    const master_port_raw = mesh_table.getInt("master_port");
    const master_port: u16 = if (master_port_raw) |port| @intCast(@min(65535, @max(1, port))) else 29500;

    return .{
        .world_size = @intCast(world_size_raw),
        .gpus_per_rank = gpus_per_rank,
        .master_port = master_port,
    };
}

pub fn parseHealthCheck(
    alloc: std.mem.Allocator,
    service_name: []const u8,
    table: ?*const toml.Table,
) common.LoadError!?spec.HealthCheck {
    const hc_table = table orelse return null;

    const type_str = hc_table.getString("type") orelse {
        log.err("manifest: service '{s}' health_check is missing required field 'type'", .{service_name});
        return common.LoadError.InvalidHealthCheck;
    };

    const check_type: spec.CheckType = if (std.mem.eql(u8, type_str, "http")) blk: {
        const path = hc_table.getString("path") orelse {
            log.err("manifest: service '{s}' http health_check is missing 'path'", .{service_name});
            return common.LoadError.InvalidHealthCheck;
        };
        const port = hc_table.getInt("port") orelse {
            log.err("manifest: service '{s}' http health_check is missing 'port'", .{service_name});
            return common.LoadError.InvalidHealthCheck;
        };
        if (port < 1 or port > 65535) {
            log.err("manifest: service '{s}' health_check port out of range", .{service_name});
            return common.LoadError.InvalidHealthCheck;
        }
        break :blk .{ .http = .{
            .path = alloc.dupe(u8, path) catch return common.LoadError.OutOfMemory,
            .port = @intCast(port),
        } };
    } else if (std.mem.eql(u8, type_str, "tcp")) blk: {
        const port = hc_table.getInt("port") orelse {
            log.err("manifest: service '{s}' tcp health_check is missing 'port'", .{service_name});
            return common.LoadError.InvalidHealthCheck;
        };
        if (port < 1 or port > 65535) {
            log.err("manifest: service '{s}' health_check port out of range", .{service_name});
            return common.LoadError.InvalidHealthCheck;
        }
        break :blk .{ .tcp = .{ .port = @intCast(port) } };
    } else if (std.mem.eql(u8, type_str, "exec")) blk: {
        const cmd = try parseStringArray(alloc, hc_table.getArray("command"));
        if (cmd.len == 0) {
            alloc.free(cmd);
            log.err("manifest: service '{s}' exec health_check has empty command", .{service_name});
            return common.LoadError.InvalidHealthCheck;
        }
        break :blk .{ .exec = .{ .command = cmd } };
    } else {
        log.err("manifest: service '{s}' health_check has unknown type '{s}'", .{ service_name, type_str });
        return common.LoadError.InvalidHealthCheck;
    };

    var health_check = spec.HealthCheck{ .check_type = check_type };

    if (hc_table.getInt("interval")) |value| {
        if (value < 1) {
            log.err("manifest: service '{s}' health_check interval must be >= 1", .{service_name});
            health_check.deinit(alloc);
            return common.LoadError.InvalidHealthCheck;
        }
        health_check.interval = @intCast(value);
    }
    if (hc_table.getInt("timeout")) |value| {
        if (value < 1) {
            log.err("manifest: service '{s}' health_check timeout must be >= 1", .{service_name});
            health_check.deinit(alloc);
            return common.LoadError.InvalidHealthCheck;
        }
        health_check.timeout = @intCast(value);
    }
    if (hc_table.getInt("retries")) |value| {
        if (value < 1) {
            log.err("manifest: service '{s}' health_check retries must be >= 1", .{service_name});
            health_check.deinit(alloc);
            return common.LoadError.InvalidHealthCheck;
        }
        health_check.retries = @intCast(value);
    }
    if (hc_table.getInt("start_period")) |value| {
        if (value < 0) {
            log.err("manifest: service '{s}' health_check start_period must be >= 0", .{service_name});
            health_check.deinit(alloc);
            return common.LoadError.InvalidHealthCheck;
        }
        health_check.start_period = @intCast(value);
    }

    return health_check;
}

pub fn parseDuration(s: []const u8) ?u64 {
    if (s.len < 2) return null;

    const suffix = s[s.len - 1];
    const number_part = s[0 .. s.len - 1];
    const value = std.fmt.parseInt(u64, number_part, 10) catch return null;
    if (value == 0) return null;

    return switch (suffix) {
        's' => value,
        'm' => value * 60,
        'h' => value * 3600,
        else => null,
    };
}
