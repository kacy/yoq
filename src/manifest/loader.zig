// loader — manifest TOML parser
//
// reads a manifest.toml file and returns typed spec structs.
// handles field parsing (ports, env, volumes), validation,
// and dependency ordering (topological sort).
//
// load flow:
//   1. expand environment variables (${VAR}, ${VAR:-default})
//   2. parse TOML
//   3. iterate [service.*] subtables → parseService() each one
//   4. iterate [volume.*] subtables → parseVolume() each one
//   5. validate dependencies and required fields
//   6. topological sort services by depends_on
//   7. return Manifest with services in dependency order

const std = @import("std");
const spec = @import("spec.zig");
const toml = @import("../lib/toml.zig");
const log = @import("../lib/log.zig");

pub const LoadError = error{
    /// the manifest file does not exist at the given path
    FileNotFound,
    /// the manifest file exists but could not be read (permissions, I/O error)
    ReadFailed,
    /// the file content is not valid TOML
    ParseFailed,
    /// a service declaration is missing the required `image` field
    MissingImage,
    /// a port mapping string is malformed (expected "host:container" or "container")
    InvalidPortMapping,
    /// an environment variable string is malformed (expected "KEY=VALUE")
    InvalidEnvVar,
    /// a volume mount string is malformed (expected "source:target" or "source:target:ro")
    InvalidVolumeMount,
    /// a health check configuration has invalid or missing fields
    InvalidHealthCheck,
    /// an unrecognized restart policy was specified
    InvalidRestartPolicy,
    /// a TLS configuration has invalid or missing fields
    InvalidTlsConfig,
    /// a volume configuration has invalid or missing fields (e.g. host driver without path)
    InvalidVolumeConfig,
    /// a service declares a dependency on a service name that doesn't exist in the manifest
    UnknownDependency,
    /// the service dependency graph contains a cycle
    CircularDependency,
    /// the manifest contains no service definitions
    NoServices,
    /// a cron schedule interval is missing or malformed (expected "30s", "5m", "1h")
    InvalidSchedule,
    /// memory allocation failed during parsing
    OutOfMemory,
};

pub const default_filename = "manifest.toml";

/// load a manifest from a file path.
/// reads the file, parses it, and returns a typed Manifest.
/// caller must call result.deinit() when done.
pub fn load(alloc: std.mem.Allocator, path: []const u8) LoadError!spec.Manifest {
    const content = std.fs.cwd().readFileAlloc(alloc, path, 1024 * 1024) catch |err| {
        switch (err) {
            error.FileNotFound => {
                log.err("manifest: file not found: {s}", .{path});
                return LoadError.FileNotFound;
            },
            else => {
                log.err("manifest: failed to read: {s}", .{path});
                return LoadError.ReadFailed;
            },
        }
    };
    defer alloc.free(content);

    return loadFromString(alloc, content);
}

/// parse a manifest from a TOML string.
/// environment variables (${VAR}, ${VAR:-default}) are expanded before
/// TOML parsing. use $$ for a literal dollar sign.
/// returns a Manifest with services in dependency order.
/// caller must call result.deinit() when done.
pub fn loadFromString(alloc: std.mem.Allocator, content: []const u8) LoadError!spec.Manifest {
    // expand environment variable references before parsing TOML.
    // this allows variables in any string value throughout the manifest.
    const expanded = try expandVariables(alloc, content);
    defer alloc.free(expanded);

    var parsed = toml.parse(alloc, expanded) catch {
        log.err("manifest: failed to parse TOML", .{});
        return LoadError.ParseFailed;
    };
    defer parsed.deinit();

    return buildManifest(alloc, &parsed.root);
}

// -- variable substitution --

/// expand environment variable references in a string.
///
/// supported patterns:
///   ${VAR}              — replaced with the value of $VAR, or "" if not set
///   ${VAR:-default}     — replaced with $VAR if set, otherwise "default"
///   $$                  — literal "$" (escape sequence)
///
/// returns a new allocated string with all variables expanded.
/// caller owns the returned memory.
pub fn expandVariables(alloc: std.mem.Allocator, input: []const u8) LoadError![]const u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(alloc);

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '$') {
            // escaped dollar: $$ → literal $
            if (i + 1 < input.len and input[i + 1] == '$') {
                result.append(alloc, '$') catch return LoadError.OutOfMemory;
                i += 2;
                continue;
            }

            // variable reference: ${...}
            if (i + 1 < input.len and input[i + 1] == '{') {
                const start = i + 2;
                const close = std.mem.indexOfScalarPos(u8, input, start, '}') orelse {
                    // unclosed ${, emit literally
                    result.append(alloc, '$') catch return LoadError.OutOfMemory;
                    i += 1;
                    continue;
                };

                const content = input[start..close];

                // check for default value syntax: VAR:-default
                var var_name: []const u8 = content;
                var default_value: ?[]const u8 = null;

                if (std.mem.indexOf(u8, content, ":-")) |sep| {
                    var_name = content[0..sep];
                    default_value = content[sep + 2 ..];
                }

                // look up the environment variable
                const value = if (var_name.len > 0)
                    std.process.getEnvVarOwned(alloc, var_name) catch |err| switch (err) {
                        error.EnvironmentVariableNotFound => null,
                        error.OutOfMemory => return LoadError.OutOfMemory,
                        else => null,
                    }
                else
                    null;
                defer if (value) |v| alloc.free(v);

                // use the env value if found, otherwise the default, otherwise empty string
                const expanded = value orelse (default_value orelse "");

                result.appendSlice(alloc, expanded) catch return LoadError.OutOfMemory;
                i = close + 1;
                continue;
            }

            // bare $ not followed by { or $ — emit literally
            result.append(alloc, '$') catch return LoadError.OutOfMemory;
            i += 1;
        } else {
            result.append(alloc, input[i]) catch return LoadError.OutOfMemory;
            i += 1;
        }
    }

    return result.toOwnedSlice(alloc) catch return LoadError.OutOfMemory;
}

// -- internal --

/// build a Manifest from a parsed TOML root table
fn buildManifest(alloc: std.mem.Allocator, root: *const toml.Table) LoadError!spec.Manifest {
    // parse services from [service.*] subtables
    var services: std.ArrayListUnmanaged(spec.Service) = .empty;
    defer {
        for (services.items) |svc| svc.deinit(alloc);
        services.deinit(alloc);
    }

    if (root.getTable("service")) |service_table| {
        for (service_table.entries.keys(), service_table.entries.values()) |name, val| {
            switch (val) {
                .table => |tbl| {
                    const svc = try parseService(alloc, name, tbl);
                    services.append(alloc, svc) catch return LoadError.OutOfMemory;
                },
                else => {},
            }
        }
    }

    if (services.items.len == 0) {
        log.err("manifest: no services defined", .{});
        return LoadError.NoServices;
    }

    // parse workers from [worker.*] subtables
    var workers: std.ArrayListUnmanaged(spec.Worker) = .empty;
    defer {
        for (workers.items) |w| w.deinit(alloc);
        workers.deinit(alloc);
    }

    if (root.getTable("worker")) |worker_table| {
        for (worker_table.entries.keys(), worker_table.entries.values()) |name, val| {
            switch (val) {
                .table => |tbl| {
                    const worker = try parseWorker(alloc, name, tbl);
                    workers.append(alloc, worker) catch return LoadError.OutOfMemory;
                },
                else => {},
            }
        }
    }

    // parse crons from [cron.*] subtables
    var crons: std.ArrayListUnmanaged(spec.Cron) = .empty;
    defer {
        for (crons.items) |cron_job| cron_job.deinit(alloc);
        crons.deinit(alloc);
    }

    if (root.getTable("cron")) |cron_table| {
        for (cron_table.entries.keys(), cron_table.entries.values()) |name, val| {
            switch (val) {
                .table => |tbl| {
                    const cron_job = try parseCron(alloc, name, tbl);
                    crons.append(alloc, cron_job) catch return LoadError.OutOfMemory;
                },
                else => {},
            }
        }
    }

    // parse volumes from [volume.*] subtables
    var volumes: std.ArrayListUnmanaged(spec.Volume) = .empty;
    defer {
        for (volumes.items) |vol| vol.deinit(alloc);
        volumes.deinit(alloc);
    }

    if (root.getTable("volume")) |volume_table| {
        for (volume_table.entries.keys(), volume_table.entries.values()) |name, val| {
            switch (val) {
                .table => |tbl| {
                    const vol = try parseVolume(alloc, name, tbl);
                    volumes.append(alloc, vol) catch return LoadError.OutOfMemory;
                },
                else => {},
            }
        }
    }

    // validate that all depends_on entries reference real services or workers
    try validateDependencies(services.items, workers.items);

    // topological sort — returns services in dependency order
    const sorted = try sortByDependency(alloc, services.items);
    errdefer alloc.free(sorted);

    // the sorted array owns the services now — clear the original list
    // so the defer doesn't double-free
    services.items.len = 0;

    const owned_workers = workers.toOwnedSlice(alloc) catch return LoadError.OutOfMemory;
    errdefer {
        for (owned_workers) |w| w.deinit(alloc);
        alloc.free(owned_workers);
    }

    const owned_crons = crons.toOwnedSlice(alloc) catch return LoadError.OutOfMemory;
    errdefer {
        for (owned_crons) |c| c.deinit(alloc);
        alloc.free(owned_crons);
    }

    const owned_volumes = volumes.toOwnedSlice(alloc) catch return LoadError.OutOfMemory;
    errdefer {
        for (owned_volumes) |vol| vol.deinit(alloc);
        alloc.free(owned_volumes);
    }

    return spec.Manifest{
        .services = sorted,
        .workers = owned_workers,
        .crons = owned_crons,
        .volumes = owned_volumes,
        .alloc = alloc,
    };
}

/// fields shared by services, workers, and crons.
const CommonFields = struct {
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    volumes: []const spec.VolumeMount,
    working_dir: ?[]const u8,

    fn deinit(self: CommonFields, alloc: std.mem.Allocator) void {
        alloc.free(self.image);
        for (self.command) |cmd| alloc.free(cmd);
        alloc.free(self.command);
        for (self.env) |e| alloc.free(e);
        alloc.free(self.env);
        for (self.volumes) |vm| vm.deinit(alloc);
        alloc.free(self.volumes);
        if (self.working_dir) |wd| alloc.free(wd);
    }
};

/// parse the common fields (image, command, env, volumes, working_dir) from a TOML subtable.
fn parseCommonFields(alloc: std.mem.Allocator, kind: []const u8, name: []const u8, table: *const toml.Table) LoadError!CommonFields {
    const image_raw = table.getString("image") orelse {
        log.err("manifest: {s} '{s}' is missing required field 'image'", .{ kind, name });
        return LoadError.MissingImage;
    };

    const command = try parseStringArray(alloc, table.getArray("command"));
    errdefer {
        for (command) |cmd| alloc.free(cmd);
        alloc.free(command);
    }

    const env = try parseEnvVars(alloc, table.getArray("env"));
    errdefer {
        for (env) |e| alloc.free(e);
        alloc.free(env);
    }

    const volume_mounts = try parseVolumeMounts(alloc, table.getArray("volumes"));
    errdefer {
        for (volume_mounts) |vm| vm.deinit(alloc);
        alloc.free(volume_mounts);
    }

    const working_dir: ?[]const u8 = if (table.getString("working_dir")) |wd|
        alloc.dupe(u8, wd) catch return LoadError.OutOfMemory
    else
        null;

    return .{
        .image = alloc.dupe(u8, image_raw) catch return LoadError.OutOfMemory,
        .command = command,
        .env = env,
        .volumes = volume_mounts,
        .working_dir = working_dir,
    };
}

/// parse a single service from its TOML subtable
fn parseService(alloc: std.mem.Allocator, name: []const u8, table: *const toml.Table) LoadError!spec.Service {
    var common = try parseCommonFields(alloc, "service", name, table);
    errdefer common.deinit(alloc);

    const ports = try parsePortMappings(alloc, table.getArray("ports"));
    errdefer alloc.free(ports);

    const depends_on = try parseStringArray(alloc, table.getArray("depends_on"));
    errdefer {
        for (depends_on) |dep| alloc.free(dep);
        alloc.free(depends_on);
    }

    const health_check = try parseHealthCheck(alloc, name, table.getTable("health_check"));
    errdefer if (health_check) |hc| hc.deinit(alloc);

    const restart = try parseRestartPolicy(name, table.getString("restart"));

    const tls_config = try parseTlsConfig(alloc, name, table.getTable("tls"));
    errdefer if (tls_config) |tc| tc.deinit(alloc);

    return .{
        .name = alloc.dupe(u8, name) catch return LoadError.OutOfMemory,
        .image = common.image,
        .command = common.command,
        .ports = ports,
        .env = common.env,
        .depends_on = depends_on,
        .working_dir = common.working_dir,
        .volumes = common.volumes,
        .health_check = health_check,
        .restart = restart,
        .tls = tls_config,
    };
}

/// parse a volume definition from its TOML subtable.
/// accepts `type` (plan-v2 syntax) or `driver` (backward compat), default "local".
/// for host driver: requires `path` field.
fn parseVolume(alloc: std.mem.Allocator, name: []const u8, table: *const toml.Table) LoadError!spec.Volume {
    const driver_str = table.getString("type") orelse table.getString("driver") orelse "local";

    const driver: spec.VolumeDriver = if (std.mem.eql(u8, driver_str, "host")) blk: {
        const path = table.getString("path") orelse {
            log.err("manifest: volume '{s}' with host driver requires 'path' field", .{name});
            return LoadError.InvalidVolumeConfig;
        };
        break :blk .{ .host = .{ .path = alloc.dupe(u8, path) catch return LoadError.OutOfMemory } };
    } else if (std.mem.eql(u8, driver_str, "nfs")) blk: {
        const server = table.getString("server") orelse {
            log.err("manifest: volume '{s}' with nfs driver requires 'server' field", .{name});
            return LoadError.InvalidVolumeConfig;
        };
        if (server.len == 0) {
            log.err("manifest: volume '{s}' nfs server must not be empty", .{name});
            return LoadError.InvalidVolumeConfig;
        }
        const path = table.getString("path") orelse {
            log.err("manifest: volume '{s}' with nfs driver requires 'path' field", .{name});
            return LoadError.InvalidVolumeConfig;
        };
        if (path.len == 0 or path[0] != '/') {
            log.err("manifest: volume '{s}' nfs path must be absolute (start with /)", .{name});
            return LoadError.InvalidVolumeConfig;
        }
        const options_str = table.getString("options");
        const server_dup = alloc.dupe(u8, server) catch return LoadError.OutOfMemory;
        errdefer alloc.free(server_dup);
        const path_dup = alloc.dupe(u8, path) catch return LoadError.OutOfMemory;
        errdefer alloc.free(path_dup);
        const options_dup = if (options_str) |o| (alloc.dupe(u8, o) catch return LoadError.OutOfMemory) else null;
        break :blk .{ .nfs = .{
            .server = server_dup,
            .path = path_dup,
            .options = options_dup,
        } };
    } else if (std.mem.eql(u8, driver_str, "parallel")) blk: {
        const path = table.getString("path") orelse {
            log.err("manifest: volume '{s}' with parallel driver requires 'path' field", .{name});
            return LoadError.InvalidVolumeConfig;
        };
        break :blk .{ .parallel = .{ .mount_path = alloc.dupe(u8, path) catch return LoadError.OutOfMemory } };
    } else .{ .local = .{} };

    return .{
        .name = alloc.dupe(u8, name) catch return LoadError.OutOfMemory,
        .driver = driver,
    };
}

/// parse a worker definition from its TOML subtable.
/// workers are like services but without ports, health checks, restart, or TLS.
fn parseWorker(alloc: std.mem.Allocator, name: []const u8, table: *const toml.Table) LoadError!spec.Worker {
    var common = try parseCommonFields(alloc, "worker", name, table);
    errdefer common.deinit(alloc);

    const depends_on = try parseStringArray(alloc, table.getArray("depends_on"));
    errdefer {
        for (depends_on) |dep| alloc.free(dep);
        alloc.free(depends_on);
    }

    return .{
        .name = alloc.dupe(u8, name) catch return LoadError.OutOfMemory,
        .image = common.image,
        .command = common.command,
        .env = common.env,
        .depends_on = depends_on,
        .working_dir = common.working_dir,
        .volumes = common.volumes,
    };
}

/// parse a cron definition from its TOML subtable.
/// crons are like workers but with a required `every` interval field.
fn parseCron(alloc: std.mem.Allocator, name: []const u8, table: *const toml.Table) LoadError!spec.Cron {
    const every_str = table.getString("every") orelse {
        log.err("manifest: cron '{s}' is missing required field 'every'", .{name});
        return LoadError.InvalidSchedule;
    };

    const every = parseDuration(every_str) orelse {
        log.err("manifest: cron '{s}' has invalid schedule '{s}' (expected e.g. '30s', '5m', '1h')", .{ name, every_str });
        return LoadError.InvalidSchedule;
    };

    var common = try parseCommonFields(alloc, "cron", name, table);
    errdefer common.deinit(alloc);

    return .{
        .name = alloc.dupe(u8, name) catch return LoadError.OutOfMemory,
        .image = common.image,
        .command = common.command,
        .env = common.env,
        .working_dir = common.working_dir,
        .volumes = common.volumes,
        .every = every,
    };
}

/// parse a duration string like "30s", "5m", "1h", "24h" into seconds.
/// returns null if the format is invalid.
fn parseDuration(s: []const u8) ?u64 {
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

// -- dependency validation and ordering --

/// check that all depends_on entries reference existing services or workers
fn validateDependencies(services: []const spec.Service, workers: []const spec.Worker) LoadError!void {
    for (services) |svc| {
        for (svc.depends_on) |dep| {
            // self-dependency check
            if (std.mem.eql(u8, svc.name, dep)) {
                log.err("manifest: service '{s}' depends on itself", .{svc.name});
                return LoadError.CircularDependency;
            }

            // look in services and workers
            var found = false;
            for (services) |other| {
                if (std.mem.eql(u8, other.name, dep)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                for (workers) |w| {
                    if (std.mem.eql(u8, w.name, dep)) {
                        found = true;
                        break;
                    }
                }
            }
            if (!found) {
                log.err("manifest: service '{s}' depends on unknown service or worker '{s}'", .{ svc.name, dep });
                return LoadError.UnknownDependency;
            }
        }
    }
}

/// topological sort using Kahn's algorithm.
/// returns a new slice with services in dependency order (dependencies first).
/// detects cycles — returns CircularDependency if the graph has one.
fn sortByDependency(alloc: std.mem.Allocator, services: []const spec.Service) LoadError![]const spec.Service {
    const service_count = services.len;

    // build name → index mapping
    var name_to_idx: std.StringHashMapUnmanaged(usize) = .empty;
    defer name_to_idx.deinit(alloc);

    for (services, 0..) |svc, i| {
        name_to_idx.put(alloc, svc.name, i) catch return LoadError.OutOfMemory;
    }

    // compute in-degrees (number of dependencies for each service)
    const in_degree = alloc.alloc(usize, service_count) catch return LoadError.OutOfMemory;
    defer alloc.free(in_degree);
    @memset(in_degree, 0);

    for (services) |svc| {
        const idx = name_to_idx.get(svc.name).?;
        // only count dependencies on other services — worker deps are
        // validated by validateDependencies() but don't affect sort order
        var service_dep_count: usize = 0;
        for (svc.depends_on) |dep| {
            if (name_to_idx.contains(dep)) service_dep_count += 1;
        }
        in_degree[idx] = service_dep_count;
    }

    // initialize queue with services that have no dependencies
    var queue: std.ArrayListUnmanaged(usize) = .empty;
    defer queue.deinit(alloc);

    for (in_degree, 0..) |deg, i| {
        if (deg == 0) {
            queue.append(alloc, i) catch return LoadError.OutOfMemory;
        }
    }

    // BFS — process services in dependency order
    var sorted: std.ArrayListUnmanaged(spec.Service) = .empty;
    defer sorted.deinit(alloc);

    var queue_pos: usize = 0;
    while (queue_pos < queue.items.len) {
        const idx = queue.items[queue_pos];
        queue_pos += 1;
        sorted.append(alloc, services[idx]) catch return LoadError.OutOfMemory;

        // for each service that depends on the one we just added,
        // decrement its in-degree and enqueue if it reaches zero
        for (services, 0..) |svc, i| {
            for (svc.depends_on) |dep| {
                if (std.mem.eql(u8, dep, services[idx].name)) {
                    in_degree[i] -= 1;
                    if (in_degree[i] == 0) {
                        queue.append(alloc, i) catch return LoadError.OutOfMemory;
                    }
                }
            }
        }
    }

    if (sorted.items.len != service_count) {
        log.err("manifest: circular dependency detected among services", .{});
        return LoadError.CircularDependency;
    }

    return sorted.toOwnedSlice(alloc) catch return LoadError.OutOfMemory;
}

// -- field parsing helpers --

/// dupe an optional TOML string array into owned slices
fn parseStringArray(alloc: std.mem.Allocator, raw: ?[]const []const u8) LoadError![]const []const u8 {
    const items = raw orelse {
        return alloc.alloc([]const u8, 0) catch return LoadError.OutOfMemory;
    };

    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (result.items) |s| alloc.free(s);
        result.deinit(alloc);
    }

    for (items) |item| {
        const duped = alloc.dupe(u8, item) catch return LoadError.OutOfMemory;
        result.append(alloc, duped) catch {
            alloc.free(duped);
            return LoadError.OutOfMemory;
        };
    }

    return result.toOwnedSlice(alloc) catch return LoadError.OutOfMemory;
}

/// parse port mapping strings like "80:8080" into PortMapping structs
fn parsePortMappings(alloc: std.mem.Allocator, raw: ?[]const []const u8) LoadError![]const spec.PortMapping {
    const items = raw orelse {
        return alloc.alloc(spec.PortMapping, 0) catch return LoadError.OutOfMemory;
    };

    var result: std.ArrayListUnmanaged(spec.PortMapping) = .empty;
    errdefer result.deinit(alloc);

    for (items) |item| {
        const mapping = parseOnePort(item) orelse {
            log.err("manifest: invalid port mapping: '{s}'", .{item});
            return LoadError.InvalidPortMapping;
        };
        result.append(alloc, mapping) catch return LoadError.OutOfMemory;
    }

    return result.toOwnedSlice(alloc) catch return LoadError.OutOfMemory;
}

/// parse a single "host:container" port string
fn parseOnePort(s: []const u8) ?spec.PortMapping {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return null;
    if (colon == 0 or colon >= s.len - 1) return null;

    const host_port = std.fmt.parseInt(u16, s[0..colon], 10) catch return null;
    const container_port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return null;

    return .{ .host_port = host_port, .container_port = container_port };
}

/// validate and dupe env var strings (must contain '=' with non-empty key)
fn parseEnvVars(alloc: std.mem.Allocator, raw: ?[]const []const u8) LoadError![]const []const u8 {
    const items = raw orelse {
        return alloc.alloc([]const u8, 0) catch return LoadError.OutOfMemory;
    };

    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (result.items) |s| alloc.free(s);
        result.deinit(alloc);
    }

    for (items) |item| {
        if (!validateEnvVar(item)) {
            log.err("manifest: invalid env var: '{s}'", .{item});
            return LoadError.InvalidEnvVar;
        }
        const duped = alloc.dupe(u8, item) catch return LoadError.OutOfMemory;
        result.append(alloc, duped) catch {
            alloc.free(duped);
            return LoadError.OutOfMemory;
        };
    }

    return result.toOwnedSlice(alloc) catch return LoadError.OutOfMemory;
}

/// check that an env var string has the form "KEY=VALUE" with a non-empty key
fn validateEnvVar(s: []const u8) bool {
    const eq = std.mem.indexOfScalar(u8, s, '=') orelse return false;
    return eq > 0; // key must be non-empty, value can be empty
}

/// parse volume mount strings like "./src:/app" into VolumeMount structs
fn parseVolumeMounts(alloc: std.mem.Allocator, raw: ?[]const []const u8) LoadError![]const spec.VolumeMount {
    const items = raw orelse {
        return alloc.alloc(spec.VolumeMount, 0) catch return LoadError.OutOfMemory;
    };

    var result: std.ArrayListUnmanaged(spec.VolumeMount) = .empty;
    errdefer {
        for (result.items) |vm| vm.deinit(alloc);
        result.deinit(alloc);
    }

    for (items) |item| {
        const mount = try parseOneVolumeMount(alloc, item);
        result.append(alloc, mount) catch {
            mount.deinit(alloc);
            return LoadError.OutOfMemory;
        };
    }

    return result.toOwnedSlice(alloc) catch return LoadError.OutOfMemory;
}

/// parse a single "source:target" volume mount string.
/// bind detection: source starts with /, ./, or ../ → bind, otherwise → named.
fn parseOneVolumeMount(alloc: std.mem.Allocator, s: []const u8) LoadError!spec.VolumeMount {
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse {
        log.err("manifest: invalid volume mount (missing ':'): '{s}'", .{s});
        return LoadError.InvalidVolumeMount;
    };
    if (colon == 0 or colon >= s.len - 1) {
        log.err("manifest: invalid volume mount: '{s}'", .{s});
        return LoadError.InvalidVolumeMount;
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
        .source = alloc.dupe(u8, source) catch return LoadError.OutOfMemory,
        .target = alloc.dupe(u8, target) catch return LoadError.OutOfMemory,
        .kind = kind,
    };
}

// -- restart policy parsing --

/// parse the restart policy string into a RestartPolicy enum.
/// valid values: "none", "always", "on_failure".
/// returns .none when no value is specified (the default).
fn parseRestartPolicy(service_name: []const u8, raw: ?[]const u8) LoadError!spec.RestartPolicy {
    const value = raw orelse return .none;

    if (std.mem.eql(u8, value, "none")) return .none;
    if (std.mem.eql(u8, value, "always")) return .always;
    if (std.mem.eql(u8, value, "on_failure")) return .on_failure;

    log.err("manifest: service '{s}' has invalid restart policy '{s}' (expected none, always, or on_failure)", .{ service_name, value });
    return LoadError.InvalidRestartPolicy;
}

// -- TLS config parsing --

/// parse an optional [service.*.tls] sub-table into a TlsConfig.
/// returns null if the table is not present.
///
/// expected TOML format:
///   [service.web.tls]
///   domain = "example.com"   # required
///   acme = true              # optional, default false
fn parseTlsConfig(
    alloc: std.mem.Allocator,
    service_name: []const u8,
    table: ?*const toml.Table,
) LoadError!?spec.TlsConfig {
    const tls_table = table orelse return null;

    const domain = tls_table.getString("domain") orelse {
        log.err("manifest: service '{s}' tls is missing required field 'domain'", .{service_name});
        return LoadError.InvalidTlsConfig;
    };

    if (domain.len == 0) {
        log.err("manifest: service '{s}' tls domain cannot be empty", .{service_name});
        return LoadError.InvalidTlsConfig;
    }

    const acme = tls_table.getBool("acme") orelse false;

    // email is required when acme is enabled
    const email_raw = tls_table.getString("email");
    if (acme and email_raw == null) {
        log.err("manifest: service '{s}' tls has acme = true but no email", .{service_name});
        return LoadError.InvalidTlsConfig;
    }

    const email: ?[]const u8 = if (email_raw) |e|
        alloc.dupe(u8, e) catch return LoadError.OutOfMemory
    else
        null;

    return .{
        .domain = alloc.dupe(u8, domain) catch return LoadError.OutOfMemory,
        .acme = acme,
        .email = email,
    };
}

// -- health check parsing --

/// parse an optional [service.*.health_check] sub-table into a HealthCheck.
/// returns null if the table is not present (no health check configured).
///
/// expected TOML format:
///   [service.web.health_check]
///   type = "http"       # "http", "tcp", or "exec"
///   path = "/health"    # http only
///   port = 8080         # http and tcp
///   command = ["cmd"]   # exec only
///   interval = 10       # optional, seconds
///   timeout = 5         # optional, seconds
///   retries = 3         # optional
///   start_period = 0    # optional, seconds
fn parseHealthCheck(
    alloc: std.mem.Allocator,
    service_name: []const u8,
    table: ?*const toml.Table,
) LoadError!?spec.HealthCheck {
    const hc_table = table orelse return null;

    const type_str = hc_table.getString("type") orelse {
        log.err("manifest: service '{s}' health_check is missing required field 'type'", .{service_name});
        return LoadError.InvalidHealthCheck;
    };

    const check_type: spec.CheckType = if (std.mem.eql(u8, type_str, "http")) blk: {
        const path = hc_table.getString("path") orelse {
            log.err("manifest: service '{s}' http health_check is missing 'path'", .{service_name});
            return LoadError.InvalidHealthCheck;
        };
        const port = hc_table.getInt("port") orelse {
            log.err("manifest: service '{s}' http health_check is missing 'port'", .{service_name});
            return LoadError.InvalidHealthCheck;
        };
        if (port < 1 or port > 65535) {
            log.err("manifest: service '{s}' health_check port out of range", .{service_name});
            return LoadError.InvalidHealthCheck;
        }
        break :blk .{ .http = .{
            .path = alloc.dupe(u8, path) catch return LoadError.OutOfMemory,
            .port = @intCast(port),
        } };
    } else if (std.mem.eql(u8, type_str, "tcp")) blk: {
        const port = hc_table.getInt("port") orelse {
            log.err("manifest: service '{s}' tcp health_check is missing 'port'", .{service_name});
            return LoadError.InvalidHealthCheck;
        };
        if (port < 1 or port > 65535) {
            log.err("manifest: service '{s}' health_check port out of range", .{service_name});
            return LoadError.InvalidHealthCheck;
        }
        break :blk .{ .tcp = .{ .port = @intCast(port) } };
    } else if (std.mem.eql(u8, type_str, "exec")) blk: {
        const cmd = try parseStringArray(alloc, hc_table.getArray("command"));
        if (cmd.len == 0) {
            alloc.free(cmd);
            log.err("manifest: service '{s}' exec health_check has empty command", .{service_name});
            return LoadError.InvalidHealthCheck;
        }
        break :blk .{ .exec = .{ .command = cmd } };
    } else {
        log.err("manifest: service '{s}' health_check has unknown type '{s}'", .{ service_name, type_str });
        return LoadError.InvalidHealthCheck;
    };

    // parse optional timing parameters (use defaults if missing)
    var hc = spec.HealthCheck{ .check_type = check_type };

    if (hc_table.getInt("interval")) |v| {
        if (v < 1) {
            log.err("manifest: service '{s}' health_check interval must be >= 1", .{service_name});
            hc.deinit(alloc);
            return LoadError.InvalidHealthCheck;
        }
        hc.interval = @intCast(v);
    }
    if (hc_table.getInt("timeout")) |v| {
        if (v < 1) {
            log.err("manifest: service '{s}' health_check timeout must be >= 1", .{service_name});
            hc.deinit(alloc);
            return LoadError.InvalidHealthCheck;
        }
        hc.timeout = @intCast(v);
    }
    if (hc_table.getInt("retries")) |v| {
        if (v < 1) {
            log.err("manifest: service '{s}' health_check retries must be >= 1", .{service_name});
            hc.deinit(alloc);
            return LoadError.InvalidHealthCheck;
        }
        hc.retries = @intCast(v);
    }
    if (hc_table.getInt("start_period")) |v| {
        if (v < 0) {
            log.err("manifest: service '{s}' health_check start_period must be >= 0", .{service_name});
            hc.deinit(alloc);
            return LoadError.InvalidHealthCheck;
        }
        hc.start_period = @intCast(v);
    }

    return hc;
}

// -- tests --

test "minimal manifest — one service with just image" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.services.len);
    try std.testing.expectEqualStrings("web", manifest.services[0].name);
    try std.testing.expectEqualStrings("nginx:latest", manifest.services[0].image);
    try std.testing.expectEqual(@as(usize, 0), manifest.services[0].command.len);
    try std.testing.expectEqual(@as(usize, 0), manifest.services[0].ports.len);
    try std.testing.expectEqual(@as(usize, 0), manifest.services[0].env.len);
    try std.testing.expectEqual(@as(usize, 0), manifest.services[0].depends_on.len);
    try std.testing.expect(manifest.services[0].working_dir == null);
    try std.testing.expectEqual(@as(usize, 0), manifest.services[0].volumes.len);
    try std.testing.expectEqual(@as(usize, 0), manifest.volumes.len);
}

test "full service — all fields populated" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\command = ["/bin/sh", "-c", "echo hello"]
        \\ports = ["80:8080", "443:8443"]
        \\env = ["DEBUG=true", "PORT=8080"]
        \\depends_on = ["db"]
        \\working_dir = "/app"
        \\volumes = ["./src:/app", "data:/var/data"]
        \\
        \\[service.db]
        \\image = "postgres:15"
    );
    defer manifest.deinit();

    // find web service (order may vary before topo sort is added)
    const web = manifest.serviceByName("web").?;

    try std.testing.expectEqualStrings("nginx:latest", web.image);

    try std.testing.expectEqual(@as(usize, 3), web.command.len);
    try std.testing.expectEqualStrings("/bin/sh", web.command[0]);
    try std.testing.expectEqualStrings("-c", web.command[1]);
    try std.testing.expectEqualStrings("echo hello", web.command[2]);

    try std.testing.expectEqual(@as(usize, 2), web.ports.len);
    try std.testing.expectEqual(@as(u16, 80), web.ports[0].host_port);
    try std.testing.expectEqual(@as(u16, 8080), web.ports[0].container_port);
    try std.testing.expectEqual(@as(u16, 443), web.ports[1].host_port);
    try std.testing.expectEqual(@as(u16, 8443), web.ports[1].container_port);

    try std.testing.expectEqual(@as(usize, 2), web.env.len);
    try std.testing.expectEqualStrings("DEBUG=true", web.env[0]);
    try std.testing.expectEqualStrings("PORT=8080", web.env[1]);

    try std.testing.expectEqual(@as(usize, 1), web.depends_on.len);
    try std.testing.expectEqualStrings("db", web.depends_on[0]);

    try std.testing.expectEqualStrings("/app", web.working_dir.?);

    try std.testing.expectEqual(@as(usize, 2), web.volumes.len);
    try std.testing.expectEqualStrings("./src", web.volumes[0].source);
    try std.testing.expectEqualStrings("/app", web.volumes[0].target);
    try std.testing.expectEqual(spec.VolumeMount.Kind.bind, web.volumes[0].kind);
    try std.testing.expectEqualStrings("data", web.volumes[1].source);
    try std.testing.expectEqualStrings("/var/data", web.volumes[1].target);
    try std.testing.expectEqual(spec.VolumeMount.Kind.named, web.volumes[1].kind);
}

test "volume parsing — driver defaults to local" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[volume.data]
        \\
        \\[volume.logs]
        \\driver = "local"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 2), manifest.volumes.len);

    // find volumes by name (order matches TOML insertion order)
    var found_data = false;
    var found_logs = false;
    for (manifest.volumes) |vol| {
        if (std.mem.eql(u8, vol.name, "data")) {
            try std.testing.expectEqualStrings("local", vol.driver.driverName());
            found_data = true;
        }
        if (std.mem.eql(u8, vol.name, "logs")) {
            try std.testing.expectEqualStrings("local", vol.driver.driverName());
            found_logs = true;
        }
    }
    try std.testing.expect(found_data);
    try std.testing.expect(found_logs);
}

test "volume parsing — host driver requires path" {
    const alloc = std.testing.allocator;

    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[volume.data]
        \\type = "host"
    );
    try std.testing.expectError(LoadError.InvalidVolumeConfig, result);
}

test "volume parsing — host driver with path" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[volume.data]
        \\type = "host"
        \\path = "/mnt/storage/data"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.volumes.len);
    try std.testing.expectEqualStrings("data", manifest.volumes[0].name);
    try std.testing.expectEqualStrings("host", manifest.volumes[0].driver.driverName());
    try std.testing.expectEqualStrings("/mnt/storage/data", manifest.volumes[0].driver.host.path);
}

test "volume parsing — type field takes precedence over driver" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[volume.data]
        \\type = "host"
        \\driver = "local"
        \\path = "/mnt/data"
    );
    defer manifest.deinit();

    try std.testing.expectEqualStrings("host", manifest.volumes[0].driver.driverName());
}

test "volume parsing — nfs requires server" {
    const alloc = std.testing.allocator;

    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[volume.data]
        \\type = "nfs"
        \\path = "/exports/data"
    );
    try std.testing.expectError(LoadError.InvalidVolumeConfig, result);
}

test "volume parsing — nfs requires path" {
    const alloc = std.testing.allocator;

    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[volume.data]
        \\type = "nfs"
        \\server = "10.0.0.1"
    );
    try std.testing.expectError(LoadError.InvalidVolumeConfig, result);
}

test "volume parsing — nfs path must be absolute" {
    const alloc = std.testing.allocator;

    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[volume.data]
        \\type = "nfs"
        \\server = "10.0.0.1"
        \\path = "relative/path"
    );
    try std.testing.expectError(LoadError.InvalidVolumeConfig, result);
}

test "volume parsing — nfs with all fields" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[volume.shared_data]
        \\type = "nfs"
        \\server = "10.0.0.1"
        \\path = "/exports/data"
        \\options = "hard,timeo=600"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.volumes.len);
    try std.testing.expectEqualStrings("shared_data", manifest.volumes[0].name);
    try std.testing.expectEqualStrings("nfs", manifest.volumes[0].driver.driverName());
    try std.testing.expectEqualStrings("10.0.0.1", manifest.volumes[0].driver.nfs.server);
    try std.testing.expectEqualStrings("/exports/data", manifest.volumes[0].driver.nfs.path);
    try std.testing.expectEqualStrings("hard,timeo=600", manifest.volumes[0].driver.nfs.options.?);
}

test "volume parsing — nfs default options is null" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[volume.data]
        \\type = "nfs"
        \\server = "10.0.0.1"
        \\path = "/exports/data"
    );
    defer manifest.deinit();

    try std.testing.expect(manifest.volumes[0].driver.nfs.options == null);
}

test "port parsing — valid formats" {
    const p1 = parseOnePort("80:8080").?;
    try std.testing.expectEqual(@as(u16, 80), p1.host_port);
    try std.testing.expectEqual(@as(u16, 8080), p1.container_port);

    const p2 = parseOnePort("443:443").?;
    try std.testing.expectEqual(@as(u16, 443), p2.host_port);
    try std.testing.expectEqual(@as(u16, 443), p2.container_port);
}

test "port parsing — invalid formats" {
    try std.testing.expect(parseOnePort("invalid") == null);
    try std.testing.expect(parseOnePort(":80") == null);
    try std.testing.expect(parseOnePort("80:") == null);
    try std.testing.expect(parseOnePort("99999:80") == null);
    try std.testing.expect(parseOnePort("80:99999") == null);
}

test "env var validation" {
    try std.testing.expect(validateEnvVar("KEY=VALUE"));
    try std.testing.expect(validateEnvVar("KEY="));
    try std.testing.expect(validateEnvVar("K=V=W"));
    try std.testing.expect(!validateEnvVar("NOEQUALS"));
    try std.testing.expect(!validateEnvVar("=VALUE"));
    try std.testing.expect(!validateEnvVar(""));
}

test "volume mount kind detection" {
    const alloc = std.testing.allocator;

    const bind1 = try parseOneVolumeMount(alloc, "./src:/app");
    defer bind1.deinit(alloc);
    try std.testing.expectEqual(spec.VolumeMount.Kind.bind, bind1.kind);

    const bind2 = try parseOneVolumeMount(alloc, "/data:/mnt");
    defer bind2.deinit(alloc);
    try std.testing.expectEqual(spec.VolumeMount.Kind.bind, bind2.kind);

    const bind3 = try parseOneVolumeMount(alloc, "../config:/etc/app");
    defer bind3.deinit(alloc);
    try std.testing.expectEqual(spec.VolumeMount.Kind.bind, bind3.kind);

    const named = try parseOneVolumeMount(alloc, "myvolume:/var/data");
    defer named.deinit(alloc);
    try std.testing.expectEqual(spec.VolumeMount.Kind.named, named.kind);
}

test "missing image returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\command = ["/bin/sh"]
    );
    try std.testing.expectError(LoadError.MissingImage, result);
}

test "no services returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc, "# empty manifest\n");
    try std.testing.expectError(LoadError.NoServices, result);
}

test "invalid port mapping returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\ports = ["not-a-port"]
    );
    try std.testing.expectError(LoadError.InvalidPortMapping, result);
}

test "invalid env var returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\env = ["NOEQUALS"]
    );
    try std.testing.expectError(LoadError.InvalidEnvVar, result);
}

test "invalid volume mount returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\volumes = ["no-colon"]
    );
    try std.testing.expectError(LoadError.InvalidVolumeMount, result);
}

test "unknown dependency returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\depends_on = ["nonexistent"]
    );
    try std.testing.expectError(LoadError.UnknownDependency, result);
}

test "self-dependency returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\depends_on = ["web"]
    );
    try std.testing.expectError(LoadError.CircularDependency, result);
}

test "circular dependency returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\depends_on = ["api"]
        \\
        \\[service.api]
        \\image = "node:20"
        \\depends_on = ["web"]
    );
    try std.testing.expectError(LoadError.CircularDependency, result);
}

test "dependency ordering — db before web" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\depends_on = ["db"]
        \\
        \\[service.db]
        \\image = "postgres:15"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 2), manifest.services.len);
    // db has no dependencies, so it should come first
    try std.testing.expectEqualStrings("db", manifest.services[0].name);
    try std.testing.expectEqualStrings("web", manifest.services[1].name);
}

test "dependency ordering — three service chain" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.frontend]
        \\image = "nginx:latest"
        \\depends_on = ["api"]
        \\
        \\[service.api]
        \\image = "node:20"
        \\depends_on = ["db"]
        \\
        \\[service.db]
        \\image = "postgres:15"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 3), manifest.services.len);
    // db → api → frontend
    try std.testing.expectEqualStrings("db", manifest.services[0].name);
    try std.testing.expectEqualStrings("api", manifest.services[1].name);
    try std.testing.expectEqualStrings("frontend", manifest.services[2].name);
}

test "dependency ordering — independent services stay stable" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.alpha]
        \\image = "scratch"
        \\
        \\[service.beta]
        \\image = "scratch"
        \\
        \\[service.gamma]
        \\image = "scratch"
    );
    defer manifest.deinit();

    // no dependencies — all have in-degree 0, should come out in insertion order
    try std.testing.expectEqual(@as(usize, 3), manifest.services.len);
    try std.testing.expectEqualStrings("alpha", manifest.services[0].name);
    try std.testing.expectEqualStrings("beta", manifest.services[1].name);
    try std.testing.expectEqualStrings("gamma", manifest.services[2].name);
}

test "load from file — not found" {
    const alloc = std.testing.allocator;
    const result = load(alloc, "/tmp/yoq_test_nonexistent_manifest.toml");
    try std.testing.expectError(LoadError.FileNotFound, result);
}

test "load from file — writes and reads back" {
    const alloc = std.testing.allocator;

    const content =
        \\[service.web]
        \\image = "nginx:latest"
        \\ports = ["80:8080"]
    ;

    // write a temp file
    const path = "/tmp/yoq_test_manifest.toml";
    const file = std.fs.cwd().createFile(path, .{}) catch return;
    defer std.fs.cwd().deleteFile(path) catch {};
    file.writeAll(content) catch return;
    file.close();

    var manifest = try load(alloc, path);
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.services.len);
    try std.testing.expectEqualStrings("web", manifest.services[0].name);
    try std.testing.expectEqual(@as(u16, 80), manifest.services[0].ports[0].host_port);
}

test "full integration — target manifest format" {
    const alloc = std.testing.allocator;

    // this is the manifest format that `yoq up` will use
    var manifest = try loadFromString(alloc,
        \\# yoq manifest for a web app with database
        \\
        \\[service.web]
        \\image = "nginx:latest"
        \\command = ["/bin/sh", "-c", "nginx -g 'daemon off;'"]
        \\ports = ["80:8080", "443:8443"]
        \\env = ["UPSTREAM=api:3000", "DEBUG=false"]
        \\depends_on = ["api"]
        \\working_dir = "/usr/share/nginx"
        \\
        \\[service.api]
        \\image = "node:20-slim"
        \\command = ["node", "server.js"]
        \\ports = ["3000:3000"]
        \\env = ["DATABASE_URL=postgres://db:5432/app", "NODE_ENV=production"]
        \\depends_on = ["db"]
        \\working_dir = "/app"
        \\volumes = ["./src:/app", "node_modules:/app/node_modules"]
        \\
        \\[service.db]
        \\image = "postgres:15"
        \\env = ["POSTGRES_PASSWORD=secret", "POSTGRES_DB=app"]
        \\volumes = ["pgdata:/var/lib/postgresql/data"]
        \\
        \\[volume.pgdata]
        \\driver = "local"
        \\
        \\[volume.node_modules]
    );
    defer manifest.deinit();

    // -- verify service count and dependency order --
    try std.testing.expectEqual(@as(usize, 3), manifest.services.len);
    try std.testing.expectEqualStrings("db", manifest.services[0].name);
    try std.testing.expectEqualStrings("api", manifest.services[1].name);
    try std.testing.expectEqualStrings("web", manifest.services[2].name);

    // -- verify db service --
    const db = manifest.serviceByName("db").?;
    try std.testing.expectEqualStrings("postgres:15", db.image);
    try std.testing.expectEqual(@as(usize, 0), db.command.len);
    try std.testing.expectEqual(@as(usize, 0), db.ports.len);
    try std.testing.expectEqual(@as(usize, 2), db.env.len);
    try std.testing.expectEqualStrings("POSTGRES_PASSWORD=secret", db.env[0]);
    try std.testing.expectEqual(@as(usize, 0), db.depends_on.len);
    try std.testing.expect(db.working_dir == null);
    try std.testing.expectEqual(@as(usize, 1), db.volumes.len);
    try std.testing.expectEqualStrings("pgdata", db.volumes[0].source);
    try std.testing.expectEqual(spec.VolumeMount.Kind.named, db.volumes[0].kind);

    // -- verify api service --
    const api = manifest.serviceByName("api").?;
    try std.testing.expectEqualStrings("node:20-slim", api.image);
    try std.testing.expectEqual(@as(usize, 2), api.command.len);
    try std.testing.expectEqualStrings("node", api.command[0]);
    try std.testing.expectEqualStrings("server.js", api.command[1]);
    try std.testing.expectEqual(@as(usize, 1), api.ports.len);
    try std.testing.expectEqual(@as(u16, 3000), api.ports[0].host_port);
    try std.testing.expectEqual(@as(u16, 3000), api.ports[0].container_port);
    try std.testing.expectEqualStrings("/app", api.working_dir.?);
    try std.testing.expectEqual(@as(usize, 2), api.volumes.len);
    try std.testing.expectEqual(spec.VolumeMount.Kind.bind, api.volumes[0].kind);
    try std.testing.expectEqual(spec.VolumeMount.Kind.named, api.volumes[1].kind);

    // -- verify web service --
    const web = manifest.serviceByName("web").?;
    try std.testing.expectEqualStrings("nginx:latest", web.image);
    try std.testing.expectEqual(@as(usize, 3), web.command.len);
    try std.testing.expectEqual(@as(usize, 2), web.ports.len);
    try std.testing.expectEqual(@as(usize, 2), web.env.len);
    try std.testing.expectEqual(@as(usize, 1), web.depends_on.len);
    try std.testing.expectEqualStrings("api", web.depends_on[0]);

    // -- verify volumes --
    try std.testing.expectEqual(@as(usize, 2), manifest.volumes.len);

    var found_pgdata = false;
    var found_node_modules = false;
    for (manifest.volumes) |vol| {
        if (std.mem.eql(u8, vol.name, "pgdata")) {
            try std.testing.expectEqualStrings("local", vol.driver.driverName());
            found_pgdata = true;
        }
        if (std.mem.eql(u8, vol.name, "node_modules")) {
            // no driver specified → defaults to "local"
            try std.testing.expectEqualStrings("local", vol.driver.driverName());
            found_node_modules = true;
        }
    }
    try std.testing.expect(found_pgdata);
    try std.testing.expect(found_node_modules);
}

test "edge case — no volumes section" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 0), manifest.volumes.len);
}

test "edge case — empty arrays" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\command = []
        \\ports = []
        \\env = []
        \\depends_on = []
        \\volumes = []
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 0), manifest.services[0].command.len);
    try std.testing.expectEqual(@as(usize, 0), manifest.services[0].ports.len);
    try std.testing.expectEqual(@as(usize, 0), manifest.services[0].env.len);
    try std.testing.expectEqual(@as(usize, 0), manifest.services[0].depends_on.len);
    try std.testing.expectEqual(@as(usize, 0), manifest.services[0].volumes.len);
}

// -- health check parsing tests --

test "health check — http type" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.health_check]
        \\type = "http"
        \\path = "/health"
        \\port = 8080
        \\interval = 15
        \\timeout = 3
        \\retries = 5
        \\start_period = 30
    );
    defer manifest.deinit();

    const hc = manifest.services[0].health_check.?;
    switch (hc.check_type) {
        .http => |h| {
            try std.testing.expectEqualStrings("/health", h.path);
            try std.testing.expectEqual(@as(u16, 8080), h.port);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u32, 15), hc.interval);
    try std.testing.expectEqual(@as(u32, 3), hc.timeout);
    try std.testing.expectEqual(@as(u32, 5), hc.retries);
    try std.testing.expectEqual(@as(u32, 30), hc.start_period);
}

test "health check — tcp type" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.db]
        \\image = "postgres:15"
        \\
        \\[service.db.health_check]
        \\type = "tcp"
        \\port = 5432
    );
    defer manifest.deinit();

    const hc = manifest.services[0].health_check.?;
    switch (hc.check_type) {
        .tcp => |t| {
            try std.testing.expectEqual(@as(u16, 5432), t.port);
        },
        else => return error.TestUnexpectedResult,
    }
    // defaults
    try std.testing.expectEqual(@as(u32, 10), hc.interval);
    try std.testing.expectEqual(@as(u32, 5), hc.timeout);
    try std.testing.expectEqual(@as(u32, 3), hc.retries);
    try std.testing.expectEqual(@as(u32, 0), hc.start_period);
}

test "health check — exec type" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.db]
        \\image = "postgres:15"
        \\
        \\[service.db.health_check]
        \\type = "exec"
        \\command = ["pg_isready", "-U", "postgres"]
        \\interval = 5
    );
    defer manifest.deinit();

    const hc = manifest.services[0].health_check.?;
    switch (hc.check_type) {
        .exec => |e| {
            try std.testing.expectEqual(@as(usize, 3), e.command.len);
            try std.testing.expectEqualStrings("pg_isready", e.command[0]);
            try std.testing.expectEqualStrings("-U", e.command[1]);
            try std.testing.expectEqualStrings("postgres", e.command[2]);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u32, 5), hc.interval);
}

test "health check — not specified" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
    );
    defer manifest.deinit();

    try std.testing.expect(manifest.services[0].health_check == null);
}

test "health check — missing type returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.health_check]
        \\port = 8080
    );
    try std.testing.expectError(LoadError.InvalidHealthCheck, result);
}

test "health check — unknown type returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.health_check]
        \\type = "grpc"
        \\port = 50051
    );
    try std.testing.expectError(LoadError.InvalidHealthCheck, result);
}

test "health check — http missing path returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.health_check]
        \\type = "http"
        \\port = 8080
    );
    try std.testing.expectError(LoadError.InvalidHealthCheck, result);
}

test "health check — http missing port returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.health_check]
        \\type = "http"
        \\path = "/health"
    );
    try std.testing.expectError(LoadError.InvalidHealthCheck, result);
}

test "health check — tcp missing port returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.health_check]
        \\type = "tcp"
    );
    try std.testing.expectError(LoadError.InvalidHealthCheck, result);
}

test "health check — exec empty command returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.health_check]
        \\type = "exec"
        \\command = []
    );
    try std.testing.expectError(LoadError.InvalidHealthCheck, result);
}

// -- restart policy parsing tests --

test "restart policy — defaults to none when not specified" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(spec.RestartPolicy.none, manifest.services[0].restart);
}

test "restart policy — always" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\restart = "always"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(spec.RestartPolicy.always, manifest.services[0].restart);
}

test "restart policy — on_failure" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\restart = "on_failure"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(spec.RestartPolicy.on_failure, manifest.services[0].restart);
}

test "restart policy — none (explicit)" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\restart = "none"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(spec.RestartPolicy.none, manifest.services[0].restart);
}

test "restart policy — invalid value returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\restart = "invalid"
    );
    try std.testing.expectError(LoadError.InvalidRestartPolicy, result);
}

test "restart policy — parseRestartPolicy unit tests" {
    try std.testing.expectEqual(spec.RestartPolicy.none, try parseRestartPolicy("test", null));
    try std.testing.expectEqual(spec.RestartPolicy.none, try parseRestartPolicy("test", "none"));
    try std.testing.expectEqual(spec.RestartPolicy.always, try parseRestartPolicy("test", "always"));
    try std.testing.expectEqual(spec.RestartPolicy.on_failure, try parseRestartPolicy("test", "on_failure"));
    try std.testing.expectError(LoadError.InvalidRestartPolicy, parseRestartPolicy("test", "bogus"));
}

// -- variable substitution tests --

test "expandVariables — plain text unchanged" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "hello world");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("hello world", result);
}

test "expandVariables — empty string" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "expandVariables — escaped dollar sign" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "price is $$5");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("price is $5", result);
}

test "expandVariables — double escaped dollar" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "$$$$");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("$$", result);
}

test "expandVariables — env var from environment" {
    const alloc = std.testing.allocator;

    // PATH should always be set in a normal environment
    const result = try expandVariables(alloc, "path is ${PATH}");
    defer alloc.free(result);

    // we can't predict the exact value but it should not contain "${PATH}"
    try std.testing.expect(!std.mem.containsAtLeast(u8, result, 1, "${PATH}"));
    try std.testing.expect(std.mem.startsWith(u8, result, "path is "));
}

test "expandVariables — undefined var becomes empty" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "prefix${YOQ_TEST_UNDEFINED_VAR_12345}suffix");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("prefixsuffix", result);
}

test "expandVariables — default value when var is undefined" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "${YOQ_TEST_UNDEFINED_VAR_12345:-fallback}");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("fallback", result);
}

test "expandVariables — default value with empty default" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "${YOQ_TEST_UNDEFINED_VAR_12345:-}");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "expandVariables — unclosed brace emitted literally" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "hello ${UNCLOSED");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("hello ${UNCLOSED", result);
}

test "expandVariables — bare dollar emitted literally" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "cost $5");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("cost $5", result);
}

test "expandVariables — dollar at end of string" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "end$");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("end$", result);
}

test "expandVariables — empty var name" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "${}");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "expandVariables — empty var name with default" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "${:-hello}");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("hello", result);
}

test "expandVariables — multiple variables in one string" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "${YOQ_TEST_UNDEF_A:-alpha}-${YOQ_TEST_UNDEF_B:-beta}");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("alpha-beta", result);
}

test "expandVariables — nested braces not supported (inner brace closes)" {
    const alloc = std.testing.allocator;
    // ${FOO${BAR}} — the first } closes the outer ${
    // so this becomes: value of "FOO${BAR" + literal "}"
    const result = try expandVariables(alloc, "${YOQ_TEST_UNDEF:-${inner}}");
    defer alloc.free(result);
    // the first } closes at "YOQ_TEST_UNDEF:-${inner", which has default "${inner"
    try std.testing.expectEqualStrings("${inner}", result);
}

test "expandVariables — default value containing colon" {
    const alloc = std.testing.allocator;
    const result = try expandVariables(alloc, "${YOQ_TEST_UNDEF:-postgres://host:5432/db}");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("postgres://host:5432/db", result);
}

test "variable substitution in manifest — image field" {
    const alloc = std.testing.allocator;

    // use a default value since the test env won't have this var set
    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "${YOQ_TEST_IMAGE:-nginx:alpine}"
    );
    defer manifest.deinit();

    try std.testing.expectEqualStrings("nginx:alpine", manifest.services[0].image);
}

test "variable substitution in manifest — env vars" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\env = ["DB_HOST=${YOQ_TEST_DB:-localhost}", "PORT=${YOQ_TEST_PORT:-3000}"]
    );
    defer manifest.deinit();

    try std.testing.expectEqualStrings("DB_HOST=localhost", manifest.services[0].env[0]);
    try std.testing.expectEqualStrings("PORT=3000", manifest.services[0].env[1]);
}

test "variable substitution in manifest — escaped dollar" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\env = ["PRICE=$$5"]
    );
    defer manifest.deinit();

    try std.testing.expectEqualStrings("PRICE=$5", manifest.services[0].env[0]);
}

test "variable substitution in manifest — working_dir" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\working_dir = "${YOQ_TEST_WD:-/app}"
    );
    defer manifest.deinit();

    try std.testing.expectEqualStrings("/app", manifest.services[0].working_dir.?);
}

test "tls config — domain and acme" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.tls]
        \\domain = "example.com"
        \\acme = true
        \\email = "admin@example.com"
    );
    defer manifest.deinit();

    const tls = manifest.services[0].tls orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("example.com", tls.domain);
    try std.testing.expect(tls.acme);
}

test "tls config — domain only, acme defaults to false" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.tls]
        \\domain = "test.org"
    );
    defer manifest.deinit();

    const tls = manifest.services[0].tls orelse return error.TestExpectedNonNull;
    try std.testing.expectEqualStrings("test.org", tls.domain);
    try std.testing.expect(!tls.acme);
}

test "tls config — not specified" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
    );
    defer manifest.deinit();

    try std.testing.expect(manifest.services[0].tls == null);
}

test "tls config — missing domain returns error" {
    const alloc = std.testing.allocator;

    try std.testing.expectError(LoadError.InvalidTlsConfig, loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.tls]
        \\acme = true
    ));
}

// -- worker tests --

test "worker parsing — basic worker" {
    const alloc = std.testing.allocator;
    var manifest = try loadFromString(alloc,
        \\[service.api]
        \\image = "myapp:latest"
        \\ports = ["8000:8000"]
        \\
        \\[worker.migrate]
        \\image = "myapp:latest"
        \\command = ["python", "manage.py", "migrate"]
        \\env = ["DATABASE_URL=postgres://localhost/app"]
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.workers.len);
    const w = manifest.workers[0];
    try std.testing.expectEqualStrings("migrate", w.name);
    try std.testing.expectEqualStrings("myapp:latest", w.image);
    try std.testing.expectEqual(@as(usize, 3), w.command.len);
    try std.testing.expectEqualStrings("python", w.command[0]);
    try std.testing.expectEqual(@as(usize, 1), w.env.len);
}

test "worker as dependency — service depends on worker" {
    const alloc = std.testing.allocator;
    var manifest = try loadFromString(alloc,
        \\[worker.migrate]
        \\image = "myapp:latest"
        \\command = ["python", "manage.py", "migrate"]
        \\
        \\[service.api]
        \\image = "myapp:latest"
        \\depends_on = ["migrate"]
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.services.len);
    try std.testing.expectEqual(@as(usize, 1), manifest.workers.len);
    try std.testing.expectEqualStrings("migrate", manifest.services[0].depends_on[0]);
}

test "worker — missing image returns error" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(LoadError.MissingImage, loadFromString(alloc,
        \\[service.api]
        \\image = "myapp:latest"
        \\
        \\[worker.migrate]
        \\command = ["python", "manage.py", "migrate"]
    ));
}

// -- cron tests --

test "parseDuration — valid durations" {
    try std.testing.expectEqual(@as(?u64, 30), parseDuration("30s"));
    try std.testing.expectEqual(@as(?u64, 300), parseDuration("5m"));
    try std.testing.expectEqual(@as(?u64, 3600), parseDuration("1h"));
    try std.testing.expectEqual(@as(?u64, 86400), parseDuration("24h"));
    try std.testing.expectEqual(@as(?u64, 1), parseDuration("1s"));
}

test "parseDuration — invalid durations" {
    try std.testing.expectEqual(@as(?u64, null), parseDuration(""));
    try std.testing.expectEqual(@as(?u64, null), parseDuration("s"));
    try std.testing.expectEqual(@as(?u64, null), parseDuration("0s"));
    try std.testing.expectEqual(@as(?u64, null), parseDuration("5d"));
    try std.testing.expectEqual(@as(?u64, null), parseDuration("abc"));
    try std.testing.expectEqual(@as(?u64, null), parseDuration("10"));
}

test "cron parsing — basic cron" {
    const alloc = std.testing.allocator;
    var manifest = try loadFromString(alloc,
        \\[service.api]
        \\image = "myapp:latest"
        \\
        \\[cron.backup]
        \\image = "postgres:15"
        \\command = ["pg_dump", "-h", "db", "-U", "postgres"]
        \\every = "24h"
        \\env = ["PGPASSWORD=secret"]
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.crons.len);
    const c = manifest.crons[0];
    try std.testing.expectEqualStrings("backup", c.name);
    try std.testing.expectEqualStrings("postgres:15", c.image);
    try std.testing.expectEqual(@as(u64, 86400), c.every);
    try std.testing.expectEqual(@as(usize, 5), c.command.len);
    try std.testing.expectEqual(@as(usize, 1), c.env.len);
}

test "cron — missing every returns error" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(LoadError.InvalidSchedule, loadFromString(alloc,
        \\[service.api]
        \\image = "myapp:latest"
        \\
        \\[cron.backup]
        \\image = "postgres:15"
        \\command = ["pg_dump"]
    ));
}

test "cron — invalid every returns error" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(LoadError.InvalidSchedule, loadFromString(alloc,
        \\[service.api]
        \\image = "myapp:latest"
        \\
        \\[cron.backup]
        \\image = "postgres:15"
        \\every = "5d"
    ));
}

test "volume parsing — parallel driver" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "app:latest"
        \\
        \\[volume.scratch]
        \\type = "parallel"
        \\path = "/mnt/lustre/scratch"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.volumes.len);
    try std.testing.expectEqualStrings("scratch", manifest.volumes[0].name);
    try std.testing.expectEqualStrings("parallel", manifest.volumes[0].driver.driverName());
    try std.testing.expectEqualStrings("/mnt/lustre/scratch", manifest.volumes[0].driver.parallel.mount_path);
}

test "volume parsing — parallel driver requires path" {
    const alloc = std.testing.allocator;

    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "app:latest"
        \\
        \\[volume.scratch]
        \\type = "parallel"
    );
    try std.testing.expectError(LoadError.InvalidVolumeConfig, result);
}
