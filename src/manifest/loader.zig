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
const common = @import("loader/common.zig");
const variables = @import("loader/variables.zig");
const fields = @import("loader/fields.zig");
const dependencies = @import("loader/dependencies.zig");
const entries = @import("loader/entries.zig");

pub const LoadError = common.LoadError;

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
    const expanded = try expandVariables(alloc, content);
    defer alloc.free(expanded);

    var parsed = toml.parse(alloc, expanded) catch {
        log.err("manifest: failed to parse TOML", .{});
        return LoadError.ParseFailed;
    };
    defer parsed.deinit();

    return buildManifest(alloc, &parsed.root);
}

pub fn expandVariables(alloc: std.mem.Allocator, input: []const u8) LoadError![]const u8 {
    return variables.expandVariables(alloc, input);
}

fn buildManifest(alloc: std.mem.Allocator, root: *const toml.Table) LoadError!spec.Manifest {
    var services: std.ArrayListUnmanaged(spec.Service) = .empty;
    defer {
        for (services.items) |svc| svc.deinit(alloc);
        services.deinit(alloc);
    }

    if (root.getTable("service")) |service_table| {
        for (service_table.entries.keys(), service_table.entries.values()) |name, val| {
            switch (val) {
                .table => |tbl| {
                    const svc = try entries.parseService(alloc, name, tbl);
                    services.append(alloc, svc) catch return LoadError.OutOfMemory;
                },
                else => {},
            }
        }
    }

    var training_jobs: std.ArrayListUnmanaged(spec.TrainingJob) = .empty;
    defer {
        for (training_jobs.items) |tj| tj.deinit(alloc);
        training_jobs.deinit(alloc);
    }

    if (root.getTable("training")) |training_table| {
        for (training_table.entries.keys(), training_table.entries.values()) |name, val| {
            switch (val) {
                .table => |tbl| {
                    const tj = try entries.parseTrainingJob(alloc, name, tbl);
                    training_jobs.append(alloc, tj) catch return LoadError.OutOfMemory;
                },
                else => {},
            }
        }
    }

    if (services.items.len == 0 and training_jobs.items.len == 0) {
        log.err("manifest: no services or training jobs defined", .{});
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
                    const worker = try entries.parseWorker(alloc, name, tbl);
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
                    const cron_job = try entries.parseCron(alloc, name, tbl);
                    crons.append(alloc, cron_job) catch return LoadError.OutOfMemory;
                },
                else => {},
            }
        }
    }

    var volumes: std.ArrayListUnmanaged(spec.Volume) = .empty;
    defer {
        for (volumes.items) |vol| vol.deinit(alloc);
        volumes.deinit(alloc);
    }

    if (root.getTable("volume")) |volume_table| {
        for (volume_table.entries.keys(), volume_table.entries.values()) |name, val| {
            switch (val) {
                .table => |tbl| {
                    const vol = try entries.parseVolume(alloc, name, tbl);
                    volumes.append(alloc, vol) catch return LoadError.OutOfMemory;
                },
                else => {},
            }
        }
    }

    try dependencies.validateDependencies(services.items, workers.items);

    const sorted = try dependencies.sortByDependency(alloc, services.items);
    errdefer alloc.free(sorted);

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

    const owned_training_jobs = training_jobs.toOwnedSlice(alloc) catch return LoadError.OutOfMemory;
    errdefer {
        for (owned_training_jobs) |tj| tj.deinit(alloc);
        alloc.free(owned_training_jobs);
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
        .training_jobs = owned_training_jobs,
        .volumes = owned_volumes,
        .alloc = alloc,
    };
}

fn parseDuration(s: []const u8) ?u64 {
    return fields.parseDuration(s);
}

fn parseOnePort(s: []const u8) ?spec.PortMapping {
    return fields.parseOnePort(s);
}

fn validateEnvVar(s: []const u8) bool {
    return fields.validateEnvVar(s);
}

fn parseOneVolumeMount(alloc: std.mem.Allocator, s: []const u8) LoadError!spec.VolumeMount {
    return fields.parseOneVolumeMount(alloc, s);
}

fn parseRestartPolicy(service_name: []const u8, raw: ?[]const u8) LoadError!spec.RestartPolicy {
    return fields.parseRestartPolicy(service_name, raw);
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

test "health check — grpc type" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.api]
        \\image = "grpc-server:latest"
        \\
        \\[service.api.health_check]
        \\type = "grpc"
        \\port = 50051
        \\interval = 5
    );
    defer manifest.deinit();

    const hc = manifest.services[0].health_check.?;
    switch (hc.check_type) {
        .grpc => |g| {
            try std.testing.expectEqual(@as(u16, 50051), g.port);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u32, 5), hc.interval);
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
        \\type = "udp"
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

test "health check — grpc missing port returns error" {
    const alloc = std.testing.allocator;
    const result = loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.health_check]
        \\type = "grpc"
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

test "http proxy config — host and path prefix" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.http_proxy]
        \\host = "api.internal"
        \\path_prefix = "/v1"
        \\retries = 2
        \\connect_timeout_ms = 1500
        \\request_timeout_ms = 9000
        \\preserve_host = false
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.services[0].http_routes.len);
    const proxy = manifest.services[0].http_routes[0];
    try std.testing.expectEqualStrings("default", proxy.name);
    try std.testing.expectEqualStrings("api.internal", proxy.host);
    try std.testing.expectEqualStrings("/v1", proxy.path_prefix);
    try std.testing.expectEqual(@as(?[]const u8, null), proxy.rewrite_prefix);
    try std.testing.expectEqual(@as(u8, 2), proxy.retries);
    try std.testing.expectEqual(@as(u32, 1500), proxy.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 9000), proxy.request_timeout_ms);
    try std.testing.expect(!proxy.preserve_host);
}

test "http proxy config — defaults" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.http_proxy]
        \\host = "api.internal"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.services[0].http_routes.len);
    const proxy = manifest.services[0].http_routes[0];
    try std.testing.expectEqualStrings("api.internal", proxy.host);
    try std.testing.expectEqualStrings("/", proxy.path_prefix);
    try std.testing.expectEqual(@as(u8, 0), proxy.retries);
    try std.testing.expectEqual(@as(u32, 1000), proxy.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 5000), proxy.request_timeout_ms);
    try std.testing.expect(proxy.preserve_host);
}

test "http proxy config — missing host returns error" {
    const alloc = std.testing.allocator;

    try std.testing.expectError(LoadError.InvalidHttpProxyConfig, loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.http_proxy]
        \\path_prefix = "/v1"
    ));
}

test "http proxy config — invalid path prefix returns error" {
    const alloc = std.testing.allocator;

    try std.testing.expectError(LoadError.InvalidHttpProxyConfig, loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.http_proxy]
        \\host = "api.internal"
        \\path_prefix = "v1"
    ));
}

test "http routes config — parses named routes" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.http_routes.api]
        \\host = "api.internal"
        \\path_prefix = "/v1"
        \\
        \\[service.web.http_routes.admin]
        \\host = "api.internal"
        \\path_prefix = "/admin"
        \\preserve_host = false
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 2), manifest.services[0].http_routes.len);
    try std.testing.expectEqualStrings("api", manifest.services[0].http_routes[0].name);
    try std.testing.expectEqualStrings("/v1", manifest.services[0].http_routes[0].path_prefix);
    try std.testing.expectEqualStrings("admin", manifest.services[0].http_routes[1].name);
    try std.testing.expect(!manifest.services[0].http_routes[1].preserve_host);
}

test "http proxy config — rewrite prefix" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.http_proxy]
        \\host = "api.internal"
        \\path_prefix = "/api"
        \\rewrite_prefix = "/"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.services[0].http_routes.len);
    try std.testing.expectEqualStrings("/api", manifest.services[0].http_routes[0].path_prefix);
    try std.testing.expectEqualStrings("/", manifest.services[0].http_routes[0].rewrite_prefix.?);
}

test "http routes config — exact header matches" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.http_routes.canary]
        \\host = "api.internal"
        \\path_prefix = "/v1"
        \\match_headers = ["X-Env=canary", "x-region=us-east"]
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.services[0].http_routes.len);
    try std.testing.expectEqual(@as(usize, 2), manifest.services[0].http_routes[0].match_headers.len);
    try std.testing.expectEqualStrings("x-env", manifest.services[0].http_routes[0].match_headers[0].name);
    try std.testing.expectEqualStrings("canary", manifest.services[0].http_routes[0].match_headers[0].value);
    try std.testing.expectEqualStrings("x-region", manifest.services[0].http_routes[0].match_headers[1].name);
    try std.testing.expectEqualStrings("us-east", manifest.services[0].http_routes[0].match_headers[1].value);
}

test "http proxy config — invalid rewrite prefix returns error" {
    const alloc = std.testing.allocator;

    try std.testing.expectError(LoadError.InvalidHttpProxyConfig, loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.http_proxy]
        \\host = "api.internal"
        \\path_prefix = "/api"
        \\rewrite_prefix = "internal"
    ));
}

test "http routes config — mixed shorthand and route tables returns error" {
    const alloc = std.testing.allocator;

    try std.testing.expectError(LoadError.InvalidHttpProxyConfig, loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.http_proxy]
        \\host = "api.internal"
        \\
        \\[service.web.http_routes.admin]
        \\host = "admin.internal"
    ));
}

test "http routes config — duplicate host path returns error" {
    const alloc = std.testing.allocator;

    try std.testing.expectError(LoadError.InvalidHttpProxyConfig, loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.http_routes.api]
        \\host = "api.internal"
        \\path_prefix = "/v1"
        \\
        \\[service.web.http_routes.again]
        \\host = "api.internal"
        \\path_prefix = "/v1"
    ));
}

test "http routes config — duplicate route header name returns error" {
    const alloc = std.testing.allocator;

    try std.testing.expectError(LoadError.InvalidHttpProxyConfig, loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.http_routes.canary]
        \\host = "api.internal"
        \\path_prefix = "/v1"
        \\match_headers = ["x-env=canary", "X-Env=stable"]
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

test "training job — minimal parse" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[training.my-llm]
        \\image = "trainer:v1"
        \\gpus = 8
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 0), manifest.services.len);
    try std.testing.expectEqual(@as(usize, 1), manifest.training_jobs.len);

    const tj = manifest.training_jobs[0];
    try std.testing.expectEqualStrings("my-llm", tj.name);
    try std.testing.expectEqualStrings("trainer:v1", tj.image);
    try std.testing.expectEqual(@as(u32, 8), tj.gpus);
    try std.testing.expect(tj.gpu_type == null);
    try std.testing.expect(tj.data == null);
    try std.testing.expect(tj.checkpoint == null);
    try std.testing.expectEqual(@as(u32, 1000), tj.resources.cpu);
    try std.testing.expectEqual(@as(u64, 65536), tj.resources.memory_mb);
}

test "training job — full parse with all sub-tables" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[training.big-model]
        \\image = "trainer:v2"
        \\command = ["torchrun", "train.py"]
        \\gpus = 100
        \\gpu_type = "H100"
        \\env = ["EPOCHS=10"]
        \\
        \\[training.big-model.data]
        \\dataset = "/mnt/lustre/pile"
        \\sharding = "file"
        \\preprocessing = "tokenize"
        \\
        \\[training.big-model.checkpoint]
        \\path = "/mnt/checkpoints"
        \\interval = "15m"
        \\keep = 3
        \\
        \\[training.big-model.resources]
        \\cpu = 16000
        \\memory_mb = 131072
        \\ib_required = true
        \\
        \\[training.big-model.fault_tolerance]
        \\spare_ranks = 5
        \\auto_restart = true
        \\max_restarts = 20
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.training_jobs.len);
    const tj = manifest.training_jobs[0];

    try std.testing.expectEqualStrings("big-model", tj.name);
    try std.testing.expectEqual(@as(u32, 100), tj.gpus);
    try std.testing.expectEqualStrings("H100", tj.gpu_type.?);
    try std.testing.expectEqual(@as(usize, 2), tj.command.len);

    // data
    try std.testing.expect(tj.data != null);
    try std.testing.expectEqualStrings("/mnt/lustre/pile", tj.data.?.dataset);
    try std.testing.expectEqualStrings("file", tj.data.?.sharding);
    try std.testing.expectEqualStrings("tokenize", tj.data.?.preprocessing.?);

    // checkpoint
    try std.testing.expect(tj.checkpoint != null);
    try std.testing.expectEqualStrings("/mnt/checkpoints", tj.checkpoint.?.path);
    try std.testing.expectEqual(@as(u64, 900), tj.checkpoint.?.interval_secs);
    try std.testing.expectEqual(@as(u32, 3), tj.checkpoint.?.keep);

    // resources
    try std.testing.expectEqual(@as(u32, 16000), tj.resources.cpu);
    try std.testing.expectEqual(@as(u64, 131072), tj.resources.memory_mb);
    try std.testing.expect(tj.resources.ib_required);

    // fault tolerance
    try std.testing.expectEqual(@as(u32, 5), tj.fault_tolerance.spare_ranks);
    try std.testing.expect(tj.fault_tolerance.auto_restart);
    try std.testing.expectEqual(@as(u32, 20), tj.fault_tolerance.max_restarts);
}

test "training job — missing gpus returns error" {
    const alloc = std.testing.allocator;

    const result = loadFromString(alloc,
        \\[training.bad]
        \\image = "trainer:v1"
    );
    try std.testing.expectError(LoadError.InvalidTrainingConfig, result);
}

test "training job — missing image returns error" {
    const alloc = std.testing.allocator;

    const result = loadFromString(alloc,
        \\[training.bad]
        \\gpus = 4
    );
    try std.testing.expectError(LoadError.MissingImage, result);
}

test "training job — manifest with only training jobs is valid" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[training.test]
        \\image = "scratch"
        \\gpus = 1
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 0), manifest.services.len);
    try std.testing.expectEqual(@as(usize, 1), manifest.training_jobs.len);
}

test "training job — checkpoint interval default" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[training.test]
        \\image = "scratch"
        \\gpus = 1
        \\
        \\[training.test.checkpoint]
        \\path = "/mnt/ckpt"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(u64, 1800), manifest.training_jobs[0].checkpoint.?.interval_secs);
    try std.testing.expectEqual(@as(u32, 5), manifest.training_jobs[0].checkpoint.?.keep);
}

test "training job — data sharding default" {
    const alloc = std.testing.allocator;

    var manifest = try loadFromString(alloc,
        \\[training.test]
        \\image = "scratch"
        \\gpus = 1
        \\
        \\[training.test.data]
        \\dataset = "/data/pile"
    );
    defer manifest.deinit();

    try std.testing.expectEqualStrings("file", manifest.training_jobs[0].data.?.sharding);
    try std.testing.expect(manifest.training_jobs[0].data.?.preprocessing == null);
}
