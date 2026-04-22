// integration tests — manifest loading and validation
//
// tests the manifest TOML parser with various inputs including
// error cases, dependency ordering, and variable expansion.
// runs without sqlite or root.

const std = @import("std");
const loader = @import("manifest/loader.zig");
const validator = @import("manifest/validate.zig");

const alloc = std.testing.allocator;

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("expected to contain: \"{s}\"\n  actual: \"{s}\"\n", .{ needle, haystack });
        return error.TestExpectedContains;
    }
}

fn expectManifestLoadsAndValidatesCleanly(path: []const u8) !void {
    errdefer std.debug.print("example manifest failed validation: {s}\n", .{path});

    var manifest = try loader.load(alloc, path);
    defer manifest.deinit();

    var result = try validator.check(alloc, &manifest);
    defer result.deinit();

    if (result.diagnostics.len != 0) {
        std.debug.print("unexpected diagnostics for {s}:\n", .{path});
        for (result.diagnostics) |diagnostic| {
            std.debug.print("  {s}: {s}\n", .{ @tagName(diagnostic.severity), diagnostic.message });
        }
        return error.TestUnexpectedManifestDiagnostics;
    }
}

// -- basic loading --

test "load minimal manifest" {
    var manifest = try loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.services.len);
    try std.testing.expectEqualStrings("web", manifest.services[0].name);
    try std.testing.expectEqualStrings("nginx:latest", manifest.services[0].image);
}

test "load manifest with ports and env" {
    var manifest = try loader.loadFromString(alloc,
        \\[service.api]
        \\image = "myapp:latest"
        \\ports = ["8080:3000", "9090:9090"]
        \\env = ["NODE_ENV=production", "PORT=3000"]
    );
    defer manifest.deinit();

    const svc = manifest.services[0];
    try std.testing.expectEqual(@as(usize, 2), svc.ports.len);
    try std.testing.expectEqual(@as(u16, 8080), svc.ports[0].host_port);
    try std.testing.expectEqual(@as(u16, 3000), svc.ports[0].container_port);
    try std.testing.expectEqual(@as(usize, 2), svc.env.len);
    try std.testing.expectEqualStrings("NODE_ENV=production", svc.env[0]);
}

test "services ordered by dependency" {
    var manifest = try loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\ports = ["80:80"]
        \\depends_on = ["api"]
        \\
        \\[service.api]
        \\image = "myapp:latest"
        \\ports = ["3000:3000"]
        \\depends_on = ["db"]
        \\
        \\[service.db]
        \\image = "postgres:16"
        \\ports = ["5432:5432"]
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 3), manifest.services.len);
    try std.testing.expectEqualStrings("db", manifest.services[0].name);
    try std.testing.expectEqualStrings("api", manifest.services[1].name);
    try std.testing.expectEqualStrings("web", manifest.services[2].name);
}

test "load manifest with volumes" {
    var manifest = try loader.loadFromString(alloc,
        \\[service.db]
        \\image = "postgres:16"
        \\volumes = ["pgdata:/var/lib/postgresql/data", "./src:/app"]
        \\
        \\[volume.pgdata]
        \\driver = "local"
    );
    defer manifest.deinit();

    const svc = manifest.services[0];
    try std.testing.expectEqual(@as(usize, 2), svc.volumes.len);
    try std.testing.expectEqualStrings("pgdata", svc.volumes[0].source);
    try std.testing.expectEqualStrings("/var/lib/postgresql/data", svc.volumes[0].target);
    try std.testing.expect(svc.volumes[0].kind == .named);
    try std.testing.expectEqualStrings("./src", svc.volumes[1].source);
    try std.testing.expect(svc.volumes[1].kind == .bind);
}

test "load manifest with http health check" {
    var manifest = try loader.loadFromString(alloc,
        \\[service.web]
        \\image = "myapp:latest"
        \\
        \\[service.web.health_check]
        \\type = "http"
        \\path = "/health"
        \\port = 8080
        \\interval = 15
        \\timeout = 3
    );
    defer manifest.deinit();

    const hc = manifest.services[0].health_check orelse return error.ExpectedHealthCheck;
    switch (hc.check_type) {
        .http => |h| {
            try std.testing.expectEqualStrings("/health", h.path);
            try std.testing.expectEqual(@as(u16, 8080), h.port);
        },
        else => return error.ExpectedHttpHealthCheck,
    }
    try std.testing.expectEqual(@as(u32, 15), hc.interval);
    try std.testing.expectEqual(@as(u32, 3), hc.timeout);
}

test "load manifest with grpc health check" {
    var manifest = try loader.loadFromString(alloc,
        \\[service.api]
        \\image = "grpc-server:latest"
        \\
        \\[service.api.health_check]
        \\type = "grpc"
        \\port = 50051
        \\interval = 5
    );
    defer manifest.deinit();

    const hc = manifest.services[0].health_check orelse return error.ExpectedHealthCheck;
    switch (hc.check_type) {
        .grpc => |g| {
            try std.testing.expectEqual(@as(u16, 50051), g.port);
        },
        else => return error.ExpectedHealthCheck,
    }
    try std.testing.expectEqual(@as(u32, 5), hc.interval);
}

test "load manifest with workers" {
    var manifest = try loader.loadFromString(alloc,
        \\[service.db]
        \\image = "postgres:16"
        \\
        \\[worker.migrate]
        \\image = "myapp:latest"
        \\command = ["python", "manage.py", "migrate"]
        \\depends_on = ["db"]
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.workers.len);
    try std.testing.expectEqualStrings("migrate", manifest.workers[0].name);
    try std.testing.expectEqualStrings("myapp:latest", manifest.workers[0].image);
    try std.testing.expectEqual(@as(usize, 3), manifest.workers[0].command.len);
}

test "load manifest with cron" {
    var manifest = try loader.loadFromString(alloc,
        \\[service.db]
        \\image = "postgres:16"
        \\
        \\[cron.backup]
        \\image = "myapp:latest"
        \\command = ["pg_dump", "-f", "/backup/db.sql"]
        \\every = "1h"
    );
    defer manifest.deinit();

    try std.testing.expectEqual(@as(usize, 1), manifest.crons.len);
    try std.testing.expectEqualStrings("backup", manifest.crons[0].name);
    try std.testing.expectEqual(@as(u64, 3600), manifest.crons[0].every);
}

test "load manifest with restart policy" {
    var manifest = try loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\restart = "on_failure"
    );
    defer manifest.deinit();

    try std.testing.expect(manifest.services[0].restart == .on_failure);
}

test "load manifest with tls config" {
    var manifest = try loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.tls]
        \\domain = "example.com"
        \\acme = true
        \\email = "admin@example.com"
    );
    defer manifest.deinit();

    const tls = manifest.services[0].tls orelse return error.ExpectedTlsConfig;
    try std.testing.expectEqualStrings("example.com", tls.domain);
    try std.testing.expect(tls.acme);
    try std.testing.expectEqualStrings("admin@example.com", tls.email.?);
}

// -- error cases --

test "reject manifest with no services" {
    const result = loader.loadFromString(alloc,
        \\[volume.data]
        \\driver = "local"
    );
    try std.testing.expectError(loader.LoadError.NoServices, result);
}

test "reject circular dependencies" {
    const result = loader.loadFromString(alloc,
        \\[service.a]
        \\image = "x"
        \\depends_on = ["b"]
        \\
        \\[service.b]
        \\image = "x"
        \\depends_on = ["a"]
    );
    try std.testing.expectError(loader.LoadError.CircularDependency, result);
}

test "reject unknown dependency" {
    const result = loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\depends_on = ["nonexistent"]
    );
    try std.testing.expectError(loader.LoadError.UnknownDependency, result);
}

test "reject missing image" {
    const result = loader.loadFromString(alloc,
        \\[service.web]
        \\ports = ["80:80"]
    );
    try std.testing.expectError(loader.LoadError.MissingImage, result);
}

test "reject invalid port mapping" {
    const result = loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\ports = ["not-a-port"]
    );
    try std.testing.expectError(loader.LoadError.InvalidPortMapping, result);
}

test "reject invalid env var" {
    const result = loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\env = ["NOEQUALS"]
    );
    try std.testing.expectError(loader.LoadError.InvalidEnvVar, result);
}

test "reject invalid volume mount" {
    const result = loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\volumes = ["no-colon"]
    );
    try std.testing.expectError(loader.LoadError.InvalidVolumeMount, result);
}

test "reject invalid restart policy" {
    const result = loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\restart = "never"
    );
    try std.testing.expectError(loader.LoadError.InvalidRestartPolicy, result);
}

test "reject invalid cron schedule" {
    const result = loader.loadFromString(alloc,
        \\[service.db]
        \\image = "postgres:16"
        \\
        \\[cron.backup]
        \\image = "myapp:latest"
        \\every = "invalid"
    );
    try std.testing.expectError(loader.LoadError.InvalidSchedule, result);
}

test "reject invalid TOML syntax" {
    const result = loader.loadFromString(alloc,
        \\this is not valid toml {{{
    );
    try std.testing.expectError(loader.LoadError.ParseFailed, result);
}

// -- validation --

test "validate detects host port conflicts" {
    var manifest = try loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\ports = ["80:8080"]
        \\
        \\[service.api]
        \\image = "myapp:latest"
        \\ports = ["80:3000"]
    );
    defer manifest.deinit();

    var result = try validator.check(alloc, &manifest);
    defer result.deinit();

    try std.testing.expect(result.hasErrors());
    try std.testing.expect(result.diagnostics.len > 0);
    try expectContains(result.diagnostics[0].message, "host port 80");
}

test "validate passes for valid manifest" {
    var manifest = try loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\ports = ["80:80"]
        \\
        \\[service.api]
        \\image = "myapp:latest"
        \\ports = ["3000:3000"]
    );
    defer manifest.deinit();

    var result = try validator.check(alloc, &manifest);
    defer result.deinit();

    try std.testing.expect(!result.hasErrors());
}

// -- variable expansion --

test "expand environment variables with defaults" {
    var manifest = try loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\env = ["DB_NAME=${NONEXISTENT_VAR:-mydb}"]
    );
    defer manifest.deinit();

    try std.testing.expectEqualStrings("DB_NAME=mydb", manifest.services[0].env[0]);
}

// -- file loading --

test "load from nonexistent file returns FileNotFound" {
    const result = loader.load(alloc, "/tmp/nonexistent-yoq-manifest-test.toml");
    try std.testing.expectError(loader.LoadError.FileNotFound, result);
}

test "checked-in example manifests load and validate cleanly" {
    var examples_dir = try @import("compat").cwd().openDir("examples", .{ .iterate = true });
    defer examples_dir.close();

    var walker = try examples_dir.walk(alloc);
    defer walker.deinit();

    var checked: usize = 0;
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.eql(u8, entry.basename, "manifest.toml")) continue;

        const path = try std.fmt.allocPrint(alloc, "examples/{s}", .{entry.path});
        defer alloc.free(path);

        try expectManifestLoadsAndValidatesCleanly(path);
        checked += 1;
    }

    try std.testing.expect(checked > 0);
}
