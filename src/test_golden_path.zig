const std = @import("std");
const helpers = @import("helpers");
const loader = @import("manifest/loader.zig");
const manifest_spec = @import("manifest/spec.zig");
const validator = @import("manifest/validate.zig");

const alloc = std.testing.allocator;

const example_manifests = [_][]const u8{
    "examples/redis/manifest.toml",
    "examples/web-app/manifest.toml",
    "examples/http-routing/manifest.toml",
    "examples/cluster/manifest.toml",
    "examples/cron/manifest.toml",
};

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("expected output to contain \"{s}\"\nactual:\n{s}\n", .{ needle, haystack });
        return error.TestExpectedContains;
    }
}

fn expectCommandOk(result: helpers.RunResult) !void {
    if (result.exit_code != 0) {
        std.debug.print(
            "command failed with exit code {d}\nstdout:\n{s}\nstderr:\n{s}\n",
            .{ result.exit_code, result.stdout, result.stderr },
        );
        return error.TestCommandFailed;
    }
}

fn loadExample(path: []const u8) !manifest_spec.Manifest {
    var manifest = try loader.load(alloc, path);
    errdefer manifest.deinit();

    var result = try validator.check(alloc, &manifest);
    defer result.deinit();

    if (result.diagnostics.len != 0) {
        std.debug.print("unexpected diagnostics for {s}:\n", .{path});
        for (result.diagnostics) |diagnostic| {
            std.debug.print("  {s}: {s}\n", .{ @tagName(diagnostic.severity), diagnostic.message });
        }
        return error.TestUnexpectedDiagnostics;
    }

    return manifest;
}

fn expectService(manifest: *const manifest_spec.Manifest, name: []const u8) !*const manifest_spec.Service {
    return manifest.serviceByName(name) orelse {
        std.debug.print("missing service: {s}\n", .{name});
        return error.TestMissingService;
    };
}

fn expectWorker(manifest: *const manifest_spec.Manifest, name: []const u8) !*const manifest_spec.Worker {
    return manifest.workerByName(name) orelse {
        std.debug.print("missing worker: {s}\n", .{name});
        return error.TestMissingWorker;
    };
}

fn expectCron(manifest: *const manifest_spec.Manifest, name: []const u8) !*const manifest_spec.Cron {
    for (manifest.crons) |*cron| {
        if (std.mem.eql(u8, cron.name, name)) return cron;
    }
    std.debug.print("missing cron: {s}\n", .{name});
    return error.TestMissingCron;
}

fn putPathEnv(env_map: *std.process.Environ.Map, key: []const u8, path: []const u8) !void {
    try env_map.put(key, path);
    try std.Io.Dir.cwd().createDirPath(std.testing.io, path);
}

test "golden path cli entry points and examples stay executable" {
    const tmp = try helpers.tmpDir();
    defer tmp.cleanup();

    const home = try std.fmt.allocPrint(alloc, "{s}/home", .{tmp.slice()});
    defer alloc.free(home);
    const xdg_data_home = try std.fmt.allocPrint(alloc, "{s}/xdg-data", .{tmp.slice()});
    defer alloc.free(xdg_data_home);
    const xdg_config_home = try std.fmt.allocPrint(alloc, "{s}/xdg-config", .{tmp.slice()});
    defer alloc.free(xdg_config_home);
    const xdg_cache_home = try std.fmt.allocPrint(alloc, "{s}/xdg-cache", .{tmp.slice()});
    defer alloc.free(xdg_cache_home);

    var env_map = std.process.Environ.Map.init(alloc);
    defer env_map.deinit();
    try env_map.put("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    try putPathEnv(&env_map, "HOME", home);
    try putPathEnv(&env_map, "XDG_DATA_HOME", xdg_data_home);
    try putPathEnv(&env_map, "XDG_CONFIG_HOME", xdg_config_home);
    try putPathEnv(&env_map, "XDG_CACHE_HOME", xdg_cache_home);

    {
        var result = try helpers.runYoqWithOptions(alloc, &.{"version"}, .{ .env_map = &env_map });
        defer result.deinit();
        try expectCommandOk(result);
        try expectContains(result.stdout, "yoq");
    }

    {
        var result = try helpers.runYoqWithOptions(alloc, &.{"help"}, .{ .env_map = &env_map });
        defer result.deinit();
        try expectCommandOk(result);
        try expectContains(result.stdout, "usage");
    }

    inline for (example_manifests) |path| {
        var result = try helpers.runYoqWithOptions(alloc, &.{ "validate", "-f", path, "-q" }, .{ .env_map = &env_map });
        defer result.deinit();
        try expectCommandOk(result);
    }
}

test "golden path example manifests preserve documented app shapes" {
    {
        var manifest = try loadExample("examples/redis/manifest.toml");
        defer manifest.deinit();

        try std.testing.expectEqual(@as(usize, 1), manifest.services.len);
        const redis = try expectService(&manifest, "redis");
        try std.testing.expectEqual(manifest_spec.RestartPolicy.always, redis.restart);
        try std.testing.expectEqual(@as(usize, 1), redis.ports.len);
        try std.testing.expectEqual(@as(u16, 6379), redis.ports[0].host_port);
        try std.testing.expect(redis.health_check != null);
    }

    {
        var manifest = try loadExample("examples/web-app/manifest.toml");
        defer manifest.deinit();

        try std.testing.expectEqual(@as(usize, 4), manifest.services.len);
        try std.testing.expectEqual(@as(usize, 1), manifest.workers.len);
        try std.testing.expectEqual(@as(usize, 1), manifest.volumes.len);

        const api = try expectService(&manifest, "api");
        try std.testing.expectEqual(manifest_spec.RestartPolicy.on_failure, api.restart);
        try std.testing.expectEqual(@as(usize, 2), api.depends_on.len);
        try std.testing.expect(api.health_check != null);

        const migrate = try expectWorker(&manifest, "migrate");
        try std.testing.expectEqualStrings("postgres", migrate.depends_on[0]);
    }

    {
        var manifest = try loadExample("examples/http-routing/manifest.toml");
        defer manifest.deinit();

        try std.testing.expectEqual(@as(usize, 5), manifest.services.len);

        const gateway = try expectService(&manifest, "gateway");
        try std.testing.expectEqual(@as(usize, 2), gateway.http_routes.len);
        try std.testing.expectEqualStrings("demo.local", gateway.http_routes[0].host);
        try std.testing.expectEqualStrings("/admin", gateway.http_routes[1].path_prefix);
        try std.testing.expect(!gateway.http_routes[1].preserve_host);

        const api = try expectService(&manifest, "api");
        try std.testing.expectEqual(@as(usize, 1), api.http_routes.len);
        const route = api.http_routes[0];
        try std.testing.expectEqualStrings("/api", route.path_prefix);
        try std.testing.expectEqualStrings("/", route.rewrite_prefix.?);
        try std.testing.expectEqual(@as(usize, 2), route.backend_services.len);
        try std.testing.expectEqualStrings("api-shadow", route.mirror_service.?);
        try std.testing.expectEqual(@as(u8, 2), route.retries);
        try std.testing.expect(route.retry_on_5xx);
    }

    {
        var manifest = try loadExample("examples/cluster/manifest.toml");
        defer manifest.deinit();

        try std.testing.expectEqual(@as(usize, 3), manifest.services.len);
        try std.testing.expectEqual(@as(usize, 1), manifest.crons.len);
        try std.testing.expectEqual(@as(usize, 2), manifest.volumes.len);

        const web = try expectService(&manifest, "web");
        const tls = web.tls orelse return error.TestExpectedTls;
        try std.testing.expectEqualStrings("myapp.example.com", tls.domain);
        try std.testing.expect(tls.acme != null);
        try std.testing.expectEqualStrings("ops@example.com", tls.acme.?.email);

        const backup = try expectCron(&manifest, "backup");
        try std.testing.expectEqual(@as(u64, 3600), backup.every);
    }
}

test "golden path shell drills remain parseable" {
    var result = try helpers.run(alloc, &.{ "bash", "-n", "scripts/http-routing-recovery-smoke.sh" });
    defer result.deinit();
    try expectCommandOk(result);
}
