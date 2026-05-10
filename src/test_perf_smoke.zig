const std = @import("std");

const loader = @import("manifest/loader.zig");
const validator = @import("manifest/validate.zig");
const request_plan = @import("network/proxy/request_plan.zig");
const router = @import("network/proxy/router.zig");
const status_writers = @import("api/routes/status_metrics/writers.zig");
const monitor = @import("runtime/monitor.zig");

const alloc = std.testing.allocator;

const example_manifests = [_][]const u8{
    "examples/redis/manifest.toml",
    "examples/web-app/manifest.toml",
    "examples/http-routing/manifest.toml",
    "examples/cluster/manifest.toml",
    "examples/cron/manifest.toml",
};

fn nowMicros() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toMicroseconds();
}

fn expectUnder(comptime label: []const u8, elapsed_us: i64, ceiling_us: i64) !void {
    std.debug.print("perf smoke: {s} elapsed_us={d} ceiling_us={d}\n", .{ label, elapsed_us, ceiling_us });
    if (elapsed_us > ceiling_us) return error.PerfSmokeThresholdExceeded;
}

fn makeLargeManifest(service_count: usize) ![]u8 {
    var out = std.Io.Writer.Allocating.init(alloc);
    errdefer out.deinit();
    const writer = &out.writer;

    var i: usize = 0;
    while (i < service_count) : (i += 1) {
        try writer.print("[service.svc{d}]\n", .{i});
        try writer.writeAll("image = \"example/app:latest\"\n");
        try writer.print("env = [\"SERVICE_INDEX={d}\"]\n", .{i});
        if (i > 0) {
            try writer.print("depends_on = [\"svc{d}\"]\n", .{i - 1});
        }
        try writer.writeAll("\n");
        try writer.print("[service.svc{d}.health_check]\n", .{i});
        try writer.writeAll("type = \"tcp\"\n");
        try writer.print("port = {d}\n", .{8000 + i});
        try writer.writeAll("interval = 10\ntimeout = 3\n\n");
    }

    return out.toOwnedSlice();
}

fn loadAndValidateManifest(content: []const u8) !void {
    var manifest = try loader.loadFromString(alloc, content);
    defer manifest.deinit();

    if (manifest.services.len == 0) return error.PerfSmokeExpectedServices;

    var result = try validator.check(alloc, &manifest);
    defer result.deinit();
    if (result.hasErrors()) return error.PerfSmokeManifestInvalid;
}

test "perf smoke: manifest load throughput stays bounded" {
    const generated = try makeLargeManifest(80);
    defer alloc.free(generated);

    const start = nowMicros();

    var round: usize = 0;
    while (round < 15) : (round += 1) {
        inline for (example_manifests) |path| {
            {
                var manifest = try loader.load(alloc, path);
                defer manifest.deinit();
                try std.testing.expect(manifest.services.len + manifest.workers.len + manifest.crons.len + manifest.training_jobs.len > 0);
            }
        }
        try loadAndValidateManifest(generated);
    }

    try expectUnder("manifest-load", nowMicros() - start, 5_000_000);
}

test "perf smoke: HTTP route planning stays bounded" {
    const routes = [_]router.Route{
        .{
            .name = "api-default",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.internal", .path_prefix = "/v1" },
        },
        .{
            .name = "api-canary",
            .service = "api-canary",
            .vip_address = "10.43.0.3",
            .match = .{ .host = "api.internal", .path_prefix = "/v1" },
            .header_matches = &.{
                .{ .name = "x-env", .value = "canary" },
            },
        },
        .{
            .name = "api-write",
            .service = "api-write",
            .vip_address = "10.43.0.4",
            .match = .{ .host = "api.internal", .path_prefix = "/v1" },
            .method_matches = &.{
                .{ .method = "POST" },
            },
        },
    };
    const raw_request =
        "GET /v1/users?limit=25 HTTP/1.1\r\n" ++
        "Host: api.internal:17080\r\n" ++
        "User-Agent: perf-smoke\r\n" ++
        "X-Env: canary\r\n" ++
        "Accept: application/json\r\n\r\n";

    const start = nowMicros();
    var i: usize = 0;
    while (i < 10_000) : (i += 1) {
        {
            const plan = try request_plan.planRequest(alloc, &routes, raw_request);
            defer plan.deinit(alloc);
            if (!std.mem.eql(u8, plan.route.name, "api-canary")) return error.PerfSmokeWrongRoute;
        }
    }

    try expectUnder("http-route-plan", nowMicros() - start, 2_000_000);
}

test "perf smoke: status snapshot JSON serialization stays bounded" {
    const snap = monitor.ServiceSnapshot{
        .name = "api",
        .status = .running,
        .health_status = .healthy,
        .cpu_pct = 37.5,
        .memory_bytes = 256 * 1024 * 1024,
        .running_count = 8,
        .desired_count = 8,
        .uptime_secs = 3600,
        .psi_cpu = null,
        .psi_memory = null,
        .io_read_bytes = 4096,
        .io_write_bytes = 8192,
    };

    const start = nowMicros();
    var i: usize = 0;
    while (i < 20_000) : (i += 1) {
        var buf: [512]u8 = undefined;
        var stream: std.Io.Writer = .fixed(&buf);
        try status_writers.writeSnapshotJson(&stream, snap);
        if (stream.buffered().len == 0) return error.PerfSmokeExpectedJson;
    }

    try expectUnder("status-json", nowMicros() - start, 2_000_000);
}
