const std = @import("std");
const spec = @import("spec.zig");
const app_spec = @import("app_spec.zig");
const release_plan = @import("release_plan.zig");

const JsonPort = struct {
    host_port: u16,
    container_port: u16,
};

const JsonVolume = struct {
    source: []const u8,
    target: []const u8,
    kind: []const u8 = "bind",
};

const JsonHealthCheck = struct {
    kind: []const u8,
    path: ?[]const u8 = null,
    port: ?u16 = null,
    service: ?[]const u8 = null,
    command: []const []const u8 = &.{},
    interval: u32 = 10,
    timeout: u32 = 5,
    retries: u32 = 3,
    start_period: u32 = 0,
};

const JsonTls = struct {
    domain: []const u8,
    acme: bool = false,
    email: ?[]const u8 = null,
};

const JsonRollout = struct {
    strategy: []const u8 = "rolling",
    parallelism: u32 = 1,
    delay_between_batches: u32 = 0,
    failure_action: []const u8 = "rollback",
    health_check_timeout: u32 = 0,
};

const JsonMethodMatch = struct {
    method: []const u8,
};

const JsonHeaderMatch = struct {
    name: []const u8,
    value: []const u8,
};

const JsonBackendRoute = struct {
    service_name: []const u8,
    weight: u8,
};

const JsonHttpRoute = struct {
    name: []const u8,
    host: []const u8,
    path_prefix: []const u8 = "/",
    rewrite_prefix: ?[]const u8 = null,
    match_methods: []const JsonMethodMatch = &.{},
    match_headers: []const JsonHeaderMatch = &.{},
    backend_services: []const JsonBackendRoute = &.{},
    mirror_service: ?[]const u8 = null,
    retries: u8 = 0,
    connect_timeout_ms: u32 = 1000,
    request_timeout_ms: u32 = 5000,
    http2_idle_timeout_ms: u32 = 30000,
    preserve_host: bool = true,
    retry_on_5xx: bool = true,
    circuit_breaker_threshold: u8 = 3,
    circuit_breaker_timeout_ms: u32 = 30000,
};

const JsonGpu = struct {
    count: u32 = 0,
    model: ?[]const u8 = null,
    vram_min_mb: ?u64 = null,
};

const JsonGpuMesh = struct {
    world_size: u32,
    gpus_per_rank: u32 = 1,
    master_port: u16 = 29500,
};

const JsonService = struct {
    name: []const u8,
    image: []const u8,
    command: []const []const u8 = &.{},
    ports: []const JsonPort = &.{},
    env: []const []const u8 = &.{},
    depends_on: []const []const u8 = &.{},
    working_dir: ?[]const u8 = null,
    volumes: []const JsonVolume = &.{},
    health_check: ?JsonHealthCheck = null,
    restart: []const u8 = "none",
    rollout: JsonRollout = .{},
    tls: ?JsonTls = null,
    http_routes: []const JsonHttpRoute = &.{},
    gpu: ?JsonGpu = null,
    gpu_mesh: ?JsonGpuMesh = null,
};

const JsonApp = struct {
    app_name: []const u8,
    services: []const JsonService = &.{},
};

pub const LoadedRollbackSnapshot = struct {
    manifest: spec.Manifest,
    release: release_plan.ReleasePlan,

    pub fn deinit(self: *LoadedRollbackSnapshot) void {
        self.release.deinit();
        self.manifest.deinit();
    }
};

pub fn loadLocalRollbackSnapshot(alloc: std.mem.Allocator, snapshot_json: []const u8) !LoadedRollbackSnapshot {
    const parsed = try std.json.parseFromSlice(JsonApp, alloc, snapshot_json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer parsed.deinit();

    var manifest = try manifestFromSnapshot(alloc, parsed.value);
    errdefer manifest.deinit();

    var app = try app_spec.fromManifest(alloc, parsed.value.app_name, &manifest);
    defer app.deinit();

    var release = try release_plan.ReleasePlan.fromAppSpecWithSnapshot(alloc, &app, &.{}, snapshot_json);
    errdefer release.deinit();

    return .{
        .manifest = manifest,
        .release = release,
    };
}

fn manifestFromSnapshot(alloc: std.mem.Allocator, parsed: JsonApp) !spec.Manifest {
    const services = try alloc.alloc(spec.Service, parsed.services.len);
    errdefer alloc.free(services);

    for (parsed.services, 0..) |svc, i| {
        services[i] = try serviceFromSnapshot(alloc, svc);
    }

    return .{
        .services = services,
        .workers = try alloc.alloc(spec.Worker, 0),
        .crons = try alloc.alloc(spec.Cron, 0),
        .training_jobs = try alloc.alloc(spec.TrainingJob, 0),
        .volumes = try alloc.alloc(spec.Volume, 0),
        .alloc = alloc,
    };
}

fn serviceFromSnapshot(alloc: std.mem.Allocator, svc: JsonService) !spec.Service {
    return .{
        .name = try alloc.dupe(u8, svc.name),
        .image = try alloc.dupe(u8, svc.image),
        .command = try dupeStringArray(alloc, svc.command),
        .ports = try dupPorts(alloc, svc.ports),
        .env = try dupeStringArray(alloc, svc.env),
        .depends_on = try dupeStringArray(alloc, svc.depends_on),
        .working_dir = if (svc.working_dir) |working_dir| try alloc.dupe(u8, working_dir) else null,
        .volumes = try dupVolumes(alloc, svc.volumes),
        .health_check = if (svc.health_check) |health_check| try dupHealthCheck(alloc, health_check) else null,
        .restart = parseRestartPolicy(svc.restart),
        .rollout = parseRolloutPolicy(svc.rollout),
        .tls = if (svc.tls) |tls| try dupTls(alloc, tls) else null,
        .http_routes = try dupHttpRoutes(alloc, svc.http_routes),
        .gpu = if (svc.gpu) |gpu| try dupGpu(alloc, gpu) else null,
        .gpu_mesh = if (svc.gpu_mesh) |mesh| .{
            .world_size = mesh.world_size,
            .gpus_per_rank = mesh.gpus_per_rank,
            .master_port = mesh.master_port,
        } else null,
    };
}

fn dupeStringArray(alloc: std.mem.Allocator, items: []const []const u8) ![]const []const u8 {
    const out = try alloc.alloc([]const u8, items.len);
    errdefer alloc.free(out);
    for (items, 0..) |item, i| {
        out[i] = try alloc.dupe(u8, item);
    }
    return out;
}

fn dupPorts(alloc: std.mem.Allocator, ports: []const JsonPort) ![]const spec.PortMapping {
    const out = try alloc.alloc(spec.PortMapping, ports.len);
    for (ports, 0..) |port, i| {
        out[i] = .{
            .host_port = port.host_port,
            .container_port = port.container_port,
        };
    }
    return out;
}

fn dupVolumes(alloc: std.mem.Allocator, volumes: []const JsonVolume) ![]const spec.VolumeMount {
    const out = try alloc.alloc(spec.VolumeMount, volumes.len);
    errdefer alloc.free(out);
    for (volumes, 0..) |vol, i| {
        out[i] = .{
            .source = try alloc.dupe(u8, vol.source),
            .target = try alloc.dupe(u8, vol.target),
            .kind = if (std.mem.eql(u8, vol.kind, "named")) .named else .bind,
        };
    }
    return out;
}

fn dupHealthCheck(alloc: std.mem.Allocator, health_check: JsonHealthCheck) !spec.HealthCheck {
    const check_type: spec.CheckType = if (std.mem.eql(u8, health_check.kind, "http"))
        .{ .http = .{
            .path = try alloc.dupe(u8, health_check.path orelse "/"),
            .port = health_check.port orelse 0,
        } }
    else if (std.mem.eql(u8, health_check.kind, "tcp"))
        .{ .tcp = .{
            .port = health_check.port orelse 0,
        } }
    else if (std.mem.eql(u8, health_check.kind, "grpc"))
        .{ .grpc = .{
            .port = health_check.port orelse 0,
            .service = if (health_check.service) |service| try alloc.dupe(u8, service) else null,
        } }
    else
        .{ .exec = .{
            .command = try dupeStringArray(alloc, health_check.command),
        } };

    return .{
        .check_type = check_type,
        .interval = health_check.interval,
        .timeout = health_check.timeout,
        .retries = health_check.retries,
        .start_period = health_check.start_period,
    };
}

fn dupTls(alloc: std.mem.Allocator, tls: JsonTls) !spec.TlsConfig {
    return .{
        .domain = try alloc.dupe(u8, tls.domain),
        .acme = tls.acme,
        .email = if (tls.email) |email| try alloc.dupe(u8, email) else null,
    };
}

fn parseRolloutPolicy(rollout: JsonRollout) spec.RolloutPolicy {
    return .{
        .strategy = if (std.mem.eql(u8, rollout.strategy, "rolling")) .rolling else .rolling,
        .parallelism = @max(1, rollout.parallelism),
        .delay_between_batches = rollout.delay_between_batches,
        .failure_action = if (std.mem.eql(u8, rollout.failure_action, "pause")) .pause else .rollback,
        .health_check_timeout = rollout.health_check_timeout,
    };
}

fn dupHttpRoutes(alloc: std.mem.Allocator, routes: []const JsonHttpRoute) ![]const spec.HttpProxyRoute {
    const out = try alloc.alloc(spec.HttpProxyRoute, routes.len);
    errdefer alloc.free(out);
    for (routes, 0..) |route, i| {
        out[i] = .{
            .name = try alloc.dupe(u8, route.name),
            .host = try alloc.dupe(u8, route.host),
            .path_prefix = try alloc.dupe(u8, route.path_prefix),
            .rewrite_prefix = if (route.rewrite_prefix) |rewrite_prefix| try alloc.dupe(u8, rewrite_prefix) else null,
            .match_methods = try dupMethodMatches(alloc, route.match_methods),
            .match_headers = try dupHeaderMatches(alloc, route.match_headers),
            .backend_services = try dupBackendRoutes(alloc, route.backend_services),
            .mirror_service = if (route.mirror_service) |mirror_service| try alloc.dupe(u8, mirror_service) else null,
            .retries = route.retries,
            .connect_timeout_ms = route.connect_timeout_ms,
            .request_timeout_ms = route.request_timeout_ms,
            .http2_idle_timeout_ms = route.http2_idle_timeout_ms,
            .preserve_host = route.preserve_host,
            .retry_on_5xx = route.retry_on_5xx,
            .circuit_breaker_threshold = route.circuit_breaker_threshold,
            .circuit_breaker_timeout_ms = route.circuit_breaker_timeout_ms,
        };
    }
    return out;
}

fn dupMethodMatches(alloc: std.mem.Allocator, methods: []const JsonMethodMatch) ![]const spec.HttpMethodMatch {
    const out = try alloc.alloc(spec.HttpMethodMatch, methods.len);
    errdefer alloc.free(out);
    for (methods, 0..) |method, i| {
        out[i] = .{ .method = try alloc.dupe(u8, method.method) };
    }
    return out;
}

fn dupHeaderMatches(alloc: std.mem.Allocator, headers: []const JsonHeaderMatch) ![]const spec.HttpHeaderMatch {
    const out = try alloc.alloc(spec.HttpHeaderMatch, headers.len);
    errdefer alloc.free(out);
    for (headers, 0..) |header, i| {
        out[i] = .{
            .name = try alloc.dupe(u8, header.name),
            .value = try alloc.dupe(u8, header.value),
        };
    }
    return out;
}

fn dupBackendRoutes(alloc: std.mem.Allocator, backends: []const JsonBackendRoute) ![]const spec.HttpRouteBackend {
    const out = try alloc.alloc(spec.HttpRouteBackend, backends.len);
    errdefer alloc.free(out);
    for (backends, 0..) |backend, i| {
        out[i] = .{
            .service_name = try alloc.dupe(u8, backend.service_name),
            .weight = backend.weight,
        };
    }
    return out;
}

fn dupGpu(alloc: std.mem.Allocator, gpu: JsonGpu) !spec.GpuSpec {
    return .{
        .count = gpu.count,
        .model = if (gpu.model) |model| try alloc.dupe(u8, model) else null,
        .vram_min_mb = gpu.vram_min_mb,
    };
}

fn parseRestartPolicy(text: []const u8) spec.RestartPolicy {
    if (std.mem.eql(u8, text, "always")) return .always;
    if (std.mem.eql(u8, text, "on_failure")) return .on_failure;
    return .none;
}

test "loadLocalRollbackSnapshot preserves service runtime fields while keeping original snapshot" {
    const alloc = std.testing.allocator;
    const snapshot =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx:1","command":["nginx","-g","daemon off"],"ports":[{"host_port":8080,"container_port":80}],"env":["MODE=prod"],"depends_on":["db"],"working_dir":"/srv/app","volumes":[{"source":"./src","target":"/app","kind":"bind"}],"health_check":{"kind":"http","path":"/health","port":8080,"interval":11,"timeout":6,"retries":4,"start_period":2},"restart":"always","rollout":{"strategy":"rolling","parallelism":2,"delay_between_batches":3,"failure_action":"pause","health_check_timeout":12},"tls":{"domain":"demo.internal","acme":true,"email":"ops@example.com"},"http_routes":[{"name":"default","host":"demo.internal","path_prefix":"/","retries":2,"connect_timeout_ms":1500,"request_timeout_ms":6000,"http2_idle_timeout_ms":30000,"preserve_host":false,"retry_on_5xx":true,"circuit_breaker_threshold":3,"circuit_breaker_timeout_ms":30000,"match_methods":[{"method":"GET"}],"match_headers":[{"name":"x-env","value":"prod"}],"backend_services":[{"service_name":"web","weight":100}]}],"gpu":{"count":1,"model":"L4","vram_min_mb":24576},"gpu_mesh":{"world_size":2,"gpus_per_rank":1,"master_port":29501}}],"workers":[{"name":"migrate"}],"crons":[{"name":"nightly"}],"training_jobs":[{"name":"finetune"}]}
    ;

    var loaded = try loadLocalRollbackSnapshot(alloc, snapshot);
    defer loaded.deinit();

    try std.testing.expectEqualStrings("demo-app", loaded.release.app.app_name);
    try std.testing.expectEqualStrings(snapshot, loaded.release.config_snapshot);
    try std.testing.expectEqual(@as(usize, 1), loaded.manifest.services.len);
    try std.testing.expectEqualStrings("web", loaded.manifest.services[0].name);
    try std.testing.expectEqualStrings("nginx", loaded.manifest.services[0].command[0]);
    try std.testing.expectEqual(@as(u16, 8080), loaded.manifest.services[0].ports[0].host_port);
    try std.testing.expectEqual(spec.RestartPolicy.always, loaded.manifest.services[0].restart);
    try std.testing.expectEqual(@as(u32, 2), loaded.manifest.services[0].rollout.parallelism);
    try std.testing.expectEqual(spec.RolloutFailureAction.pause, loaded.manifest.services[0].rollout.failure_action);
    try std.testing.expectEqualStrings("demo.internal", loaded.manifest.services[0].tls.?.domain);
    try std.testing.expectEqual(@as(usize, 1), loaded.manifest.services[0].http_routes.len);
    try std.testing.expectEqual(@as(u32, 2), loaded.manifest.services[0].gpu_mesh.?.world_size);
}
