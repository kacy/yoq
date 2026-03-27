// spec — manifest type definitions
//
// pure data types for the yoq manifest format. no parsing, no I/O.
// the loader module reads TOML and produces these structs.
//
// a manifest describes a multi-service application:
//   [service.web]
//   image = "nginx:latest"
//   ports = ["80:8080"]
//   depends_on = ["db"]
//
// services are stored in dependency order (topologically sorted)
// so the orchestrator can start them in sequence.

const std = @import("std");
const shared_types = @import("spec/shared_types.zig");
const test_support = @import("spec/test_support.zig");
const workloads = @import("spec/workloads.zig");

pub const GpuSpec = shared_types.GpuSpec;
pub const GpuMeshSpec = shared_types.GpuMeshSpec;
pub const AlertSpec = shared_types.AlertSpec;
pub const CheckpointSpec = shared_types.CheckpointSpec;
pub const DataSpec = shared_types.DataSpec;
pub const FaultToleranceSpec = shared_types.FaultToleranceSpec;
pub const TrainingResourceSpec = shared_types.TrainingResourceSpec;
pub const RestartPolicy = shared_types.RestartPolicy;
pub const CheckType = shared_types.CheckType;
pub const HealthCheck = shared_types.HealthCheck;
pub const TlsConfig = shared_types.TlsConfig;
pub const HttpProxyConfig = shared_types.HttpProxyConfig;
pub const PortMapping = shared_types.PortMapping;
pub const VolumeMount = shared_types.VolumeMount;
pub const VolumeDriver = shared_types.VolumeDriver;
pub const Volume = shared_types.Volume;

pub const TrainingJob = workloads.TrainingJob;
pub const Service = workloads.Service;
pub const Worker = workloads.Worker;
pub const Cron = workloads.Cron;

pub const Manifest = struct {
    services: []const Service,
    workers: []const Worker,
    crons: []const Cron,
    training_jobs: []const TrainingJob,
    volumes: []const Volume,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *Manifest) void {
        for (self.services) |svc| svc.deinit(self.alloc);
        self.alloc.free(self.services);

        for (self.workers) |w| w.deinit(self.alloc);
        self.alloc.free(self.workers);

        for (self.crons) |c| c.deinit(self.alloc);
        self.alloc.free(self.crons);

        for (self.training_jobs) |tj| tj.deinit(self.alloc);
        self.alloc.free(self.training_jobs);

        for (self.volumes) |vol| vol.deinit(self.alloc);
        self.alloc.free(self.volumes);
    }

    pub fn serviceByName(self: *const Manifest, name: []const u8) ?*const Service {
        for (self.services) |*svc| {
            if (std.mem.eql(u8, svc.name, name)) return svc;
        }
        return null;
    }

    pub fn workerByName(self: *const Manifest, name: []const u8) ?*const Worker {
        for (self.workers) |*w| {
            if (std.mem.eql(u8, w.name, name)) return w;
        }
        return null;
    }

    pub fn trainingJobByName(self: *const Manifest, name: []const u8) ?*const TrainingJob {
        for (self.training_jobs) |*tj| {
            if (std.mem.eql(u8, tj.name, name)) return tj;
        }
        return null;
    }
};

// -- tests --

test "serviceByName finds existing service" {
    const alloc = std.testing.allocator;

    const services = try alloc.alloc(Service, 2);
    services[0] = try test_support.testService(alloc, "web");
    services[1] = try test_support.testService(alloc, "db");

    const volumes = try alloc.alloc(Volume, 0);

    var manifest = Manifest{
        .services = services,
        .workers = &.{},
        .crons = &.{},
        .training_jobs = &.{},
        .volumes = volumes,
        .alloc = alloc,
    };
    defer manifest.deinit();

    const found = manifest.serviceByName("db");
    try std.testing.expect(found != null);
    try std.testing.expectEqualStrings("db", found.?.name);
}

test "serviceByName returns null for missing service" {
    const alloc = std.testing.allocator;

    const services = try alloc.alloc(Service, 1);
    services[0] = try test_support.testService(alloc, "web");

    const volumes = try alloc.alloc(Volume, 0);

    var manifest = Manifest{
        .services = services,
        .workers = &.{},
        .crons = &.{},
        .training_jobs = &.{},
        .volumes = volumes,
        .alloc = alloc,
    };
    defer manifest.deinit();

    try std.testing.expect(manifest.serviceByName("missing") == null);
}

test "deinit frees all memory" {
    const alloc = std.testing.allocator;

    const ports = try alloc.alloc(PortMapping, 1);
    ports[0] = .{ .host_port = 80, .container_port = 8080 };

    const env = try alloc.alloc([]const u8, 1);
    env[0] = try alloc.dupe(u8, "KEY=VALUE");

    const deps = try alloc.alloc([]const u8, 1);
    deps[0] = try alloc.dupe(u8, "db");

    const cmd = try alloc.alloc([]const u8, 1);
    cmd[0] = try alloc.dupe(u8, "/bin/sh");

    const vol_mounts = try alloc.alloc(VolumeMount, 1);
    vol_mounts[0] = .{
        .source = try alloc.dupe(u8, "./src"),
        .target = try alloc.dupe(u8, "/app"),
        .kind = .bind,
    };

    const services = try alloc.alloc(Service, 1);
    services[0] = .{
        .name = try alloc.dupe(u8, "web"),
        .image = try alloc.dupe(u8, "nginx:latest"),
        .command = cmd,
        .ports = ports,
        .env = env,
        .depends_on = deps,
        .working_dir = try alloc.dupe(u8, "/app"),
        .volumes = vol_mounts,
        .health_check = .{
            .check_type = .{ .http = .{
                .path = try alloc.dupe(u8, "/health"),
                .port = 8080,
            } },
            .interval = 10,
            .timeout = 5,
            .retries = 3,
            .start_period = 0,
        },
        .http_proxy = .{
            .host = try alloc.dupe(u8, "api.internal"),
            .path_prefix = try alloc.dupe(u8, "/v1"),
            .retries = 2,
            .connect_timeout_ms = 1500,
            .request_timeout_ms = 6000,
            .preserve_host = false,
        },
    };

    const volumes = try alloc.alloc(Volume, 1);
    volumes[0] = .{
        .name = try alloc.dupe(u8, "data"),
        .driver = .{ .local = .{} },
    };

    var manifest = Manifest{
        .services = services,
        .workers = &.{},
        .crons = &.{},
        .training_jobs = &.{},
        .volumes = volumes,
        .alloc = alloc,
    };

    manifest.deinit();
}

test "health check defaults" {
    const hc = HealthCheck{
        .check_type = .{ .tcp = .{ .port = 5432 } },
    };
    try std.testing.expectEqual(@as(u32, 10), hc.interval);
    try std.testing.expectEqual(@as(u32, 5), hc.timeout);
    try std.testing.expectEqual(@as(u32, 3), hc.retries);
    try std.testing.expectEqual(@as(u32, 0), hc.start_period);
}

test "health check deinit frees http path" {
    const alloc = std.testing.allocator;

    var hc = HealthCheck{
        .check_type = .{ .http = .{
            .path = try alloc.dupe(u8, "/health"),
            .port = 8080,
        } },
    };
    hc.deinit(alloc);
}

test "health check deinit frees exec command" {
    const alloc = std.testing.allocator;

    const cmds = try alloc.alloc([]const u8, 2);
    cmds[0] = try alloc.dupe(u8, "pg_isready");
    cmds[1] = try alloc.dupe(u8, "-h localhost");

    var hc = HealthCheck{
        .check_type = .{ .exec = .{ .command = cmds } },
    };
    hc.deinit(alloc);
}

test "health check tcp deinit is no-op" {
    const alloc = std.testing.allocator;

    var hc = HealthCheck{
        .check_type = .{ .tcp = .{ .port = 5432 } },
    };
    hc.deinit(alloc);
}

test "restart policy defaults to none" {
    const svc = Service{
        .name = "test",
        .image = "scratch",
        .command = &.{},
        .ports = &.{},
        .env = &.{},
        .depends_on = &.{},
        .working_dir = null,
        .volumes = &.{},
    };
    try std.testing.expectEqual(RestartPolicy.none, svc.restart);
}

test "trainingJobByName finds existing job" {
    const alloc = std.testing.allocator;

    const tjs = try alloc.alloc(TrainingJob, 1);
    tjs[0] = try test_support.testTrainingJob(alloc, "my-llm");

    var manifest = Manifest{
        .services = &.{},
        .workers = &.{},
        .crons = &.{},
        .training_jobs = tjs,
        .volumes = &.{},
        .alloc = alloc,
    };
    defer manifest.deinit();

    const found = manifest.trainingJobByName("my-llm");
    try std.testing.expect(found != null);
    try std.testing.expectEqualStrings("my-llm", found.?.name);
    try std.testing.expect(manifest.trainingJobByName("missing") == null);
}

test "training job deinit frees all memory" {
    const alloc = std.testing.allocator;

    const cmd = try alloc.alloc([]const u8, 1);
    cmd[0] = try alloc.dupe(u8, "torchrun train.py");

    const env = try alloc.alloc([]const u8, 1);
    env[0] = try alloc.dupe(u8, "EPOCHS=10");

    const vol_mounts = try alloc.alloc(VolumeMount, 1);
    vol_mounts[0] = .{
        .source = try alloc.dupe(u8, "/mnt/data"),
        .target = try alloc.dupe(u8, "/data"),
        .kind = .bind,
    };

    var tj = TrainingJob{
        .name = try alloc.dupe(u8, "test-train"),
        .image = try alloc.dupe(u8, "trainer:v1"),
        .command = cmd,
        .env = env,
        .working_dir = try alloc.dupe(u8, "/workspace"),
        .volumes = vol_mounts,
        .gpus = 8,
        .gpu_type = try alloc.dupe(u8, "H100"),
        .data = .{
            .dataset = try alloc.dupe(u8, "/mnt/lustre/pile"),
            .sharding = try alloc.dupe(u8, "file"),
            .preprocessing = try alloc.dupe(u8, "tokenize"),
        },
        .checkpoint = .{
            .path = try alloc.dupe(u8, "/mnt/checkpoints"),
            .interval_secs = 900,
            .keep = 3,
        },
    };
    tj.deinit(alloc);
}

test "training job defaults" {
    const tj = TrainingJob{
        .name = "test",
        .image = "scratch",
        .command = &.{},
        .env = &.{},
        .working_dir = null,
        .volumes = &.{},
        .gpus = 4,
    };
    try std.testing.expectEqual(@as(u32, 1000), tj.resources.cpu);
    try std.testing.expectEqual(@as(u64, 65536), tj.resources.memory_mb);
    try std.testing.expect(!tj.resources.ib_required);
    try std.testing.expectEqual(@as(u32, 0), tj.fault_tolerance.spare_ranks);
    try std.testing.expect(tj.fault_tolerance.auto_restart);
    try std.testing.expectEqual(@as(u32, 10), tj.fault_tolerance.max_restarts);
    try std.testing.expect(tj.data == null);
    try std.testing.expect(tj.checkpoint == null);
    try std.testing.expect(tj.gpu_type == null);
}
