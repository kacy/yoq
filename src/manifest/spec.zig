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

    /// find a service by name. returns null if not found.
    pub fn serviceByName(self: *const Manifest, name: []const u8) ?*const Service {
        for (self.services) |*svc| {
            if (std.mem.eql(u8, svc.name, name)) return svc;
        }
        return null;
    }

    /// find a worker by name. returns null if not found.
    pub fn workerByName(self: *const Manifest, name: []const u8) ?*const Worker {
        for (self.workers) |*w| {
            if (std.mem.eql(u8, w.name, name)) return w;
        }
        return null;
    }

    /// find a training job by name. returns null if not found.
    pub fn trainingJobByName(self: *const Manifest, name: []const u8) ?*const TrainingJob {
        for (self.training_jobs) |*tj| {
            if (std.mem.eql(u8, tj.name, name)) return tj;
        }
        return null;
    }
};

/// restart policy for a service — controls what happens when the
/// container exits. mirrors common container restart semantics:
///   none:       don't restart (default)
///   always:     restart unconditionally
///   on_failure: restart only on non-zero exit code
pub const GpuSpec = struct {
    count: u32 = 0,
    model: ?[]const u8 = null,
    vram_min_mb: ?u64 = null,

    pub fn deinit(self: GpuSpec, alloc: std.mem.Allocator) void {
        if (self.model) |m| alloc.free(m);
    }
};

pub const GpuMeshSpec = struct {
    world_size: u32,
    gpus_per_rank: u32 = 1,
    master_port: u16 = 29500,
};

pub const CheckpointSpec = struct {
    path: []const u8,
    interval_secs: u64 = 1800,
    keep: u32 = 5,

    pub fn deinit(self: CheckpointSpec, alloc: std.mem.Allocator) void {
        alloc.free(self.path);
    }
};

pub const DataSpec = struct {
    dataset: []const u8,
    sharding: []const u8,
    preprocessing: ?[]const u8 = null,

    pub fn deinit(self: DataSpec, alloc: std.mem.Allocator) void {
        alloc.free(self.dataset);
        alloc.free(self.sharding);
        if (self.preprocessing) |p| alloc.free(p);
    }
};

pub const FaultToleranceSpec = struct {
    spare_ranks: u32 = 0,
    auto_restart: bool = true,
    max_restarts: u32 = 10,
};

pub const TrainingResourceSpec = struct {
    cpu: u32 = 1000,
    memory_mb: u64 = 65536,
    ib_required: bool = false,
};

pub const TrainingJob = struct {
    name: []const u8,
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    working_dir: ?[]const u8,
    volumes: []const VolumeMount,
    gpus: u32,
    gpu_type: ?[]const u8 = null,
    data: ?DataSpec = null,
    checkpoint: ?CheckpointSpec = null,
    resources: TrainingResourceSpec = .{},
    fault_tolerance: FaultToleranceSpec = .{},

    pub fn deinit(self: TrainingJob, alloc: std.mem.Allocator) void {
        freeCommonFields(alloc, self.name, self.image, self.command, self.env, self.working_dir, self.volumes);
        if (self.gpu_type) |gt| alloc.free(gt);
        if (self.data) |d| d.deinit(alloc);
        if (self.checkpoint) |c| c.deinit(alloc);
    }
};

pub const RestartPolicy = enum {
    none,
    always,
    on_failure,
};

pub const Service = struct {
    name: []const u8,
    image: []const u8,
    command: []const []const u8,
    ports: []const PortMapping,
    env: []const []const u8,
    depends_on: []const []const u8,
    working_dir: ?[]const u8,
    volumes: []const VolumeMount,
    health_check: ?HealthCheck = null,
    restart: RestartPolicy = .none,
    tls: ?TlsConfig = null,
    gpu: ?GpuSpec = null,
    gpu_mesh: ?GpuMeshSpec = null,

    pub fn deinit(self: Service, alloc: std.mem.Allocator) void {
        freeCommonFields(alloc, self.name, self.image, self.command, self.env, self.working_dir, self.volumes);
        for (self.depends_on) |dep| alloc.free(dep);
        alloc.free(self.depends_on);
        alloc.free(self.ports);
        if (self.health_check) |hc| hc.deinit(alloc);
        if (self.tls) |tc| tc.deinit(alloc);
        if (self.gpu) |g| g.deinit(alloc);

    }
};

/// a one-shot task defined in the manifest. workers run to completion
/// and exit — they're used for things like database migrations.
/// workers can be dependencies of services (runs before the service starts)
/// or invoked manually with `yoq run-worker <name>`.
pub const Worker = struct {
    name: []const u8,
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    depends_on: []const []const u8,
    working_dir: ?[]const u8,
    volumes: []const VolumeMount,
    gpu: ?GpuSpec = null,
    gpu_mesh: ?GpuMeshSpec = null,

    pub fn deinit(self: Worker, alloc: std.mem.Allocator) void {
        freeCommonFields(alloc, self.name, self.image, self.command, self.env, self.working_dir, self.volumes);
        for (self.depends_on) |dep| alloc.free(dep);
        alloc.free(self.depends_on);
        if (self.gpu) |g| g.deinit(alloc);

    }
};

/// a scheduled recurring task. crons run on a fixed interval — e.g.,
/// database backups every 24 hours. the cron scheduler spawns a
/// container for each execution and cleans up after completion.
pub const Cron = struct {
    name: []const u8,
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    working_dir: ?[]const u8,
    volumes: []const VolumeMount,
    every: u64, // interval in seconds

    pub fn deinit(self: Cron, alloc: std.mem.Allocator) void {
        freeCommonFields(alloc, self.name, self.image, self.command, self.env, self.working_dir, self.volumes);
    }
};

/// the type of health check to perform.
/// http: connect and send a GET request, check for 2xx response.
/// tcp: connect to a port, success if connection is accepted.
/// exec: run a command inside the container, success if exit code is 0.
pub const CheckType = union(enum) {
    http: struct {
        path: []const u8,
        port: u16,
    },
    tcp: struct {
        port: u16,
    },
    exec: struct {
        command: []const []const u8,
    },
};

/// health check configuration for a service.
/// attached to a service definition in the manifest. the health checker
/// uses these parameters to periodically probe the service.
pub const HealthCheck = struct {
    check_type: CheckType,
    interval: u32 = 10, // seconds between checks
    timeout: u32 = 5, // seconds before check times out
    retries: u32 = 3, // consecutive failures before unhealthy
    start_period: u32 = 0, // grace period after container start (seconds)

    pub fn deinit(self: HealthCheck, alloc: std.mem.Allocator) void {
        switch (self.check_type) {
            .http => |h| alloc.free(h.path),
            .exec => |e| {
                for (e.command) |cmd| alloc.free(cmd);
                alloc.free(e.command);
            },
            .tcp => {},
        }
    }
};

/// TLS configuration for a service.
/// enables TLS termination via the reverse proxy. traffic between the
/// proxy and the container is plaintext — TLS is terminated at the edge.
pub const TlsConfig = struct {
    domain: []const u8,
    acme: bool = false, // automatic certificate provisioning via Let's Encrypt
    email: ?[]const u8 = null, // contact email for ACME account (required if acme = true)

    pub fn deinit(self: TlsConfig, alloc: std.mem.Allocator) void {
        alloc.free(self.domain);
        if (self.email) |e| alloc.free(e);
    }
};

pub const PortMapping = struct {
    host_port: u16,
    container_port: u16,
};

pub const VolumeMount = struct {
    source: []const u8,
    target: []const u8,
    kind: Kind,

    pub const Kind = enum { named, bind };

    pub fn deinit(self: VolumeMount, alloc: std.mem.Allocator) void {
        alloc.free(self.source);
        alloc.free(self.target);
    }
};

pub const VolumeDriver = union(enum) {
    local: struct {},
    host: struct { path: []const u8 },
    nfs: struct {
        server: []const u8,
        path: []const u8,
        options: ?[]const u8,
    },
    parallel: struct { mount_path: []const u8 },

    pub fn deinit(self: VolumeDriver, alloc: std.mem.Allocator) void {
        switch (self) {
            .host => |h| alloc.free(h.path),
            .nfs => |n| {
                alloc.free(n.server);
                alloc.free(n.path);
                if (n.options) |o| alloc.free(o);
            },
            .parallel => |p| alloc.free(p.mount_path),
            .local => {},
        }
    }

    pub fn driverName(self: VolumeDriver) []const u8 {
        return switch (self) {
            .local => "local",
            .host => "host",
            .nfs => "nfs",
            .parallel => "parallel",
        };
    }
};

pub const Volume = struct {
    name: []const u8,
    driver: VolumeDriver,

    pub fn deinit(self: Volume, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        self.driver.deinit(alloc);
    }
};

/// free fields shared by Service, Worker, and Cron.
fn freeCommonFields(
    alloc: std.mem.Allocator,
    name: []const u8,
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    working_dir: ?[]const u8,
    volumes: []const VolumeMount,
) void {
    alloc.free(name);
    alloc.free(image);
    for (command) |cmd| alloc.free(cmd);
    alloc.free(command);
    for (env) |e| alloc.free(e);
    alloc.free(env);
    if (working_dir) |wd| alloc.free(wd);
    for (volumes) |vol| vol.deinit(alloc);
    alloc.free(volumes);
}

// -- tests --

test "serviceByName finds existing service" {
    const alloc = std.testing.allocator;

    const services = try alloc.alloc(Service, 2);
    services[0] = try testService(alloc, "web");
    services[1] = try testService(alloc, "db");

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
    services[0] = try testService(alloc, "web");

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

    // build a service with all fields populated
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

    // testing allocator will catch any leaks
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
    // testing allocator catches leaks
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
    tjs[0] = try testTrainingJob(alloc, "my-llm");

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

fn testTrainingJob(alloc: std.mem.Allocator, name: []const u8) !TrainingJob {
    return .{
        .name = try alloc.dupe(u8, name),
        .image = try alloc.dupe(u8, "scratch"),
        .command = try alloc.alloc([]const u8, 0),
        .env = try alloc.alloc([]const u8, 0),
        .working_dir = null,
        .volumes = try alloc.alloc(VolumeMount, 0),
        .gpus = 1,
    };
}

/// helper for tests — creates a minimal service with an allocated name
fn testService(alloc: std.mem.Allocator, name: []const u8) !Service {
    return .{
        .name = try alloc.dupe(u8, name),
        .image = try alloc.dupe(u8, "scratch"),
        .command = try alloc.alloc([]const u8, 0),
        .ports = try alloc.alloc(PortMapping, 0),
        .env = try alloc.alloc([]const u8, 0),
        .depends_on = try alloc.alloc([]const u8, 0),
        .working_dir = null,
        .volumes = try alloc.alloc(VolumeMount, 0),
        .health_check = null,
    };
}
