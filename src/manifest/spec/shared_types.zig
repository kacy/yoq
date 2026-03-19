const std = @import("std");

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

pub const AlertSpec = struct {
    cpu_percent: ?f64 = null,
    memory_percent: ?f64 = null,
    restart_count: ?u32 = null,
    latency_p99_ms: ?f64 = null,
    error_rate_percent: ?f64 = null,
    webhook: ?[]const u8 = null,

    pub fn deinit(self: AlertSpec, alloc: std.mem.Allocator) void {
        if (self.webhook) |w| alloc.free(w);
    }
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

pub const RestartPolicy = enum {
    none,
    always,
    on_failure,
};

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

pub const HealthCheck = struct {
    check_type: CheckType,
    interval: u32 = 10,
    timeout: u32 = 5,
    retries: u32 = 3,
    start_period: u32 = 0,

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

pub const TlsConfig = struct {
    domain: []const u8,
    acme: bool = false,
    email: ?[]const u8 = null,

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
