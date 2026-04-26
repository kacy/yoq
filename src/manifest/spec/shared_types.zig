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

pub const RolloutFailureAction = enum {
    rollback,
    pause,
};

pub const RolloutStrategy = enum {
    rolling,
    blue_green,
    canary,
};

pub const RolloutPolicy = struct {
    strategy: RolloutStrategy = .rolling,
    parallelism: u32 = 1,
    delay_between_batches: u32 = 0,
    failure_action: RolloutFailureAction = .rollback,
    health_check_timeout: u32 = 0,
};

pub const CheckType = union(enum) {
    http: struct {
        path: []const u8,
        port: u16,
    },
    tcp: struct {
        port: u16,
    },
    grpc: struct {
        port: u16,
        service: ?[]const u8 = null,
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
            .grpc => |g| if (g.service) |service| alloc.free(service),
        }
    }
};

pub const TlsConfig = struct {
    pub const ChallengeType = enum {
        http_01,
        dns_01,

        pub fn label(self: ChallengeType) []const u8 {
            return switch (self) {
                .http_01 => "http-01",
                .dns_01 => "dns-01",
            };
        }

        pub fn parse(value: []const u8) ?ChallengeType {
            if (std.mem.eql(u8, value, "http-01")) return .http_01;
            if (std.mem.eql(u8, value, "dns-01")) return .dns_01;
            return null;
        }
    };

    pub const DnsProvider = enum {
        cloudflare,
        route53,
        gcloud,
        exec,

        pub fn label(self: DnsProvider) []const u8 {
            return switch (self) {
                .cloudflare => "cloudflare",
                .route53 => "route53",
                .gcloud => "gcloud",
                .exec => "exec",
            };
        }

        pub fn parse(value: []const u8) ?DnsProvider {
            if (std.mem.eql(u8, value, "cloudflare")) return .cloudflare;
            if (std.mem.eql(u8, value, "route53")) return .route53;
            if (std.mem.eql(u8, value, "gcloud")) return .gcloud;
            if (std.mem.eql(u8, value, "exec")) return .exec;
            return null;
        }
    };

    pub const KeyValueRef = struct {
        key: []const u8,
        value: []const u8,

        pub fn deinit(self: KeyValueRef, alloc: std.mem.Allocator) void {
            alloc.free(self.key);
            alloc.free(self.value);
        }
    };

    pub const DnsConfig = struct {
        provider: DnsProvider,
        secrets: []const KeyValueRef = &.{},
        config: []const KeyValueRef = &.{},
        hook: []const []const u8 = &.{},
        propagation_timeout_secs: u32 = 300,
        poll_interval_secs: u32 = 5,

        pub fn deinit(self: DnsConfig, alloc: std.mem.Allocator) void {
            for (self.secrets) |entry| entry.deinit(alloc);
            alloc.free(self.secrets);
            for (self.config) |entry| entry.deinit(alloc);
            alloc.free(self.config);
            for (self.hook) |entry| alloc.free(entry);
            alloc.free(self.hook);
        }
    };

    pub const AcmeConfig = struct {
        email: []const u8,
        directory_url: []const u8,
        challenge: ChallengeType = .http_01,
        dns: ?DnsConfig = null,

        pub fn deinit(self: AcmeConfig, alloc: std.mem.Allocator) void {
            alloc.free(self.email);
            alloc.free(self.directory_url);
            if (self.dns) |dns| dns.deinit(alloc);
        }
    };

    domain: []const u8,
    acme: ?AcmeConfig = null,

    pub fn deinit(self: TlsConfig, alloc: std.mem.Allocator) void {
        alloc.free(self.domain);
        if (self.acme) |acme| acme.deinit(alloc);
    }
};

pub const HttpHeaderMatch = struct {
    name: []const u8,
    value: []const u8,

    pub fn deinit(self: HttpHeaderMatch, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.value);
    }
};

pub const HttpRouteBackend = struct {
    service_name: []const u8,
    weight: u8,

    pub fn deinit(self: HttpRouteBackend, alloc: std.mem.Allocator) void {
        alloc.free(self.service_name);
    }
};

pub const HttpMethodMatch = struct {
    method: []const u8,

    pub fn deinit(self: HttpMethodMatch, alloc: std.mem.Allocator) void {
        alloc.free(self.method);
    }
};

pub const HttpProxyRoute = struct {
    name: []const u8,
    host: []const u8,
    path_prefix: []const u8 = "/",
    rewrite_prefix: ?[]const u8 = null,
    match_methods: []const HttpMethodMatch = &.{},
    match_headers: []const HttpHeaderMatch = &.{},
    backend_services: []const HttpRouteBackend = &.{},
    mirror_service: ?[]const u8 = null,
    retries: u8 = 0,
    connect_timeout_ms: u32 = 1000,
    request_timeout_ms: u32 = 5000,
    http2_idle_timeout_ms: u32 = 30000,
    preserve_host: bool = true,
    retry_on_5xx: bool = true,
    circuit_breaker_threshold: u8 = 3,
    circuit_breaker_timeout_ms: u32 = 30_000,

    pub fn deinit(self: HttpProxyRoute, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.host);
        alloc.free(self.path_prefix);
        if (self.rewrite_prefix) |rewrite_prefix| alloc.free(rewrite_prefix);
        for (self.match_methods) |method_match| method_match.deinit(alloc);
        if (self.match_methods.len > 0) alloc.free(self.match_methods);
        for (self.match_headers) |header_match| header_match.deinit(alloc);
        if (self.match_headers.len > 0) alloc.free(self.match_headers);
        for (self.backend_services) |backend| backend.deinit(alloc);
        if (self.backend_services.len > 0) alloc.free(self.backend_services);
        if (self.mirror_service) |mirror_service| alloc.free(mirror_service);
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
