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
    volumes: []const Volume,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *Manifest) void {
        for (self.services) |svc| svc.deinit(self.alloc);
        self.alloc.free(self.services);

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
};

/// restart policy for a service — controls what happens when the
/// container exits. mirrors common container restart semantics:
///   none:       don't restart (default)
///   always:     restart unconditionally
///   on_failure: restart only on non-zero exit code
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

    pub fn deinit(self: Service, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.image);

        for (self.command) |cmd| alloc.free(cmd);
        alloc.free(self.command);

        alloc.free(self.ports);

        for (self.env) |e| alloc.free(e);
        alloc.free(self.env);

        for (self.depends_on) |dep| alloc.free(dep);
        alloc.free(self.depends_on);

        if (self.working_dir) |wd| alloc.free(wd);

        for (self.volumes) |vol| vol.deinit(alloc);
        alloc.free(self.volumes);

        if (self.health_check) |hc| hc.deinit(alloc);
        if (self.tls) |tc| tc.deinit(alloc);
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

pub const Volume = struct {
    name: []const u8,
    driver: []const u8,

    pub fn deinit(self: Volume, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.driver);
    }
};

// -- tests --

test "serviceByName finds existing service" {
    const alloc = std.testing.allocator;

    const services = try alloc.alloc(Service, 2);
    services[0] = try testService(alloc, "web");
    services[1] = try testService(alloc, "db");

    const volumes = try alloc.alloc(Volume, 0);

    var manifest = Manifest{
        .services = services,
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
        .driver = try alloc.dupe(u8, "local"),
    };

    var manifest = Manifest{
        .services = services,
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
