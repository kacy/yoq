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

pub const Service = struct {
    name: []const u8,
    image: []const u8,
    command: []const []const u8,
    ports: []const PortMapping,
    env: []const []const u8,
    depends_on: []const []const u8,
    working_dir: ?[]const u8,
    volumes: []const VolumeMount,

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
    };
}
