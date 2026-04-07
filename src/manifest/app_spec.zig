const std = @import("std");
const spec = @import("spec.zig");
const json_helpers = @import("../lib/json_helpers.zig");
const loader = @import("loader.zig");

pub const ApplicationServiceSpec = struct {
    name: []const u8,
    image: []const u8,
    command: []const []const u8,
    ports: []const spec.PortMapping,
    env: []const []const u8,
    depends_on: []const []const u8,
    working_dir: ?[]const u8,
    volumes: []const spec.VolumeMount,
    health_check: ?spec.HealthCheck,
    restart: spec.RestartPolicy,
    tls: ?spec.TlsConfig,
    http_routes: []const spec.HttpProxyRoute,
    gpu: ?spec.GpuSpec,
    gpu_mesh: ?spec.GpuMeshSpec,
    cpu_limit: i64 = 1000,
    memory_limit_mb: i64 = 256,
    required_labels: []const u8 = "",
};

pub const ApplicationSpec = struct {
    app_name: []const u8,
    services: []const ApplicationServiceSpec,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *ApplicationSpec) void {
        self.alloc.free(self.app_name);
        self.alloc.free(self.services);
    }

    pub fn serviceByName(self: *const ApplicationSpec, name: []const u8) ?*const ApplicationServiceSpec {
        for (self.services) |*svc| {
            if (std.mem.eql(u8, svc.name, name)) return svc;
        }
        return null;
    }

    pub fn toLegacyDeployJson(self: *const ApplicationSpec, alloc: std.mem.Allocator) ![]u8 {
        var json_buf: std.ArrayList(u8) = .empty;
        errdefer json_buf.deinit(alloc);
        const writer = json_buf.writer(alloc);

        try writer.writeAll("{\"volume_app\":\"");
        try json_helpers.writeJsonEscaped(writer, self.app_name);
        try writer.writeAll("\",\"services\":[");

        for (self.services, 0..) |svc, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll("{\"name\":\"");
            try json_helpers.writeJsonEscaped(writer, svc.name);
            try writer.writeAll("\",\"image\":\"");
            try json_helpers.writeJsonEscaped(writer, svc.image);
            try writer.writeAll("\",\"command\":\"");
            try writeJsonJoinedCommand(writer, svc.command);
            try writer.print("\",\"cpu_limit\":{d},\"memory_limit_mb\":{d}", .{
                svc.cpu_limit,
                svc.memory_limit_mb,
            });

            if (svc.gpu) |gpu| {
                try writer.print(",\"gpu_limit\":{d}", .{gpu.count});
                if (gpu.model) |model| {
                    try writer.writeAll(",\"gpu_model\":\"");
                    try json_helpers.writeJsonEscaped(writer, model);
                    try writer.writeByte('"');
                }
                if (gpu.vram_min_mb) |vram_min_mb| {
                    try writer.print(",\"gpu_vram_min_mb\":{d}", .{vram_min_mb});
                }
            }

            if (svc.gpu_mesh) |mesh| {
                try writer.print(",\"gang_world_size\":{d},\"gpus_per_rank\":{d}", .{
                    mesh.world_size,
                    mesh.gpus_per_rank,
                });
            }

            if (svc.required_labels.len > 0) {
                try writer.writeAll(",\"required_labels\":\"");
                try json_helpers.writeJsonEscaped(writer, svc.required_labels);
                try writer.writeByte('"');
            }

            try writer.writeByte('}');
        }

        try writer.writeAll("]}");
        return json_buf.toOwnedSlice(alloc);
    }
};

pub fn fromManifest(alloc: std.mem.Allocator, app_name: []const u8, manifest: *const spec.Manifest) !ApplicationSpec {
    const services = try alloc.alloc(ApplicationServiceSpec, manifest.services.len);
    errdefer alloc.free(services);

    for (manifest.services, 0..) |svc, i| {
        services[i] = .{
            .name = svc.name,
            .image = svc.image,
            .command = svc.command,
            .ports = svc.ports,
            .env = svc.env,
            .depends_on = svc.depends_on,
            .working_dir = svc.working_dir,
            .volumes = svc.volumes,
            .health_check = svc.health_check,
            .restart = svc.restart,
            .tls = svc.tls,
            .http_routes = svc.http_routes,
            .gpu = svc.gpu,
            .gpu_mesh = svc.gpu_mesh,
        };
    }

    return .{
        .app_name = try alloc.dupe(u8, app_name),
        .services = services,
        .alloc = alloc,
    };
}

fn writeJsonJoinedCommand(writer: anytype, command: []const []const u8) !void {
    for (command, 0..) |arg, i| {
        if (i > 0) try writer.writeByte(' ');
        try json_helpers.writeJsonEscaped(writer, arg);
    }
}

test "fromManifest builds canonical service app spec" {
    const alloc = std.testing.allocator;

    var manifest = try loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\command = ["nginx", "-g", "daemon off;"]
        \\ports = ["8080:80"]
        \\env = ["MODE=prod"]
        \\depends_on = ["db"]
        \\working_dir = "/app"
        \\volumes = ["./src:/app:ro"]
        \\
        \\[service.web.gpu]
        \\count = 1
        \\model = "A100"
        \\vram_min_mb = 40960
        \\
        \\[service.web.gpu_mesh]
        \\world_size = 4
        \\gpus_per_rank = 2
        \\
        \\[service.db]
        \\image = "postgres:16"
    );
    defer manifest.deinit();

    var app = try fromManifest(alloc, "demo-app", &manifest);
    defer app.deinit();

    try std.testing.expectEqualStrings("demo-app", app.app_name);
    try std.testing.expectEqual(@as(usize, 2), app.services.len);
    try std.testing.expectEqualStrings("web", app.services[1].name);
    try std.testing.expectEqualStrings("nginx:latest", app.services[1].image);
    try std.testing.expectEqual(@as(usize, 3), app.services[1].command.len);
    try std.testing.expectEqual(@as(usize, 1), app.services[1].ports.len);
    try std.testing.expectEqual(@as(usize, 1), app.services[1].env.len);
    try std.testing.expectEqual(@as(usize, 1), app.services[1].depends_on.len);
    try std.testing.expectEqualStrings("/app", app.services[1].working_dir.?);
    try std.testing.expectEqual(@as(usize, 1), app.services[1].volumes.len);
    try std.testing.expectEqual(@as(u32, 1), app.services[1].gpu.?.count);
    try std.testing.expectEqual(@as(u32, 4), app.services[1].gpu_mesh.?.world_size);
    try std.testing.expectEqual(@as(u32, 2), app.services[1].gpu_mesh.?.gpus_per_rank);
}

test "toLegacyDeployJson preserves service semantics needed by deploy shim" {
    const alloc = std.testing.allocator;

    var manifest = try loader.loadFromString(alloc,
        \\[service.api]
        \\image = "alpine:latest"
        \\command = ["sleep", "30"]
        \\
        \\[service.api.gpu]
        \\count = 2
        \\model = "H100"
        \\vram_min_mb = 81920
        \\
        \\[service.api.gpu_mesh]
        \\world_size = 8
        \\gpus_per_rank = 2
    );
    defer manifest.deinit();

    var app = try fromManifest(alloc, "cluster-app", &manifest);
    defer app.deinit();

    const json = try app.toLegacyDeployJson(alloc);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"volume_app\":\"cluster-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"name\":\"api\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"image\":\"alpine:latest\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":\"sleep 30\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"gpu_limit\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"gpu_model\":\"H100\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"gpu_vram_min_mb\":81920") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"gang_world_size\":8") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"gpus_per_rank\":2") != null);
}
