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

    pub fn selectServices(self: *const ApplicationSpec, alloc: std.mem.Allocator, targets: []const []const u8) !ApplicationSpec {
        if (targets.len == 0) return self.clone(alloc);

        var selected: std.StringHashMapUnmanaged(void) = .empty;
        defer selected.deinit(alloc);

        for (targets) |name| {
            try selected.put(alloc, name, {});
        }

        var changed = true;
        while (changed) {
            changed = false;
            for (self.services) |svc| {
                if (!selected.contains(svc.name)) continue;
                for (svc.depends_on) |dep| {
                    if (!selected.contains(dep)) {
                        try selected.put(alloc, dep, {});
                        changed = true;
                    }
                }
            }
        }

        var count: usize = 0;
        for (self.services) |svc| {
            if (selected.contains(svc.name)) count += 1;
        }

        const services = try alloc.alloc(ApplicationServiceSpec, count);
        errdefer alloc.free(services);

        var out_idx: usize = 0;
        for (self.services) |svc| {
            if (!selected.contains(svc.name)) continue;
            services[out_idx] = svc;
            out_idx += 1;
        }

        return .{
            .app_name = try alloc.dupe(u8, self.app_name),
            .services = services,
            .alloc = alloc,
        };
    }

    pub fn clone(self: *const ApplicationSpec, alloc: std.mem.Allocator) !ApplicationSpec {
        const services = try alloc.dupe(ApplicationServiceSpec, self.services);
        errdefer alloc.free(services);

        return .{
            .app_name = try alloc.dupe(u8, self.app_name),
            .services = services,
            .alloc = alloc,
        };
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

    pub fn toApplyJson(self: *const ApplicationSpec, alloc: std.mem.Allocator) ![]u8 {
        var json_buf: std.ArrayList(u8) = .empty;
        errdefer json_buf.deinit(alloc);
        const writer = json_buf.writer(alloc);

        try writer.writeAll("{\"app_name\":\"");
        try json_helpers.writeJsonEscaped(writer, self.app_name);
        try writer.writeAll("\",\"services\":[");

        for (self.services, 0..) |svc, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll("{\"name\":\"");
            try json_helpers.writeJsonEscaped(writer, svc.name);
            try writer.writeAll("\",\"image\":\"");
            try json_helpers.writeJsonEscaped(writer, svc.image);
            try writer.writeAll("\",\"command\":");
            try writeJsonStringArray(writer, svc.command);
            try writer.writeAll(",\"ports\":");
            try writeJsonPorts(writer, svc.ports);
            try writer.writeAll(",\"env\":");
            try writeJsonStringArray(writer, svc.env);
            try writer.writeAll(",\"depends_on\":");
            try writeJsonStringArray(writer, svc.depends_on);
            try writer.print(",\"cpu_limit\":{d},\"memory_limit_mb\":{d}", .{
                svc.cpu_limit,
                svc.memory_limit_mb,
            });

            if (svc.working_dir) |working_dir| {
                try writer.writeAll(",\"working_dir\":\"");
                try json_helpers.writeJsonEscaped(writer, working_dir);
                try writer.writeByte('"');
            }

            try writer.writeAll(",\"volumes\":");
            try writeJsonVolumes(writer, svc.volumes);
            try writer.writeAll(",\"restart\":\"");
            try writer.writeAll(restartPolicyString(svc.restart));
            try writer.writeByte('"');

            if (svc.health_check) |health_check| {
                try writer.writeAll(",\"health_check\":");
                try writeJsonHealthCheck(writer, health_check);
            }

            if (svc.tls) |tls| {
                try writer.writeAll(",\"tls\":");
                try writeJsonTls(writer, tls);
            }

            try writer.writeAll(",\"http_routes\":");
            try writeJsonHttpRoutes(writer, svc.http_routes);

            if (svc.gpu) |gpu| {
                try writer.writeAll(",\"gpu\":");
                try writeJsonGpu(writer, gpu);
            }

            if (svc.gpu_mesh) |mesh| {
                try writer.writeAll(",\"gpu_mesh\":");
                try writeJsonGpuMesh(writer, mesh);
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

fn writeJsonStringArray(writer: anytype, items: []const []const u8) !void {
    try writer.writeByte('[');
    for (items, 0..) |item, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.writeByte('"');
        try json_helpers.writeJsonEscaped(writer, item);
        try writer.writeByte('"');
    }
    try writer.writeByte(']');
}

fn writeJsonPorts(writer: anytype, ports: []const spec.PortMapping) !void {
    try writer.writeByte('[');
    for (ports, 0..) |port, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.print("{{\"host_port\":{d},\"container_port\":{d}}}", .{
            port.host_port,
            port.container_port,
        });
    }
    try writer.writeByte(']');
}

fn writeJsonVolumes(writer: anytype, volumes: []const spec.VolumeMount) !void {
    try writer.writeByte('[');
    for (volumes, 0..) |vol, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.writeAll("{\"source\":\"");
        try json_helpers.writeJsonEscaped(writer, vol.source);
        try writer.writeAll("\",\"target\":\"");
        try json_helpers.writeJsonEscaped(writer, vol.target);
        try writer.writeAll("\",\"kind\":\"");
        try writer.writeAll(volumeKindString(vol.kind));
        try writer.writeAll("\"}");
    }
    try writer.writeByte(']');
}

fn writeJsonHealthCheck(writer: anytype, health_check: spec.HealthCheck) !void {
    try writer.writeByte('{');
    switch (health_check.check_type) {
        .http => |http| {
            try writer.writeAll("\"kind\":\"http\",\"path\":\"");
            try json_helpers.writeJsonEscaped(writer, http.path);
            try writer.print("\",\"port\":{d}", .{http.port});
        },
        .tcp => |tcp| {
            try writer.print("\"kind\":\"tcp\",\"port\":{d}", .{tcp.port});
        },
        .grpc => |grpc| {
            try writer.print("\"kind\":\"grpc\",\"port\":{d}", .{grpc.port});
            if (grpc.service) |service| {
                try writer.writeAll(",\"service\":\"");
                try json_helpers.writeJsonEscaped(writer, service);
                try writer.writeByte('"');
            }
        },
        .exec => |exec| {
            try writer.writeAll("\"kind\":\"exec\",\"command\":");
            try writeJsonStringArray(writer, exec.command);
        },
    }
    try writer.print(",\"interval\":{d},\"timeout\":{d},\"retries\":{d},\"start_period\":{d}", .{
        health_check.interval,
        health_check.timeout,
        health_check.retries,
        health_check.start_period,
    });
    try writer.writeByte('}');
}

fn writeJsonTls(writer: anytype, tls: spec.TlsConfig) !void {
    try writer.writeAll("{\"domain\":\"");
    try json_helpers.writeJsonEscaped(writer, tls.domain);
    try writer.print("\",\"acme\":{}", .{tls.acme});
    if (tls.email) |email| {
        try writer.writeAll(",\"email\":\"");
        try json_helpers.writeJsonEscaped(writer, email);
        try writer.writeByte('"');
    }
    try writer.writeByte('}');
}

fn writeJsonHttpRoutes(writer: anytype, routes: []const spec.HttpProxyRoute) !void {
    try writer.writeByte('[');
    for (routes, 0..) |route, i| {
        if (i > 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":\"");
        try json_helpers.writeJsonEscaped(writer, route.name);
        try writer.writeAll("\",\"host\":\"");
        try json_helpers.writeJsonEscaped(writer, route.host);
        try writer.writeAll("\",\"path_prefix\":\"");
        try json_helpers.writeJsonEscaped(writer, route.path_prefix);
        try writer.print(
            "\",\"retries\":{d},\"connect_timeout_ms\":{d},\"request_timeout_ms\":{d},\"http2_idle_timeout_ms\":{d},\"preserve_host\":{},\"retry_on_5xx\":{},\"circuit_breaker_threshold\":{d},\"circuit_breaker_timeout_ms\":{d}",
            .{
                route.retries,
                route.connect_timeout_ms,
                route.request_timeout_ms,
                route.http2_idle_timeout_ms,
                route.preserve_host,
                route.retry_on_5xx,
                route.circuit_breaker_threshold,
                route.circuit_breaker_timeout_ms,
            },
        );

        if (route.rewrite_prefix) |rewrite_prefix| {
            try writer.writeAll(",\"rewrite_prefix\":\"");
            try json_helpers.writeJsonEscaped(writer, rewrite_prefix);
            try writer.writeByte('"');
        }

        try writer.writeAll(",\"match_methods\":");
        try writer.writeByte('[');
        for (route.match_methods, 0..) |method, method_idx| {
            if (method_idx > 0) try writer.writeByte(',');
            try writer.writeAll("{\"method\":\"");
            try json_helpers.writeJsonEscaped(writer, method.method);
            try writer.writeAll("\"}");
        }
        try writer.writeByte(']');

        try writer.writeAll(",\"match_headers\":");
        try writer.writeByte('[');
        for (route.match_headers, 0..) |header, header_idx| {
            if (header_idx > 0) try writer.writeByte(',');
            try writer.writeAll("{\"name\":\"");
            try json_helpers.writeJsonEscaped(writer, header.name);
            try writer.writeAll("\",\"value\":\"");
            try json_helpers.writeJsonEscaped(writer, header.value);
            try writer.writeAll("\"}");
        }
        try writer.writeByte(']');

        try writer.writeAll(",\"backend_services\":");
        try writer.writeByte('[');
        for (route.backend_services, 0..) |backend, backend_idx| {
            if (backend_idx > 0) try writer.writeByte(',');
            try writer.writeAll("{\"service_name\":\"");
            try json_helpers.writeJsonEscaped(writer, backend.service_name);
            try writer.print("\",\"weight\":{d}", .{backend.weight});
            try writer.writeByte('}');
        }
        try writer.writeByte(']');

        if (route.mirror_service) |mirror_service| {
            try writer.writeAll(",\"mirror_service\":\"");
            try json_helpers.writeJsonEscaped(writer, mirror_service);
            try writer.writeByte('"');
        }

        try writer.writeByte('}');
    }
    try writer.writeByte(']');
}

fn writeJsonGpu(writer: anytype, gpu: spec.GpuSpec) !void {
    try writer.print("{{\"count\":{d}", .{gpu.count});
    if (gpu.model) |model| {
        try writer.writeAll(",\"model\":\"");
        try json_helpers.writeJsonEscaped(writer, model);
        try writer.writeByte('"');
    }
    if (gpu.vram_min_mb) |vram_min_mb| {
        try writer.print(",\"vram_min_mb\":{d}", .{vram_min_mb});
    }
    try writer.writeByte('}');
}

fn writeJsonGpuMesh(writer: anytype, mesh: spec.GpuMeshSpec) !void {
    try writer.print(
        "{{\"world_size\":{d},\"gpus_per_rank\":{d},\"master_port\":{d}}}",
        .{ mesh.world_size, mesh.gpus_per_rank, mesh.master_port },
    );
}

fn restartPolicyString(restart: spec.RestartPolicy) []const u8 {
    return switch (restart) {
        .none => "none",
        .always => "always",
        .on_failure => "on_failure",
    };
}

fn volumeKindString(kind: spec.VolumeMount.Kind) []const u8 {
    return switch (kind) {
        .named => "named",
        .bind => "bind",
    };
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

test "selectServices includes transitive dependencies in manifest order" {
    const alloc = std.testing.allocator;

    var manifest = try loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\depends_on = ["api"]
        \\
        \\[service.api]
        \\image = "alpine:latest"
        \\depends_on = ["db"]
        \\
        \\[service.db]
        \\image = "postgres:16"
    );
    defer manifest.deinit();

    var app = try fromManifest(alloc, "demo-app", &manifest);
    defer app.deinit();

    var filtered = try app.selectServices(alloc, &.{"web"});
    defer filtered.deinit();

    try std.testing.expectEqual(@as(usize, 3), filtered.services.len);
    try std.testing.expectEqualStrings("db", filtered.services[0].name);
    try std.testing.expectEqualStrings("api", filtered.services[1].name);
    try std.testing.expectEqualStrings("web", filtered.services[2].name);
}

test "toApplyJson preserves structured command and service metadata" {
    const alloc = std.testing.allocator;

    var manifest = try loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\command = ["nginx", "-g", "daemon off;"]
        \\ports = ["8080:80"]
        \\env = ["MODE=prod"]
        \\depends_on = ["db"]
        \\working_dir = "/app"
        \\volumes = ["./src:/app"]
        \\restart = "always"
        \\
        \\[service.db]
        \\image = "postgres:16"
    );
    defer manifest.deinit();

    var app = try fromManifest(alloc, "demo-app", &manifest);
    defer app.deinit();

    const json = try app.toApplyJson(alloc);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"command\":[\"nginx\",\"-g\",\"daemon off;\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"ports\":[{\"host_port\":8080,\"container_port\":80}]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"env\":[\"MODE=prod\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"depends_on\":[\"db\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"working_dir\":\"/app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"restart\":\"always\"") != null);
}
