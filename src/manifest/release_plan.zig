const std = @import("std");
const app_spec = @import("app_spec.zig");
const loader = @import("loader.zig");
const deployment_store = @import("update/deployment_store.zig");

pub const ReleasePlan = struct {
    app: app_spec.ApplicationSpec,
    service_filter: ?[]const []const u8,
    manifest_hash: []const u8,
    config_snapshot: []const u8,
    requested_target_count: usize,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *ReleasePlan) void {
        if (self.service_filter) |filter| self.alloc.free(filter);
        self.alloc.free(self.manifest_hash);
        self.alloc.free(self.config_snapshot);
        self.app.deinit();
    }

    pub fn fromAppSpec(
        alloc: std.mem.Allocator,
        app: *const app_spec.ApplicationSpec,
        targets: []const []const u8,
    ) !ReleasePlan {
        const config_snapshot = try makeConfigSnapshot(alloc, app, targets);
        defer alloc.free(config_snapshot);
        return fromAppSpecWithSnapshot(alloc, app, targets, config_snapshot);
    }

    pub fn fromAppSpecWithSnapshot(
        alloc: std.mem.Allocator,
        app: *const app_spec.ApplicationSpec,
        targets: []const []const u8,
        config_snapshot: []const u8,
    ) !ReleasePlan {
        var planned_app = if (targets.len == 0)
            try app.clone(alloc)
        else
            try app.selectServices(alloc, targets);
        errdefer planned_app.deinit();

        var service_filter: ?[]const []const u8 = null;
        if (targets.len > 0) {
            const filter = try alloc.alloc([]const u8, planned_app.services.len);
            errdefer alloc.free(filter);
            for (planned_app.services, 0..) |svc, i| {
                filter[i] = svc.name;
            }
            service_filter = filter;
        }

        const owned_snapshot = try alloc.dupe(u8, config_snapshot);
        errdefer alloc.free(owned_snapshot);
        const manifest_hash = try deployment_store.computeManifestHash(alloc, owned_snapshot);
        errdefer alloc.free(manifest_hash);

        return .{
            .app = planned_app,
            .service_filter = service_filter,
            .manifest_hash = manifest_hash,
            .config_snapshot = owned_snapshot,
            .requested_target_count = targets.len,
            .alloc = alloc,
        };
    }

    pub fn includesService(self: *const ReleasePlan, name: []const u8) bool {
        if (self.service_filter == null) return true;
        return self.app.serviceByName(name) != null;
    }

    pub fn resolvedServiceCount(self: *const ReleasePlan) usize {
        return self.app.services.len;
    }

    pub fn toApplyJson(self: *const ReleasePlan, alloc: std.mem.Allocator) ![]u8 {
        return alloc.dupe(u8, self.config_snapshot);
    }
};

fn makeConfigSnapshot(alloc: std.mem.Allocator, app: *const app_spec.ApplicationSpec, targets: []const []const u8) ![]u8 {
    var planned_app = if (targets.len == 0)
        try app.clone(alloc)
    else
        try app.selectServices(alloc, targets);
    defer planned_app.deinit();
    return planned_app.toApplyJson(alloc);
}

test "full release plan clones full app without a service filter" {
    const alloc = std.testing.allocator;

    var manifest = try loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.db]
        \\image = "postgres:16"
    );
    defer manifest.deinit();

    var app = try app_spec.fromManifest(alloc, "demo-app", &manifest);
    defer app.deinit();

    var release = try ReleasePlan.fromAppSpec(alloc, &app, &.{});
    defer release.deinit();

    try std.testing.expect(release.service_filter == null);
    try std.testing.expectEqual(@as(usize, 2), release.resolvedServiceCount());
    try std.testing.expect(std.mem.startsWith(u8, release.manifest_hash, "sha256:"));
    try std.testing.expect(std.mem.indexOf(u8, release.config_snapshot, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(release.includesService("web"));
    try std.testing.expect(release.includesService("db"));
}

test "partial release plan resolves transitive dependencies and exposes a filter" {
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

    var app = try app_spec.fromManifest(alloc, "demo-app", &manifest);
    defer app.deinit();

    var release = try ReleasePlan.fromAppSpec(alloc, &app, &.{"web"});
    defer release.deinit();

    try std.testing.expectEqual(@as(usize, 1), release.requested_target_count);
    try std.testing.expectEqual(@as(usize, 3), release.resolvedServiceCount());
    try std.testing.expect(release.service_filter != null);
    try std.testing.expectEqualStrings("db", release.service_filter.?[0]);
    try std.testing.expectEqualStrings("api", release.service_filter.?[1]);
    try std.testing.expectEqualStrings("web", release.service_filter.?[2]);
    try std.testing.expect(std.mem.indexOf(u8, release.config_snapshot, "\"depends_on\":[\"db\"]") != null);
    try std.testing.expect(std.mem.startsWith(u8, release.manifest_hash, "sha256:"));
    try std.testing.expect(release.includesService("api"));
    try std.testing.expect(!release.includesService("missing"));
}
