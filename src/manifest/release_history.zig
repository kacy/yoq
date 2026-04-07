const std = @import("std");
const store = @import("../state/store.zig");
const deployment_store = @import("update/deployment_store.zig");
const release_plan = @import("release_plan.zig");

pub fn recordAppReleaseStart(plan: *const release_plan.ReleasePlan) ![]const u8 {
    const id = try deployment_store.generateDeploymentId(plan.alloc);
    errdefer plan.alloc.free(id);

    try deployment_store.recordDeployment(
        id,
        plan.app.app_name,
        plan.app.app_name,
        plan.manifest_hash,
        plan.config_snapshot,
        .in_progress,
        null,
    );
    return id;
}

pub fn markAppReleaseCompleted(id: []const u8, message: ?[]const u8) !void {
    try deployment_store.updateDeploymentStatus(id, .completed, message);
}

pub fn markAppReleaseFailed(id: []const u8, message: ?[]const u8) !void {
    try deployment_store.updateDeploymentStatus(id, .failed, message);
}

pub fn rollbackApp(alloc: std.mem.Allocator, app_name: []const u8) ![]const u8 {
    const prev = try store.getLastSuccessfulDeploymentByApp(alloc, app_name);
    defer prev.deinit(alloc);
    return alloc.dupe(u8, prev.config_snapshot);
}

pub fn listAppReleases(alloc: std.mem.Allocator, app_name: []const u8) !std.ArrayList(store.DeploymentRecord) {
    return store.listDeploymentsByApp(alloc, app_name);
}

test "recordAppReleaseStart stores app-scoped deployment metadata" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();

    const app_spec = @import("app_spec.zig");
    const loader = @import("loader.zig");

    var manifest = try loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
    );
    defer manifest.deinit();

    var app = try app_spec.fromManifest(alloc, "demo-app", &manifest);
    defer app.deinit();

    var plan = try release_plan.ReleasePlan.fromAppSpec(alloc, &app, &.{});
    defer plan.deinit();

    const id = try recordAppReleaseStart(&plan);
    defer alloc.free(id);

    var deployments = try listAppReleases(alloc, "demo-app");
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), deployments.items.len);
    try std.testing.expectEqualStrings("demo-app", deployments.items[0].app_name.?);
    try std.testing.expectEqualStrings("demo-app", deployments.items[0].service_name);
    try std.testing.expectEqualStrings("in_progress", deployments.items[0].status);
}
