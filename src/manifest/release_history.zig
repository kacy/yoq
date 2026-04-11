const std = @import("std");
const apply_release = @import("apply_release.zig");
const store = @import("../state/store.zig");
const deployment_store = @import("update/deployment_store.zig");
const release_plan = @import("release_plan.zig");
const update_common = @import("update/common.zig");

pub fn recordAppReleaseStart(plan: *const release_plan.ReleasePlan, context: apply_release.ApplyContext) ![]const u8 {
    const id = try deployment_store.generateDeploymentId(plan.alloc);
    errdefer plan.alloc.free(id);

    try deployment_store.recordDeployment(
        id,
        plan.app.app_name,
        plan.app.app_name,
        context.trigger.toString(),
        context.source_release_id,
        plan.manifest_hash,
        plan.config_snapshot,
        0,
        0,
        .pending,
        null,
    );
    return id;
}

pub fn markAppReleaseStatus(id: []const u8, status: update_common.DeploymentStatus, message: ?[]const u8) !void {
    try deployment_store.updateDeploymentStatus(id, status, message);
}

pub fn markAppReleaseCompleted(id: []const u8, message: ?[]const u8) !void {
    try markAppReleaseStatus(id, .completed, message);
}

pub fn markAppReleaseFailed(id: []const u8, message: ?[]const u8) !void {
    try markAppReleaseStatus(id, .failed, message);
}

pub fn rollbackApp(alloc: std.mem.Allocator, app_name: []const u8) ![]const u8 {
    return rollbackAppToRelease(alloc, app_name, null);
}

pub fn rollbackAppToRelease(alloc: std.mem.Allocator, app_name: []const u8, explicit_release_id: ?[]const u8) ![]const u8 {
    const target = try store.getRollbackTargetDeploymentByApp(alloc, app_name, explicit_release_id);
    defer target.deinit(alloc);

    return alloc.dupe(u8, target.config_snapshot);
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

    const id = try recordAppReleaseStart(&plan, .{});
    defer alloc.free(id);

    var deployments = try listAppReleases(alloc, "demo-app");
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), deployments.items.len);
    try std.testing.expectEqualStrings("demo-app", deployments.items[0].app_name.?);
    try std.testing.expectEqualStrings("demo-app", deployments.items[0].service_name);
    try std.testing.expectEqualStrings("pending", deployments.items[0].status);
}

test "markAppReleaseStatus persists partially failed state" {
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

    const id = try recordAppReleaseStart(&plan, .{});
    defer alloc.free(id);

    try markAppReleaseStatus(id, .partially_failed, "one or more placements failed");

    const dep = try store.getLatestDeploymentByApp(alloc, "demo-app");
    defer dep.deinit(alloc);

    try std.testing.expectEqualStrings(id, dep.id);
    try std.testing.expectEqualStrings("partially_failed", dep.status);
    try std.testing.expectEqualStrings("one or more placements failed", dep.message.?);
}

test "recordAppReleaseStart persists rollback transition metadata" {
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

    const id = try recordAppReleaseStart(&plan, .{
        .trigger = .rollback,
        .source_release_id = "dep-1",
    });
    defer alloc.free(id);

    const dep = try store.getLatestDeploymentByApp(alloc, "demo-app");
    defer dep.deinit(alloc);

    try std.testing.expectEqualStrings("rollback", dep.trigger.?);
    try std.testing.expectEqualStrings("dep-1", dep.source_release_id.?);
}

test "rollbackApp returns previous successful snapshot instead of current successful release" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();

    try store.saveDeployment(.{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\",\"image\":\"nginx:1\"}]}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 100,
    });
    try store.saveDeployment(.{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\",\"image\":\"nginx:2\"}]}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 200,
    });

    const config = try rollbackApp(alloc, "demo-app");
    defer alloc.free(config);

    try std.testing.expectEqualStrings(
        "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\",\"image\":\"nginx:1\"}]}",
        config,
    );
}

test "rollbackApp returns last successful snapshot when latest release failed" {
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();

    try store.saveDeployment(.{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\",\"image\":\"nginx:1\"}]}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 100,
    });
    try store.saveDeployment(.{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\",\"image\":\"nginx:2\"}]}",
        .status = "failed",
        .message = "apply failed",
        .created_at = 200,
    });

    const config = try rollbackApp(alloc, "demo-app");
    defer alloc.free(config);

    try std.testing.expectEqualStrings(
        "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\",\"image\":\"nginx:1\"}]}",
        config,
    );
}
