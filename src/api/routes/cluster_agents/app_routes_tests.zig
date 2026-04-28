const std = @import("std");
const http = @import("../../http.zig");
const sqlite = @import("sqlite");

const agent_registry = @import("../../../cluster/registry.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");
const apply_release = @import("../../../manifest/apply_release.zig");
const app_snapshot = @import("../../../manifest/app_snapshot.zig");
const schema = @import("../../../state/schema.zig");
const store = @import("../../../state/store.zig");
const app_route_responses = @import("app_route_responses.zig");
const app_routes = @import("app_routes.zig");
const test_support = @import("route_test_support.zig");

const RouteContext = test_support.RouteContext;

const route = app_routes.route;
const recoverActiveClusterRolloutsOnce = app_routes.recoverActiveClusterRolloutsOnce;
const RouteFlowHarness = test_support.Harness;
const makeRequest = test_support.makeRequest;
const freeResponse = test_support.freeResponse;
const expectJsonContains = test_support.expectJsonContains;
const expectResponseOk = test_support.expectResponseOk;

fn formatAppsResponse(alloc: std.mem.Allocator, db: *sqlite.Db, latest_deployments: []const store.DeploymentRecord) ![]u8 {
    return app_route_responses.formatApps(alloc, db, latest_deployments);
}

fn formatAppHistoryResponse(alloc: std.mem.Allocator, deployments: []const store.DeploymentRecord) ![]u8 {
    return app_route_responses.formatHistory(alloc, deployments);
}

fn formatAppStatusResponse(
    alloc: std.mem.Allocator,
    report: apply_release.ApplyReport,
    previous_successful: ?apply_release.ApplyReport,
    summary: app_snapshot.Summary,
    training_summary: store.TrainingJobSummary,
) ![]u8 {
    return app_route_responses.formatStatus(alloc, report, previous_successful, summary, training_summary);
}

test "formatAppHistoryResponse emits release records" {
    const alloc = std.testing.allocator;
    const deployments = [_]store.DeploymentRecord{
        .{
            .id = "dep-2",
            .app_name = "demo-app",
            .service_name = "demo-app",
            .manifest_hash = "sha256:222",
            .config_snapshot = "{}",
            .status = "failed",
            .message = "placement failed",
            .created_at = 200,
        },
        .{
            .id = "dep-1",
            .app_name = "demo-app",
            .service_name = "demo-app",
            .manifest_hash = "sha256:111",
            .config_snapshot = "{}",
            .status = "completed",
            .message = null,
            .created_at = 100,
        },
    };

    const json = try formatAppHistoryResponse(alloc, &deployments);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"app\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"apply\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_release_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":\"placement failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"message\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release\":{\"id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"workloads\":{\"services\":0,\"workers\":0,\"crons\":0,\"training_jobs\":0}") != null);
}

test "formatAppStatusResponse summarizes latest release" {
    const alloc = std.testing.allocator;
    const latest = store.DeploymentRecord{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"},{\"name\":\"db\"}]}",
        .status = "completed",
        .message = null,
        .created_at = 200,
    };

    const json = try formatAppStatusResponse(alloc, apply_release.reportFromDeployment(latest), null, app_snapshot.summarize(latest.config_snapshot), .{});
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"apply\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"service_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"completed_targets\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed_targets\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"remaining_targets\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_release_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"previous_successful_release_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"current_release\":{\"id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"workloads\":{\"services\":2,\"workers\":0,\"crons\":0,\"training_jobs\":0}") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"training_runtime\":{\"active\":0,\"paused\":0,\"failed\":0}") != null);
}

test "formatAppsResponse emits one latest summary per app" {
    const alloc = std.testing.allocator;

    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try store.saveDeploymentInDb(&db, .{
        .id = "dep-1",
        .app_name = "app-a",
        .service_name = "app-a",
        .trigger = "apply",
        .manifest_hash = "sha256:a1",
        .config_snapshot = "{\"app_name\":\"app-a\",\"services\":[{\"name\":\"web\"}],\"workers\":[],\"crons\":[],\"training_jobs\":[]}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 100,
    });
    try store.saveDeploymentInDb(&db, .{
        .id = "dep-2",
        .app_name = "app-b",
        .service_name = "app-b",
        .trigger = "apply",
        .manifest_hash = "sha256:b1",
        .config_snapshot = "{\"app_name\":\"app-b\",\"services\":[{\"name\":\"api\"}],\"workers\":[],\"crons\":[],\"training_jobs\":[]}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 150,
    });
    try store.saveDeploymentInDb(&db, .{
        .id = "dep-3",
        .app_name = "app-a",
        .service_name = "app-a",
        .trigger = "apply",
        .manifest_hash = "sha256:a2",
        .config_snapshot = "{\"app_name\":\"app-a\",\"services\":[{\"name\":\"web\"},{\"name\":\"db\"}],\"workers\":[{\"name\":\"migrate\"}],\"crons\":[{\"name\":\"nightly\"}],\"training_jobs\":[{\"name\":\"finetune\"}]}",
        .status = "failed",
        .message = "scheduler error during apply",
        .created_at = 200,
    });
    try store.saveTrainingJobInDb(&db, .{
        .id = "job-1",
        .name = "finetune-a",
        .app_name = "app-a",
        .state = "running",
        .image = "trainer:v1",
        .gpus = 1,
        .checkpoint_path = null,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = 0,
        .created_at = 210,
        .updated_at = 210,
    });
    try store.saveTrainingJobInDb(&db, .{
        .id = "job-2",
        .name = "finetune-b",
        .app_name = "app-a",
        .state = "paused",
        .image = "trainer:v1",
        .gpus = 1,
        .checkpoint_path = null,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = 0,
        .created_at = 220,
        .updated_at = 220,
    });
    try store.saveTrainingJobInDb(&db, .{
        .id = "job-3",
        .name = "finetune-c",
        .app_name = "app-a",
        .state = "failed",
        .image = "trainer:v1",
        .gpus = 1,
        .checkpoint_path = null,
        .checkpoint_interval = null,
        .checkpoint_keep = null,
        .restart_count = 0,
        .created_at = 230,
        .updated_at = 230,
    });

    var latest = try store.listLatestDeploymentsByAppInDb(&db, alloc);
    defer {
        for (latest.items) |dep| dep.deinit(alloc);
        latest.deinit(alloc);
    }

    const json = try formatAppsResponse(alloc, &db, latest.items);
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"app-a\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"dep-3\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"previous_successful_release_id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"worker_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"cron_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"training_job_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"active_training_jobs\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"paused_training_jobs\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"failed_training_jobs\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"app_name\":\"app-b\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"release_id\":\"dep-2\"") != null);
}

test "formatAppsResponse returns empty array when no app releases exist" {
    const alloc = std.testing.allocator;

    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const json = try formatAppsResponse(alloc, &db, &.{});
    defer alloc.free(json);

    try std.testing.expectEqualStrings("[]", json);
}

test "handleRolloutControl updates the active release state" {
    const alloc = std.testing.allocator;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    try store.saveDeploymentInDb(harness.node.stateMachineDb(), .{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "in_progress",
        .message = "apply in progress",
        .created_at = 100,
        .rollout_control_state = "active",
    });

    const pause_response = try harness.rolloutControl("demo-app", "pause");
    defer freeResponse(alloc, pause_response);
    try expectResponseOk(pause_response);
    try expectJsonContains(pause_response.body, "\"rollout_control_state\":\"paused\"");
    {
        const active = try store.getActiveDeploymentByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
        defer active.deinit(alloc);
        try std.testing.expectEqualStrings("paused", active.rollout_control_state.?);
    }

    const resume_response = try harness.rolloutControl("demo-app", "resume");
    defer freeResponse(alloc, resume_response);
    try expectResponseOk(resume_response);
    try expectJsonContains(resume_response.body, "\"rollout_control_state\":\"active\"");
    {
        const active = try store.getActiveDeploymentByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
        defer active.deinit(alloc);
        try std.testing.expectEqualStrings("active", active.rollout_control_state.?);
    }

    const cancel_response = try harness.rolloutControl("demo-app", "cancel");
    defer freeResponse(alloc, cancel_response);
    try expectResponseOk(cancel_response);
    try expectJsonContains(cancel_response.body, "\"rollout_control_state\":\"cancel_requested\"");
    {
        const active = try store.getActiveDeploymentByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
        defer active.deinit(alloc);
        try std.testing.expectEqualStrings("cancel_requested", active.rollout_control_state.?);
    }
}

test "handleRolloutControl resumes a paused stored rollout when no executor is active" {
    const alloc = std.testing.allocator;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    try store.saveDeploymentInDb(harness.node.stateMachineDb(), .{
        .id = "dep-paused",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:paused",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\",\"image\":\"alpine\",\"command\":[\"echo\",\"hello\"]}]}",
        .completed_targets = 0,
        .failed_targets = 0,
        .status = "in_progress",
        .message = "apply in progress",
        .rollout_checkpoint_json = "{\"engine\":\"cluster\",\"phase\":\"cutover\",\"batch_start\":0,\"batch_end\":1,\"total_targets\":1,\"completed_targets\":0,\"failed_targets\":0,\"remaining_targets\":1,\"control_state\":\"paused\"}",
        .rollout_control_state = "paused",
        .created_at = 100,
    });

    const response = try harness.rolloutControl("demo-app", "resume");
    defer freeResponse(alloc, response);
    try expectResponseOk(response);
    try expectJsonContains(response.body, "\"status\":\"completed\"");
    try expectJsonContains(response.body, "\"release_id\":\"dep-paused\"");

    const old_dep = try store.getDeploymentInDb(harness.node.stateMachineDb(), alloc, "dep-paused");
    defer old_dep.deinit(alloc);
    try std.testing.expectEqualStrings("completed", old_dep.status);
    try std.testing.expect(old_dep.superseded_by_release_id == null);

    const latest = try store.getLatestDeploymentByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer latest.deinit(alloc);
    try std.testing.expect(std.mem.eql(u8, latest.id, "dep-paused"));
    try std.testing.expectEqualStrings("completed", latest.status);
    try std.testing.expect(latest.resumed_from_release_id == null);
}

test "recoverActiveClusterRolloutsOnce resumes active stored rollout in place" {
    const alloc = std.testing.allocator;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    try store.saveDeploymentInDb(harness.node.stateMachineDb(), .{
        .id = "dep-active",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:active",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\",\"image\":\"alpine\",\"command\":[\"echo\",\"hello\"]}]}",
        .completed_targets = 0,
        .failed_targets = 0,
        .status = "in_progress",
        .message = "apply in progress",
        .rollout_checkpoint_json = "{\"engine\":\"cluster\",\"phase\":\"cutover\",\"batch_start\":0,\"batch_end\":1,\"total_targets\":1,\"completed_targets\":0,\"failed_targets\":0,\"remaining_targets\":1,\"control_state\":\"active\"}",
        .rollout_control_state = "active",
        .created_at = 100,
    });

    const recovered = try recoverActiveClusterRolloutsOnce(alloc, .{ .cluster = harness.node, .join_token = null });
    try std.testing.expectEqual(@as(usize, 1), recovered);

    const latest = try store.getLatestDeploymentByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer latest.deinit(alloc);
    try std.testing.expectEqualStrings("dep-active", latest.id);
    try std.testing.expectEqualStrings("completed", latest.status);
    try std.testing.expect(latest.resumed_from_release_id == null);
    try std.testing.expect(latest.superseded_by_release_id == null);
}

test "paused rollout control stays coherent across apps status history and resume" {
    const alloc = std.testing.allocator;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    try store.saveDeploymentInDb(harness.node.stateMachineDb(), .{
        .id = "dep-paused",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:paused",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\",\"image\":\"alpine\",\"command\":[\"echo\",\"hello\"]}],\"workers\":[{\"name\":\"migrate\",\"image\":\"postgres:16\",\"command\":[\"sh\",\"-c\",\"psql -f /m.sql\"]}],\"crons\":[],\"training_jobs\":[]}",
        .completed_targets = 0,
        .failed_targets = 0,
        .status = "in_progress",
        .message = "apply in progress",
        .rollout_targets_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"pending\",\"reason\":null}]",
        .rollout_checkpoint_json = "{\"engine\":\"cluster\",\"phase\":\"cutover\",\"batch_start\":0,\"batch_end\":1,\"total_targets\":1,\"completed_targets\":0,\"failed_targets\":0,\"remaining_targets\":1,\"control_state\":\"paused\"}",
        .rollout_control_state = "paused",
        .created_at = 100,
    });

    const apps_before = harness.listApps();
    defer freeResponse(alloc, apps_before);
    try expectResponseOk(apps_before);
    try expectJsonContains(apps_before.body, "\"release_id\":\"dep-paused\"");
    try expectJsonContains(apps_before.body, "\"rollout_state\":\"blocked\"");
    try expectJsonContains(apps_before.body, "\"rollout_control_state\":\"paused\"");

    const status_before = harness.status("demo-app");
    defer freeResponse(alloc, status_before);
    try expectResponseOk(status_before);
    try expectJsonContains(status_before.body, "\"release_id\":\"dep-paused\"");
    try expectJsonContains(status_before.body, "\"rollout_state\":\"blocked\"");
    try expectJsonContains(status_before.body, "\"rollout_control_state\":\"paused\"");
    try expectJsonContains(status_before.body, "\"worker_count\":1");

    const history_before = harness.history("demo-app");
    defer freeResponse(alloc, history_before);
    try expectResponseOk(history_before);
    try expectJsonContains(history_before.body, "\"id\":\"dep-paused\"");
    try expectJsonContains(history_before.body, "\"rollout_state\":\"blocked\"");
    try expectJsonContains(history_before.body, "\"rollout_control_state\":\"paused\"");

    const resume_response = try harness.rolloutControl("demo-app", "resume");
    defer freeResponse(alloc, resume_response);
    try expectResponseOk(resume_response);
    try expectJsonContains(resume_response.body, "\"release_id\":\"dep-paused\"");
    try expectJsonContains(resume_response.body, "\"status\":\"completed\"");
    try expectJsonContains(resume_response.body, "\"rollout_control_state\":\"active\"");

    const apps_after = harness.listApps();
    defer freeResponse(alloc, apps_after);
    try expectResponseOk(apps_after);
    try expectJsonContains(apps_after.body, "\"release_id\":\"dep-paused\"");
    try expectJsonContains(apps_after.body, "\"status\":\"completed\"");
    try expectJsonContains(apps_after.body, "\"rollout_control_state\":\"active\"");

    const status_after = harness.status("demo-app");
    defer freeResponse(alloc, status_after);
    try expectResponseOk(status_after);
    try expectJsonContains(status_after.body, "\"release_id\":\"dep-paused\"");
    try expectJsonContains(status_after.body, "\"status\":\"completed\"");
    try expectJsonContains(status_after.body, "\"rollout_state\":\"stable\"");
    try expectJsonContains(status_after.body, "\"rollout_control_state\":\"active\"");

    const history_after = harness.history("demo-app");
    defer freeResponse(alloc, history_after);
    try expectResponseOk(history_after);
    try expectJsonContains(history_after.body, "\"id\":\"dep-paused\"");
    try expectJsonContains(history_after.body, "\"status\":\"completed\"");
    try expectJsonContains(history_after.body, "\"rollout_control_state\":\"active\"");
}

test "formatAppStatusResponse includes structured rollback metadata" {
    const alloc = std.testing.allocator;
    const latest = store.DeploymentRecord{
        .id = "dep-3",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "rollback",
        .source_release_id = "dep-1",
        .manifest_hash = "sha256:333",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .completed_targets = 1,
        .failed_targets = 0,
        .status = "completed",
        .message = "rollback to dep-1 completed: all placements succeeded",
        .rollout_checkpoint_json = "{\"engine\":\"cluster\",\"phase\":\"cutover\",\"batch_start\":0,\"batch_end\":1,\"total_targets\":1,\"completed_targets\":1,\"failed_targets\":0,\"remaining_targets\":0,\"control_state\":\"active\"}",
        .created_at = 300,
    };

    const json = try formatAppStatusResponse(alloc, apply_release.reportFromDeployment(latest), null, app_snapshot.summarize(latest.config_snapshot), .{});
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"rollback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_release_id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"completed_targets\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"remaining_targets\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_checkpoint\":{\"engine\":\"cluster\",\"phase\":\"cutover\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"checkpoint\":{\"engine\":\"cluster\",\"phase\":\"cutover\"") != null);
}

test "formatAppStatusResponse shows blocked rollout state for paused releases" {
    const alloc = std.testing.allocator;
    const latest = store.DeploymentRecord{
        .id = "dep-pause",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:pause",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .completed_targets = 0,
        .failed_targets = 0,
        .status = "in_progress",
        .message = "apply in progress",
        .rollout_control_state = "paused",
        .created_at = 350,
    };

    const json = try formatAppStatusResponse(alloc, apply_release.reportFromDeployment(latest), null, app_snapshot.summarize(latest.config_snapshot), .{});
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_state\":\"blocked\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"rollout_control_state\":\"paused\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"control_state\":\"paused\"") != null);
}

test "formatAppStatusResponse falls back to rollback metadata inferred from legacy message" {
    const alloc = std.testing.allocator;
    const latest = store.DeploymentRecord{
        .id = "dep-4",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .manifest_hash = "sha256:444",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "completed",
        .message = "rollback to dep-1 completed: all placements succeeded",
        .created_at = 400,
    };

    const json = try formatAppStatusResponse(alloc, apply_release.reportFromDeployment(latest), null, app_snapshot.summarize(latest.config_snapshot), .{});
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"trigger\":\"rollback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"source_release_id\":\"dep-1\"") != null);
}

test "app status and history surface rollback release metadata from persisted rows" {
    const alloc = std.testing.allocator;

    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try store.saveDeploymentInDb(&db, .{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 100,
    });
    try store.saveDeploymentInDb(&db, .{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "rollback",
        .source_release_id = "dep-1",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "completed",
        .message = "rollback to dep-1 completed: all placements succeeded",
        .created_at = 200,
    });

    var deployments = try store.listDeploymentsByAppInDb(&db, alloc, "demo-app");
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    const history_json = try formatAppHistoryResponse(alloc, deployments.items);
    defer alloc.free(history_json);

    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"trigger\":\"rollback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"source_release_id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"trigger\":\"apply\"") != null);

    const latest = try store.getLatestDeploymentByAppInDb(&db, alloc, "demo-app");
    defer latest.deinit(alloc);

    const previous_successful = try store.getPreviousSuccessfulDeploymentByAppInDb(&db, alloc, "demo-app", latest.id);
    defer previous_successful.deinit(alloc);

    const status_json = try formatAppStatusResponse(
        alloc,
        apply_release.reportFromDeployment(latest),
        apply_release.reportFromDeployment(previous_successful),
        app_snapshot.summarize(latest.config_snapshot),
        .{},
    );
    defer alloc.free(status_json);

    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"release_id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"trigger\":\"rollback\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"source_release_id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"previous_successful_release_id\":\"dep-1\"") != null);
}

test "app status and history surface failed apply metadata from persisted rows" {
    const alloc = std.testing.allocator;

    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try store.saveDeploymentInDb(&db, .{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "completed",
        .message = "apply completed",
        .created_at = 100,
    });
    try store.saveDeploymentInDb(&db, .{
        .id = "dep-2",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:222",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"},{\"name\":\"db\"}]}",
        .status = "failed",
        .message = "scheduler error during apply",
        .created_at = 200,
    });

    var deployments = try store.listDeploymentsByAppInDb(&db, alloc, "demo-app");
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    const history_json = try formatAppHistoryResponse(alloc, deployments.items);
    defer alloc.free(history_json);

    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"trigger\":\"apply\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"status\":\"failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"source_release_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"message\":\"scheduler error during apply\"") != null);

    const latest = try store.getLatestDeploymentByAppInDb(&db, alloc, "demo-app");
    defer latest.deinit(alloc);

    const previous_successful = try store.getPreviousSuccessfulDeploymentByAppInDb(&db, alloc, "demo-app", latest.id);
    defer previous_successful.deinit(alloc);

    const status_json = try formatAppStatusResponse(
        alloc,
        apply_release.reportFromDeployment(latest),
        apply_release.reportFromDeployment(previous_successful),
        app_snapshot.summarize(latest.config_snapshot),
        .{},
    );
    defer alloc.free(status_json);

    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"release_id\":\"dep-2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"trigger\":\"apply\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"status\":\"failed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"service_count\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"source_release_id\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"previous_successful_release_id\":\"dep-1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"message\":\"scheduler error during apply\"") != null);
}

test "app status and history preserve exact cluster failure reasons from persisted rows" {
    const alloc = std.testing.allocator;

    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try store.saveDeploymentInDb(&db, .{
        .id = "dep-1",
        .app_name = "demo-app",
        .service_name = "demo-app",
        .trigger = "apply",
        .manifest_hash = "sha256:111",
        .config_snapshot = "{\"app_name\":\"demo-app\",\"services\":[{\"name\":\"web\"}]}",
        .status = "failed",
        .message = "one or more rollout targets failed readiness checks",
        .failure_details_json = "[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"reason\":\"image_pull_failed\"}]",
        .created_at = 100,
    });

    var deployments = try store.listDeploymentsByAppInDb(&db, alloc, "demo-app");
    defer {
        for (deployments.items) |dep| dep.deinit(alloc);
        deployments.deinit(alloc);
    }

    const history_json = try formatAppHistoryResponse(alloc, deployments.items);
    defer alloc.free(history_json);

    try std.testing.expect(std.mem.indexOf(u8, history_json, "\"reason\":\"image_pull_failed\"") != null);

    const latest = try store.getLatestDeploymentByAppInDb(&db, alloc, "demo-app");
    defer latest.deinit(alloc);

    const status_json = try formatAppStatusResponse(
        alloc,
        apply_release.reportFromDeployment(latest),
        null,
        app_snapshot.summarize(latest.config_snapshot),
        .{},
    );
    defer alloc.free(status_json);

    try std.testing.expect(std.mem.indexOf(u8, status_json, "\"reason\":\"image_pull_failed\"") != null);
}

test "app apply then rollback routes preserve release transition metadata" {
    const alloc = std.testing.allocator;
    const apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"alpine","command":["echo","hello"]}]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const apply_response = harness.appApply(apply_body);
    defer freeResponse(alloc, apply_response);

    try expectResponseOk(apply_response);
    try expectJsonContains(apply_response.body, "\"trigger\":\"apply\"");

    const source_release_id = json_helpers.extractJsonString(apply_response.body, "release_id").?;

    const rollback_response = try harness.rollback("demo-app", source_release_id);
    defer freeResponse(alloc, rollback_response);

    try expectResponseOk(rollback_response);
    try expectJsonContains(rollback_response.body, "\"trigger\":\"rollback\"");
    try expectJsonContains(rollback_response.body, "\"source_release_id\":\"");
    try expectJsonContains(rollback_response.body, source_release_id);

    const latest = try store.getLatestDeploymentByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer latest.deinit(alloc);

    try std.testing.expectEqualStrings("rollback", latest.trigger.?);
    try std.testing.expectEqualStrings(source_release_id, latest.source_release_id.?);

    const status_response = harness.status("demo-app");
    defer freeResponse(alloc, status_response);

    try expectResponseOk(status_response);
    try expectJsonContains(status_response.body, "\"trigger\":\"rollback\"");
    try expectJsonContains(status_response.body, "\"source_release_id\":\"");
    try expectJsonContains(status_response.body, source_release_id);

    const history_response = harness.history("demo-app");
    defer freeResponse(alloc, history_response);

    try expectResponseOk(history_response);
    try expectJsonContains(history_response.body, "\"trigger\":\"rollback\"");
    try expectJsonContains(history_response.body, "\"source_release_id\":\"");
    try expectJsonContains(history_response.body, source_release_id);
}

test "app rollback defaults to the previous successful release when release id is omitted" {
    const alloc = std.testing.allocator;
    const first_apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx:1","command":["echo","first"]}]}
    ;
    const second_apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx:2","command":["echo","second"]}]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const first_apply_response = harness.appApply(first_apply_body);
    defer freeResponse(alloc, first_apply_response);
    std.debug.print("first_apply_response={s}\n", .{first_apply_response.body});
    try expectResponseOk(first_apply_response);
    const source_release_id = json_helpers.extractJsonString(first_apply_response.body, "release_id").?;

    const second_apply_response = harness.appApply(second_apply_body);
    defer freeResponse(alloc, second_apply_response);
    try expectResponseOk(second_apply_response);

    const rollback_response = try harness.rollbackDefault("demo-app");
    defer freeResponse(alloc, rollback_response);
    try expectResponseOk(rollback_response);
    try expectJsonContains(rollback_response.body, "\"source_release_id\":\"");
    try expectJsonContains(rollback_response.body, source_release_id);

    const latest = try store.getLatestDeploymentByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer latest.deinit(alloc);
    try std.testing.expectEqualStrings("rollback", latest.trigger.?);
    try std.testing.expectEqualStrings(source_release_id, latest.source_release_id.?);
}

test "app rollback print returns the selected snapshot without creating a new release" {
    const alloc = std.testing.allocator;
    const first_apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx:1","command":["echo","first"]}]}
    ;
    const second_apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx:2","command":["echo","second"]}]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const first_apply_response = harness.appApply(first_apply_body);
    defer freeResponse(alloc, first_apply_response);
    try expectResponseOk(first_apply_response);

    const second_apply_response = harness.appApply(second_apply_body);
    defer freeResponse(alloc, second_apply_response);
    try expectResponseOk(second_apply_response);

    var before = try store.listDeploymentsByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer {
        for (before.items) |dep| dep.deinit(alloc);
        before.deinit(alloc);
    }

    const rollback_response = try harness.rollbackPrint("demo-app");
    defer freeResponse(alloc, rollback_response);
    try expectResponseOk(rollback_response);
    try std.testing.expect(std.mem.indexOf(u8, rollback_response.body, "\"image\":\"nginx:1\"") != null);

    var after = try store.listDeploymentsByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer {
        for (after.items) |dep| dep.deinit(alloc);
        after.deinit(alloc);
    }
    try std.testing.expectEqual(before.items.len, after.items.len);
}

test "app apply registers cluster cron schedules from snapshot" {
    const alloc = std.testing.allocator;
    const apply_body =
        \\{"app_name":"demo-app","services":[],"workers":[],"crons":[{"name":"nightly","image":"alpine","command":["/bin/sh","-c","echo cron"],"every":3600}],"training_jobs":[]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const apply_response = harness.appApply(apply_body);
    defer freeResponse(alloc, apply_response);

    try expectResponseOk(apply_response);
    try expectJsonContains(apply_response.body, "\"cron_count\":1");

    var schedules = try store.listCronSchedulesByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer {
        for (schedules.items) |schedule| schedule.deinit(alloc);
        schedules.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), schedules.items.len);
    try std.testing.expectEqualStrings("nightly", schedules.items[0].name);
    try std.testing.expectEqual(@as(i64, 3600), schedules.items[0].every);
}

test "app rollback restores worker and training workload snapshot" {
    const alloc = std.testing.allocator;
    const first_apply_body =
        \\{"app_name":"demo-app","services":[],"workers":[{"name":"migrate","image":"alpine","command":["/bin/sh","-c","echo first"]}],"crons":[],"training_jobs":[{"name":"finetune","image":"trainer:v1","command":["python","train.py"],"gpus":1}]}
    ;
    const second_apply_body =
        \\{"app_name":"demo-app","services":[],"workers":[{"name":"compact","image":"alpine","command":["/bin/sh","-c","echo second"]}],"crons":[{"name":"nightly","schedule":"0 2 * * *","command":["/bin/sh","-c","echo cron"]}],"training_jobs":[]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const first_apply_response = harness.appApply(first_apply_body);
    defer freeResponse(alloc, first_apply_response);
    try expectResponseOk(first_apply_response);

    const source_release_id = json_helpers.extractJsonString(first_apply_response.body, "release_id").?;

    const second_apply_response = harness.appApply(second_apply_body);
    defer freeResponse(alloc, second_apply_response);
    try expectResponseOk(second_apply_response);

    const rollback_response = try harness.rollback("demo-app", source_release_id);
    defer freeResponse(alloc, rollback_response);
    try expectResponseOk(rollback_response);

    const latest = try store.getLatestDeploymentByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer latest.deinit(alloc);

    try std.testing.expectEqualStrings("rollback", latest.trigger.?);
    try std.testing.expectEqualStrings(source_release_id, latest.source_release_id.?);
    try std.testing.expect(std.mem.indexOf(u8, latest.config_snapshot, "\"workers\":[{\"name\":\"migrate\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, latest.config_snapshot, "\"training_jobs\":[{\"name\":\"finetune\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, latest.config_snapshot, "\"crons\":[]") != null);

    var schedules = try store.listCronSchedulesByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer {
        for (schedules.items) |schedule| schedule.deinit(alloc);
        schedules.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 0), schedules.items.len);

    const status_response = harness.status("demo-app");
    defer freeResponse(alloc, status_response);
    try expectResponseOk(status_response);
    try expectJsonContains(status_response.body, "\"worker_count\":1");
    try expectJsonContains(status_response.body, "\"training_job_count\":1");
    try expectJsonContains(status_response.body, "\"cron_count\":0");
}

test "app rollback restores cluster cron schedules from selected release" {
    const alloc = std.testing.allocator;
    const first_apply_body =
        \\{"app_name":"demo-app","services":[],"workers":[],"crons":[{"name":"cleanup","image":"alpine","command":["/bin/sh","-c","echo first"],"every":60}],"training_jobs":[]}
    ;
    const second_apply_body =
        \\{"app_name":"demo-app","services":[],"workers":[],"crons":[{"name":"backup","image":"alpine","command":["/bin/sh","-c","echo second"],"every":3600}],"training_jobs":[]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const first_apply_response = harness.appApply(first_apply_body);
    defer freeResponse(alloc, first_apply_response);
    try expectResponseOk(first_apply_response);
    const source_release_id = json_helpers.extractJsonString(first_apply_response.body, "release_id").?;

    const second_apply_response = harness.appApply(second_apply_body);
    defer freeResponse(alloc, second_apply_response);
    try expectResponseOk(second_apply_response);

    const rollback_response = try harness.rollback("demo-app", source_release_id);
    defer freeResponse(alloc, rollback_response);
    try expectResponseOk(rollback_response);

    var schedules = try store.listCronSchedulesByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer {
        for (schedules.items) |schedule| schedule.deinit(alloc);
        schedules.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), schedules.items.len);
    try std.testing.expectEqualStrings("cleanup", schedules.items[0].name);
    try std.testing.expectEqual(@as(i64, 60), schedules.items[0].every);
}

test "remote app lifecycle keeps apps status and history coherent after mixed workload rollback" {
    const alloc = std.testing.allocator;
    const first_apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx:1","command":["echo","first"]}],"workers":[{"name":"migrate","image":"postgres:16","command":["sh","-c","psql -f /m.sql"]}],"crons":[{"name":"nightly","image":"alpine:3","command":["sh","-c","echo nightly"],"every":3600}],"training_jobs":[{"name":"finetune","image":"trainer:v1","command":["python","train.py"],"gpus":4,"gpu_type":"H100"}]}
    ;
    const second_apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"nginx:2","command":["echo","second"]}],"workers":[],"crons":[],"training_jobs":[]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const first_apply_response = harness.appApply(first_apply_body);
    defer freeResponse(alloc, first_apply_response);
    try expectResponseOk(first_apply_response);
    const source_release_id = json_helpers.extractJsonString(first_apply_response.body, "release_id").?;

    const second_apply_response = harness.appApply(second_apply_body);
    defer freeResponse(alloc, second_apply_response);
    try expectResponseOk(second_apply_response);
    const previous_successful_release_id = json_helpers.extractJsonString(second_apply_response.body, "release_id").?;

    const rollback_response = try harness.rollback("demo-app", source_release_id);
    defer freeResponse(alloc, rollback_response);
    try expectResponseOk(rollback_response);
    try expectJsonContains(rollback_response.body, "\"trigger\":\"rollback\"");
    try expectJsonContains(rollback_response.body, "\"source_release_id\":\"");
    try expectJsonContains(rollback_response.body, source_release_id);

    const apps_response = harness.listApps();
    defer freeResponse(alloc, apps_response);
    try expectResponseOk(apps_response);
    try expectJsonContains(apps_response.body, "\"app_name\":\"demo-app\"");
    try expectJsonContains(apps_response.body, "\"trigger\":\"rollback\"");
    try expectJsonContains(apps_response.body, "\"worker_count\":1");
    try expectJsonContains(apps_response.body, "\"cron_count\":1");
    try expectJsonContains(apps_response.body, "\"training_job_count\":1");
    try expectJsonContains(apps_response.body, "\"previous_successful_release_id\":\"");
    try expectJsonContains(apps_response.body, previous_successful_release_id);

    const status_response = harness.status("demo-app");
    defer freeResponse(alloc, status_response);
    try expectResponseOk(status_response);
    try expectJsonContains(status_response.body, "\"release_id\":\"");
    try expectJsonContains(status_response.body, "\"trigger\":\"rollback\"");
    try expectJsonContains(status_response.body, "\"source_release_id\":\"");
    try expectJsonContains(status_response.body, source_release_id);
    try expectJsonContains(status_response.body, "\"worker_count\":1");
    try expectJsonContains(status_response.body, "\"cron_count\":1");
    try expectJsonContains(status_response.body, "\"training_job_count\":1");
    try expectJsonContains(status_response.body, "\"previous_successful_release_id\":\"");
    try expectJsonContains(status_response.body, previous_successful_release_id);

    const history_response = harness.history("demo-app");
    defer freeResponse(alloc, history_response);
    try expectResponseOk(history_response);
    try expectJsonContains(history_response.body, "\"id\":\"");
    try expectJsonContains(history_response.body, "\"trigger\":\"rollback\"");
    try expectJsonContains(history_response.body, "\"source_release_id\":\"");
    try expectJsonContains(history_response.body, source_release_id);
    try expectJsonContains(history_response.body, "\"id\":\"");
    try expectJsonContains(history_response.body, previous_successful_release_id);
    try expectJsonContains(history_response.body, "\"previous_successful\":true");

    const latest = try store.getLatestDeploymentByAppInDb(harness.node.stateMachineDb(), alloc, "demo-app");
    defer latest.deinit(alloc);
    try std.testing.expectEqualStrings("rollback", latest.trigger.?);
    try std.testing.expectEqualStrings(source_release_id, latest.source_release_id.?);
    try std.testing.expect(std.mem.indexOf(u8, latest.config_snapshot, "\"workers\":[{\"name\":\"migrate\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, latest.config_snapshot, "\"crons\":[{\"name\":\"nightly\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, latest.config_snapshot, "\"training_jobs\":[{\"name\":\"finetune\"") != null);
}

test "app apply route preserves failed release metadata across reads" {
    const alloc = std.testing.allocator;
    const apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"alpine","command":["echo","hello"],"cpu_limit":999999,"memory_limit_mb":999999}]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const apply_response = harness.appApply(apply_body);
    defer freeResponse(alloc, apply_response);

    try expectResponseOk(apply_response);
    try expectJsonContains(apply_response.body, "\"trigger\":\"apply\"");
    try expectJsonContains(apply_response.body, "\"status\":\"failed\"");
    try expectJsonContains(apply_response.body, "\"failed\":1");
    try expectJsonContains(apply_response.body, "\"source_release_id\":null");
    try expectJsonContains(apply_response.body, "\"message\":\"one or more placements failed\"");

    const release_id = json_helpers.extractJsonString(apply_response.body, "release_id").?;

    const status_response = harness.status("demo-app");
    defer freeResponse(alloc, status_response);

    try expectResponseOk(status_response);
    try expectJsonContains(status_response.body, "\"release_id\":\"");
    try expectJsonContains(status_response.body, release_id);
    try expectJsonContains(status_response.body, "\"trigger\":\"apply\"");
    try expectJsonContains(status_response.body, "\"status\":\"failed\"");
    try expectJsonContains(status_response.body, "\"source_release_id\":null");
    try expectJsonContains(status_response.body, "\"message\":\"one or more placements failed\"");

    const history_response = harness.history("demo-app");
    defer freeResponse(alloc, history_response);

    try expectResponseOk(history_response);
    try expectJsonContains(history_response.body, "\"id\":\"");
    try expectJsonContains(history_response.body, release_id);
    try expectJsonContains(history_response.body, "\"trigger\":\"apply\"");
    try expectJsonContains(history_response.body, "\"status\":\"failed\"");
    try expectJsonContains(history_response.body, "\"source_release_id\":null");
    try expectJsonContains(history_response.body, "\"message\":\"one or more placements failed\"");
}

test "app apply route preserves partially failed release metadata across reads" {
    const alloc = std.testing.allocator;
    const apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"alpine","command":["echo","hello"]},{"name":"db","image":"alpine","command":["echo","db"],"cpu_limit":999999,"memory_limit_mb":999999}]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const apply_response = harness.appApply(apply_body);
    defer freeResponse(alloc, apply_response);

    try expectResponseOk(apply_response);
    try expectJsonContains(apply_response.body, "\"trigger\":\"apply\"");
    try expectJsonContains(apply_response.body, "\"status\":\"partially_failed\"");
    try expectJsonContains(apply_response.body, "\"placed\":1");
    try expectJsonContains(apply_response.body, "\"failed\":1");
    try expectJsonContains(apply_response.body, "\"source_release_id\":null");
    try expectJsonContains(apply_response.body, "\"message\":\"one or more placements failed\"");
    try expectJsonContains(apply_response.body, "\"rollout_targets\":[");
    try expectJsonContains(apply_response.body, "\"workload_name\":\"web\",\"state\":\"ready\"");
    try expectJsonContains(apply_response.body, "\"workload_name\":\"db\",\"state\":\"failed\",\"reason\":\"placement_failed\"");

    const release_id = json_helpers.extractJsonString(apply_response.body, "release_id").?;

    const status_response = harness.status("demo-app");
    defer freeResponse(alloc, status_response);

    try expectResponseOk(status_response);
    try expectJsonContains(status_response.body, "\"release_id\":\"");
    try expectJsonContains(status_response.body, release_id);
    try expectJsonContains(status_response.body, "\"trigger\":\"apply\"");
    try expectJsonContains(status_response.body, "\"status\":\"partially_failed\"");
    try expectJsonContains(status_response.body, "\"source_release_id\":null");
    try expectJsonContains(status_response.body, "\"message\":\"one or more placements failed\"");
    try expectJsonContains(status_response.body, "\"rollout_targets\":[");
    try expectJsonContains(status_response.body, "\"workload_name\":\"web\",\"state\":\"ready\"");
    try expectJsonContains(status_response.body, "\"workload_name\":\"db\",\"state\":\"failed\",\"reason\":\"placement_failed\"");

    const history_response = harness.history("demo-app");
    defer freeResponse(alloc, history_response);

    try expectResponseOk(history_response);
    try expectJsonContains(history_response.body, "\"id\":\"");
    try expectJsonContains(history_response.body, release_id);
    try expectJsonContains(history_response.body, "\"trigger\":\"apply\"");
    try expectJsonContains(history_response.body, "\"status\":\"partially_failed\"");
    try expectJsonContains(history_response.body, "\"source_release_id\":null");
    try expectJsonContains(history_response.body, "\"message\":\"one or more placements failed\"");
    try expectJsonContains(history_response.body, "\"rollout_targets\":[");
    try expectJsonContains(history_response.body, "\"workload_name\":\"web\",\"state\":\"ready\"");
    try expectJsonContains(history_response.body, "\"workload_name\":\"db\",\"state\":\"failed\",\"reason\":\"placement_failed\"");
}

test "partial failure stays coherent across apps status and history with exact reasons" {
    const alloc = std.testing.allocator;
    const apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"alpine","command":["echo","hello"]},{"name":"db","image":"alpine","command":["echo","db"],"cpu_limit":999999,"memory_limit_mb":999999}],"workers":[{"name":"migrate","image":"postgres:16","command":["sh","-c","psql -f /m.sql"]}],"crons":[{"name":"nightly","image":"alpine:3","command":["sh","-c","echo nightly"],"every":3600}],"training_jobs":[{"name":"finetune","image":"trainer:v1","command":["python","train.py"],"gpus":4,"gpu_type":"H100"}]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const apply_response = harness.appApply(apply_body);
    defer freeResponse(alloc, apply_response);

    try expectResponseOk(apply_response);
    try expectJsonContains(apply_response.body, "\"status\":\"partially_failed\"");
    try expectJsonContains(apply_response.body, "\"rollout_state\":\"degraded\"");
    try expectJsonContains(apply_response.body, "\"failed_targets\":1");
    try expectJsonContains(apply_response.body, "\"reason\":\"placement_failed\"");

    const release_id = json_helpers.extractJsonString(apply_response.body, "release_id").?;

    const apps_response = harness.listApps();
    defer freeResponse(alloc, apps_response);
    try expectResponseOk(apps_response);
    try expectJsonContains(apps_response.body, "\"release_id\":\"");
    try expectJsonContains(apps_response.body, release_id);
    try expectJsonContains(apps_response.body, "\"status\":\"partially_failed\"");
    try expectJsonContains(apps_response.body, "\"rollout_state\":\"degraded\"");
    try expectJsonContains(apps_response.body, "\"worker_count\":1");
    try expectJsonContains(apps_response.body, "\"cron_count\":1");
    try expectJsonContains(apps_response.body, "\"training_job_count\":1");
    try expectJsonContains(apps_response.body, "\"failure_details\":[{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"reason\":\"placement_failed\"}]");

    const status_response = harness.status("demo-app");
    defer freeResponse(alloc, status_response);
    try expectResponseOk(status_response);
    try expectJsonContains(status_response.body, "\"release_id\":\"");
    try expectJsonContains(status_response.body, release_id);
    try expectJsonContains(status_response.body, "\"status\":\"partially_failed\"");
    try expectJsonContains(status_response.body, "\"rollout_state\":\"degraded\"");
    try expectJsonContains(status_response.body, "\"failure_details\":[{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"reason\":\"placement_failed\"}]");
    try expectJsonContains(status_response.body, "\"workload_name\":\"db\",\"state\":\"failed\",\"reason\":\"placement_failed\"");

    const history_response = harness.history("demo-app");
    defer freeResponse(alloc, history_response);
    try expectResponseOk(history_response);
    try expectJsonContains(history_response.body, "\"id\":\"");
    try expectJsonContains(history_response.body, release_id);
    try expectJsonContains(history_response.body, "\"status\":\"partially_failed\"");
    try expectJsonContains(history_response.body, "\"rollout_state\":\"degraded\"");
    try expectJsonContains(history_response.body, "\"failure_details\":[{\"workload_kind\":\"service\",\"workload_name\":\"db\",\"reason\":\"placement_failed\"}]");
    try expectJsonContains(history_response.body, "\"workload_name\":\"db\",\"state\":\"failed\",\"reason\":\"placement_failed\"");
}

test "readiness-gated apply keeps prior assignments when cutover fails" {
    const alloc = std.testing.allocator;
    const apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"alpine","command":["echo","hello"],"rollout":{"health_check_timeout":1}}]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    harness.node.stateMachineDb().exec(
        "INSERT INTO assignments (id, agent_id, image, status, created_at, app_name, workload_kind, workload_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "old-web", "abc123def456", "alpine", "running", @as(i64, 1), "demo-app", "service", "web" },
    ) catch return error.SkipZigTest;

    const before = try agent_registry.countAssignmentsForWorkload(harness.node.stateMachineDb(), "demo-app", "service", "web");
    try std.testing.expectEqual(@as(usize, 1), before);

    const apply_response = harness.appApply(apply_body);
    defer freeResponse(alloc, apply_response);

    try expectResponseOk(apply_response);
    try expectJsonContains(apply_response.body, "\"status\":\"failed\"");
    try expectJsonContains(apply_response.body, "\"message\":\"one or more rollout targets failed readiness checks\"");
    try expectJsonContains(
        apply_response.body,
        "\"failure_details\":[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"reason\":\"assignment_missing\"}]",
    );
    try expectJsonContains(
        apply_response.body,
        "\"rollout_targets\":[{\"workload_kind\":\"service\",\"workload_name\":\"web\",\"state\":\"failed\",\"reason\":\"assignment_missing\"}]",
    );

    const after = try agent_registry.countAssignmentsForWorkload(harness.node.stateMachineDb(), "demo-app", "service", "web");
    try std.testing.expectEqual(@as(usize, 1), after);

    const AssignmentRow = struct { id: sqlite.Text, status: sqlite.Text };
    const row = (try harness.node.stateMachineDb().oneAlloc(
        AssignmentRow,
        alloc,
        "SELECT id, status FROM assignments WHERE app_name = ? AND workload_kind = ? AND workload_name = ?;",
        .{},
        .{ "demo-app", "service", "web" },
    )).?;
    defer {
        alloc.free(row.id.data);
        alloc.free(row.status.data);
    }

    try std.testing.expectEqualStrings("old-web", row.id.data);
    try std.testing.expectEqualStrings("running", row.status.data);
}

test "app apply rejects invalid rollout config" {
    const alloc = std.testing.allocator;
    const apply_body =
        \\{"app_name":"demo-app","services":[{"name":"web","image":"alpine","command":["echo","hello"],"rollout":{"strategy":"burst"}}]}
    ;

    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();

    const response = harness.appApply(apply_body);
    defer freeResponse(alloc, response);

    try std.testing.expectEqual(http.StatusCode.bad_request, response.status);
    try expectJsonContains(response.body, "\"error\":\"invalid rollout config\"");
}

test "route rejects app rollback without cluster" {
    const body = "{\"release_id\":\"abc123def456\"}";
    const request = http.Request{
        .method = .POST,
        .path = "/apps/demo-app/rollback",
        .path_only = "/apps/demo-app/rollback",
        .query = "",
        .headers_raw = "",
        .body = body,
        .content_length = body.len,
    };
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };

    const response = route(request, std.testing.allocator, ctx).?;
    try std.testing.expectEqual(http.StatusCode.bad_request, response.status);
}
