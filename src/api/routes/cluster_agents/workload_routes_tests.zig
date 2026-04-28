const std = @import("std");
const sqlite = @import("sqlite");

const store = @import("../../../state/store.zig");
const http = @import("../../http.zig");
const test_support = @import("route_test_support.zig");
const workload_routes = @import("workload_routes.zig");

const RouteContext = test_support.RouteContext;

const route = workload_routes.route;
const setTestProxyTrainingLogsResponse = workload_routes.setTestProxyTrainingLogsResponse;
const clearTestProxyTrainingLogsResponse = workload_routes.clearTestProxyTrainingLogsResponse;
const RouteFlowHarness = test_support.Harness;
const makeRequest = test_support.makeRequestWithQuery;
const freeResponse = test_support.freeResponse;

fn countTrainingAssignments(db: *sqlite.Db, app_name: []const u8, job_name: []const u8) usize {
    const Row = struct { count: i64 };
    const row = (db.one(
        Row,
        "SELECT COUNT(*) AS count FROM assignments WHERE app_name = ? AND workload_kind = 'training' AND workload_name = ?;",
        .{},
        .{ app_name, job_name },
    ) catch unreachable) orelse unreachable;
    return @intCast(row.count);
}

fn updateHarnessAgentEndpoint(harness: *RouteFlowHarness, address: []const u8, port: u16) !void {
    harness.node.stateMachineDb().exec(
        "UPDATE agents SET address = ?, agent_api_port = ? WHERE id = ?;",
        .{},
        .{ address, @as(i64, port), "abc123def456" },
    ) catch return error.SkipZigTest;
}

fn clearHarnessAgentEndpoint(harness: *RouteFlowHarness) !void {
    harness.node.stateMachineDb().exec(
        "UPDATE agents SET agent_api_port = NULL WHERE id = ?;",
        .{},
        .{"abc123def456"},
    ) catch return error.SkipZigTest;
}

fn seedTrainingAssignment(harness: *RouteFlowHarness, app_name: []const u8, job_name: []const u8, rank: u32) !void {
    harness.node.stateMachineDb().exec(
        "INSERT INTO assignments (id, agent_id, image, command, status, app_name, workload_kind, workload_name, gang_rank, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{ "assign12345678", "abc123def456", "pytorch:latest", "python train.py", "running", app_name, "training", job_name, @as(i64, rank), @as(i64, 100) },
    ) catch return error.SkipZigTest;
}

test "route rejects worker run without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = makeRequest(.POST, "/apps/demo-app/workers/migrate/run", "", "");
    const resp = route(req, std.testing.allocator, ctx).?;
    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "route rejects training status without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = makeRequest(.GET, "/apps/demo-app/training/finetune/status", "", "");
    const resp = route(req, std.testing.allocator, ctx).?;
    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "worker run route schedules worker from latest app snapshot" {
    const alloc = std.testing.allocator;
    var harness = RouteFlowHarness.initWithRuntimeStore(alloc) catch return error.ProxyHarnessInitFailed;
    defer harness.deinit();

    try harness.seedLatestRelease(
        "demo-app",
        "{\"app_name\":\"demo-app\",\"services\":[],\"workers\":[{\"name\":\"migrate\",\"image\":\"alpine:latest\",\"command\":[\"/bin/sh\",\"-c\",\"echo ok\"],\"gpu_limit\":0,\"required_labels\":[]}],\"crons\":[],\"training_jobs\":[]}",
    );

    const resp = route(
        makeRequest(.POST, "/apps/demo-app/workers/migrate/run", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, resp);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"worker\":\"migrate\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"placed\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp.body, "\"failed\":0") != null);
}

test "training start and status routes persist job state from app snapshot" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    try harness.seedLatestRelease(
        "demo-app",
        "{\"app_name\":\"demo-app\",\"services\":[],\"workers\":[],\"crons\":[],\"training_jobs\":[{\"name\":\"finetune\",\"image\":\"pytorch:latest\",\"command\":[\"python\",\"train.py\"],\"gpus\":1,\"cpu_limit\":2000,\"memory_limit_mb\":4096}]}",
    );

    const start_resp = route(
        makeRequest(.POST, "/apps/demo-app/training/finetune/start", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, start_resp);

    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);
    try std.testing.expect(std.mem.indexOf(u8, start_resp.body, "\"app_name\":\"demo-app\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, start_resp.body, "\"training_job\":\"finetune\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, start_resp.body, "\"state\":\"running\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, start_resp.body, "\"gpus\":1") != null);

    const status_resp = route(
        makeRequest(.GET, "/apps/demo-app/training/finetune/status", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, status_resp);

    try std.testing.expectEqual(http.StatusCode.ok, status_resp.status);
    try std.testing.expect(std.mem.indexOf(u8, status_resp.body, "\"state\":\"running\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, status_resp.body, "\"training_job\":\"finetune\"") != null);
}

test "training start tags assignments with workload metadata" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    try harness.seedLatestRelease(
        "demo-app",
        "{\"app_name\":\"demo-app\",\"services\":[],\"workers\":[],\"crons\":[],\"training_jobs\":[{\"name\":\"finetune\",\"image\":\"pytorch:latest\",\"command\":[\"python\",\"train.py\"],\"gpus\":2,\"cpu_limit\":2000,\"memory_limit_mb\":4096}]}",
    );

    const start_resp = route(
        makeRequest(.POST, "/apps/demo-app/training/finetune/start", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, start_resp);
    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);
    harness.applyCommitted();
    try std.testing.expectEqual(@as(usize, 2), countTrainingAssignments(harness.node.stateMachineDb(), "demo-app", "finetune"));
}

test "training pause route clears scheduled assignments" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    try harness.seedLatestRelease(
        "demo-app",
        "{\"app_name\":\"demo-app\",\"services\":[],\"workers\":[],\"crons\":[],\"training_jobs\":[{\"name\":\"finetune\",\"image\":\"pytorch:latest\",\"command\":[\"python\",\"train.py\"],\"gpus\":2,\"cpu_limit\":2000,\"memory_limit_mb\":4096}]}",
    );

    const start_resp = route(
        makeRequest(.POST, "/apps/demo-app/training/finetune/start", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, start_resp);
    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);

    const pause_resp = route(
        makeRequest(.POST, "/apps/demo-app/training/finetune/pause", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, pause_resp);
    harness.applyCommitted();

    try std.testing.expectEqual(http.StatusCode.ok, pause_resp.status);
    try std.testing.expect(std.mem.indexOf(u8, pause_resp.body, "\"state\":\"paused\"") != null);
    try std.testing.expectEqual(@as(usize, 0), countTrainingAssignments(harness.node.stateMachineDb(), "demo-app", "finetune"));
}

test "training scale route replaces prior scheduled assignments" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    try harness.seedLatestRelease(
        "demo-app",
        "{\"app_name\":\"demo-app\",\"services\":[],\"workers\":[],\"crons\":[],\"training_jobs\":[{\"name\":\"finetune\",\"image\":\"pytorch:latest\",\"command\":[\"python\",\"train.py\"],\"gpus\":1,\"cpu_limit\":2000,\"memory_limit_mb\":4096}]}",
    );

    const start_resp = route(
        makeRequest(.POST, "/apps/demo-app/training/finetune/start", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, start_resp);
    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);

    const scale_resp = route(
        makeRequest(.POST, "/apps/demo-app/training/finetune/scale", "{\"gpus\":2}", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, scale_resp);
    harness.applyCommitted();

    try std.testing.expectEqual(http.StatusCode.ok, scale_resp.status);
    try std.testing.expect(std.mem.indexOf(u8, scale_resp.body, "\"state\":\"running\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, scale_resp.body, "\"gpus\":2") != null);
    try std.testing.expectEqual(@as(usize, 2), countTrainingAssignments(harness.node.stateMachineDb(), "demo-app", "finetune"));
}

test "training logs route reports remote-hosted ranks explicitly" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    try harness.seedLatestRelease(
        "demo-app",
        "{\"app_name\":\"demo-app\",\"services\":[],\"workers\":[],\"crons\":[],\"training_jobs\":[{\"name\":\"finetune\",\"image\":\"pytorch:latest\",\"command\":[\"python\",\"train.py\"],\"gpus\":1,\"cpu_limit\":2000,\"memory_limit_mb\":4096}]}",
    );

    const start_resp = route(
        makeRequest(.POST, "/apps/demo-app/training/finetune/start", "", ""),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, start_resp);
    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);
    harness.applyCommitted();

    const logs_resp = route(
        makeRequest(.GET, "/apps/demo-app/training/finetune/logs", "", "rank=0"),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, logs_resp);

    try std.testing.expectEqual(http.StatusCode.bad_request, logs_resp.status);
    try std.testing.expect(std.mem.indexOf(u8, logs_resp.body, "hosting agent") != null);
}

test "training logs route rejects invalid rank query" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    const logs_resp = route(
        makeRequest(.GET, "/apps/demo-app/training/finetune/logs", "", "rank=abc"),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, logs_resp);

    try std.testing.expectEqual(http.StatusCode.bad_request, logs_resp.status);
    try std.testing.expect(std.mem.indexOf(u8, logs_resp.body, "invalid rank") != null);
}

test "training logs route prefers local logs when available" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    try store.save(.{
        .id = "abc123def456",
        .rootfs = "/tmp/rootfs",
        .command = "python train.py",
        .hostname = "finetune-rank-0",
        .status = "running",
        .pid = null,
        .exit_code = null,
        .app_name = "demo-app",
        .created_at = 100,
    });
    var file = try @import("../../../runtime/logs.zig").createLogFile("abc123def456");
    try file.writeStreamingAll(std.Options.debug_io, "local rank logs\n");
    file.close(std.Options.debug_io);

    try seedTrainingAssignment(&harness, "demo-app", "finetune", 0);
    try clearHarnessAgentEndpoint(&harness);

    const logs_resp = route(
        makeRequest(.GET, "/apps/demo-app/training/finetune/logs", "", "rank=0"),
        alloc,
        harness.ctx(),
    ).?;
    defer freeResponse(alloc, logs_resp);

    try std.testing.expectEqual(http.StatusCode.ok, logs_resp.status);
    try std.testing.expectEqualStrings("local rank logs\n", logs_resp.body);
}

test "training logs route proxies logs from hosting agent" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    const app_name = "proxylogs-app";
    const job_name = "proxylogsjob";
    setTestProxyTrainingLogsResponse("/training/proxylogs-app/proxylogsjob/logs?rank=0", "proxied rank logs\n");
    defer clearTestProxyTrainingLogsResponse();

    try updateHarnessAgentEndpoint(&harness, "127.0.0.1", 41001);

    try harness.seedLatestRelease(
        app_name,
        "{\"app_name\":\"" ++ app_name ++ "\",\"services\":[],\"workers\":[],\"crons\":[],\"training_jobs\":[{\"name\":\"" ++ job_name ++ "\",\"image\":\"pytorch:latest\",\"command\":[\"python\",\"train.py\"],\"gpus\":1,\"cpu_limit\":2000,\"memory_limit_mb\":4096}]}",
    );

    const start_resp = route(
        makeRequest(.POST, "/apps/" ++ app_name ++ "/training/" ++ job_name ++ "/start", "", ""),
        alloc,
        .{ .cluster = harness.node, .join_token = "join-token" },
    ).?;
    defer freeResponse(alloc, start_resp);
    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);
    harness.applyCommitted();

    const logs_resp = route(
        makeRequest(.GET, "/apps/" ++ app_name ++ "/training/" ++ job_name ++ "/logs", "", "rank=0"),
        alloc,
        .{ .cluster = harness.node, .join_token = "join-token" },
    ).?;
    defer freeResponse(alloc, logs_resp);

    try std.testing.expectEqual(http.StatusCode.ok, logs_resp.status);
    try std.testing.expectEqualStrings("proxied rank logs\n", logs_resp.body);
}
