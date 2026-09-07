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
const expectJsonContains = test_support.expectJsonContains;

fn countTrainingAssignments(db: *sqlite.Db, app_name: []const u8, job_name: []const u8) !usize {
    const Row = struct { count: i64 };
    const row = try db.one(
        Row,
        "SELECT COUNT(*) AS count FROM assignments WHERE app_name = ? AND workload_kind = 'training' AND workload_name = ?;",
        .{},
        .{ app_name, job_name },
    ) orelse return error.TrainingAssignmentCountMissing;
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

    try harness.seedWorkerRelease("demo-app", "migrate");

    const resp = try harness.workerRun("demo-app", "migrate");
    defer freeResponse(alloc, resp);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try expectJsonContains(resp.body, "\"app_name\":\"demo-app\"");
    try expectJsonContains(resp.body, "\"worker\":\"migrate\"");
    try expectJsonContains(resp.body, "\"placed\":1");
    try expectJsonContains(resp.body, "\"failed\":0");
}

test "training start and status routes persist job state from app snapshot" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    try harness.seedTrainingRelease("demo-app", "finetune", 1);

    const start_resp = try harness.trainingStart("demo-app", "finetune");
    defer freeResponse(alloc, start_resp);

    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);
    try expectJsonContains(start_resp.body, "\"app_name\":\"demo-app\"");
    try expectJsonContains(start_resp.body, "\"training_job\":\"finetune\"");
    try expectJsonContains(start_resp.body, "\"state\":\"running\"");
    try expectJsonContains(start_resp.body, "\"gpus\":1");

    const status_resp = try harness.trainingStatus("demo-app", "finetune");
    defer freeResponse(alloc, status_resp);

    try std.testing.expectEqual(http.StatusCode.ok, status_resp.status);
    try expectJsonContains(status_resp.body, "\"state\":\"running\"");
    try expectJsonContains(status_resp.body, "\"training_job\":\"finetune\"");
}

test "training start tags assignments with workload metadata" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    try harness.seedTrainingRelease("demo-app", "finetune", 2);

    const start_resp = try harness.trainingStart("demo-app", "finetune");
    defer freeResponse(alloc, start_resp);
    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);
    harness.applyCommitted();
    try std.testing.expectEqual(@as(usize, 2), try countTrainingAssignments(harness.node.stateMachineDb(), "demo-app", "finetune"));
}

test "training pause route clears scheduled assignments" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    try harness.seedTrainingRelease("demo-app", "finetune", 2);

    const start_resp = try harness.trainingStart("demo-app", "finetune");
    defer freeResponse(alloc, start_resp);
    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);

    const pause_resp = try harness.trainingPause("demo-app", "finetune");
    defer freeResponse(alloc, pause_resp);
    harness.applyCommitted();

    try std.testing.expectEqual(http.StatusCode.ok, pause_resp.status);
    try expectJsonContains(pause_resp.body, "\"state\":\"paused\"");
    try std.testing.expectEqual(@as(usize, 0), try countTrainingAssignments(harness.node.stateMachineDb(), "demo-app", "finetune"));
}

test "training scale route replaces prior scheduled assignments" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    try harness.seedTrainingRelease("demo-app", "finetune", 1);

    const start_resp = try harness.trainingStart("demo-app", "finetune");
    defer freeResponse(alloc, start_resp);
    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);

    const scale_resp = try harness.trainingScale("demo-app", "finetune", 2);
    defer freeResponse(alloc, scale_resp);
    harness.applyCommitted();

    try std.testing.expectEqual(http.StatusCode.ok, scale_resp.status);
    try expectJsonContains(scale_resp.body, "\"state\":\"running\"");
    try expectJsonContains(scale_resp.body, "\"gpus\":2");
    try std.testing.expectEqual(@as(usize, 2), try countTrainingAssignments(harness.node.stateMachineDb(), "demo-app", "finetune"));
    const pause = try harness.trainingPause("demo-app", "finetune");
    defer freeResponse(alloc, pause);
    const resumed = route(makeRequest(.POST, "/apps/demo-app/training/finetune/resume", "", ""), alloc, harness.ctx()).?;
    defer freeResponse(alloc, resumed);
    try std.testing.expectEqual(http.StatusCode.ok, resumed.status);
    try expectJsonContains(resumed.body, "\"gpus\":2");
    try std.testing.expectEqual(@as(usize, 2), try countTrainingAssignments(harness.node.stateMachineDb(), "demo-app", "finetune"));
}

test "training logs route reports remote-hosted ranks explicitly" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    try harness.seedTrainingRelease("demo-app", "finetune", 1);

    const start_resp = try harness.trainingStart("demo-app", "finetune");
    defer freeResponse(alloc, start_resp);
    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);
    harness.applyCommitted();

    const logs_resp = try harness.trainingLogsRank("demo-app", "finetune", "0");
    defer freeResponse(alloc, logs_resp);

    try std.testing.expectEqual(http.StatusCode.bad_request, logs_resp.status);
    try expectJsonContains(logs_resp.body, "hosting agent");
}

test "training logs route rejects invalid rank query" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();

    const logs_resp = try harness.trainingLogsRank("demo-app", "finetune", "abc");
    defer freeResponse(alloc, logs_resp);

    try std.testing.expectEqual(http.StatusCode.bad_request, logs_resp.status);
    try expectJsonContains(logs_resp.body, "invalid rank");
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

    const logs_resp = try harness.trainingLogsRank("demo-app", "finetune", "0");
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

    try harness.seedTrainingRelease(app_name, job_name, 1);

    const joined_ctx: RouteContext = .{ .cluster = harness.node, .join_token = "join-token" };
    const start_resp = try harness.trainingStartWithContext(app_name, job_name, joined_ctx);
    defer freeResponse(alloc, start_resp);
    try std.testing.expectEqual(http.StatusCode.ok, start_resp.status);
    harness.applyCommitted();

    const logs_resp = try harness.trainingLogsRankWithContext(app_name, job_name, "0", joined_ctx);
    defer freeResponse(alloc, logs_resp);

    try std.testing.expectEqual(http.StatusCode.ok, logs_resp.status);
    try std.testing.expectEqualStrings("proxied rank logs\n", logs_resp.body);
}

test "placement numbers reject invalid training scale then accept valid scale" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.init(alloc);
    defer harness.deinit();
    try harness.seedTrainingRelease("numeric-training", "train", 1);
    const started = try harness.trainingStart("numeric-training", "train");
    defer freeResponse(alloc, started);
    try std.testing.expectEqual(http.StatusCode.ok, started.status);
    for ([_][]const u8{ "4294967296", "184467440737095516160", "-1", "0", "1.5", "1e2", "null", "\"2\"" }) |value| {
        const body = try std.fmt.allocPrint(alloc, "{{\"gpus\":{s}}}", .{value});
        defer alloc.free(body);
        const response = route(makeRequest(.POST, "/apps/numeric-training/training/train/scale", "", body), alloc, harness.ctx()).?;
        defer freeResponse(alloc, response);
        try std.testing.expectEqual(http.StatusCode.bad_request, response.status);
    }
    const scaled = try harness.trainingScale("numeric-training", "train", 2);
    defer freeResponse(alloc, scaled);
    try std.testing.expectEqual(http.StatusCode.ok, scaled.status);
    try expectJsonContains(scaled.body, "\"gpus\":2");
}

fn replayTrainingCommands(leader: *RouteFlowHarness, replica: *RouteFlowHarness) !void {
    const entries = try leader.node.log.getEntries(leader.alloc, replica.node.log.lastIndex() + 1, leader.node.raft.commit_index);
    defer {
        for (entries) |entry| leader.alloc.free(entry.data);
        leader.alloc.free(entries);
    }
    for (entries) |entry| try replica.node.log.append(entry);
    replica.node.state_machine.applyUpTo(&replica.node.log, replica.alloc, leader.node.raft.commit_index);
    replica.node.raft.commit_index = leader.node.raft.commit_index;
}

test "training state and assignments survive replica promotion and pause together" {
    const alloc = std.testing.allocator;
    var leader = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer leader.deinit();
    var replica = try RouteFlowHarness.init(alloc);
    defer replica.deinit();
    try leader.seedTrainingRelease("replicated-training", "finetune", 2);
    const start = try leader.trainingStart("replicated-training", "finetune");
    defer freeResponse(alloc, start);
    try std.testing.expectEqual(http.StatusCode.ok, start.status);
    try replayTrainingCommands(&leader, &replica);
    const original = (try store.findTrainingJobInDb(leader.node.stateMachineDb(), alloc, "replicated-training", "finetune")).?;
    defer original.deinit(alloc);
    const copied = (try store.findTrainingJobInDb(replica.node.stateMachineDb(), alloc, "replicated-training", "finetune")).?;
    defer copied.deinit(alloc);
    try std.testing.expectEqualStrings(original.id, copied.id);
    try std.testing.expectEqualStrings("running", copied.state);
    try std.testing.expectEqual(@as(i64, 2), copied.gpus);
    try std.testing.expectEqual(@as(usize, 2), try countTrainingAssignments(replica.node.stateMachineDb(), "replicated-training", "finetune"));

    leader.node.raft.role = .follower;
    replica.node.raft.persistent_state.current_term = 1;
    try std.testing.expect(replica.node.log.setCurrentTerm(1));
    const pause = try replica.trainingPause("replicated-training", "finetune");
    defer freeResponse(alloc, pause);
    try std.testing.expectEqual(http.StatusCode.ok, pause.status);
    try replayTrainingCommands(&replica, &leader);
    const paused = (try store.findTrainingJobInDb(leader.node.stateMachineDb(), alloc, "replicated-training", "finetune")).?;
    defer paused.deinit(alloc);
    try std.testing.expectEqualStrings("paused", paused.state);
    try std.testing.expectEqual(@as(usize, 0), try countTrainingAssignments(leader.node.stateMachineDb(), "replicated-training", "finetune"));
}

test "rejected training pause preserves assignments and running metadata atomically" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();
    try harness.seedTrainingRelease("pause-conflict", "finetune", 1);
    const start = try harness.trainingStart("pause-conflict", "finetune");
    defer freeResponse(alloc, start);
    try std.testing.expectEqual(http.StatusCode.ok, start.status);
    try harness.node.stateMachineDb().exec("CREATE TRIGGER reject_training_pause BEFORE UPDATE ON training_jobs WHEN NEW.state = 'paused' BEGIN SELECT RAISE(ABORT, 'injected conflict'); END;", .{}, .{});
    const pause = try harness.trainingPause("pause-conflict", "finetune");
    defer freeResponse(alloc, pause);
    try std.testing.expectEqual(http.StatusCode.conflict, pause.status);
    const unchanged = (try store.findTrainingJobInDb(harness.node.stateMachineDb(), alloc, "pause-conflict", "finetune")).?;
    defer unchanged.deinit(alloc);
    try std.testing.expectEqualStrings("running", unchanged.state);
    try std.testing.expectEqual(@as(usize, 1), try countTrainingAssignments(harness.node.stateMachineDb(), "pause-conflict", "finetune"));
    const claims = (try harness.node.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignment_claims;", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 1), claims.count);
}

test "training mutations reject follower and concurrent app apply before changing state" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();
    try harness.seedTrainingRelease("locked-training", "finetune", 1);
    const start = try harness.trainingStart("locked-training", "finetune");
    defer freeResponse(alloc, start);
    try std.testing.expectEqual(http.StatusCode.ok, start.status);
    const index = harness.node.log.lastIndex();
    {
        var app_lock = try @import("../../../manifest/apply_lock.zig").acquire(alloc, "locked-training");
        defer app_lock.release();
        const pause = try harness.trainingPause("locked-training", "finetune");
        defer freeResponse(alloc, pause);
        try std.testing.expectEqual(http.StatusCode.conflict, pause.status);
    }
    harness.node.raft.role = .follower;
    const pause = try harness.trainingPause("locked-training", "finetune");
    defer freeResponse(alloc, pause);
    try std.testing.expectEqual(http.StatusCode.bad_request, pause.status);
    try std.testing.expectEqual(index, harness.node.log.lastIndex());
    try std.testing.expectEqual(@as(usize, 1), try countTrainingAssignments(harness.node.stateMachineDb(), "locked-training", "finetune"));
}

test "oversized training scale preserves prior metadata and assignments" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();
    try harness.seedTrainingRelease("bounded-training", "finetune", 1);
    const start = try harness.trainingStart("bounded-training", "finetune");
    defer freeResponse(alloc, start);
    try std.testing.expectEqual(http.StatusCode.ok, start.status);
    const index = harness.node.log.lastIndex();
    const scaled = try harness.trainingScale("bounded-training", "finetune", @import("../../../cluster/placement_transaction.zig").max_gang_ranks + 1);
    defer freeResponse(alloc, scaled);
    try std.testing.expectEqual(http.StatusCode.bad_request, scaled.status);
    try std.testing.expectEqual(index, harness.node.log.lastIndex());
    const record = (try store.findTrainingJobInDb(harness.node.stateMachineDb(), alloc, "bounded-training", "finetune")).?;
    defer record.deinit(alloc);
    try std.testing.expectEqualStrings("running", record.state);
    try std.testing.expectEqual(@as(i64, 1), record.gpus);
    try std.testing.expectEqual(@as(usize, 1), try countTrainingAssignments(harness.node.stateMachineDb(), "bounded-training", "finetune"));
}

test "training replacement keeps the original job when capacity or metadata rejects it" {
    const alloc = std.testing.allocator;
    var harness = try RouteFlowHarness.initWithRuntimeStore(alloc);
    defer harness.deinit();
    try harness.seedTrainingRelease("atomic-training", "finetune", 1);
    const start = try harness.trainingStart("atomic-training", "finetune");
    defer freeResponse(alloc, start);
    try std.testing.expectEqual(http.StatusCode.ok, start.status);
    const original_id = (try harness.node.stateMachineDb().oneAlloc(struct { id: []const u8 }, alloc, "SELECT id FROM assignments;", .{}, .{})).?;
    defer alloc.free(original_id.id);
    const no_capacity = try harness.trainingScale("atomic-training", "finetune", 5);
    defer freeResponse(alloc, no_capacity);
    try std.testing.expectEqual(http.StatusCode.conflict, no_capacity.status);
    try harness.node.stateMachineDb().exec("CREATE TRIGGER reject_training_scale BEFORE INSERT ON training_jobs WHEN NEW.gpus = 2 BEGIN SELECT RAISE(ABORT, 'injected metadata failure'); END;", .{}, .{});
    const rejected = try harness.trainingScale("atomic-training", "finetune", 2);
    defer freeResponse(alloc, rejected);
    try std.testing.expectEqual(http.StatusCode.conflict, rejected.status);
    const record = (try store.findTrainingJobInDb(harness.node.stateMachineDb(), alloc, "atomic-training", "finetune")).?;
    defer record.deinit(alloc);
    try std.testing.expectEqualStrings("running", record.state);
    try std.testing.expectEqual(@as(i64, 1), record.gpus);
    try std.testing.expectEqual(@as(usize, 1), try countTrainingAssignments(harness.node.stateMachineDb(), "atomic-training", "finetune"));
    const retained = (try harness.node.stateMachineDb().oneAlloc(struct { id: []const u8 }, alloc, "SELECT id FROM assignments;", .{}, .{})).?;
    defer alloc.free(retained.id);
    try std.testing.expectEqualStrings(original_id.id, retained.id);
}
