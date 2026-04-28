const std = @import("std");
const sqlite = @import("sqlite");

const cluster_node = @import("../../../cluster/node.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const http = @import("../../http.zig");
const workload_routes = @import("workload_routes.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

const route = workload_routes.route;
const setTestProxyTrainingLogsResponse = workload_routes.setTestProxyTrainingLogsResponse;
const clearTestProxyTrainingLogsResponse = workload_routes.clearTestProxyTrainingLogsResponse;

const RouteFlowHarness = struct {
    alloc: std.mem.Allocator,
    tmp: std.testing.TmpDir,
    node: *cluster_node.Node,

    fn init(alloc: std.mem.Allocator) !RouteFlowHarness {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        try store.initTestDb();
        errdefer store.deinitTestDb();

        var path_buf: [512]u8 = undefined;
        const tmp_path_len = try tmp.dir.realPathFile(std.testing.io, ".", &path_buf);
        const tmp_path = path_buf[0..tmp_path_len];

        const node = try alloc.create(cluster_node.Node);
        errdefer alloc.destroy(node);

        node.* = try cluster_node.Node.initForTests(alloc, .{
            .id = 1,
            .port = 0,
            .peers = &.{},
            .data_dir = tmp_path,
        });
        errdefer node.deinit();
        node.fixPointers();

        node.raft.role = .leader;
        node.leader_id = node.config.id;

        var harness = RouteFlowHarness{
            .alloc = alloc,
            .tmp = tmp,
            .node = node,
        };
        try harness.seedActiveAgent();
        return harness;
    }

    fn deinit(self: *RouteFlowHarness) void {
        self.node.deinit();
        self.alloc.destroy(self.node);
        store.deinitTestDb();
        self.tmp.cleanup();
    }

    fn ctx(self: *RouteFlowHarness) RouteContext {
        return .{ .cluster = self.node, .join_token = null };
    }

    fn applyCommitted(self: *RouteFlowHarness) void {
        self.node.state_machine.applyUpTo(&self.node.log, self.alloc, self.node.log.lastIndex());
        self.node.raft.role = .leader;
        self.node.leader_id = self.node.config.id;
    }

    fn seedActiveAgent(self: *RouteFlowHarness) !void {
        self.node.stateMachineDb().exec(
            "INSERT INTO agents (id, address, agent_api_port, status, cpu_cores, memory_mb, cpu_used, memory_used_mb, containers, last_heartbeat, registered_at, role, labels, gpu_count, gpu_used, gpu_model, gpu_vram_mb) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            .{},
            .{ "abc123def456", "10.0.0.2", @as(i64, 7701), "active", @as(i64, 8), @as(i64, 16384), @as(i64, 0), @as(i64, 0), @as(i64, 0), @as(i64, 100), @as(i64, 100), "agent", "", @as(i64, 4), @as(i64, 0), "L4", @as(i64, 24576) },
        ) catch return error.SkipZigTest;
    }

    fn seedLatestRelease(self: *RouteFlowHarness, app_name: []const u8, snapshot: []const u8) !void {
        try store.saveDeploymentInDb(self.node.stateMachineDb(), .{
            .id = "dep-seed",
            .app_name = app_name,
            .service_name = app_name,
            .trigger = "apply",
            .manifest_hash = "sha256:seed",
            .config_snapshot = snapshot,
            .status = "completed",
            .message = "apply completed",
            .created_at = 100,
        });
    }
};

fn makeRequest(method: http.Method, path: []const u8, body: []const u8, query: []const u8) http.Request {
    return .{
        .method = method,
        .path = path,
        .path_only = path,
        .query = query,
        .headers_raw = "",
        .body = body,
        .content_length = body.len,
    };
}

fn freeResponse(alloc: std.mem.Allocator, response: Response) void {
    if (response.allocated) alloc.free(response.body);
}

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
    var harness = RouteFlowHarness.init(alloc) catch return error.ProxyHarnessInitFailed;
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
    var harness = try RouteFlowHarness.init(alloc);
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
    var harness = try RouteFlowHarness.init(alloc);
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
    var harness = try RouteFlowHarness.init(alloc);
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
    var harness = try RouteFlowHarness.init(alloc);
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
    var harness = try RouteFlowHarness.init(alloc);
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
    var harness = try RouteFlowHarness.init(alloc);
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
    var harness = try RouteFlowHarness.init(alloc);
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
    var harness = try RouteFlowHarness.init(alloc);
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
