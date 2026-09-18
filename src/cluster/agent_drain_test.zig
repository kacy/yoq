const std = @import("std");
const sqlite = @import("sqlite");
const Node = @import("node.zig").Node;
const drain = @import("agent_drain.zig");
const mutation = @import("mutation_session.zig");
const scheduler = @import("scheduler.zig");
const sql = @import("sql_command.zig");
const alloc = std.testing.allocator;

fn seed(local_volume: bool) !Node {
    var node = try Node.initForTests(alloc, .{ .id = 1, .port = 0, .peers = &.{}, .data_dir = "/unused-drain-test" });
    errdefer node.deinit();
    node.raft.role = .leader;
    const session = try mutation.Session.begin(&node);
    try session.commit("INSERT INTO agents (id, address, status, cpu_cores, memory_mb, last_heartbeat, registered_at) VALUES ('source', '127.0.0.1', 'drain_pending', 2, 2048, 0, 0);" ++
        "INSERT INTO assignments (id, agent_id, image, command, status, cpu_limit, memory_limit_mb, app_name, workload_kind, workload_name, generation, created_at) VALUES ('original', 'source', 'example', '', 'running', 500, 128, 'demo', 'service', 'web', 7, 0);");
    const request: scheduler.PlacementRequest = .{ .image = "example", .command = "", .cpu_limit = 500, .memory_limit_mb = 128, .app_name = "demo", .workload_kind = "service", .workload_name = "web", .volume_constraints = if (local_volume) &.{.{ .driver = "local", .node_id = null }} else &.{} };
    const encoded = try std.json.Stringify.valueAlloc(alloc, request, .{});
    defer alloc.free(encoded);
    const command = try sql.render(alloc, "INSERT OR REPLACE INTO assignment_claims (assignment_id, gpu_count, release_id, group_id, request_json) VALUES ('original', 0, 'release', 'original', ?);", .{encoded});
    defer alloc.free(command);
    try session.commit(command);
    return node;
}

fn addTarget(session: mutation.Session) !void {
    try session.commit("INSERT INTO agents (id, address, status, cpu_cores, memory_mb, last_heartbeat, registered_at) VALUES ('target', '127.0.0.2', 'active', 2, 2048, 0, 1);");
}

fn expectStatus(node: *Node, comptime table: []const u8, id: []const u8, expected: []const u8) !void {
    const row = (try node.stateMachineDb().oneAlloc(struct { status: sqlite.Text }, alloc, "SELECT status FROM " ++ table ++ " WHERE id = ?;", .{}, .{id})).?;
    defer alloc.free(row.status.data);
    try std.testing.expectEqualStrings(expected, row.status.data);
}

fn replacement(node: *Node) ![]const u8 {
    const row = (try node.stateMachineDb().oneAlloc(struct { replacement_id: sqlite.Text }, alloc, "SELECT replacement_id FROM assignment_handoffs WHERE assignment_id = 'original';", .{}, .{})).?;
    return row.replacement_id.data;
}

test "cluster reliability: agent drain retains the original through readiness and snapshot recovery" {
    var node = try seed(false);
    defer node.deinit();
    node.fixPointers();
    const session = try mutation.Session.begin(&node);
    try addTarget(session);
    const response = @import("../api/routes/cluster_agents/agent_routes.zig").handleAgentDrain(alloc, "source", .{ .cluster = &node, .join_token = null });
    defer if (response.allocated) alloc.free(response.body);
    try std.testing.expectEqual(@import("../api/http.zig").StatusCode.ok, response.status);
    const id = try replacement(&node);
    defer alloc.free(id);
    try expectStatus(&node, "assignments", "original", "running");
    try expectStatus(&node, "assignments", id, "pending");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const len = try tmp.dir.realPathFile(std.testing.io, ".", &path_buf);
    const path = try std.fmt.allocPrint(alloc, "{s}/drain.snapshot", .{path_buf[0..len]});
    defer alloc.free(path);
    try node.state_machine.takeSnapshot(path, .{ .last_included_index = node.state_machine.last_applied, .last_included_term = node.raft.persistent_state.current_term, .data_len = 0 });
    _ = try node.state_machine.restoreFromSnapshot(path);
    node.fixPointers();
    try drain.reconcile(alloc, session, "source");
    const recovered_id = try replacement(&node);
    defer alloc.free(recovered_id);
    try std.testing.expectEqualStrings(id, recovered_id);
    try expectStatus(&node, "assignments", "original", "running");

    const ready = try sql.render(alloc, "UPDATE assignments SET status = 'running' WHERE id = ? AND generation = 0;", .{id});
    defer alloc.free(ready);
    try session.commit(ready);
    try drain.reconcile(alloc, session, "source");
    try expectStatus(&node, "assignments", "original", "stopped");
    try expectStatus(&node, "assignments", id, "running");
    const body = "{\"status\":\"running\",\"generation\":7}";
    const late = @import("../api/routes/cluster_agents/agent_routes.zig").handleAssignmentStatusUpdate(alloc, .{
        .method = .POST,
        .path = "/unused",
        .path_only = "/unused",
        .query = "",
        .content_length = body.len,
        .body = body,
        .headers_raw = "",
    }, "source", "original", .{ .cluster = &node, .join_token = null });
    defer if (late.allocated) alloc.free(late.body);
    try std.testing.expectEqual(@import("../api/http.zig").StatusCode.ok, late.status);
    try expectStatus(&node, "assignments", "original", "stopped");
    try drain.reconcile(alloc, session, "source");
    try expectStatus(&node, "agents", "source", "drained");
}

test "cluster reliability: agent drain remains blocked without capacity or after replacement failure" {
    var node = try seed(false);
    defer node.deinit();
    node.fixPointers();
    const session = try mutation.Session.begin(&node);
    try drain.reconcile(alloc, session, "source");
    try expectStatus(&node, "agents", "source", "drain_blocked");
    try expectStatus(&node, "assignments", "original", "running");
    try addTarget(session);
    try drain.reconcile(alloc, session, "source");
    try expectStatus(&node, "agents", "source", "drain_pending");
    const id = try replacement(&node);
    defer alloc.free(id);
    const failed = try sql.render(alloc, "UPDATE assignments SET status = 'failed' WHERE id = ?;", .{id});
    defer alloc.free(failed);
    try session.commit(failed);
    try drain.reconcile(alloc, session, "source");
    try expectStatus(&node, "agents", "source", "drain_blocked");
    try expectStatus(&node, "assignments", "original", "running");
}

test "cluster reliability: agent drain blocks local volumes and fences a newer original generation" {
    var local = try seed(true);
    defer local.deinit();
    local.fixPointers();
    const local_session = try mutation.Session.begin(&local);
    try addTarget(local_session);
    try drain.reconcile(alloc, local_session, "source");
    try expectStatus(&local, "agents", "source", "drain_blocked");
    const count = (try local.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignment_handoffs;", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 0), count.count);

    var node = try seed(false);
    defer node.deinit();
    node.fixPointers();
    const session = try mutation.Session.begin(&node);
    try addTarget(session);
    try drain.reconcile(alloc, session, "source");
    try session.commit("UPDATE assignments SET status = 'running'; UPDATE assignments SET generation = 8 WHERE id = 'original';");
    try drain.reconcile(alloc, session, "source");
    try expectStatus(&node, "agents", "source", "drain_blocked");
    try expectStatus(&node, "assignments", "original", "running");
}

test "cluster reliability: agent drain keeps a handoff original out of ordinary failover" {
    var node = try seed(false);
    defer node.deinit();
    node.fixPointers();
    const session = try mutation.Session.begin(&node);
    try addTarget(session);
    try drain.reconcile(alloc, session, "source");
    var buffer: [256]u8 = undefined;
    const registry = @import("registry.zig");
    try session.commit(try registry.markOfflineSql(&buffer, "source"));
    try session.commit(try drain.orphanAssignmentsSql(&buffer, "source"));
    try expectStatus(&node, "agents", "source", "drain_pending");
    const row = (try node.stateMachineDb().oneAlloc(struct { agent_id: sqlite.Text }, alloc, "SELECT agent_id FROM assignments WHERE id = 'original';", .{}, .{})).?;
    defer alloc.free(row.agent_id.data);
    try std.testing.expectEqualStrings("source", row.agent_id.data);
    const id = try replacement(&node);
    defer alloc.free(id);
    const ready = try sql.render(alloc, "UPDATE assignments SET status = 'running' WHERE id = ?;", .{id});
    defer alloc.free(ready);
    try session.commit(ready);
    // no further heartbeat or result from the source is needed to finish.
    try drain.reconcile(alloc, session, "source");
    try drain.reconcile(alloc, session, "source");
    try expectStatus(&node, "agents", "source", "drained");
    try expectStatus(&node, "assignments", "original", "stopped");
    try expectStatus(&node, "assignments", id, "running");
}
