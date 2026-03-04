// routes — API route dispatch and handler implementations
//
// maps method + path to handler functions. handlers call into store.zig
// for data and return JSON responses. no framework — just string matching
// on paths. ~10 endpoints don't need a router.
//
// each handler returns a Response struct. the caller (server.zig) is
// responsible for formatting it into an HTTP response.

const std = @import("std");
const http = @import("http.zig");
const store = @import("../state/store.zig");
const process = @import("../runtime/process.zig");
const logs = @import("../runtime/logs.zig");
const container = @import("../runtime/container.zig");
const json_helpers = @import("../lib/json_helpers.zig");
const log = @import("../lib/log.zig");
const cluster_node = @import("../cluster/node.zig");
const agent_registry = @import("../cluster/registry.zig");
const scheduler = @import("../cluster/scheduler.zig");

/// cluster node reference (set by server when running in cluster mode)
pub var cluster: ?*cluster_node.Node = null;

/// join token for agent registration (set by cmdInitServer)
pub var join_token: ?[]const u8 = null;

pub const Response = struct {
    status: http.StatusCode,
    body: []const u8,
    /// if true, the caller must free body with the allocator passed to dispatch
    allocated: bool,
};

/// route an incoming request to the appropriate handler.
/// the caller must free response.body if response.allocated is true.
pub fn dispatch(request: http.Request, alloc: std.mem.Allocator) Response {
    const path = request.path_only;

    // static routes (no allocation needed)
    if (request.method == .GET) {
        if (std.mem.eql(u8, path, "/health")) return handleHealth();
        if (std.mem.eql(u8, path, "/version")) return handleVersion();
        if (std.mem.eql(u8, path, "/containers")) return handleListContainers(alloc);
        if (std.mem.eql(u8, path, "/images")) return handleListImages(alloc);
        if (std.mem.eql(u8, path, "/cluster/status")) return handleClusterStatus(alloc);
        if (std.mem.eql(u8, path, "/agents")) return handleListAgents(alloc);
    }

    if (request.method == .POST) {
        if (std.mem.eql(u8, path, "/cluster/propose")) return handleClusterPropose(alloc, request);
        if (std.mem.eql(u8, path, "/agents/register")) return handleAgentRegister(alloc, request);
        if (std.mem.eql(u8, path, "/deploy")) return handleDeploy(alloc, request);
    }

    // /agents/{id} routes
    if (path.len > "/agents/".len and std.mem.startsWith(u8, path, "/agents/")) {
        const rest = path["/agents/".len..];

        // validate the ID portion of the path (everything before the first /)
        const agent_id_end = std.mem.indexOf(u8, rest, "/") orelse rest.len;
        if (!validateContainerId(rest[0..agent_id_end])) return badRequest("invalid agent id");

        if (matchSubpath(rest, "/heartbeat")) |id| {
            if (request.method != .POST) return methodNotAllowed();
            return handleAgentHeartbeat(alloc, request, id);
        }

        if (matchSubpath(rest, "/assignments")) |id| {
            if (request.method != .GET) return methodNotAllowed();
            return handleAgentAssignments(alloc, id);
        }

        if (matchSubpath(rest, "/drain")) |id| {
            if (request.method != .POST) return methodNotAllowed();
            return handleAgentDrain(alloc, id);
        }

        // /agents/{id}/assignments/{assignment_id}/status
        if (matchAssignmentStatusPath(rest)) |ids| {
            if (request.method != .POST) return methodNotAllowed();
            return handleAssignmentStatusUpdate(alloc, request, ids.agent_id, ids.assignment_id);
        }
    }

    // /containers/{id} routes
    if (path.len > "/containers/".len and std.mem.startsWith(u8, path, "/containers/")) {
        const rest = path["/containers/".len..];

        // validate the ID portion of the path
        const container_id_end = std.mem.indexOf(u8, rest, "/") orelse rest.len;
        if (!validateContainerId(rest[0..container_id_end])) return badRequest("invalid container id");

        // /containers/{id}/logs
        if (matchSubpath(rest, "/logs")) |id| {
            if (request.method != .GET) return methodNotAllowed();
            return handleGetLogs(alloc, id);
        }

        // /containers/{id}/stop
        if (matchSubpath(rest, "/stop")) |id| {
            if (request.method != .POST) return methodNotAllowed();
            return handleStopContainer(alloc, id);
        }

        // /containers/{id} (no suffix)
        if (std.mem.indexOf(u8, rest, "/") == null) {
            const id = rest;
            if (request.method == .GET) return handleGetContainer(alloc, id);
            if (request.method == .DELETE) return handleRemoveContainer(alloc, id);
            return methodNotAllowed();
        }
    }

    // /images/{id} routes
    if (path.len > "/images/".len and std.mem.startsWith(u8, path, "/images/")) {
        const id = path["/images/".len..];
        if (std.mem.indexOf(u8, id, "/") == null) {
            if (request.method == .DELETE) return handleRemoveImage(id);
            return methodNotAllowed();
        }
    }

    return notFound();
}

// -- handlers --

fn handleHealth() Response {
    return .{
        .status = .ok,
        .body = "{\"status\":\"ok\"}",
        .allocated = false,
    };
}

fn handleVersion() Response {
    return .{
        .status = .ok,
        .body = "{\"version\":\"0.0.1\"}",
        .allocated = false,
    };
}

fn handleListContainers(alloc: std.mem.Allocator) Response {
    var ids = store.listIds(alloc) catch return internalError();
    defer {
        for (ids.items) |id| alloc.free(id);
        ids.deinit(alloc);
    }

    // build JSON array of container objects
    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return internalError();

    var first = true;
    for (ids.items) |id| {
        const record = store.load(alloc, id) catch continue;
        defer record.deinit(alloc);

        if (!first) writer.writeByte(',') catch return internalError();
        first = false;

        writeContainerJson(writer, record) catch return internalError();
    }

    writer.writeByte(']') catch return internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleGetContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return notFound();
        return internalError();
    };
    defer record.deinit(alloc);

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writeContainerJson(writer, record) catch return internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleGetLogs(alloc: std.mem.Allocator, id: []const u8) Response {
    // verify container exists
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return notFound();
        return internalError();
    };
    record.deinit(alloc);

    const log_data = logs.readLogs(alloc, id) catch {
        // no log file is fine — return empty
        const empty = alloc.dupe(u8, "{\"logs\":\"\"}") catch return internalError();
        return .{ .status = .ok, .body = empty, .allocated = true };
    };
    defer alloc.free(log_data);

    // escape the log content for JSON and build response
    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeAll("{\"logs\":\"") catch return internalError();
    json_helpers.writeJsonEscaped(writer, log_data) catch return internalError();
    writer.writeAll("\"}") catch return internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleStopContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return notFound();
        return internalError();
    };
    defer record.deinit(alloc);

    if (!std.mem.eql(u8, record.status, "running")) {
        return badRequest("container is not running");
    }

    const pid = record.pid orelse return badRequest("container has no pid");

    process.terminate(pid) catch return internalError();
    store.updateStatus(id, "stopped", null, null) catch |e| {
        log.warn("failed to update status after stopping {s}: {}", .{ id, e });
    };

    return .{
        .status = .ok,
        .body = "{\"status\":\"stopped\"}",
        .allocated = false,
    };
}

fn handleRemoveContainer(alloc: std.mem.Allocator, id: []const u8) Response {
    const record = store.load(alloc, id) catch |err| {
        if (err == store.StoreError.NotFound) return notFound();
        return internalError();
    };

    if (std.mem.eql(u8, record.status, "running")) {
        record.deinit(alloc);
        return badRequest("cannot remove running container");
    }
    record.deinit(alloc);

    store.remove(id) catch return internalError();
    logs.deleteLogFile(id);
    container.cleanupContainerDirs(id);

    return .{
        .status = .ok,
        .body = "{\"status\":\"removed\"}",
        .allocated = false,
    };
}

fn handleListImages(alloc: std.mem.Allocator) Response {
    var images = store.listImages(alloc) catch return internalError();
    defer {
        for (images.items) |img| img.deinit(alloc);
        images.deinit(alloc);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return internalError();

    var first = true;
    for (images.items) |img| {
        if (!first) writer.writeByte(',') catch return internalError();
        first = false;

        writeImageJson(writer, img) catch return internalError();
    }

    writer.writeByte(']') catch return internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleRemoveImage(id: []const u8) Response {
    store.removeImage(id) catch |err| {
        if (err == store.StoreError.NotFound) return notFound();
        return internalError();
    };

    return .{
        .status = .ok,
        .body = "{\"status\":\"removed\"}",
        .allocated = false,
    };
}

fn handleClusterStatus(alloc: std.mem.Allocator) Response {
    const node = cluster orelse {
        return .{
            .status = .ok,
            .body = "{\"cluster\":false}",
            .allocated = false,
        };
    };

    const role_str = switch (node.role()) {
        .follower => "follower",
        .candidate => "candidate",
        .leader => "leader",
    };

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeAll("{\"cluster\":true") catch return internalError();
    std.fmt.format(writer, ",\"id\":{d}", .{node.config.id}) catch return internalError();
    writer.writeAll(",\"role\":\"") catch return internalError();
    writer.writeAll(role_str) catch return internalError();
    writer.writeByte('"') catch return internalError();
    std.fmt.format(writer, ",\"term\":{d}", .{node.currentTerm()}) catch return internalError();
    std.fmt.format(writer, ",\"peers\":{d}", .{node.config.peers.len}) catch return internalError();
    writer.writeByte('}') catch return internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleClusterPropose(alloc: std.mem.Allocator, request: http.Request) Response {
    _ = alloc;
    const node = cluster orelse {
        return badRequest("not running in cluster mode");
    };

    if (request.body.len == 0) return badRequest("missing request body");

    _ = node.propose(request.body) catch {
        return .{
            .status = .bad_request,
            .body = "{\"error\":\"not leader\"}",
            .allocated = false,
        };
    };

    return .{
        .status = .ok,
        .body = "{\"status\":\"proposed\"}",
        .allocated = false,
    };
}

// -- agent handlers --

fn handleAgentRegister(alloc: std.mem.Allocator, request: http.Request) Response {
    const node = cluster orelse return badRequest("not running in cluster mode");
    const expected_token = join_token orelse return badRequest("no join token configured");

    if (request.body.len == 0) return badRequest("missing request body");

    // parse JSON body manually: {"token":"...","address":"...","cpu_cores":N,"memory_mb":N}
    const token = extractJsonString(request.body, "token") orelse
        return badRequest("missing token field");
    const address = extractJsonString(request.body, "address") orelse
        return badRequest("missing address field");
    const cpu_cores = extractJsonInt(request.body, "cpu_cores") orelse
        return badRequest("missing cpu_cores field");
    const memory_mb = extractJsonInt(request.body, "memory_mb") orelse
        return badRequest("missing memory_mb field");

    if (!validateClusterInput(address)) {
        return badRequest("invalid address");
    }

    if (!agent_registry.validateToken(token, expected_token)) {
        return .{
            .status = .bad_request,
            .body = "{\"error\":\"invalid token\"}",
            .allocated = false,
        };
    }

    // generate agent ID
    var id_buf: [12]u8 = undefined;
    agent_registry.generateAgentId(&id_buf);

    // generate SQL and propose through raft
    var sql_buf: [1024]u8 = undefined;
    const sql = agent_registry.registerSql(
        &sql_buf,
        &id_buf,
        address,
        .{
            .cpu_cores = @intCast(cpu_cores),
            .memory_mb = @intCast(memory_mb),
        },
        std.time.timestamp(),
    ) catch return internalError();

    _ = node.propose(sql) catch {
        return .{
            .status = .internal_server_error,
            .body = "{\"error\":\"not leader\"}",
            .allocated = false,
        };
    };

    // return the agent ID
    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);
    writer.writeAll("{\"id\":\"") catch return internalError();
    writer.writeAll(&id_buf) catch return internalError();
    writer.writeAll("\"}") catch return internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleAgentHeartbeat(alloc: std.mem.Allocator, request: http.Request, id: []const u8) Response {
    const node = cluster orelse return badRequest("not running in cluster mode");

    if (request.body.len == 0) return badRequest("missing request body");

    // parse resource update: {"cpu_used":N,"memory_used_mb":N,"containers":N}
    const cpu_used = extractJsonInt(request.body, "cpu_used") orelse 0;
    const memory_used_mb = extractJsonInt(request.body, "memory_used_mb") orelse 0;
    const containers = extractJsonInt(request.body, "containers") orelse 0;

    // also report total capacity so the server has a fresh view
    const cpu_cores = extractJsonInt(request.body, "cpu_cores") orelse 0;
    const memory_mb = extractJsonInt(request.body, "memory_mb") orelse 0;

    var sql_buf: [512]u8 = undefined;
    const sql = agent_registry.heartbeatSql(
        &sql_buf,
        id,
        .{
            .cpu_cores = @intCast(cpu_cores),
            .memory_mb = @intCast(memory_mb),
            .cpu_used = @intCast(cpu_used),
            .memory_used_mb = @intCast(memory_used_mb),
            .containers = @intCast(containers),
        },
        std.time.timestamp(),
    ) catch return internalError();

    _ = node.propose(sql) catch {
        return .{
            .status = .internal_server_error,
            .body = "{\"error\":\"not leader\"}",
            .allocated = false,
        };
    };

    // look up agent status so the agent knows if it's being drained
    const db = node.stateMachineDb();
    const agent = agent_registry.getAgent(alloc, db, id) catch {
        return .{ .status = .ok, .body = "{\"status\":\"ok\"}", .allocated = false };
    };

    if (agent) |a| {
        defer a.deinit(alloc);
        var json_buf: std.ArrayList(u8) = .empty;
        defer json_buf.deinit(alloc);
        const writer = json_buf.writer(alloc);
        writer.writeAll("{\"status\":\"") catch return internalError();
        writer.writeAll(a.status) catch return internalError();
        writer.writeAll("\"}") catch return internalError();
        const body = json_buf.toOwnedSlice(alloc) catch return internalError();
        return .{ .status = .ok, .body = body, .allocated = true };
    }

    return .{ .status = .ok, .body = "{\"status\":\"ok\"}", .allocated = false };
}

fn handleListAgents(alloc: std.mem.Allocator) Response {
    const node = cluster orelse {
        return .{ .status = .ok, .body = "[]", .allocated = false };
    };

    const db = node.stateMachineDb();
    const agents = agent_registry.listAgents(alloc, db) catch return internalError();
    defer {
        for (agents) |a| a.deinit(alloc);
        alloc.free(agents);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return internalError();
    for (agents, 0..) |a, i| {
        if (i > 0) writer.writeByte(',') catch return internalError();
        writeAgentJson(writer, a) catch return internalError();
    }
    writer.writeByte(']') catch return internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleAgentAssignments(alloc: std.mem.Allocator, agent_id: []const u8) Response {
    const node = cluster orelse return badRequest("not running in cluster mode");

    const db = node.stateMachineDb();
    const assignments = agent_registry.getAssignments(alloc, db, agent_id) catch return internalError();
    defer {
        for (assignments) |a| a.deinit(alloc);
        alloc.free(assignments);
    }

    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    writer.writeByte('[') catch return internalError();
    for (assignments, 0..) |a, i| {
        if (i > 0) writer.writeByte(',') catch return internalError();
        writeAssignmentJson(writer, a) catch return internalError();
    }
    writer.writeByte(']') catch return internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleAssignmentStatusUpdate(alloc: std.mem.Allocator, request: http.Request, agent_id: []const u8, assignment_id: []const u8) Response {
    _ = agent_id;
    const node = cluster orelse return badRequest("not running in cluster mode");

    if (request.body.len == 0) return badRequest("missing request body");

    const status = extractJsonString(request.body, "status") orelse
        return badRequest("missing status field");

    // validate status value
    const valid_statuses = [_][]const u8{ "running", "stopped", "failed" };
    var valid = false;
    for (valid_statuses) |s| {
        if (std.mem.eql(u8, status, s)) {
            valid = true;
            break;
        }
    }
    if (!valid) return badRequest("invalid status value");

    var sql_buf: [256]u8 = undefined;
    const sql = agent_registry.updateAssignmentStatusSql(&sql_buf, assignment_id, status) catch return internalError();

    _ = node.propose(sql) catch {
        return .{
            .status = .internal_server_error,
            .body = "{\"error\":\"not leader\"}",
            .allocated = false,
        };
    };

    const body = std.fmt.allocPrint(alloc, "{{\"ok\":true,\"status\":\"{s}\"}}", .{status}) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn handleAgentDrain(alloc: std.mem.Allocator, id: []const u8) Response {
    _ = alloc;
    const node = cluster orelse return badRequest("not running in cluster mode");

    var sql_buf: [256]u8 = undefined;
    const sql = agent_registry.drainSql(&sql_buf, id) catch return internalError();

    _ = node.propose(sql) catch {
        return .{
            .status = .internal_server_error,
            .body = "{\"error\":\"not leader\"}",
            .allocated = false,
        };
    };

    return .{
        .status = .ok,
        .body = "{\"status\":\"draining\"}",
        .allocated = false,
    };
}

fn handleDeploy(alloc: std.mem.Allocator, request: http.Request) Response {
    const node = cluster orelse return badRequest("not running in cluster mode");

    if (request.body.len == 0) return badRequest("missing request body");

    // parse deployment request: {"services":[{"image":"...","command":"...","cpu_limit":N,"memory_limit_mb":N},...]}
    // for now, parse a simple flat list of services from the body
    var requests: std.ArrayListUnmanaged(scheduler.PlacementRequest) = .empty;
    defer requests.deinit(alloc);

    // simple parser: find each {"image":"...",...} block
    var pos: usize = 0;
    while (pos < request.body.len) {
        const block_start = std.mem.indexOfPos(u8, request.body, pos, "{\"image\":\"") orelse break;

        // find the end of this block
        const block_end = std.mem.indexOfPos(u8, request.body, block_start + 1, "}") orelse break;
        const block = request.body[block_start .. block_end + 1];

        const image = extractJsonString(block, "image") orelse {
            pos = block_end + 1;
            continue;
        };
        const command = extractJsonString(block, "command") orelse "";
        const cpu_limit = extractJsonInt(block, "cpu_limit") orelse 1000;
        const memory_limit_mb = extractJsonInt(block, "memory_limit_mb") orelse 256;

        // validate user-controlled fields before they reach SQL generation
        if (!validateClusterInput(image)) {
            pos = block_end + 1;
            continue;
        }
        if (command.len > 0 and !validateClusterInput(command)) {
            pos = block_end + 1;
            continue;
        }

        requests.append(alloc, .{
            .image = image,
            .command = command,
            .cpu_limit = cpu_limit,
            .memory_limit_mb = memory_limit_mb,
        }) catch return internalError();

        pos = block_end + 1;
    }

    if (requests.items.len == 0) return badRequest("no services to deploy");

    // get active agents
    const db = node.stateMachineDb();
    const agents = agent_registry.listAgents(alloc, db) catch return internalError();
    defer {
        for (agents) |a| a.deinit(alloc);
        alloc.free(agents);
    }

    if (agents.len == 0) {
        return .{
            .status = .bad_request,
            .body = "{\"error\":\"no agents available\"}",
            .allocated = false,
        };
    }

    // run scheduler
    const placements = scheduler.schedule(alloc, requests.items, agents) catch return internalError();
    defer alloc.free(placements);

    // propose assignments through raft
    var placed: usize = 0;
    var failed: usize = 0;

    for (placements) |maybe_placement| {
        if (maybe_placement) |placement| {
            var id_buf: [12]u8 = undefined;
            scheduler.generateAssignmentId(&id_buf);

            var sql_buf: [1024]u8 = undefined;
            const sql = scheduler.assignmentSql(
                &sql_buf,
                &id_buf,
                placement.agent_id,
                requests.items[placement.request_idx],
                std.time.timestamp(),
            ) catch {
                failed += 1;
                continue;
            };

            _ = node.propose(sql) catch {
                failed += 1;
                continue;
            };
            placed += 1;
        } else {
            failed += 1;
        }
    }

    // build response
    var json_buf: std.ArrayList(u8) = .empty;
    defer json_buf.deinit(alloc);
    const writer = json_buf.writer(alloc);

    std.fmt.format(writer, "{{\"placed\":{d},\"failed\":{d}}}", .{ placed, failed }) catch return internalError();

    const body = json_buf.toOwnedSlice(alloc) catch return internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

fn writeAgentJson(writer: anytype, agent: agent_registry.AgentRecord) !void {
    try writer.writeAll("{\"id\":\"");
    try writer.writeAll(agent.id);
    try writer.writeAll("\",\"address\":\"");
    try json_helpers.writeJsonEscaped(writer, agent.address);
    try writer.writeAll("\",\"status\":\"");
    try writer.writeAll(agent.status);
    try writer.writeAll("\",\"cpu_cores\":");
    try std.fmt.format(writer, "{d}", .{agent.cpu_cores});
    try writer.writeAll(",\"memory_mb\":");
    try std.fmt.format(writer, "{d}", .{agent.memory_mb});
    try writer.writeAll(",\"cpu_used\":");
    try std.fmt.format(writer, "{d}", .{agent.cpu_used});
    try writer.writeAll(",\"memory_used_mb\":");
    try std.fmt.format(writer, "{d}", .{agent.memory_used_mb});
    try writer.writeAll(",\"containers\":");
    try std.fmt.format(writer, "{d}", .{agent.containers});
    try writer.writeAll(",\"last_heartbeat\":");
    try std.fmt.format(writer, "{d}", .{agent.last_heartbeat});
    try writer.writeByte('}');
}

fn writeAssignmentJson(writer: anytype, assignment: agent_registry.Assignment) !void {
    try writer.writeAll("{\"id\":\"");
    try writer.writeAll(assignment.id);
    try writer.writeAll("\",\"agent_id\":\"");
    try writer.writeAll(assignment.agent_id);
    try writer.writeAll("\",\"image\":\"");
    try json_helpers.writeJsonEscaped(writer, assignment.image);
    try writer.writeAll("\",\"command\":\"");
    try json_helpers.writeJsonEscaped(writer, assignment.command);
    try writer.writeAll("\",\"status\":\"");
    try writer.writeAll(assignment.status);
    try writer.writeAll("\",\"cpu_limit\":");
    try std.fmt.format(writer, "{d}", .{assignment.cpu_limit});
    try writer.writeAll(",\"memory_limit_mb\":");
    try std.fmt.format(writer, "{d}", .{assignment.memory_limit_mb});
    try writer.writeByte('}');
}

// use shared JSON extraction helpers
const extractJsonString = json_helpers.extractJsonString;
const extractJsonInt = json_helpers.extractJsonInt;

// -- input validation --

/// reject values containing SQL metacharacters or control characters.
/// defense-in-depth: SQL generation also escapes, but rejecting at the
/// API boundary is the first line of defense.
fn validateClusterInput(value: []const u8) bool {
    if (value.len == 0 or value.len > 256) return false;
    for (value) |c| {
        if (c == '\'' or c == '"' or c == ';' or c == '\\') return false;
        if (c < 0x20) return false; // control characters
    }
    return true;
}

/// validate that a container or agent ID from a URL path is safe.
/// IDs are always 12 hex chars from generateId(), but the API accepts
/// arbitrary strings from HTTP requests. defense-in-depth: reject
/// anything that isn't lowercase hex.
fn validateContainerId(id: []const u8) bool {
    if (id.len == 0 or id.len > 64) return false;
    for (id) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    }
    return true;
}

// -- response helpers --

fn notFound() Response {
    return .{ .status = .not_found, .body = "{\"error\":\"not found\"}", .allocated = false };
}

fn methodNotAllowed() Response {
    return .{ .status = .method_not_allowed, .body = "{\"error\":\"method not allowed\"}", .allocated = false };
}

fn internalError() Response {
    return .{ .status = .internal_server_error, .body = "{\"error\":\"internal error\"}", .allocated = false };
}

fn badRequest(comptime message: []const u8) Response {
    // message is comptime-known, so we can build the JSON at comptime
    return .{
        .status = .bad_request,
        .body = "{\"error\":\"" ++ message ++ "\"}",
        .allocated = false,
    };
}

// -- JSON serialization helpers --

/// write a container record as a JSON object
fn writeContainerJson(writer: anytype, record: store.ContainerRecord) !void {
    try writer.writeAll("{\"id\":\"");
    try writer.writeAll(record.id);
    try writer.writeAll("\",\"command\":\"");
    try json_helpers.writeJsonEscaped(writer, record.command);
    try writer.writeAll("\",\"status\":\"");
    try writer.writeAll(record.status);
    try writer.writeAll("\",\"hostname\":\"");
    try json_helpers.writeJsonEscaped(writer, record.hostname);
    try writer.writeAll("\",\"pid\":");
    if (record.pid) |pid| {
        try std.fmt.format(writer, "{d}", .{pid});
    } else {
        try writer.writeAll("null");
    }
    try writer.writeAll(",\"created_at\":");
    try std.fmt.format(writer, "{d}", .{record.created_at});
    try writer.writeByte('}');
}

/// write an image record as a JSON object
fn writeImageJson(writer: anytype, img: store.ImageRecord) !void {
    try writer.writeAll("{\"id\":\"");
    try json_helpers.writeJsonEscaped(writer, img.id);
    try writer.writeAll("\",\"repository\":\"");
    try json_helpers.writeJsonEscaped(writer, img.repository);
    try writer.writeAll("\",\"tag\":\"");
    try json_helpers.writeJsonEscaped(writer, img.tag);
    try writer.writeAll("\",\"size\":");
    try std.fmt.format(writer, "{d}", .{img.total_size});
    try writer.writeAll(",\"created_at\":");
    try std.fmt.format(writer, "{d}", .{img.created_at});
    try writer.writeByte('}');
}

const AssignmentIds = struct {
    agent_id: []const u8,
    assignment_id: []const u8,
};

/// extract agent and assignment IDs from a path like
/// "{agent_id}/assignments/{assignment_id}/status".
fn matchAssignmentStatusPath(rest: []const u8) ?AssignmentIds {
    const slash = std.mem.indexOf(u8, rest, "/") orelse return null;
    const agent_id = rest[0..slash];
    if (agent_id.len == 0) return null;

    const after = rest[slash..];
    const prefix = "/assignments/";
    if (!std.mem.startsWith(u8, after, prefix)) return null;

    const remaining = after[prefix.len..];
    // find the next slash before "/status"
    const slash2 = std.mem.indexOf(u8, remaining, "/") orelse return null;
    const assignment_id = remaining[0..slash2];
    if (assignment_id.len == 0) return null;

    const suffix = remaining[slash2..];
    if (!std.mem.eql(u8, suffix, "/status")) return null;

    return .{ .agent_id = agent_id, .assignment_id = assignment_id };
}

/// extract an ID from a path like "{id}/suffix".
/// returns the id portion if the suffix matches, null otherwise.
fn matchSubpath(rest: []const u8, suffix: []const u8) ?[]const u8 {
    const slash = std.mem.indexOf(u8, rest, "/") orelse return null;
    const id = rest[0..slash];
    const after = rest[slash..];

    if (id.len == 0) return null;
    if (std.mem.eql(u8, after, suffix)) return id;
    return null;
}

// -- tests --

test "dispatch health" {
    const req = (try http.parseRequest("GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expectEqualStrings("{\"status\":\"ok\"}", resp.body);
    try std.testing.expect(!resp.allocated);
}

test "dispatch version" {
    const req = (try http.parseRequest("GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expectEqualStrings("{\"version\":\"0.0.1\"}", resp.body);
}

test "dispatch not found" {
    const req = (try http.parseRequest("GET /nonexistent HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.not_found, resp.status);
}

test "dispatch method not allowed on health" {
    const req = (try http.parseRequest("POST /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.not_found, resp.status);
}

test "dispatch POST to container stop" {
    const req = (try http.parseRequest(
        "POST /containers/abc123/stop HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    // will return not found or internal error since no DB is configured
    // but it exercises the routing path correctly
    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "dispatch GET on container stop returns method not allowed" {
    const req = (try http.parseRequest(
        "GET /containers/abc123/stop HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    try std.testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
}

test "dispatch DELETE container" {
    const req = (try http.parseRequest(
        "DELETE /containers/abc123 HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    // will fail because no DB, but routing is correct
    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "dispatch DELETE image" {
    const req = (try http.parseRequest(
        "DELETE /images/sha256:abc HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);

    // no DB configured, so this will error
    try std.testing.expect(resp.status == .not_found or resp.status == .internal_server_error);
}

test "matchSubpath" {
    try std.testing.expectEqualStrings("abc123", matchSubpath("abc123/logs", "/logs").?);
    try std.testing.expectEqualStrings("def456", matchSubpath("def456/stop", "/stop").?);
    try std.testing.expect(matchSubpath("abc123", "/logs") == null);
    try std.testing.expect(matchSubpath("abc123/other", "/logs") == null);
    try std.testing.expect(matchSubpath("/logs", "/logs") == null); // empty id
}

test "writeJsonEscaped" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    try json_helpers.writeJsonEscaped(writer, "hello \"world\"\nline2");
    try std.testing.expectEqualStrings("hello \\\"world\\\"\\nline2", buf.items);
}

test "writeJsonEscaped with backslash" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    const writer = buf.writer(std.testing.allocator);

    try json_helpers.writeJsonEscaped(writer, "path\\to\\file");
    try std.testing.expectEqualStrings("path\\\\to\\\\file", buf.items);
}

test "dispatch GET agents without cluster returns empty" {
    cluster = null;
    const req = (try http.parseRequest("GET /agents HTTP/1.1\r\nHost: localhost\r\n\r\n")).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.ok, resp.status);
    try std.testing.expectEqualStrings("[]", resp.body);
}

test "dispatch POST register without cluster returns error" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/register HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch agent heartbeat routing" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/abc123/heartbeat HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "validateClusterInput accepts normal values" {
    try std.testing.expect(validateClusterInput("10.0.0.5:7701"));
    try std.testing.expect(validateClusterInput("nginx:latest"));
    try std.testing.expect(validateClusterInput("/bin/sh -c echo hello"));
}

test "validateClusterInput rejects dangerous values" {
    try std.testing.expect(!validateClusterInput("'; DROP TABLE agents; --"));
    try std.testing.expect(!validateClusterInput("image\"name"));
    try std.testing.expect(!validateClusterInput("cmd;rm -rf /"));
    try std.testing.expect(!validateClusterInput("path\\to\\thing"));
    try std.testing.expect(!validateClusterInput("")); // empty
    try std.testing.expect(!validateClusterInput("a" ** 257)); // too long
}

test "validateClusterInput rejects control characters" {
    try std.testing.expect(!validateClusterInput("hello\x00world"));
    try std.testing.expect(!validateClusterInput("line\nbreak"));
}

test "matchAssignmentStatusPath" {
    const result = matchAssignmentStatusPath("abc123/assignments/def456/status");
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("abc123", result.?.agent_id);
    try std.testing.expectEqualStrings("def456", result.?.assignment_id);

    // missing /status suffix
    try std.testing.expect(matchAssignmentStatusPath("abc123/assignments/def456") == null);
    // no assignment id
    try std.testing.expect(matchAssignmentStatusPath("abc123/assignments//status") == null);
    // no agent id
    try std.testing.expect(matchAssignmentStatusPath("/assignments/def456/status") == null);
    // wrong prefix
    try std.testing.expect(matchAssignmentStatusPath("abc123/other/def456/status") == null);
}

test "dispatch assignment status update routing" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/abc123/assignments/def456/status HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\n\r\n{\"status\":\"running\"}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    // no cluster configured, so returns bad_request
    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch agent drain routing" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/abc123/drain HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "validateContainerId accepts valid hex ids" {
    try std.testing.expect(validateContainerId("abc123def456"));
    try std.testing.expect(validateContainerId("0123456789ab"));
    try std.testing.expect(validateContainerId("deadbeef"));
}

test "validateContainerId rejects invalid ids" {
    try std.testing.expect(!validateContainerId("")); // empty
    try std.testing.expect(!validateContainerId("ABCDEF")); // uppercase
    try std.testing.expect(!validateContainerId("abc-123")); // hyphen
    try std.testing.expect(!validateContainerId("abc_123")); // underscore
    try std.testing.expect(!validateContainerId("../etc")); // path traversal
    try std.testing.expect(!validateContainerId("abc;rm")); // injection
    try std.testing.expect(!validateContainerId("a" ** 65)); // too long
}

test "dispatch rejects non-hex container id" {
    const req = (try http.parseRequest(
        "GET /containers/INVALID! HTTP/1.1\r\nHost: localhost\r\n\r\n",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "validateContainerId accepts exactly 64 chars" {
    const id_64 = "a" ** 64;
    try std.testing.expect(validateContainerId(id_64));
}

test "validateClusterInput rejects tab character" {
    try std.testing.expect(!validateClusterInput("hello\tworld"));
}

test "dispatch deploy without cluster returns error" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /deploy HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}

test "dispatch rejects non-hex agent id" {
    cluster = null;
    const req = (try http.parseRequest(
        "POST /agents/NOT-HEX!/heartbeat HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}",
    )).?;
    const resp = dispatch(req, std.testing.allocator);
    defer if (resp.allocated) std.testing.allocator.free(resp.body);

    try std.testing.expectEqual(http.StatusCode.bad_request, resp.status);
}
