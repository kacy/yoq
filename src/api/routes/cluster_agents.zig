const std = @import("std");
const http = @import("../http.zig");
const agent_registry = @import("../../cluster/registry.zig");
const common = @import("common.zig");
const testing = std.testing;
const cluster_routes = @import("cluster_agents/cluster_routes.zig");
const agent_routes = @import("cluster_agents/agent_routes.zig");
const deploy_routes = @import("cluster_agents/deploy_routes.zig");
const writers = @import("cluster_agents/writers.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;
const writeAgentJson = writers.writeAgentJson;
const writeAssignmentJson = writers.writeAssignmentJson;
const writeWireguardPeerJson = writers.writeWireguardPeerJson;

pub fn route(request: http.Request, alloc: std.mem.Allocator, ctx: RouteContext) ?Response {
    const path = request.path_only;

    if (request.method == .GET) {
        if (std.mem.eql(u8, path, "/cluster/status")) return cluster_routes.handleClusterStatus(alloc, ctx);
        if (std.mem.eql(u8, path, "/agents")) return agent_routes.handleListAgents(alloc, ctx);
        if (std.mem.eql(u8, path, "/wireguard/peers")) return agent_routes.handleWireguardPeers(alloc, request, ctx);
    }

    if (request.method == .POST) {
        if (std.mem.eql(u8, path, "/cluster/propose")) return cluster_routes.handleClusterPropose(alloc, request, ctx);
        if (std.mem.eql(u8, path, "/cluster/step-down")) return cluster_routes.handleLeaderStepDown(alloc, ctx);
        if (std.mem.eql(u8, path, "/agents/register")) return agent_routes.handleAgentRegister(alloc, request, ctx);
        if (std.mem.eql(u8, path, "/deploy")) return deploy_routes.handleDeploy(alloc, request, ctx);
    }

    if (request.method == .GET) {
        if (std.mem.eql(u8, path, "/cluster/version")) return cluster_routes.handleClusterVersion();
    }

    if (path.len > "/agents/".len and std.mem.startsWith(u8, path, "/agents/")) {
        const rest = path["/agents/".len..];
        const agent_id_end = std.mem.indexOf(u8, rest, "/") orelse rest.len;
        if (!common.validateContainerId(rest[0..agent_id_end])) return common.badRequest("invalid agent id");

        if (common.matchSubpath(rest, "/labels")) |id| {
            if (request.method != .PUT) return common.methodNotAllowed();
            return agent_routes.handleUpdateLabels(alloc, request, id, ctx);
        }

        if (common.matchSubpath(rest, "/heartbeat")) |id| {
            if (request.method != .POST) return common.methodNotAllowed();
            return agent_routes.handleAgentHeartbeat(alloc, request, id, ctx);
        }

        if (common.matchSubpath(rest, "/assignments")) |id| {
            if (request.method != .GET) return common.methodNotAllowed();
            return agent_routes.handleAgentAssignments(alloc, id, ctx);
        }

        if (common.matchSubpath(rest, "/drain")) |id| {
            if (request.method != .POST) return common.methodNotAllowed();
            return agent_routes.handleAgentDrain(alloc, id, ctx);
        }

        if (common.matchAssignmentStatusPath(rest)) |ids| {
            if (request.method != .POST) return common.methodNotAllowed();
            return agent_routes.handleAssignmentStatusUpdate(alloc, request, ids.assignment_id, ctx);
        }
    }

    return null;
}

fn testRequest(method: http.Method, path: []const u8) http.Request {
    return .{
        .method = method,
        .path = path,
        .path_only = path,
        .query = "",
        .headers_raw = "",
        .body = "",
        .content_length = 0,
    };
}

test "route returns null for unknown path" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.GET, "/unknown");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response == null);
}

test "route handles /cluster/status GET without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.GET, "/cluster/status");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.ok, resp.status);
        try testing.expectEqualStrings("{\"cluster\":false}", resp.body);
        try testing.expect(!resp.allocated);
    }
}

test "route handles /agents GET without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.GET, "/agents");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.ok, resp.status);
        try testing.expectEqualStrings("[]", resp.body);
        try testing.expect(!resp.allocated);
    }
}

test "route handles /wireguard/peers GET without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.GET, "/wireguard/peers");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.ok, resp.status);
        try testing.expectEqualStrings("[]", resp.body);
        try testing.expect(!resp.allocated);
    }
}

test "route rejects POST /cluster/propose without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.POST, "/cluster/propose");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.bad_request, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route rejects POST /agents/register without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.POST, "/agents/register");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.bad_request, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route rejects POST /deploy without cluster" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };
    const req = testRequest(.POST, "/deploy");

    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.bad_request, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route validates agent ID format" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };

    var req = testRequest(.POST, "/agents/invalid-id/heartbeat");
    var response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.bad_request, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }

    req = testRequest(.POST, "/agents/abc123def456/heartbeat");
    response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.bad_request, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "route validates method for subpaths" {
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };

    var req = testRequest(.GET, "/agents/abc123def456/heartbeat");
    var response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
        try testing.expect(!resp.allocated);
    }

    req = testRequest(.POST, "/agents/abc123def456/assignments");
    response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
        try testing.expect(!resp.allocated);
    }

    req = testRequest(.GET, "/agents/abc123def456/drain");
    response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.method_not_allowed, resp.status);
        try testing.expect(!resp.allocated);
    }
}

test "route matches assignment status update path" {
    if (true) return error.SkipZigTest;
    const ctx: RouteContext = .{ .cluster = null, .join_token = null };

    const req = testRequest(.POST, "/agents/abc123def456/assignments/assign789/status");
    const response = route(req, testing.allocator, ctx);
    try testing.expect(response != null);
    if (response) |resp| {
        try testing.expectEqual(http.StatusCode.bad_request, resp.status);
        if (resp.allocated) testing.allocator.free(resp.body);
    }
}

test "writeAgentJson produces valid JSON" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const agent = agent_registry.AgentRecord{
        .id = "agent123",
        .address = "192.168.1.1:8080",
        .status = "active",
        .cpu_cores = 4,
        .memory_mb = 8192,
        .cpu_used = 2,
        .memory_used_mb = 4096,
        .containers = 10,
        .last_heartbeat = 1234567890,
        .registered_at = 1234560000,
        .node_id = 5,
        .wg_public_key = "pubkey123",
        .overlay_ip = "10.40.0.5",
    };

    writeAgentJson(writer, agent) catch unreachable;
    const json = stream.getWritten();

    try testing.expect(std.mem.indexOf(u8, json, "agent123") != null);
    try testing.expect(std.mem.indexOf(u8, json, "192.168.1.1:8080") != null);
    try testing.expect(std.mem.indexOf(u8, json, "active") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"cpu_cores\":4") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"memory_mb\":8192") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"node_id\":5") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"overlay_ip\":\"") != null);
}

test "writeAgentJson omits optional fields when null" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const agent = agent_registry.AgentRecord{
        .id = "agent456",
        .address = "192.168.1.2:8080",
        .status = "draining",
        .cpu_cores = 2,
        .memory_mb = 4096,
        .cpu_used = 1,
        .memory_used_mb = 2048,
        .containers = 5,
        .last_heartbeat = 9876543210,
        .registered_at = 9876500000,
        .node_id = null,
        .wg_public_key = null,
        .overlay_ip = null,
    };

    writeAgentJson(writer, agent) catch unreachable;
    const json = stream.getWritten();

    try testing.expect(std.mem.indexOf(u8, json, "agent456") != null);
    try testing.expect(std.mem.indexOf(u8, json, "draining") != null);
    try testing.expect(std.mem.indexOf(u8, json, "node_id") == null);
}

test "writeAssignmentJson produces valid JSON" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const assignment = agent_registry.Assignment{
        .id = "assign789",
        .agent_id = "agent123",
        .image = "nginx:latest",
        .command = "nginx -g daemon off;",
        .status = "running",
        .cpu_limit = 1000,
        .memory_limit_mb = 512,
    };

    writeAssignmentJson(writer, assignment) catch unreachable;
    const json = stream.getWritten();

    try testing.expect(std.mem.indexOf(u8, json, "assign789") != null);
    try testing.expect(std.mem.indexOf(u8, json, "agent123") != null);
    try testing.expect(std.mem.indexOf(u8, json, "nginx:latest") != null);
    try testing.expect(std.mem.indexOf(u8, json, "running") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"cpu_limit\":1000") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"memory_limit_mb\":512") != null);
}

test "writeWireguardPeerJson produces valid JSON" {
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const peer = agent_registry.WireguardPeer{
        .node_id = 3,
        .agent_id = "agent789",
        .public_key = "pubkeyabc",
        .endpoint = "192.168.1.3:51820",
        .overlay_ip = "10.40.0.3",
        .container_subnet = "10.42.3.0/24",
    };

    writeWireguardPeerJson(writer, peer) catch unreachable;
    const json = stream.getWritten();

    try testing.expect(std.mem.indexOf(u8, json, "\"node_id\":3") != null);
    try testing.expect(std.mem.indexOf(u8, json, "agent789") != null);
    try testing.expect(std.mem.indexOf(u8, json, "pubkeyabc") != null);
    try testing.expect(std.mem.indexOf(u8, json, "10.40.0.3") != null);
    try testing.expect(std.mem.indexOf(u8, json, "10.42.3.0/24") != null);
}

test "writeWireguardPeerJson escapes special characters" {
    var buf: [2048]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    const peer = agent_registry.WireguardPeer{
        .node_id = 1,
        .agent_id = "agent\"quoted\"",
        .public_key = "key\nwith\ttabs",
        .endpoint = "host:51820",
        .overlay_ip = "10.40.0.1",
        .container_subnet = "10.42.1.0/24",
    };

    writeWireguardPeerJson(writer, peer) catch unreachable;
    const json = stream.getWritten();

    try testing.expect(std.mem.indexOf(u8, json, "\\\"") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\\n") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\\t") != null);
}
