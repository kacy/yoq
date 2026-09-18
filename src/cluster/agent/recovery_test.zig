const std = @import("std");
const platform = @import("linux_platform");
const posix = std.posix;
const endpoints = @import("../api_endpoints.zig");
const cache = @import("../agent_store.zig");
const results = @import("result_store.zig");
const Agent = @import("../agent.zig").Agent;
const Node = @import("../node.zig").Node;
const http = @import("../../api/http.zig");
const routes = @import("../../api/routes/cluster_agents/agent_routes.zig");
const loop = @import("loop_runtime.zig");
const assignments = @import("assignment_runtime.zig");
const credential = "a" ** 64;

const Listener = struct {
    fd: posix.fd_t,
    endpoint: endpoints.Endpoint,

    fn init() !Listener {
        const fd = try platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
        errdefer platform.posix.close(fd);
        var address = platform.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
        try platform.posix.bind(fd, &address.any, address.getOsSockLen());
        try platform.posix.listen(fd, 4);
        const timeout = posix.timeval{ .sec = 3, .usec = 0 };
        try platform.posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
        var len = address.getOsSockLen();
        try platform.posix.getsockname(fd, &address.any, &len);
        return .{ .fd = fd, .endpoint = .{ .address = .{ 127, 0, 0, 1 }, .port = std.mem.bigToNative(u16, address.in.port) } };
    }
};

const Server = struct {
    listener: Listener,
    count: usize,
    node: ?*Node = null,
    static_body: []const u8 = "",
    status: http.StatusCode = .ok,
    handled: usize = 0,
    failure: ?anyerror = null,

    fn serve(self: *Server) void {
        self.run() catch |err| {
            self.failure = err;
        };
    }

    fn run(self: *Server) !void {
        for (0..self.count) |_| {
            const fd = try platform.posix.accept(self.listener.fd, null, null, 0);
            defer platform.posix.close(fd);
            const timeout = posix.timeval{ .sec = 3, .usec = 0 };
            try platform.posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
            var buffer: [8192]u8 = undefined;
            var used: usize = 0;
            const request = while (used < buffer.len) {
                const read = try platform.posix.read(fd, buffer[used..]);
                if (read == 0) return error.ShortRequest;
                used += read;
                if (try http.parseRequest(buffer[0..used])) |request| break request;
            } else return error.OversizedRequest;
            try std.testing.expectEqualStrings("Bearer " ++ credential, http.findHeaderValue(request.headers_raw, "Authorization") orelse return error.NoCredential);
            const response = if (self.node) |node| blk: {
                const ctx = @import("../../api/routes/common.zig").RouteContext{ .cluster = node, .join_token = "cluster-token" };
                break :blk if (std.mem.endsWith(u8, request.path_only, "/heartbeat"))
                    routes.handleAgentHeartbeat(std.testing.allocator, request, "worker000001", ctx)
                else
                    routes.handleAssignmentStatusUpdate(std.testing.allocator, request, "worker000001", "assignment", ctx);
            } else @import("../../api/routes/common.zig").Response{ .status = self.status, .body = self.static_body, .allocated = false };
            defer if (response.allocated) std.testing.allocator.free(response.body);
            var output: [8192]u8 = undefined;
            const wire = http.formatResponse(&output, response.status, response.body);
            var sent: usize = 0;
            while (sent < wire.len) {
                const wrote = try platform.posix.write(fd, wire[sent..]);
                if (wrote == 0) return error.ShortWrite;
                sent += wrote;
            }
            self.handled += 1;
        }
    }
};

test "agent recovery delivers a durable terminal result after hard api endpoint loss" {
    const alloc = std.testing.allocator;
    try cache.initTestDb();
    var node = try Node.initForTests(alloc, .{ .id = 1, .port = 0, .peers = &.{}, .data_dir = "/unused" });
    defer node.deinit();
    node.fixPointers();
    node.raft.role = .leader;
    try node.stateMachineDb().exec("INSERT INTO agents (id, address, status, last_heartbeat, registered_at) VALUES ('worker000001', '127.0.0.1', 'active', 1, 1);", .{}, .{});
    try node.stateMachineDb().exec("INSERT INTO assignments (id, agent_id, image, status, generation, created_at) VALUES ('assignment', 'worker000001', 'unused', 'running', 2, 1);", .{}, .{});
    const seed = try Listener.init();
    var seed_open = true;
    defer if (seed_open) platform.posix.close(seed.fd);
    const survivor = try Listener.init();
    defer platform.posix.close(survivor.fd);
    var membership = std.Io.Writer.Allocating.init(alloc);
    defer membership.deinit();
    try membership.writer.writeAll("{\"status\":\"active\",");
    try endpoints.writeFields(&membership.writer, &.{survivor.endpoint}, "cluster-token");
    try membership.writer.writeByte('}');
    var first = Server{ .listener = seed, .count = 1, .static_body = membership.written() };
    const first_thread = try std.Thread.spawn(.{}, Server.serve, .{&first});
    var agent = Agent.init(alloc, seed.endpoint.address, seed.endpoint.port, "cluster-token");
    defer agent.deinit();
    agent.id = "worker000001".*;
    agent.worker_credential = try alloc.dupe(u8, credential);
    loop.doHeartbeat(&agent);
    first_thread.join();
    if (first.failure) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), agent.api_endpoints.len);
    platform.posix.close(seed.fd);
    seed_open = false;

    try std.testing.expect(try results.claim(&agent.id, "assignment", 2));
    try results.record(&agent.id, "assignment", 2, "failed", "process_failed");
    var second = Server{ .listener = survivor, .count = 2, .node = &node };
    const second_thread = try std.Thread.spawn(.{}, Server.serve, .{&second});
    loop.doHeartbeat(&agent);
    assignments.flushResults(&agent);
    second_thread.join();
    if (second.failure) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), second.handled);
    try std.testing.expectEqual(survivor.endpoint.port, agent.server_port);
    try std.testing.expectEqualStrings("worker000001", &agent.id);
    try std.testing.expectEqualStrings(credential, agent.worker_credential.?);
    const row = (try node.stateMachineDb().one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignments WHERE status = 'failed' AND generation = 2;", .{}, .{})).?;
    try std.testing.expectEqual(@as(i64, 1), row.count);
    try std.testing.expectEqual(node.log.lastIndex(), node.state_machine.last_applied);
    const saved = try results.list(alloc, &agent.id);
    defer {
        for (saved) |result| result.deinit(alloc);
        alloc.free(saved);
    }
    try std.testing.expectEqual(@as(i64, 1), saved[0].delivered);
}

test "agent recovery retains rejected and legacy uncommitted result responses" {
    const alloc = std.testing.allocator;
    try cache.initTestDb();
    const listener = try Listener.init();
    defer platform.posix.close(listener.fd);
    var agent = Agent.init(alloc, listener.endpoint.address, listener.endpoint.port, "cluster-token");
    defer agent.deinit();
    agent.id = "worker000001".*;
    agent.worker_credential = try alloc.dupe(u8, credential);
    try std.testing.expect(try results.claim(&agent.id, "assignment", 0));
    try results.record(&agent.id, "assignment", 0, "failed", "process_failed");
    for ([_]http.StatusCode{ .service_unavailable, .ok }) |status| {
        var server = Server{ .listener = listener, .count = 1, .status = status, .static_body = "{\"ok\":true}" };
        const thread = try std.Thread.spawn(.{}, Server.serve, .{&server});
        assignments.flushResults(&agent);
        thread.join();
        if (server.failure) |err| return err;
        const saved = try results.list(alloc, &agent.id);
        defer {
            for (saved) |result| result.deinit(alloc);
            alloc.free(saved);
        }
        try std.testing.expectEqual(@as(i64, 0), saved[0].delivered);
    }
    // leave no pending network operation for Agent.deinit.
    const saved = try results.list(alloc, &agent.id);
    defer {
        for (saved) |result| result.deinit(alloc);
        alloc.free(saved);
    }
    try results.acknowledge(&agent.id, saved[0]);
}

test "agent recovery never forwards a credential to an unsigned leader hint" {
    const alloc = std.testing.allocator;
    const seed = try Listener.init();
    defer platform.posix.close(seed.fd);
    const stranger = try Listener.init();
    defer platform.posix.close(stranger.fd);
    const timeout = posix.timeval{ .sec = 0, .usec = 1000 };
    try platform.posix.setsockopt(stranger.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    const body = try std.fmt.allocPrint(alloc, "{{\"error\":\"not leader\",\"leader\":\"127.0.0.1:{d}\"}}", .{stranger.endpoint.port});
    defer alloc.free(body);
    var server = Server{ .listener = seed, .count = 1, .status = .bad_request, .static_body = body };
    const thread = try std.Thread.spawn(.{}, Server.serve, .{&server});
    var agent = Agent.init(alloc, seed.endpoint.address, seed.endpoint.port, "cluster-token");
    defer agent.deinit();
    var response = try endpoints.request(&agent, .post, "/agents/register", "{}", credential);
    defer response.deinit(alloc);
    thread.join();
    if (server.failure) |err| return err;
    try std.testing.expectEqual(@as(u16, 400), response.status_code);
    try std.testing.expectEqual(seed.endpoint.port, agent.server_port);
    try std.testing.expectError(error.WouldBlock, platform.posix.accept(stranger.fd, null, null, 0));
}
