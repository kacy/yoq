const std = @import("std");
const registry = @import("../../../cluster/registry.zig");
const common = @import("../common.zig");
const http = @import("../../http.zig");
const status_store = @import("../../../state/store/alerts.zig");

const page_size = 8;
const response_limit = 1024 * 1024;

// each page preserves host boundaries: resource maxima and request percentiles
// from different hosts cannot be combined into a service-wide measurement.
pub fn handle(alloc: std.mem.Allocator, request: http.Request, ctx: common.RouteContext) common.Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const token = ctx.join_token orelse return common.badRequest("agent authentication unavailable");
    const offset = if (common.extractQueryParam(request.path, "offset")) |text|
        std.fmt.parseInt(usize, text, 10) catch return common.badRequest("invalid offset")
    else
        0;
    const agents = registry.listAgents(alloc, node.stateMachineDb()) catch return common.internalError();
    defer {
        for (agents) |agent| agent.deinit(alloc);
        alloc.free(agents);
    }
    const start = @min(offset, agents.len);
    const end = start + @min(page_size, agents.len - start);
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    var output = std.Io.Writer.Allocating.init(alloc);
    defer output.deinit();
    const writer = &output.writer;
    writer.writeAll("{\"scope\":\"host\",\"agents\":[") catch return common.internalError();
    for (agents[start..end], 0..) |agent, index| {
        if (index > 0) writer.writeByte(',') catch return common.internalError();
        const result = fetch(alloc, threaded.io(), agent, token);
        defer if (result.body) |body| alloc.free(body);
        writer.writeAll("{\"agent_id\":") catch return common.internalError();
        std.json.Stringify.value(agent.id, .{}, writer) catch return common.internalError();
        writer.writeAll(",\"address\":") catch return common.internalError();
        std.json.Stringify.value(agent.address, .{}, writer) catch return common.internalError();
        writer.writeAll(",\"failure\":") catch return common.internalError();
        std.json.Stringify.value(result.failure, .{}, writer) catch return common.internalError();
        writer.writeAll(",\"alerts\":") catch return common.internalError();
        writer.writeAll(result.body orelse "[]") catch return common.internalError();
        writer.writeByte('}') catch return common.internalError();
    }
    writer.writeAll("],\"next_offset\":") catch return common.internalError();
    std.json.Stringify.value(if (end < agents.len) @as(?usize, end) else null, .{}, writer) catch return common.internalError();
    writer.writeByte('}') catch return common.internalError();
    const body = output.toOwnedSlice() catch return common.internalError();
    return .{ .status = .ok, .body = body, .allocated = true };
}

const Result = struct { body: ?[]u8 = null, failure: ?[]const u8 = null };

fn fetch(alloc: std.mem.Allocator, io: std.Io, agent: registry.AgentRecord, token: []const u8) Result {
    const Outcome = union(enum) { result: Result, timeout: void };
    var completed: [2]Outcome = undefined;
    var pending = std.Io.Select(Outcome).init(io, &completed);
    defer while (pending.cancel()) |outcome| switch (outcome) {
        .result => |result| if (result.body) |body| alloc.free(body),
        .timeout => {},
    };
    pending.concurrent(.timeout, sleep, .{io}) catch return .{ .failure = "TaskUnavailable" };
    pending.async(.result, fetchInner, .{ alloc, io, agent, token });
    return switch (pending.await() catch return .{ .failure = "Canceled" }) {
        .result => |result| result,
        .timeout => .{ .failure = "Timeout" },
    };
}

fn sleep(io: std.Io) void {
    std.Io.sleep(io, .fromSeconds(2), .awake) catch {};
}

fn fetchInner(alloc: std.mem.Allocator, io: std.Io, agent: registry.AgentRecord, token: []const u8) Result {
    const port = agent.agent_api_port orelse return .{ .failure = "AgentApiUnavailable" };
    if (port <= 0 or port > 65535 or @import("../../../network/ip.zig").parseIp(agent.address) == null)
        return .{ .failure = "InvalidAgentAddress" };
    var url_buffer: [128]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buffer, "http://{s}:{d}/v1/status/alerts", .{ agent.address, port }) catch return .{ .failure = "InvalidAgentAddress" };
    const uri = std.Uri.parse(url) catch return .{ .failure = "InvalidAgentAddress" };
    var auth_buffer: [1024]u8 = undefined;
    const auth = std.fmt.bufPrint(&auth_buffer, "Bearer {s}", .{token}) catch return .{ .failure = "InvalidToken" };
    var client: std.http.Client = .{ .allocator = alloc, .io = io };
    defer client.deinit();
    var request = client.request(.GET, uri, .{
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
        .headers = .{ .authorization = .{ .override = auth }, .accept_encoding = .{ .override = "identity" } },
    }) catch |err| return .{ .failure = @errorName(err) };
    defer request.deinit();
    request.sendBodiless() catch |err| return .{ .failure = @errorName(err) };
    var headers: [8192]u8 = undefined;
    var response = request.receiveHead(&headers) catch |err| return .{ .failure = @errorName(err) };
    if (response.head.status != .ok) return .{ .failure = "UnexpectedStatus" };
    var transfer: [8192]u8 = undefined;
    const body = response.reader(&transfer).allocRemaining(alloc, .limited(response_limit)) catch |err| return .{ .failure = @errorName(err) };
    const parsed = std.json.parseFromSlice([]status_store.Status, alloc, body, .{}) catch {
        alloc.free(body);
        return .{ .failure = "InvalidAlertStatus" };
    };
    parsed.deinit();
    return .{ .body = body };
}
