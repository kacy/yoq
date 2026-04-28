const std = @import("std");

const cluster_node = @import("../../../cluster/node.zig");
const agent_registry = @import("../../../cluster/registry.zig");
const store = @import("../../../state/store.zig");
const common = @import("../common.zig");
const http = @import("../../http.zig");

const Response = common.Response;
const RouteContext = common.RouteContext;

const TestProxyLogsOverride = struct {
    path: []const u8,
    body: []const u8,
};

var test_proxy_logs_mutex: std.Io.Mutex = .init;
var test_proxy_logs_override: ?TestProxyLogsOverride = null;

pub fn setTestProxyResponse(path: []const u8, body: []const u8) void {
    test_proxy_logs_mutex.lockUncancelable(std.Options.debug_io);
    defer test_proxy_logs_mutex.unlock(std.Options.debug_io);
    test_proxy_logs_override = .{ .path = path, .body = body };
}

pub fn clearTestProxyResponse() void {
    test_proxy_logs_mutex.lockUncancelable(std.Options.debug_io);
    defer test_proxy_logs_mutex.unlock(std.Options.debug_io);
    test_proxy_logs_override = null;
}

pub fn handle(
    alloc: std.mem.Allocator,
    app_name: []const u8,
    job_name: []const u8,
    request: http.Request,
    ctx: RouteContext,
) Response {
    const node = ctx.cluster orelse return common.badRequest("not running in cluster mode");
    const rank = parseRank(request.query) catch return common.badRequest("invalid rank");
    var hostname_buf: [128]u8 = undefined;
    const hostname = rankHostname(&hostname_buf, job_name, rank) catch return common.internalError();
    const record = store.findAppContainer(alloc, app_name, hostname) catch return common.internalError();
    if (record) |local_record| {
        defer local_record.deinit(alloc);
        return readLocalLogs(alloc, local_record.id);
    }

    if (proxyFromHostingAgent(alloc, node, ctx.join_token, app_name, job_name, rank)) |result| {
        return result;
    }

    const scheduled = agent_registry.countAssignmentsForWorkload(node.stateMachineDb(), app_name, "training", job_name) catch return common.internalError();
    if (scheduled > 0) {
        return .{
            .status = .bad_request,
            .body = "{\"error\":\"training logs are only available on the hosting agent\"}",
            .allocated = false,
        };
    }
    return common.notFound();
}

fn findTestProxyResponse(path: []const u8) ?[]const u8 {
    test_proxy_logs_mutex.lockUncancelable(std.Options.debug_io);
    defer test_proxy_logs_mutex.unlock(std.Options.debug_io);
    const override = test_proxy_logs_override orelse return null;
    if (!std.mem.eql(u8, override.path, path)) return null;
    return override.body;
}

fn parseRank(query: []const u8) !u32 {
    const rank_str = common.extractQueryValue(query, "rank") orelse return 0;
    return std.fmt.parseInt(u32, rank_str, 10) catch error.InvalidRank;
}

fn rankHostname(buf: []u8, job_name: []const u8, rank: u32) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}-rank-{d}", .{ job_name, rank });
}

fn readLocalLogs(alloc: std.mem.Allocator, container_id: []const u8) Response {
    const runtime_logs = @import("../../../runtime/logs.zig");
    const data = runtime_logs.readLogs(alloc, container_id) catch return common.notFound();
    return .{ .status = .ok, .body = data, .allocated = true, .content_type = "text/plain" };
}

fn proxyFromHostingAgent(
    alloc: std.mem.Allocator,
    node: *cluster_node.Node,
    join_token: ?[]const u8,
    app_name: []const u8,
    job_name: []const u8,
    rank: u32,
) ?Response {
    const token = join_token orelse return null;
    const host = agent_registry.findWorkloadHostByRank(alloc, node.stateMachineDb(), app_name, "training", job_name, rank) catch
        return common.internalError();
    if (host == null) return null;
    defer host.?.deinit(alloc);
    const port = host.?.agent_api_port orelse {
        return .{
            .status = .service_unavailable,
            .body = "{\"error\":\"hosting agent does not expose training logs\"}",
            .allocated = false,
        };
    };
    if (port <= 0 or port > 65535) {
        return common.internalError();
    }

    const ip = @import("../../../network/ip.zig").parseIp(host.?.address) orelse {
        return .{
            .status = .service_unavailable,
            .body = "{\"error\":\"hosting agent address is invalid\"}",
            .allocated = false,
        };
    };

    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/training/{s}/{s}/logs?rank={d}", .{ app_name, job_name, rank }) catch
        return common.internalError();

    if (findTestProxyResponse(path)) |body| {
        const owned = alloc.dupe(u8, body) catch return common.internalError();
        return .{ .status = .ok, .body = owned, .allocated = true, .content_type = "text/plain" };
    }

    var resp = @import("../../../cluster/http_client.zig").getWithAuth(alloc, ip, @intCast(port), path, token) catch {
        return .{
            .status = .bad_gateway,
            .body = "{\"error\":\"failed to fetch training logs from hosting agent\"}",
            .allocated = false,
        };
    };
    defer resp.deinit(alloc);

    if (resp.status_code == 200) {
        const body = alloc.dupe(u8, resp.body) catch return common.internalError();
        return .{ .status = .ok, .body = body, .allocated = true, .content_type = "text/plain" };
    }
    if (resp.status_code == 404) return null;
    if (resp.status_code == 401) return common.unauthorized();
    return .{
        .status = .bad_gateway,
        .body = "{\"error\":\"failed to fetch training logs from hosting agent\"}",
        .allocated = false,
    };
}
