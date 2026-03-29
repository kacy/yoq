const std = @import("std");
const http = @import("../../api/http.zig");
const http2 = @import("http2.zig");
const http2_request = @import("http2_request.zig");
const router = @import("router.zig");

pub const Protocol = enum {
    http1,
    http2,
};

pub const RequestPlan = struct {
    protocol: Protocol,
    method: []u8,
    host: []u8,
    path: []u8,
    route: router.Route,
    http2_stream_id: ?u32 = null,
    end_stream: bool = false,

    pub fn deinit(self: RequestPlan, alloc: std.mem.Allocator) void {
        alloc.free(self.method);
        alloc.free(self.host);
        alloc.free(self.path);
    }
};

pub const PlanError = error{
    InvalidHttp1Request,
    MissingHostHeader,
    RouteNotFound,
} || http2_request.ParseError || std.mem.Allocator.Error;

pub fn planRequest(alloc: std.mem.Allocator, routes: []const router.Route, raw_request: []const u8) PlanError!RequestPlan {
    if (http2.startsWithClientPreface(raw_request)) {
        return try planHttp2Request(alloc, routes, raw_request);
    }
    return try planHttp1Request(alloc, routes, raw_request);
}

fn planHttp1Request(alloc: std.mem.Allocator, routes: []const router.Route, raw_request: []const u8) PlanError!RequestPlan {
    const parsed = (http.parseRequest(raw_request) catch return error.InvalidHttp1Request) orelse return error.InvalidHttp1Request;
    const host_header = http.findHeaderValue(parsed.headers_raw, "Host") orelse return error.MissingHostHeader;
    const host = normalizeHost(host_header);
    const route = router.matchRoute(routes, host, parsed.path_only) orelse return error.RouteNotFound;

    return .{
        .protocol = .http1,
        .method = try alloc.dupe(u8, methodString(parsed.method)),
        .host = try alloc.dupe(u8, host),
        .path = try alloc.dupe(u8, parsed.path),
        .route = route,
    };
}

fn planHttp2Request(alloc: std.mem.Allocator, routes: []const router.Route, raw_request: []const u8) PlanError!RequestPlan {
    const parsed = try http2_request.parseClientConnectionPreface(alloc, raw_request);
    defer parsed.deinit(alloc);

    const host = normalizeHost(parsed.request.authority);
    const route = router.matchRoute(routes, host, parsed.request.path) orelse return error.RouteNotFound;

    return .{
        .protocol = .http2,
        .method = try alloc.dupe(u8, parsed.request.method),
        .host = try alloc.dupe(u8, host),
        .path = try alloc.dupe(u8, parsed.request.path),
        .route = route,
        .http2_stream_id = parsed.request.stream_id,
        .end_stream = parsed.request.end_stream,
    };
}

fn normalizeHost(host_header: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, host_header, ':')) |port_sep| {
        return host_header[0..port_sep];
    }
    return host_header;
}

fn methodString(method: http.Method) []const u8 {
    return switch (method) {
        .GET => "GET",
        .HEAD => "HEAD",
        .POST => "POST",
        .PUT => "PUT",
        .DELETE => "DELETE",
    };
}

fn appendLiteralWithIndexedName(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, name_index: u8, value: []const u8) !void {
    try buf.append(alloc, name_index);
    try buf.append(alloc, @intCast(value.len));
    try buf.appendSlice(alloc, value);
}

fn buildFrame(alloc: std.mem.Allocator, header: http2.FrameHeader, payload: []const u8) ![]u8 {
    const buf = try alloc.alloc(u8, http2.frame_header_len + payload.len);
    errdefer alloc.free(buf);
    try http2.writeFrameHeader(buf[0..http2.frame_header_len], header);
    @memcpy(buf[http2.frame_header_len..], payload);
    return buf;
}

test "planRequest matches HTTP/1 route and strips host port" {
    const alloc = std.testing.allocator;
    const routes = [_]router.Route{
        .{
            .name = "api-v1",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.internal", .path_prefix = "/v1" },
        },
    };

    const plan = try planRequest(
        alloc,
        &routes,
        "GET /v1/users HTTP/1.1\r\nHost: api.internal:17080\r\n\r\n",
    );
    defer plan.deinit(alloc);

    try std.testing.expectEqual(.http1, plan.protocol);
    try std.testing.expectEqualStrings("GET", plan.method);
    try std.testing.expectEqualStrings("api.internal", plan.host);
    try std.testing.expectEqualStrings("/v1/users", plan.path);
    try std.testing.expectEqualStrings("api-v1", plan.route.name);
    try std.testing.expectEqual(@as(?u32, null), plan.http2_stream_id);
    try std.testing.expect(!plan.end_stream);
}

test "planRequest matches prior-knowledge HTTP/2 route" {
    const alloc = std.testing.allocator;
    const routes = [_]router.Route{
        .{
            .name = "grpc",
            .service = "grpc",
            .vip_address = "10.43.0.9",
            .match = .{ .host = "grpc.internal", .path_prefix = "/pkg.Service" },
        },
    };

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(alloc);
    try header_block.append(alloc, 0x83); // :method POST
    try header_block.append(alloc, 0x86); // :scheme http
    try appendLiteralWithIndexedName(&header_block, alloc, 0x01, "grpc.internal");
    try appendLiteralWithIndexedName(&header_block, alloc, 0x04, "/pkg.Service/Call");

    const settings = try buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const headers = try buildFrame(alloc, .{
        .length = @intCast(header_block.items.len),
        .frame_type = .headers,
        .flags = 0x5,
        .stream_id = 1,
    }, header_block.items);
    defer alloc.free(headers);

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(alloc);
    try request_bytes.appendSlice(alloc, http2.client_preface);
    try request_bytes.appendSlice(alloc, settings);
    try request_bytes.appendSlice(alloc, headers);

    const plan = try planRequest(alloc, &routes, request_bytes.items);
    defer plan.deinit(alloc);

    try std.testing.expectEqual(.http2, plan.protocol);
    try std.testing.expectEqualStrings("POST", plan.method);
    try std.testing.expectEqualStrings("grpc.internal", plan.host);
    try std.testing.expectEqualStrings("/pkg.Service/Call", plan.path);
    try std.testing.expectEqualStrings("grpc", plan.route.service);
    try std.testing.expectEqual(@as(?u32, 1), plan.http2_stream_id);
    try std.testing.expect(plan.end_stream);
}

test "planRequest returns RouteNotFound for unmatched HTTP/2 request" {
    const alloc = std.testing.allocator;
    const routes = [_]router.Route{
        .{
            .name = "api",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.internal", .path_prefix = "/" },
        },
    };

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(alloc);
    try header_block.append(alloc, 0x83);
    try header_block.append(alloc, 0x86);
    try appendLiteralWithIndexedName(&header_block, alloc, 0x01, "grpc.internal");
    try appendLiteralWithIndexedName(&header_block, alloc, 0x04, "/pkg.Service/Call");

    const settings = try buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const headers = try buildFrame(alloc, .{
        .length = @intCast(header_block.items.len),
        .frame_type = .headers,
        .flags = 0x4,
        .stream_id = 1,
    }, header_block.items);
    defer alloc.free(headers);

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(alloc);
    try request_bytes.appendSlice(alloc, http2.client_preface);
    try request_bytes.appendSlice(alloc, settings);
    try request_bytes.appendSlice(alloc, headers);

    try std.testing.expectError(error.RouteNotFound, planRequest(alloc, &routes, request_bytes.items));
}
