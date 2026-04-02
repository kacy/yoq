const std = @import("std");
const http = @import("../../api/http.zig");
const http2 = @import("http2.zig");
const proxy_helpers = @import("proxy_helpers.zig");
const http2_request = @import("http2_request.zig");
const router = @import("router.zig");

pub const Protocol = enum {
    http1,
    http2,
};

pub const RequestPlan = struct {
    protocol: Protocol,
    method_enum: ?http.Method,
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
    IncompleteHttp1Request,
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
    const parsed = (http.parseRequest(raw_request) catch return error.InvalidHttp1Request) orelse return error.IncompleteHttp1Request;
    const host_header = http.findHeaderValue(parsed.headers_raw, "Host") orelse return error.MissingHostHeader;
    const host = proxy_helpers.normalizeHost(host_header);
    const request_headers = try router.collectHttp1Headers(alloc, parsed.headers_raw);
    defer alloc.free(request_headers);
    const route = router.matchRoute(routes, proxy_helpers.methodString(parsed.method), host, parsed.path_only, request_headers) orelse return error.RouteNotFound;

    return .{
        .protocol = .http1,
        .method_enum = parsed.method,
        .method = try alloc.dupe(u8, proxy_helpers.methodString(parsed.method)),
        .host = try alloc.dupe(u8, host),
        .path = try alloc.dupe(u8, parsed.path),
        .route = route,
    };
}

fn planHttp2Request(alloc: std.mem.Allocator, routes: []const router.Route, raw_request: []const u8) PlanError!RequestPlan {
    const parsed = try http2_request.parseClientConnectionPreface(alloc, raw_request);
    defer parsed.deinit(alloc);

    const host = proxy_helpers.normalizeHost(parsed.request.authority);
    var request_headers: std.ArrayList(router.RequestHeader) = .empty;
    defer request_headers.deinit(alloc);
    for (parsed.headers) |header| {
        try request_headers.append(alloc, .{
            .name = header.name,
            .value = header.value,
        });
    }
    const route = router.matchRoute(routes, parsed.request.method, host, parsed.request.path, request_headers.items) orelse return error.RouteNotFound;

    return .{
        .protocol = .http2,
        .method_enum = proxy_helpers.parseMethodString(parsed.request.method),
        .method = try alloc.dupe(u8, parsed.request.method),
        .host = try alloc.dupe(u8, host),
        .path = try alloc.dupe(u8, parsed.request.path),
        .route = route,
        .http2_stream_id = parsed.request.stream_id,
        .end_stream = parsed.request.end_stream,
    };
}

fn appendLiteralWithIndexedName(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, name_index: u8, value: []const u8) !void {
    if (value.len > 127) return error.HeaderTooLong;
    try buf.append(alloc, name_index);
    try buf.append(alloc, @intCast(value.len));
    try buf.appendSlice(alloc, value);
}

fn appendLiteralHeader(buf: *std.ArrayList(u8), alloc: std.mem.Allocator, name: []const u8, value: []const u8) !void {
    if (name.len > 127 or value.len > 127) return error.HeaderTooLong;
    try buf.append(alloc, 0x00);
    try buf.append(alloc, @intCast(name.len));
    try buf.appendSlice(alloc, name);
    try buf.append(alloc, @intCast(value.len));
    try buf.appendSlice(alloc, value);
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
    try std.testing.expectEqual(http.Method.GET, plan.method_enum.?);
    try std.testing.expectEqualStrings("GET", plan.method);
    try std.testing.expectEqualStrings("api.internal", plan.host);
    try std.testing.expectEqualStrings("/v1/users", plan.path);
    try std.testing.expectEqualStrings("api-v1", plan.route.name);
    try std.testing.expectEqual(@as(?u32, null), plan.http2_stream_id);
    try std.testing.expect(!plan.end_stream);
}

test "planRequest prefers header-specific HTTP/1 route" {
    const alloc = std.testing.allocator;
    const routes = [_]router.Route{
        .{
            .name = "api-default",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.internal", .path_prefix = "/v1" },
        },
        .{
            .name = "api-canary",
            .service = "api-canary",
            .vip_address = "10.43.0.3",
            .match = .{ .host = "api.internal", .path_prefix = "/v1" },
            .header_matches = &.{
                .{ .name = "x-env", .value = "canary" },
            },
        },
    };

    const plan = try planRequest(
        alloc,
        &routes,
        "GET /v1/users HTTP/1.1\r\nHost: api.internal\r\nX-Env: canary\r\n\r\n",
    );
    defer plan.deinit(alloc);

    try std.testing.expectEqualStrings("api-canary", plan.route.service);
}

test "planRequest prefers method-specific HTTP/1 route" {
    const alloc = std.testing.allocator;
    const routes = [_]router.Route{
        .{
            .name = "api-default",
            .service = "api",
            .vip_address = "10.43.0.2",
            .match = .{ .host = "api.internal", .path_prefix = "/v1" },
        },
        .{
            .name = "api-write",
            .service = "api-write",
            .vip_address = "10.43.0.3",
            .match = .{ .host = "api.internal", .path_prefix = "/v1" },
            .method_matches = &.{
                .{ .method = "POST" },
            },
        },
    };

    const plan = try planRequest(
        alloc,
        &routes,
        "POST /v1/users HTTP/1.1\r\nHost: api.internal\r\n\r\n",
    );
    defer plan.deinit(alloc);

    try std.testing.expectEqualStrings("api-write", plan.route.service);
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

    const settings = try http2.buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const headers = try http2.buildFrame(alloc, .{
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
    try std.testing.expectEqual(http.Method.POST, plan.method_enum.?);
    try std.testing.expectEqualStrings("POST", plan.method);
    try std.testing.expectEqualStrings("grpc.internal", plan.host);
    try std.testing.expectEqualStrings("/pkg.Service/Call", plan.path);
    try std.testing.expectEqualStrings("grpc", plan.route.service);
    try std.testing.expectEqual(@as(?u32, 1), plan.http2_stream_id);
    try std.testing.expect(plan.end_stream);
}

test "planRequest prefers header-specific HTTP/2 route" {
    const alloc = std.testing.allocator;
    const routes = [_]router.Route{
        .{
            .name = "grpc-default",
            .service = "grpc",
            .vip_address = "10.43.0.9",
            .match = .{ .host = "grpc.internal", .path_prefix = "/pkg.Service" },
        },
        .{
            .name = "grpc-canary",
            .service = "grpc-canary",
            .vip_address = "10.43.0.10",
            .match = .{ .host = "grpc.internal", .path_prefix = "/pkg.Service" },
            .header_matches = &.{
                .{ .name = "x-env", .value = "canary" },
            },
        },
    };

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(alloc);
    try header_block.append(alloc, 0x83);
    try header_block.append(alloc, 0x86);
    try appendLiteralWithIndexedName(&header_block, alloc, 0x01, "grpc.internal");
    try appendLiteralWithIndexedName(&header_block, alloc, 0x04, "/pkg.Service/Call");
    try appendLiteralHeader(&header_block, alloc, "x-env", "canary");

    const settings = try http2.buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const headers = try http2.buildFrame(alloc, .{
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

    try std.testing.expectEqualStrings("grpc-canary", plan.route.service);
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

    const settings = try http2.buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const headers = try http2.buildFrame(alloc, .{
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

test "planRequest preserves unsupported HTTP/2 method as null method_enum" {
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
    try appendLiteralWithIndexedName(&header_block, alloc, 0x02, "PATCH");
    try header_block.append(alloc, 0x86);
    try appendLiteralWithIndexedName(&header_block, alloc, 0x01, "grpc.internal");
    try appendLiteralWithIndexedName(&header_block, alloc, 0x04, "/pkg.Service/Call");

    const settings = try http2.buildFrame(alloc, .{
        .length = 0,
        .frame_type = .settings,
        .flags = 0,
        .stream_id = 0,
    }, "");
    defer alloc.free(settings);

    const headers = try http2.buildFrame(alloc, .{
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

    const plan = try planRequest(alloc, &routes, request_bytes.items);
    defer plan.deinit(alloc);

    try std.testing.expectEqual(.http2, plan.protocol);
    try std.testing.expectEqual(@as(?http.Method, null), plan.method_enum);
    try std.testing.expectEqualStrings("PATCH", plan.method);
}
