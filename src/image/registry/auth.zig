const std = @import("std");
const common = @import("common.zig");
const http_helpers = @import("http.zig");
const credential_store = @import("credentials.zig");

pub fn authenticate(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    scope: []const u8,
) common.AuthError!common.Token {
    return authenticateReference(alloc, client, host, repository, scope, null);
}

pub fn authenticateReference(alloc: std.mem.Allocator, client: *std.http.Client, host: []const u8, repository: []const u8, scope: []const u8, reference: ?[]const u8) common.AuthError!common.Token {
    return tokenOperationWithDeadline(alloc, client.io, authenticateReferenceInner, .{ alloc, client, host, repository, scope, reference }, common.registry_timeout_sec * 1000);
}

// cancellation covers dns, tls, headers and body reads with one elapsed-time
// budget. join both tasks before the caller can reuse the client or buffers.
fn tokenOperationWithDeadline(alloc: std.mem.Allocator, io: std.Io, comptime operation: anytype, args: anytype, timeout_ms: u64) common.AuthError!common.Token {
    const Result = union(enum) { token: common.AuthError!common.Token, expired: void };
    var results: [2]Result = undefined;
    var pending = std.Io.Select(Result).init(io, &results);
    defer while (pending.cancel()) |result| switch (result) {
        .token => |outcome| if (outcome) |token| {
            std.crypto.secureZero(u8, @constCast(token.value));
            alloc.free(token.value);
        } else |_| {},
        .expired => {},
    };
    pending.concurrent(.expired, waitForDeadline, .{ io, timeout_ms }) catch return error.NetworkError;
    pending.async(.token, operation, args);
    return switch (pending.await() catch return error.NetworkError) {
        .token => |result| result,
        .expired => error.NetworkError,
    };
}

fn waitForDeadline(io: std.Io, timeout_ms: u64) void {
    std.Io.sleep(io, .fromMilliseconds(@intCast(timeout_ms)), .awake) catch {};
}

fn authenticateReferenceInner(alloc: std.mem.Allocator, client: *std.http.Client, host: []const u8, repository: []const u8, scope: []const u8, reference: ?[]const u8) common.AuthError!common.Token {
    const credentials = try credential_store.load(alloc, host);
    defer if (credentials) |owned| owned.deinit(alloc);
    var basic_buffer: [8192]u8 = undefined;
    defer std.crypto.secureZero(u8, &basic_buffer);
    const basic = if (credentials) |owned|
        std.fmt.bufPrint(&basic_buffer, "Basic {s}", .{owned.encoded_auth}) catch return error.AuthFailed
    else
        null;

    // a public /v2/ ping does not establish access to a private repository.
    var url_buffer: [2048]u8 = undefined;
    const url = if (reference) |name|
        std.fmt.bufPrint(&url_buffer, "https://{s}/v2/{s}/manifests/{s}", .{ host, repository, name }) catch return error.AuthFailed
    else
        std.fmt.bufPrint(&url_buffer, "https://{s}/v2/", .{host}) catch return error.AuthFailed;
    const uri = std.Uri.parse(url) catch return error.AuthFailed;
    var req = http_helpers.requestWithTimeout(client, .GET, uri, .{
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
        .extra_headers = &.{.{ .name = "Accept", .value = common.manifest_accept }},
        .headers = .{ .authorization = if (basic) |value| .{ .override = value } else .omit },
    }) catch return error.NetworkError;
    defer req.deinit();
    req.sendBodiless() catch return error.NetworkError;
    var header_buffer: [8192]u8 = undefined;
    const response = req.receiveHead(&header_buffer) catch return error.NetworkError;
    if (response.head.status == .ok or response.head.status == .not_found) {
        return .{ .kind = if (credentials != null) .basic else .bearer, .value = try alloc.dupe(u8, if (credentials) |owned| owned.encoded_auth else "") };
    }
    if (response.head.status != .unauthorized) return error.AuthFailed;
    const challenge = parseAuthChallenge(response.head) orelse return error.AuthFailed;
    var token_url_buffer: [4096]u8 = undefined;
    const token_url = try buildTokenUrl(&token_url_buffer, challenge, repository, scope);

    const token_uri = std.Uri.parse(token_url) catch return error.AuthFailed;
    if (!std.ascii.eqlIgnoreCase(token_uri.scheme, "https")) return error.AuthFailed;
    if (token_uri.user != null or token_uri.password != null or token_uri.fragment != null) return error.AuthFailed;
    if (credentials) |owned| {
        if (!credential_store.permitsTokenUrl(host, owned, token_uri)) return error.AuthFailed;
    }
    return fetchToken(alloc, client, token_uri, basic);
}

fn buildTokenUrl(buffer: []u8, challenge: common.AuthChallenge, repository: []const u8, scope: []const u8) common.AuthError![]const u8 {
    var writer = std.Io.Writer.fixed(buffer);
    writer.print("{s}{s}", .{ challenge.realm, if (std.mem.indexOfScalar(u8, challenge.realm, '?') != null) "&" else "?" }) catch return error.AuthFailed;
    if (challenge.service.len > 0) {
        writer.writeAll("service=") catch return error.AuthFailed;
        std.Uri.Component.percentEncode(&writer, challenge.service, queryByte) catch return error.AuthFailed;
        writer.writeByte('&') catch return error.AuthFailed;
    }
    writer.writeAll("scope=repository%3A") catch return error.AuthFailed;
    std.Uri.Component.percentEncode(&writer, repository, queryByte) catch return error.AuthFailed;
    writer.writeAll("%3A") catch return error.AuthFailed;
    std.Uri.Component.percentEncode(&writer, scope, queryByte) catch return error.AuthFailed;
    return writer.buffer[0..writer.end];
}

fn queryByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or byte == '_' or byte == '~';
}

fn fetchToken(alloc: std.mem.Allocator, client: *std.http.Client, uri: std.Uri, authorization: ?[]const u8) common.AuthError!common.Token {
    var request = http_helpers.requestWithTimeout(client, .GET, uri, .{
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
        .headers = .{ .authorization = if (authorization) |value| .{ .override = value } else .omit },
    }) catch return error.NetworkError;
    defer request.deinit();
    request.sendBodiless() catch return error.NetworkError;
    var header_buffer: [8192]u8 = undefined;
    var response = request.receiveHead(&header_buffer) catch return error.NetworkError;
    if (response.head.status != .ok) return error.AuthFailed;
    if (response.head.content_length) |length| {
        if (length > common.max_auth_response_size) return error.ResponseTooLarge;
    }
    var transfer_buffer: [8192]u8 = undefined;
    const body_data = try http_helpers.readBody(alloc, response.reader(&transfer_buffer), common.max_auth_response_size);
    defer {
        std.crypto.secureZero(u8, body_data);
        alloc.free(body_data);
    }

    const token_json = std.json.parseFromSlice(struct {
        token: ?[]const u8 = null,
        access_token: ?[]const u8 = null,
    }, alloc, body_data, .{ .ignore_unknown_fields = true }) catch return error.ParseError;
    defer token_json.deinit();

    const token_str = token_json.value.token orelse
        token_json.value.access_token orelse
        return error.AuthFailed;

    if (token_str.len == 0 or token_str.len > 8192 - "Bearer ".len) return error.AuthFailed;
    for (token_str) |byte| if (byte < 0x21 or byte == 0x7f) return error.AuthFailed;
    return .{ .value = alloc.dupe(u8, token_str) catch return error.OutOfMemory };
}

pub fn parseAuthChallenge(head: std.http.Client.Response.Head) ?common.AuthChallenge {
    var it = head.iterateHeaders();
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "www-authenticate")) continue;

        const value = header.value;
        const space_idx = std.mem.indexOfScalar(u8, value, ' ') orelse continue;
        const scheme = value[0..space_idx];
        if (!std.ascii.eqlIgnoreCase(scheme, "Bearer")) continue;
        const params = value[space_idx + 1 ..];

        var realm: ?[]const u8 = null;
        var service: ?[]const u8 = null;
        var remaining = params;

        while (remaining.len > 0) {
            remaining = std.mem.trimStart(u8, remaining, " ,");
            if (remaining.len == 0) break;

            const eq_idx = std.mem.indexOfScalar(u8, remaining, '=') orelse break;
            const key = remaining[0..eq_idx];
            remaining = remaining[eq_idx + 1 ..];

            if (remaining.len == 0 or remaining[0] != '"') break;
            remaining = remaining[1..];
            const close_idx = std.mem.indexOfScalar(u8, remaining, '"') orelse break;
            const value_part = remaining[0..close_idx];
            remaining = remaining[close_idx + 1 ..];

            if (std.mem.eql(u8, key, "realm")) {
                realm = value_part;
            } else if (std.mem.eql(u8, key, "service")) {
                service = value_part;
            }
        }

        if (realm != null) {
            return .{
                .realm = realm.?,
                .service = service orelse "",
            };
        }
    }
    return null;
}

test "registry token fetch rejects oversized bodies before buffering them" {
    const Server = @import("test_support.zig").Server;
    const alloc = std.testing.allocator;
    for ([_]Server.Reply{
        .{ .framing = .length, .repeated_bytes = common.max_auth_response_size + 1 },
        .{ .framing = .chunked, .repeated_bytes = common.max_auth_response_size + 1 },
        .{ .framing = .close, .repeated_bytes = common.max_auth_response_size + 1 },
    }) |reply| {
        var server = try Server.init(&.{reply});
        defer server.deinit();
        try server.start();
        var host_buffer: [64]u8 = undefined;
        var url_buffer: [128]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buffer, "http://{s}/token", .{try server.host(&host_buffer)});
        var client: std.http.Client = .{ .io = std.testing.io, .allocator = alloc };
        defer client.deinit();
        try std.testing.expectError(error.ResponseTooLarge, fetchToken(alloc, &client, try std.Uri.parse(url), null));
    }
}

test "registry token fetch accepts access tokens and rejects header control bytes" {
    const Server = @import("test_support.zig").Server;
    const alloc = std.testing.allocator;
    for ([_]struct { body: []const u8, valid: bool }{
        .{ .body = "{\"access_token\":\"opaque-token\"}", .valid = true },
        .{ .body = "{\"token\":\"invalid\\r\\nheader\"}", .valid = false },
    }) |case| {
        var server = try Server.init(&.{.{ .body = case.body }});
        defer server.deinit();
        try server.start();
        var host_buffer: [64]u8 = undefined;
        var url_buffer: [128]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buffer, "http://{s}/token", .{try server.host(&host_buffer)});
        var client: std.http.Client = .{ .io = std.testing.io, .allocator = alloc };
        defer client.deinit();
        if (case.valid) {
            const token = try fetchToken(alloc, &client, try std.Uri.parse(url), null);
            defer alloc.free(token.value);
            try std.testing.expectEqualStrings("opaque-token", token.value);
        } else try std.testing.expectError(error.AuthFailed, fetchToken(alloc, &client, try std.Uri.parse(url), null));
    }
}

test "registry token query preserves realm parameters and escapes repository scope" {
    var buffer: [512]u8 = undefined;
    const url = try buildTokenUrl(&buffer, .{ .realm = "https://auth.example/token?existing=1", .service = "registry&other=bad" }, "team/image", "push,pull");
    try std.testing.expectEqualStrings("https://auth.example/token?existing=1&service=registry%26other%3Dbad&scope=repository%3Ateam%2Fimage%3Apush%2Cpull", url);
    const no_service = try buildTokenUrl(&buffer, .{ .realm = "https://auth.example/token", .service = "" }, "team/image", "pull");
    try std.testing.expectEqualStrings("https://auth.example/token?scope=repository%3Ateam%2Fimage%3Apull", no_service);
}

test "registry authentication deadline cancels a stalled token response" {
    const Server = @import("test_support.zig").Server;
    const alloc = std.testing.allocator;
    var server = try Server.init(&.{.{ .body = "{\"token\":\"late\"}", .delay_ms = 200 }});
    defer server.deinit();
    try server.start();
    var host_buffer: [64]u8 = undefined;
    var url_buffer: [128]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buffer, "http://{s}/token", .{try server.host(&host_buffer)}));
    var client: std.http.Client = .{ .io = std.testing.io, .allocator = alloc };
    defer client.deinit();
    try std.testing.expectError(error.NetworkError, tokenOperationWithDeadline(alloc, client.io, fetchToken, .{ alloc, &client, uri, @as(?[]const u8, null) }, 30));
}

test "registry token exchange sends scoped basic credentials" {
    const Server = @import("test_support.zig").Server;
    const alloc = std.testing.allocator;
    var server = try Server.init(&.{.{ .body = "{\"token\":\"private-token\"}" }});
    defer server.deinit();
    try server.start();
    var host_buffer: [64]u8 = undefined;
    var url_buffer: [128]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buffer, "http://{s}/token?scope=repository%3Aprivate%3Apull", .{try server.host(&host_buffer)}));
    var client: std.http.Client = .{ .io = std.testing.io, .allocator = alloc };
    defer client.deinit();
    const token = try fetchToken(alloc, &client, uri, "Basic dXNlcjpwYXNz");
    defer alloc.free(token.value);
    try std.testing.expectEqualStrings("private-token", token.value);
    server.worker.?.join();
    server.worker = null;
    const request = server.last_request[0..server.last_request_length];
    try std.testing.expect(std.mem.startsWith(u8, request, "GET /token?scope=repository%3Aprivate%3Apull HTTP/1.1\r\n"));
    const auth_value = @import("../../api/http.zig").findHeaderValue(request, "Authorization") orelse return error.MissingAuthorization;
    try std.testing.expectEqualStrings("Basic dXNlcjpwYXNz", auth_value);
    const encoding = @import("../../api/http.zig").findHeaderValue(request, "Accept-Encoding") orelse return error.MissingEncoding;
    try std.testing.expectEqualStrings("identity", encoding);
}

test "registry token redirect never forwards credentials to its target" {
    const Server = @import("test_support.zig").Server;
    var target = try Server.init(&.{.{ .body = "{\"token\":\"unexpected\"}" }});
    defer target.deinit();
    try target.start();
    var target_host: [64]u8 = undefined;
    var location_buffer: [128]u8 = undefined;
    const location = try std.fmt.bufPrint(&location_buffer, "Location: http://{s}/secret\r\n", .{try target.host(&target_host)});
    var source = try Server.init(&.{.{ .status = "307 Temporary Redirect", .headers = location }});
    defer source.deinit();
    try source.start();
    var host_buffer: [64]u8 = undefined;
    var url_buffer: [128]u8 = undefined;
    const uri = try std.Uri.parse(try std.fmt.bufPrint(&url_buffer, "http://{s}/token", .{try source.host(&host_buffer)}));
    var client: std.http.Client = .{ .io = std.testing.io, .allocator = std.testing.allocator };
    defer client.deinit();
    const result = fetchToken(std.testing.allocator, &client, uri, "Basic dXNlcjpwYXNz");
    if (result) |token| {
        std.testing.allocator.free(token.value);
        return error.UnexpectedToken;
    } else |err| try std.testing.expect(err == error.NetworkError or err == error.AuthFailed);
    _ = std.os.linux.shutdown(target.fd, 2);
    target.worker.?.join();
    target.worker = null;
    try std.testing.expectEqual(@as(usize, 0), target.requests);
}
