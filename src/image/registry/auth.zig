const std = @import("std");
const common = @import("common.zig");
const http_helpers = @import("http.zig");

pub fn authenticate(
    alloc: std.mem.Allocator,
    client: *std.http.Client,
    host: []const u8,
    repository: []const u8,
    scope: []const u8,
) common.AuthError!common.Token {
    var ping_url_buf: [512]u8 = undefined;
    const ping_url = std.fmt.bufPrint(&ping_url_buf, "https://{s}/v2/", .{host}) catch
        return error.OutOfMemory;

    const uri = std.Uri.parse(ping_url) catch return error.AuthFailed;
    const conn = http_helpers.connectWithTimeout(client, uri) catch return error.NetworkError;
    var req = client.request(.GET, uri, .{
        .connection = conn,
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
    }) catch return error.NetworkError;
    defer req.deinit();

    req.sendBodiless() catch return error.NetworkError;

    var redirect_buf: [4096]u8 = undefined;
    const response = req.receiveHead(&redirect_buf) catch return error.NetworkError;

    if (response.head.status == .ok) {
        return .{ .value = alloc.dupe(u8, "") catch return error.OutOfMemory };
    }
    if (response.head.status != .unauthorized) return error.AuthFailed;

    const challenge = parseAuthChallenge(response.head) orelse return error.AuthFailed;

    var token_url_buf: [1024]u8 = undefined;
    const token_url = std.fmt.bufPrint(
        &token_url_buf,
        "{s}?service={s}&scope=repository:{s}:{s}",
        .{ challenge.realm, challenge.service, repository, scope },
    ) catch return error.OutOfMemory;

    var aw: std.Io.Writer.Allocating = .init(alloc);
    defer aw.deinit();

    const result = client.fetch(.{
        .location = .{ .url = token_url },
        .response_writer = &aw.writer,
    }) catch return error.NetworkError;

    if (result.status != .ok) return error.AuthFailed;

    const body_data = aw.writer.buffer[0..aw.writer.end];
    if (body_data.len > common.max_auth_response_size) return error.ResponseTooLarge;

    const token_json = std.json.parseFromSlice(struct {
        token: ?[]const u8 = null,
        access_token: ?[]const u8 = null,
    }, alloc, body_data, .{ .ignore_unknown_fields = true }) catch return error.ParseError;
    defer token_json.deinit();

    const token_str = token_json.value.token orelse
        token_json.value.access_token orelse
        return error.AuthFailed;

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
            remaining = std.mem.trimLeft(u8, remaining, " ,");
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

        if (realm != null and service != null) {
            return .{
                .realm = realm.?,
                .service = service.?,
            };
        }
    }
    return null;
}
