const std = @import("std");
const posix = std.posix;
const log = @import("../../lib/log.zig");

pub fn extractHost(request: []const u8) ?[]const u8 {
    const headers = headerBlock(request) orelse return null;
    var iter = std.mem.splitSequence(u8, headers, "\r\n");
    while (iter.next()) |line| {
        if (line.len <= "host:".len) continue;
        if (!std.ascii.eqlIgnoreCase(line[0.."host".len], "host")) continue;
        if (line["host".len] != ':') continue;

        var start: usize = "host:".len;
        while (start < line.len and line[start] == ' ') : (start += 1) {}
        const host = line[start..];
        if (!isSafeHost(host)) return null;
        return if (host.len > 0) host else null;
    }
    return null;
}

pub fn extractAcmeChallengeToken(request: []const u8) ?[]const u8 {
    const line_end = std.mem.indexOf(u8, request, "\r\n") orelse return null;
    const line = request[0..line_end];
    if (!std.mem.startsWith(u8, line, "GET /.well-known/acme-challenge/")) return null;

    const prefix = "GET /.well-known/acme-challenge/";
    const token_start = prefix.len;
    const token_end = std.mem.indexOfScalarPos(u8, line, token_start, ' ') orelse return null;
    const token = line[token_start..token_end];
    if (token.len == 0) return null;
    for (token) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return null;
    }
    return token;
}

pub fn extractRequestTarget(request: []const u8) ?[]const u8 {
    const line_end = std.mem.indexOf(u8, request, "\r\n") orelse return null;
    const line = request[0..line_end];
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return null;
    const method = line[0..first_space];
    if (!isSupportedMethod(method)) return null;

    const target_start = first_space + 1;
    const target_end = std.mem.indexOfScalarPos(u8, line, target_start, ' ') orelse return null;
    const target = line[target_start..target_end];
    if (target.len == 0 or target[0] != '/') return null;
    return target;
}

fn headerBlock(request: []const u8) ?[]const u8 {
    const first_line_end = std.mem.indexOf(u8, request, "\r\n") orelse return null;
    const header_end = std.mem.indexOfPos(u8, request, first_line_end + 2, "\r\n\r\n") orelse return null;
    return request[first_line_end + 2 .. header_end];
}

fn isSafeHost(host: []const u8) bool {
    if (host.len == 0) return false;
    for (host) |c| {
        if (c <= 0x20 or c == 0x7f) return false;
        if (c == '/' or c == '\\') return false;
    }
    return true;
}

fn isSupportedMethod(method: []const u8) bool {
    return std.mem.eql(u8, method, "GET") or
        std.mem.eql(u8, method, "HEAD") or
        std.mem.eql(u8, method, "POST") or
        std.mem.eql(u8, method, "PUT") or
        std.mem.eql(u8, method, "DELETE") or
        std.mem.eql(u8, method, "PATCH") or
        std.mem.eql(u8, method, "OPTIONS");
}

pub fn sendCloseNotify(fd: posix.fd_t) void {
    const close_notify = [_]u8{
        0x15,
        0x03,
        0x03,
        0x00,
        0x02,
        0x01,
        0x00,
    };
    _ = @import("compat").posix.write(fd, &close_notify) catch |e| {
        log.warn("tls close_notify write failed: {}", .{e});
    };
}

pub fn sendHttpResponse(fd: posix.fd_t, status: []const u8, body: []const u8) void {
    var buf: [512]u8 = undefined;
    const response = std.fmt.bufPrint(&buf, "HTTP/1.1 {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status, body.len, body }) catch return;
    _ = @import("compat").posix.write(fd, response) catch |e| {
        log.warn("tls http response write failed: {}", .{e});
    };
}

pub fn formatRedirectResponse(
    buf: []u8,
    location: []const u8,
) ![]const u8 {
    return std.fmt.bufPrint(
        buf,
        "HTTP/1.1 308 Permanent Redirect\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        .{location},
    );
}
