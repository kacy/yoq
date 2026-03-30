const std = @import("std");
const posix = std.posix;
const types = @import("types.zig");

pub fn runCheck(container_ip: [4]u8, config: anytype) bool {
    return switch (config.check_type) {
        .http => |http| runHttpCheck(container_ip, http.port, http.path, config.timeout),
        .tcp => |tcp| runTcpCheck(container_ip, tcp.port, config.timeout),
        .grpc => |grpc| runGrpcCheck(container_ip, grpc.port, config.timeout),
        .exec => false,
    };
}

pub fn runHttpCheck(container_ip: [4]u8, port: u16, path: []const u8, timeout: u32) bool {
    const sock = tcpConnect(container_ip, port, timeout) orelse return false;
    defer posix.close(sock);

    var request_buf: [512]u8 = undefined;
    const request = std.fmt.bufPrint(
        &request_buf,
        "GET {s} HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        .{path},
    ) catch return false;

    _ = posix.write(sock, request) catch return false;

    var response_buf: [256]u8 = undefined;
    const bytes_read = posix.read(sock, &response_buf) catch return false;
    if (bytes_read < 12) return false;

    return isHttp2xx(response_buf[0..bytes_read]);
}

pub fn isHttp2xx(response: []const u8) bool {
    if (response.len < 12) return false;
    if (!std.mem.startsWith(u8, response, "HTTP/1.")) return false;
    return response[9] == '2';
}

pub fn runTcpCheck(container_ip: [4]u8, port: u16, timeout: u32) bool {
    const sock = tcpConnect(container_ip, port, timeout) orelse return false;
    posix.close(sock);
    return true;
}

pub fn runGrpcCheck(container_ip: [4]u8, port: u16, timeout: u32) bool {
    const sock = tcpConnect(container_ip, port, timeout) orelse return false;
    defer posix.close(sock);

    const client_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    writeAll(sock, client_preface) catch return false;

    const settings_frame = [_]u8{
        0, 0, 0, // payload length
        0x4, // SETTINGS
        0, // flags
        0, 0, 0, 0, // stream id
    };
    _ = posix.write(sock, &settings_frame) catch return false;

    var frame_header: [9]u8 = undefined;
    readExact(sock, &frame_header) catch return false;
    return isHttp2SettingsFrame(&frame_header);
}

pub fn isHttp2SettingsFrame(frame_header: []const u8) bool {
    if (frame_header.len < 9) return false;
    if (frame_header[3] != 0x4) return false;
    const stream_id = std.mem.readInt(u32, frame_header[5..9], .big) & 0x7fff_ffff;
    return stream_id == 0;
}

fn tcpConnect(container_ip: [4]u8, port: u16, timeout: u32) ?posix.socket_t {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch return null;
    errdefer posix.close(sock);

    const tv = posix.timeval{
        .sec = @intCast(timeout),
        .usec = 0,
    };
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};
    posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&tv)) catch {};

    const addr = posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(container_ip),
    };

    posix.connect(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch return null;
    return sock;
}

fn writeAll(sock: posix.socket_t, bytes: []const u8) !void {
    var written: usize = 0;
    while (written < bytes.len) {
        const chunk = try posix.write(sock, bytes[written..]);
        if (chunk == 0) return error.WriteFailed;
        written += chunk;
    }
}

fn readExact(sock: posix.socket_t, buf: []u8) !void {
    var read_total: usize = 0;
    while (read_total < buf.len) {
        const chunk = try posix.read(sock, buf[read_total..]);
        if (chunk == 0) return error.ReadFailed;
        read_total += chunk;
    }
}

const TestServerMode = enum {
    settings,
    wrong_frame,
};

const BoundTestListener = struct {
    fd: posix.socket_t,
    port: u16,
};

fn initTestListenerSocket() !BoundTestListener {
    const reuseaddr: i32 = 1;
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);

    var attempt: usize = 0;
    while (attempt < 50) : (attempt += 1) {
        const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch {
            if (attempt + 1 == 50) return error.SkipZigTest;
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };
        errdefer posix.close(fd);

        posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuseaddr)) catch {};

        posix.bind(fd, &addr.any, addr.getOsSockLen()) catch {
            if (attempt + 1 == 50) return error.SkipZigTest;
            posix.close(fd);
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };
        posix.listen(fd, 1) catch {
            if (attempt + 1 == 50) return error.SkipZigTest;
            posix.close(fd);
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };

        var bound_addr: posix.sockaddr.in = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        posix.getsockname(fd, @ptrCast(&bound_addr), &bound_len) catch {
            if (attempt + 1 == 50) return error.SkipZigTest;
            posix.close(fd);
            std.Thread.sleep(10 * std.time.ns_per_ms);
            continue;
        };

        return .{
            .fd = fd,
            .port = std.mem.bigToNative(u16, bound_addr.port),
        };
    }

    unreachable;
}

const TestServer = struct {
    listen_fd: posix.socket_t,
    port: u16,
    mode: TestServerMode,
    thread: ?std.Thread = null,

    fn init(mode: TestServerMode) !TestServer {
        const listener = try initTestListenerSocket();
        return .{
            .listen_fd = listener.fd,
            .port = listener.port,
            .mode = mode,
        };
    }

    fn start(self: *TestServer) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
    }

    fn deinit(self: *TestServer) void {
        if (self.thread) |thread| thread.join();
        posix.close(self.listen_fd);
    }

    fn run(self: *TestServer) void {
        const client_fd = posix.accept(self.listen_fd, null, null, posix.SOCK.CLOEXEC) catch return;
        defer posix.close(client_fd);

        var preface_and_settings: [33]u8 = undefined;
        readExact(client_fd, &preface_and_settings) catch return;

        const response = switch (self.mode) {
            .settings => [_]u8{
                0,   0, 0,
                0x4, 0, 0,
                0,   0, 0,
            },
            .wrong_frame => [_]u8{
                0,   0, 0,
                0x0, 0, 0,
                0,   0, 0,
            },
        };
        _ = posix.write(client_fd, &response) catch {};
    }
};

test "isHttp2SettingsFrame accepts server settings frame" {
    try std.testing.expect(isHttp2SettingsFrame(&[_]u8{
        0,   0, 0,
        0x4, 0, 0,
        0,   0, 0,
    }));
}

test "isHttp2SettingsFrame rejects non-settings frame" {
    try std.testing.expect(!isHttp2SettingsFrame(&[_]u8{
        0,   0, 0,
        0x0, 0, 0,
        0,   0, 0,
    }));
}

test "runGrpcCheck succeeds after HTTP/2 preface exchange" {
    var server = try TestServer.init(.settings);
    defer server.deinit();
    try server.start();

    try std.testing.expect(runGrpcCheck(.{ 127, 0, 0, 1 }, server.port, 1));
}

test "runGrpcCheck fails when server does not return settings" {
    var server = try TestServer.init(.wrong_frame);
    defer server.deinit();
    try server.start();

    try std.testing.expect(!runGrpcCheck(.{ 127, 0, 0, 1 }, server.port, 1));
}
