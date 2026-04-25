const std = @import("std");
const platform = @import("platform");
const posix = std.posix;
const http = @import("../../api/http.zig");
const connection_runtime = @import("../../api/server/connection_runtime.zig");
const common = @import("../../api/routes/common.zig");
const store = @import("../../state/store.zig");
const logs = @import("../../runtime/logs.zig");

const TestLogLookupOverride = struct {
    app_name: []const u8,
    job_name: []const u8,
    rank: u32,
    container_id: []const u8,
};

var test_log_lookup_mutex: std.Io.Mutex = .init;
var test_log_lookup_overrides: [8]TestLogLookupOverride = undefined;
var test_log_lookup_override_len: usize = 0;

pub const LogServer = struct {
    alloc: std.mem.Allocator,
    listen_fd: posix.fd_t,
    token: []const u8,
    port: u16,
    running: std.atomic.Value(bool),
    started: std.atomic.Value(bool),

    pub fn init(alloc: std.mem.Allocator, port: u16, token: []const u8) !LogServer {
        const fd = try platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0);
        errdefer platform.posix.close(fd);

        const one: c_int = 1;
        _ = posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&one)) catch {};

        const addr = platform.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
        try platform.posix.bind(fd, &addr.any, addr.getOsSockLen());
        try platform.posix.listen(fd, 32);

        var actual_addr: posix.sockaddr.in = undefined;
        var actual_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        try platform.posix.getsockname(fd, @ptrCast(&actual_addr), &actual_len);

        return .{
            .alloc = alloc,
            .listen_fd = fd,
            .token = token,
            .port = std.mem.bigToNative(u16, actual_addr.port),
            .running = std.atomic.Value(bool).init(true),
            .started = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *LogServer) void {
        self.running.store(false, .release);
        platform.posix.close(self.listen_fd);
    }

    pub fn run(self: *LogServer) void {
        self.started.store(true, .release);
        while (self.running.load(.acquire)) {
            const client_fd = platform.posix.accept(self.listen_fd, null, null, posix.SOCK.CLOEXEC) catch |err| switch (err) {
                error.WouldBlock => {
                    std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(50), .awake) catch unreachable;
                    continue;
                },
                else => return,
            };
            handleConnection(self, client_fd);
        }
    }

    pub fn waitUntilStarted(self: *LogServer) !void {
        var attempts: usize = 0;
        while (attempts < 1500) : (attempts += 1) {
            if (self.started.load(.acquire)) {
                std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(250), .awake) catch unreachable;
                return;
            }
            std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(20), .awake) catch unreachable;
        }
        return error.ServerNotReady;
    }
};

pub fn setTestLogLookupOverride(app_name: []const u8, job_name: []const u8, rank: u32, container_id: []const u8) !void {
    test_log_lookup_mutex.lockUncancelable(std.Options.debug_io);
    defer test_log_lookup_mutex.unlock(std.Options.debug_io);

    for (test_log_lookup_overrides[0..test_log_lookup_override_len]) |*entry| {
        if (std.mem.eql(u8, entry.app_name, app_name) and std.mem.eql(u8, entry.job_name, job_name) and entry.rank == rank) {
            entry.container_id = container_id;
            return;
        }
    }
    if (test_log_lookup_override_len >= test_log_lookup_overrides.len) return error.OutOfMemory;
    test_log_lookup_overrides[test_log_lookup_override_len] = .{
        .app_name = app_name,
        .job_name = job_name,
        .rank = rank,
        .container_id = container_id,
    };
    test_log_lookup_override_len += 1;
}

pub fn clearTestLogLookupOverride(app_name: []const u8, job_name: []const u8, rank: u32) void {
    test_log_lookup_mutex.lockUncancelable(std.Options.debug_io);
    defer test_log_lookup_mutex.unlock(std.Options.debug_io);

    var i: usize = 0;
    while (i < test_log_lookup_override_len) : (i += 1) {
        const entry = test_log_lookup_overrides[i];
        if (std.mem.eql(u8, entry.app_name, app_name) and std.mem.eql(u8, entry.job_name, job_name) and entry.rank == rank) {
            test_log_lookup_override_len -= 1;
            test_log_lookup_overrides[i] = test_log_lookup_overrides[test_log_lookup_override_len];
            return;
        }
    }
}

fn findTestLogContainerId(app_name: []const u8, job_name: []const u8, rank: u32) ?[]const u8 {
    test_log_lookup_mutex.lockUncancelable(std.Options.debug_io);
    defer test_log_lookup_mutex.unlock(std.Options.debug_io);

    for (test_log_lookup_overrides[0..test_log_lookup_override_len]) |entry| {
        if (std.mem.eql(u8, entry.app_name, app_name) and std.mem.eql(u8, entry.job_name, job_name) and entry.rank == rank) {
            return entry.container_id;
        }
    }
    return null;
}

fn handleConnection(self: *LogServer, client_fd: posix.fd_t) void {
    defer platform.posix.close(client_fd);

    const owned_request = connection_runtime.readRequestAlloc(self.alloc, client_fd) catch {
        sendError(client_fd, .bad_request, "malformed request");
        return;
    };
    defer owned_request.deinit(self.alloc);

    const request = owned_request.request;
    if (!common.hasValidBearerToken(&request, self.token)) {
        sendError(client_fd, .unauthorized, "unauthorized");
        return;
    }
    if (request.method != .GET) {
        sendError(client_fd, .method_not_allowed, "method not allowed");
        return;
    }

    if (matchTrainingLogs(request.path_only)) |path| {
        if (!common.validateClusterInput(path.app_name) or !common.validateClusterInput(path.job_name)) {
            sendError(client_fd, .bad_request, "invalid app or training job name");
            return;
        }
        const rank = parseRankQuery(request.query) catch {
            sendError(client_fd, .bad_request, "invalid rank");
            return;
        };
        serveTrainingLogs(self.alloc, client_fd, path.app_name, path.job_name, rank);
        return;
    }

    sendError(client_fd, .not_found, "not found");
}

const TrainingLogsPath = struct {
    app_name: []const u8,
    job_name: []const u8,
};

fn matchTrainingLogs(path: []const u8) ?TrainingLogsPath {
    if (!std.mem.startsWith(u8, path, "/training/")) return null;
    const tail = path["/training/".len..];
    const slash = std.mem.indexOfScalar(u8, tail, '/') orelse return null;
    const app_name = tail[0..slash];
    const after_app = tail[slash + 1 ..];
    const slash2 = std.mem.indexOfScalar(u8, after_app, '/') orelse return null;
    const job_name = after_app[0..slash2];
    if (!std.mem.eql(u8, after_app[slash2..], "/logs")) return null;
    if (app_name.len == 0 or job_name.len == 0) return null;
    return .{ .app_name = app_name, .job_name = job_name };
}

fn parseRankQuery(query: []const u8) !u32 {
    const rank_str = common.extractQueryValue(query, "rank") orelse return 0;
    return std.fmt.parseInt(u32, rank_str, 10) catch error.InvalidRank;
}

fn serveTrainingLogs(alloc: std.mem.Allocator, client_fd: posix.fd_t, app_name: []const u8, job_name: []const u8, rank: u32) void {
    if (findTestLogContainerId(app_name, job_name, rank)) |container_id| {
        const data = logs.readLogs(alloc, container_id) catch {
            sendError(client_fd, .not_found, "not found");
            return;
        };
        defer alloc.free(data);
        writeResponse(client_fd, .ok, "text/plain", data);
        return;
    }

    var hostname_buf: [128]u8 = undefined;
    const hostname = std.fmt.bufPrint(&hostname_buf, "{s}-rank-{d}", .{ job_name, rank }) catch {
        sendError(client_fd, .internal_server_error, "response formatting failed");
        return;
    };
    const record = store.findAppContainer(alloc, app_name, hostname) catch {
        sendError(client_fd, .internal_server_error, "container lookup failed");
        return;
    };
    if (record == null) {
        sendError(client_fd, .not_found, "not found");
        return;
    }
    defer record.?.deinit(alloc);

    const data = logs.readLogs(alloc, record.?.id) catch {
        sendError(client_fd, .not_found, "not found");
        return;
    };
    defer alloc.free(data);

    writeResponse(client_fd, .ok, "text/plain", data);
}

fn sendError(fd: posix.fd_t, status: http.StatusCode, message: []const u8) void {
    var resp_buf: [1024]u8 = undefined;
    const resp = http.formatError(&resp_buf, status, message);
    writeAll(fd, resp);
}

fn writeResponse(fd: posix.fd_t, status: http.StatusCode, content_type: []const u8, body: []const u8) void {
    var header_buf: [512]u8 = undefined;
    const headers = http.formatResponseHeaders(&header_buf, status, content_type, body.len);
    writeAll(fd, headers);
    if (body.len > 0) writeAll(fd, body);
}

fn writeAll(fd: posix.fd_t, data: []const u8) void {
    var written: usize = 0;
    while (written < data.len) {
        const bytes_written = platform.posix.write(fd, data[written..]) catch return;
        if (bytes_written == 0) return;
        written += bytes_written;
    }
}

test "log server serves remote training logs with auth" {
    const app_name = "logserver-app";
    const job_name = "logserverjob";
    const container_id = "aa11bb22cc33";
    logs.deleteLogFile(container_id);
    defer logs.deleteLogFile(container_id);
    try setTestLogLookupOverride(app_name, job_name, 0, container_id);
    defer clearTestLogLookupOverride(app_name, job_name, 0);

    var file = try logs.createLogFile(container_id);
    defer file.close(std.Options.debug_io);
    try file.writeStreamingAll(std.Options.debug_io, "rank zero logs\n");

    var sockets: [2]std.posix.fd_t = undefined;
    if (std.c.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &sockets) != 0) return error.SocketPairFailed;
    defer platform.posix.close(sockets[0]);

    const request =
        "GET /training/" ++ app_name ++ "/" ++ job_name ++ "/logs?rank=0 HTTP/1.1\r\n" ++
        "Host: localhost\r\n" ++
        "Connection: close\r\n" ++
        "Authorization: Bearer join-token\r\n\r\n";
    _ = try platform.posix.write(sockets[0], request);

    var server = LogServer{
        .alloc = std.heap.page_allocator,
        .listen_fd = -1,
        .token = "join-token",
        .port = 0,
        .running = std.atomic.Value(bool).init(true),
        .started = std.atomic.Value(bool).init(true),
    };
    handleConnection(&server, sockets[1]);

    var buf: [512]u8 = undefined;
    const n = try posix.read(sockets[0], &buf);
    try std.testing.expect(n > 0);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "rank zero logs\n") != null);
}
