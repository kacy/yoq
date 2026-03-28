const std = @import("std");
const posix = std.posix;
const proxy_runtime = @import("runtime.zig");
const reverse_proxy = @import("reverse_proxy.zig");
const router = @import("router.zig");
const service_rollout = @import("../service_rollout.zig");

pub const default_listen_port: u16 = 17080;
pub const StateChangeHook = *const fn () void;

pub const Snapshot = struct {
    enabled: bool,
    running: bool,
    port: u16,
    accepted_connections_total: u64,
    active_connections: u32,
    last_error: ?[]const u8,

    pub fn deinit(self: Snapshot, alloc: std.mem.Allocator) void {
        if (self.last_error) |message| alloc.free(message);
    }
};

var mutex: std.Thread.Mutex = .{};
var listen_fd: ?posix.fd_t = null;
var listener_thread: ?std.Thread = null;
var stop_requested: bool = false;
var running: bool = false;
var listen_port: u16 = default_listen_port;
var accepted_connections_total: u64 = 0;
var active_connections: u32 = 0;
var last_error: ?[]u8 = null;
var state_change_hook: ?StateChangeHook = null;

pub fn resetForTest() void {
    stop();

    mutex.lock();
    defer mutex.unlock();
    listen_port = default_listen_port;
    accepted_connections_total = 0;
    active_connections = 0;
    clearLastErrorLocked();
    state_change_hook = null;
}

pub fn setStateChangeHook(hook: ?StateChangeHook) void {
    mutex.lock();
    defer mutex.unlock();
    state_change_hook = hook;
}

pub fn startIfEnabled(alloc: std.mem.Allocator) void {
    if (!service_rollout.current().l7_proxy_http) return;
    start(alloc, default_listen_port);
}

pub fn startForTest(alloc: std.mem.Allocator, port: u16) void {
    start(alloc, port);
}

pub fn stop() void {
    var thread_to_join: ?std.Thread = null;
    var fd_to_close: ?posix.fd_t = null;
    var port_to_wake: ?u16 = null;
    var hook_to_call: ?StateChangeHook = null;

    mutex.lock();
    stop_requested = true;
    if (running or listen_fd != null or listener_thread != null) hook_to_call = state_change_hook;
    running = false;
    if (listen_fd) |fd| {
        fd_to_close = fd;
        port_to_wake = listen_port;
        listen_fd = null;
    }
    if (listener_thread) |thread| {
        thread_to_join = thread;
        listener_thread = null;
    }
    mutex.unlock();

    if (port_to_wake) |port| wakeAccept(port);
    if (fd_to_close) |fd| posix.close(fd);
    if (thread_to_join) |thread| thread.join();
    if (hook_to_call) |hook| hook();
}

pub fn snapshot(alloc: std.mem.Allocator) !Snapshot {
    mutex.lock();
    defer mutex.unlock();

    return .{
        .enabled = service_rollout.current().l7_proxy_http,
        .running = running,
        .port = listen_port,
        .accepted_connections_total = accepted_connections_total,
        .active_connections = active_connections,
        .last_error = if (last_error) |message| try alloc.dupe(u8, message) else null,
    };
}

pub fn portIfRunning() ?u16 {
    mutex.lock();
    defer mutex.unlock();

    if (!running) return null;
    return listen_port;
}

fn start(alloc: std.mem.Allocator, port: u16) void {
    mutex.lock();
    if (listener_thread != null) {
        mutex.unlock();
        return;
    }
    stop_requested = false;
    accepted_connections_total = 0;
    active_connections = 0;
    listen_port = port;
    clearLastErrorLocked();

    const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch {
        setLastErrorLocked(error.SocketFailed);
        const hook = state_change_hook;
        mutex.unlock();
        if (hook) |callback| callback();
        return;
    };

    const reuseaddr: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuseaddr)) catch {};

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    posix.bind(fd, &addr.any, addr.getOsSockLen()) catch {
        setLastErrorLocked(error.BindFailed);
        const hook = state_change_hook;
        mutex.unlock();
        posix.close(fd);
        if (hook) |callback| callback();
        return;
    };
    posix.listen(fd, 128) catch {
        setLastErrorLocked(error.ListenFailed);
        const hook = state_change_hook;
        mutex.unlock();
        posix.close(fd);
        if (hook) |callback| callback();
        return;
    };

    if (port == 0) {
        var bound_addr: posix.sockaddr.in = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        posix.getsockname(fd, @ptrCast(&bound_addr), &bound_len) catch {
            setLastErrorLocked(error.BindFailed);
            const hook = state_change_hook;
            mutex.unlock();
            posix.close(fd);
            if (hook) |callback| callback();
            return;
        };
        listen_port = std.mem.bigToNative(u16, bound_addr.port);
    }

    listen_fd = fd;
    running = true;
    listener_thread = std.Thread.spawn(.{}, acceptLoop, .{alloc}) catch {
        setLastErrorLocked(error.ThreadSpawnFailed);
        running = false;
        listen_fd = null;
        const hook = state_change_hook;
        mutex.unlock();
        posix.close(fd);
        if (hook) |callback| callback();
        return;
    };
    const hook = state_change_hook;
    mutex.unlock();
    if (hook) |callback| callback();
}

fn acceptLoop(alloc: std.mem.Allocator) void {
    while (true) {
        const fd = blk: {
            mutex.lock();
            defer mutex.unlock();
            if (stop_requested) break;
            break :blk listen_fd orelse break;
        };

        const client_fd = posix.accept(fd, null, null, posix.SOCK.CLOEXEC) catch {
            const hook = blk: {
                mutex.lock();
                defer mutex.unlock();
                if (stop_requested or listen_fd == null) break :blk null;
                setLastErrorLocked(error.AcceptFailed);
                running = false;
                break :blk state_change_hook;
            };
            if (hook) |callback| callback();
            break;
        };

        mutex.lock();
        accepted_connections_total += 1;
        active_connections += 1;
        mutex.unlock();

        const thread = std.Thread.spawn(.{}, connectionWorker, .{ alloc, client_fd }) catch {
            mutex.lock();
            if (active_connections > 0) active_connections -= 1;
            setLastErrorLocked(error.ThreadSpawnFailed);
            mutex.unlock();
            posix.close(client_fd);
            continue;
        };
        thread.detach();
    }
}

fn connectionWorker(alloc: std.mem.Allocator, client_fd: posix.fd_t) void {
    defer {
        mutex.lock();
        if (active_connections > 0) active_connections -= 1;
        mutex.unlock();
    }

    var routes = proxy_runtime.snapshotRouteConfigs(alloc) catch {
        posix.close(client_fd);
        return;
    };
    defer deinitRoutes(alloc, &routes);

    var proxy = reverse_proxy.ReverseProxy.init(alloc, routes.items);
    defer proxy.deinit();
    proxy.handleConnection(client_fd);
}

fn wakeAccept(port: u16) void {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch return;
    defer posix.close(fd);

    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    posix.connect(fd, &addr.any, addr.getOsSockLen()) catch {};
}

fn deinitRoutes(alloc: std.mem.Allocator, routes: *std.ArrayList(router.Route)) void {
    for (routes.items) |route| {
        alloc.free(route.name);
        alloc.free(route.service);
        alloc.free(route.vip_address);
        if (route.match.host) |host| alloc.free(host);
        alloc.free(route.match.path_prefix);
    }
    routes.deinit(alloc);
}

fn clearLastErrorLocked() void {
    if (last_error) |message| std.heap.page_allocator.free(message);
    last_error = null;
}

fn setLastErrorLocked(err: anyerror) void {
    clearLastErrorLocked();
    last_error = std.fmt.allocPrint(std.heap.page_allocator, "{}", .{err}) catch null;
}

test "listener runtime starts and stops on loopback" {
    const store = @import("../../state/store.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    service_rollout.setForTest(.{
        .service_registry_v2 = true,
        .l7_proxy_http = true,
    });
    defer service_rollout.resetForTest();
    resetForTest();
    defer resetForTest();

    startForTest(std.testing.allocator, 0);

    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);

    try std.testing.expect(state.enabled);
    try std.testing.expect(state.running);
    try std.testing.expect(state.port != 0);
    try std.testing.expectEqual(@as(u64, 0), state.accepted_connections_total);
}
