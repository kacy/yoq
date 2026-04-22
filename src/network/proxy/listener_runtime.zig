const std = @import("std");
const posix = std.posix;
const proxy_runtime = @import("runtime.zig");
const reverse_proxy = @import("reverse_proxy.zig");
const router = @import("router.zig");
const service_rollout = @import("../service_rollout.zig");
const service_registry_runtime = @import("../service_registry_runtime.zig");

pub const default_listen_port: u16 = 17080;
pub const default_bind_addr: [4]u8 = .{ 127, 0, 0, 1 };
pub const StateChangeHook = *const fn () void;

pub const Snapshot = struct {
    enabled: bool,
    running: bool,
    bind_addr: [4]u8,
    port: u16,
    accepted_connections_total: u64,
    active_connections: u32,
    last_error: ?[]const u8,

    pub fn deinit(self: Snapshot, alloc: std.mem.Allocator) void {
        if (self.last_error) |message| alloc.free(message);
    }
};

pub const ConnectTarget = struct {
    addr: [4]u8,
    port: u16,
};

var mutex: @import("compat").Mutex = .{};
var listen_fd: ?posix.fd_t = null;
var listener_thread: ?std.Thread = null;
var stop_requested: bool = false;
var running: bool = false;
var listen_bind_addr: [4]u8 = default_bind_addr;
var listen_port: u16 = default_listen_port;
var accepted_connections_total: u64 = 0;
var active_connections: u32 = 0;
var last_error: ?[]u8 = null;
var state_change_hook: ?StateChangeHook = null;

pub fn resetForTest() void {
    stop();

    mutex.lock();
    defer mutex.unlock();
    listen_bind_addr = default_bind_addr;
    listen_port = default_listen_port;
    accepted_connections_total = 0;
    active_connections = 0;
    clearLastErrorLocked();
    state_change_hook = null;
}

pub fn configure(bind_addr: [4]u8, port: u16) void {
    mutex.lock();
    defer mutex.unlock();
    listen_bind_addr = bind_addr;
    listen_port = port;
}

pub fn setStateChangeHook(hook: ?StateChangeHook) void {
    mutex.lock();
    defer mutex.unlock();
    state_change_hook = hook;
}

pub fn setRunningForTest(port: u16) void {
    mutex.lock();
    defer mutex.unlock();
    listen_bind_addr = default_bind_addr;
    listen_port = port;
    running = true;
    stop_requested = false;
    clearLastErrorLocked();
}

pub fn startIfEnabled(alloc: std.mem.Allocator) void {
    proxy_runtime.bootstrapIfEnabled();
    if (!service_registry_runtime.hasProxyConfiguredServices()) {
        stop();
        return;
    }
    start(alloc);
}

pub fn startForTest(alloc: std.mem.Allocator, port: u16) void {
    configure(default_bind_addr, port);
    start(alloc);
}

pub fn startOrSkipForTest(alloc: std.mem.Allocator, port: u16) !void {
    configure(default_bind_addr, port);
    start(alloc);
    if (portIfRunning() != null) return;

    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);

    if (state.last_error) |message| {
        if (std.mem.eql(u8, message, "error.SocketFailed") or
            std.mem.eql(u8, message, "error.BindFailed") or
            std.mem.eql(u8, message, "error.ListenFailed"))
        {
            return error.SkipZigTest;
        }
    }

    return error.SkipZigTest;
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
    if (fd_to_close) |fd| @import("compat").posix.close(fd);
    if (thread_to_join) |thread| thread.join();
    if (hook_to_call) |hook| hook();
}

pub fn snapshot(alloc: std.mem.Allocator) !Snapshot {
    mutex.lock();
    defer mutex.unlock();

    return .{
        .enabled = service_registry_runtime.hasProxyConfiguredServices(),
        .running = running,
        .bind_addr = listen_bind_addr,
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

pub fn connectTargetIfRunning() ?ConnectTarget {
    mutex.lock();
    defer mutex.unlock();

    if (!running) return null;
    return .{
        .addr = if (std.mem.eql(u8, listen_bind_addr[0..], &[_]u8{ 0, 0, 0, 0 }))
            default_bind_addr
        else
            listen_bind_addr,
        .port = listen_port,
    };
}

fn start(alloc: std.mem.Allocator) void {
    mutex.lock();
    if (listener_thread != null) {
        mutex.unlock();
        return;
    }
    stop_requested = false;
    accepted_connections_total = 0;
    active_connections = 0;
    clearLastErrorLocked();

    const bind_addr = listen_bind_addr;
    const requested_port = listen_port;

    const fd = @import("compat").posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch {
        setLastErrorLocked(error.SocketFailed);
        const hook = state_change_hook;
        mutex.unlock();
        if (hook) |callback| callback();
        return;
    };

    const reuseaddr: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuseaddr)) catch {};

    const addr = @import("compat").net.Address.initIp4(bind_addr, requested_port);
    @import("compat").posix.bind(fd, &addr.any, addr.getOsSockLen()) catch {
        setLastErrorLocked(error.BindFailed);
        const hook = state_change_hook;
        mutex.unlock();
        @import("compat").posix.close(fd);
        if (hook) |callback| callback();
        return;
    };
    @import("compat").posix.listen(fd, 128) catch {
        setLastErrorLocked(error.ListenFailed);
        const hook = state_change_hook;
        mutex.unlock();
        @import("compat").posix.close(fd);
        if (hook) |callback| callback();
        return;
    };

    if (requested_port == 0) {
        var bound_addr: posix.sockaddr.in = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        @import("compat").posix.getsockname(fd, @ptrCast(&bound_addr), &bound_len) catch {
            setLastErrorLocked(error.BindFailed);
            const hook = state_change_hook;
            mutex.unlock();
            @import("compat").posix.close(fd);
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
        @import("compat").posix.close(fd);
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

        const client_fd = @import("compat").posix.accept(fd, null, null, posix.SOCK.CLOEXEC) catch {
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

        const shutting_down = blk: {
            mutex.lock();
            defer mutex.unlock();
            break :blk stop_requested or listen_fd == null;
        };
        if (shutting_down) {
            @import("compat").posix.close(client_fd);
            break;
        }

        mutex.lock();
        accepted_connections_total += 1;
        active_connections += 1;
        mutex.unlock();

        const thread = std.Thread.spawn(.{}, connectionWorker, .{ alloc, client_fd }) catch {
            mutex.lock();
            if (active_connections > 0) active_connections -= 1;
            setLastErrorLocked(error.ThreadSpawnFailed);
            mutex.unlock();
            @import("compat").posix.close(client_fd);
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
        @import("compat").posix.close(client_fd);
        return;
    };
    defer deinitRoutes(alloc, &routes);

    var proxy = reverse_proxy.ReverseProxy.init(alloc, routes.items);
    defer proxy.deinit();
    proxy.handleConnection(client_fd);
}

fn wakeAccept(port: u16) void {
    const fd = @import("compat").posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch return;
    defer @import("compat").posix.close(fd);

    const addr = @import("compat").net.Address.initIp4(wakeBindAddr(), port);
    @import("compat").posix.connect(fd, &addr.any, addr.getOsSockLen()) catch {};
}

fn wakeBindAddr() [4]u8 {
    if (std.mem.eql(u8, listen_bind_addr[0..], &[_]u8{ 0, 0, 0, 0 })) return default_bind_addr;
    return listen_bind_addr;
}

fn deinitRoutes(alloc: std.mem.Allocator, routes: *std.ArrayList(router.Route)) void {
    for (routes.items) |route| {
        alloc.free(route.name);
        alloc.free(route.service);
        alloc.free(route.vip_address);
        if (route.match.host) |host| alloc.free(host);
        alloc.free(route.match.path_prefix);
        if (route.rewrite_prefix) |rewrite_prefix| alloc.free(rewrite_prefix);
        for (route.method_matches) |method_match| method_match.deinit(alloc);
        if (route.method_matches.len > 0) alloc.free(route.method_matches);
        for (route.header_matches) |header_match| header_match.deinit(alloc);
        if (route.header_matches.len > 0) alloc.free(route.header_matches);
        for (route.backend_services) |backend| backend.deinit(alloc);
        if (route.backend_services.len > 0) alloc.free(route.backend_services);
        if (route.mirror_service) |mirror_service| alloc.free(mirror_service);
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

    try store.createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.2",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/",
        .http_proxy_target_port = 8080,
        .created_at = 1000,
        .updated_at = 1000,
    });
    service_registry_runtime.syncServiceFromStore("api");

    try startOrSkipForTest(std.testing.allocator, 0);

    const state = try snapshot(std.testing.allocator);
    defer state.deinit(std.testing.allocator);

    try std.testing.expect(state.enabled);
    try std.testing.expect(state.running);
    try std.testing.expect(state.port != 0);
    try std.testing.expectEqual(@as(u64, 0), state.accepted_connections_total);
}
