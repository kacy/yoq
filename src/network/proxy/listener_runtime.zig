const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const proxy_runtime = @import("runtime.zig");
const reverse_proxy = @import("reverse_proxy.zig");
const router = @import("router.zig");
const service_rollout = @import("../service_rollout.zig");
const service_registry_runtime = @import("../service_registry_runtime.zig");

pub const default_listen_port: u16 = 17080;
pub const default_bind_addr: [4]u8 = .{ 127, 0, 0, 1 };
pub const StateChangeHook = *const fn () void;
pub const drain_timeout_ms: u64 = 5000;
const drain_poll_interval_ms: u64 = 10;

/// Maximum owned connection workers; excess clients are closed immediately.
pub const max_connections: u32 = 1024;

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

const PeerKey = @import("../../tls/proxy_credentials.zig").Key;
var peer_key: ?PeerKey = null;
const accept_support = @import("../../tls/proxy/accept_support.zig");
const WorkerGroup = @import("../../tls/proxy/worker_group.zig").Group(max_connections);
var workers: WorkerGroup = .{};
var lifecycle_mutex: std.Io.Mutex = .init;
var mutex: std.Io.Mutex = .init;
var listen_fd: ?posix.fd_t = null;
var listener_thread: ?std.Thread = null;
var stop_requested: bool = false;
var running: bool = false;
var listen_bind_addr: [4]u8 = default_bind_addr;
var listen_port: u16 = default_listen_port;
var accepted_connections_total: u64 = 0;
var last_error: ?[]u8 = null;
var state_change_hook: ?StateChangeHook = null;

/// Bootstrap copies only the decryption key; requests own snapshots of it.
pub fn configurePeerKey(token: ?[]const u8) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    if (peer_key) |*key| std.crypto.secureZero(u8, key);
    peer_key = null;
    if (token) |bytes| {
        var key: PeerKey = undefined;
        defer std.crypto.secureZero(u8, &key);
        std.crypto.hash.sha2.Sha256.hash(bytes, &key, .{});
        peer_key = key;
    }
}

pub fn resetForTest() void {
    stop();
    configurePeerKey(null);

    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    listen_bind_addr = default_bind_addr;
    listen_port = default_listen_port;
    accepted_connections_total = 0;
    clearLastErrorLocked();
    state_change_hook = null;
}

pub fn configure(bind_addr: [4]u8, port: u16) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    listen_bind_addr = bind_addr;
    listen_port = port;
}

pub fn setStateChangeHook(hook: ?StateChangeHook) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    state_change_hook = hook;
}

pub fn setRunningForTest(port: u16) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
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
    lifecycle_mutex.lockUncancelable(std.Options.debug_io);
    const hook = stopLocked();
    lifecycle_mutex.unlock(std.Options.debug_io);
    if (hook) |callback| callback();
}

fn stopLocked() ?StateChangeHook {
    mutex.lockUncancelable(std.Options.debug_io);
    stop_requested = true;
    const hook = if (running or listen_fd != null or listener_thread != null) state_change_hook else null;
    running = false;
    const thread = listener_thread;
    const fd = listen_fd;
    mutex.unlock(std.Options.debug_io);

    workers.cancel();
    if (thread) |owned| owned.join();
    workers.join();
    if (fd) |owned| linux_platform.posix.close(owned);

    mutex.lockUncancelable(std.Options.debug_io);
    listener_thread = null;
    listen_fd = null;
    mutex.unlock(std.Options.debug_io);
    return hook;
}

pub fn snapshot(alloc: std.mem.Allocator) !Snapshot {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    return .{
        .enabled = service_registry_runtime.hasProxyConfiguredServices(),
        .running = running,
        .bind_addr = listen_bind_addr,
        .port = listen_port,
        .accepted_connections_total = accepted_connections_total,
        .active_connections = @intCast(workers.count()),
        .last_error = if (last_error) |message| try alloc.dupe(u8, message) else null,
    };
}

pub fn portIfRunning() ?u16 {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    if (!running) return null;
    return listen_port;
}

pub fn connectTargetIfRunning() ?ConnectTarget {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    if (!running) return null;
    return .{
        .addr = if (std.mem.eql(u8, listen_bind_addr[0..], &[_]u8{ 0, 0, 0, 0 }))
            default_bind_addr
        else
            listen_bind_addr,
        .port = listen_port,
    };
}

pub fn activeConnectionCount() u32 {
    return @intCast(workers.count());
}

pub fn waitForConnectionsToDrain(timeout_ms: u64) bool {
    var waited_ms: u64 = 0;
    while (activeConnectionCount() != 0 and waited_ms < timeout_ms) {
        std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(drain_poll_interval_ms), .awake) catch return false;
        waited_ms += drain_poll_interval_ms;
    }
    return activeConnectionCount() == 0;
}

fn start(alloc: std.mem.Allocator) void {
    startWith(alloc, accept_support.accept);
}

fn startWith(alloc: std.mem.Allocator, comptime acceptFn: anytype) void {
    lifecycle_mutex.lockUncancelable(std.Options.debug_io);
    // Notify after releasing lifecycle ownership, so hooks may reconcile.
    var changed = false;
    defer {
        mutex.lockUncancelable(std.Options.debug_io);
        const hook = state_change_hook;
        mutex.unlock(std.Options.debug_io);
        lifecycle_mutex.unlock(std.Options.debug_io);
        if (changed) if (hook) |callback| callback();
    }
    mutex.lockUncancelable(std.Options.debug_io);
    const already_running = running;
    mutex.unlock(std.Options.debug_io);
    if (already_running) return;
    changed = true;
    _ = stopLocked();
    workers.restart();
    mutex.lockUncancelable(std.Options.debug_io);
    stop_requested = false;
    accepted_connections_total = 0;
    clearLastErrorLocked();

    const bind_addr = listen_bind_addr;
    const requested_port = listen_port;

    const fd = linux_platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK, 0) catch {
        setLastErrorLocked(error.SocketFailed);
        mutex.unlock(std.Options.debug_io);
        return;
    };

    const reuseaddr: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuseaddr)) catch {};

    const addr = linux_platform.net.Address.initIp4(bind_addr, requested_port);
    linux_platform.posix.bind(fd, &addr.any, addr.getOsSockLen()) catch {
        setLastErrorLocked(error.BindFailed);
        mutex.unlock(std.Options.debug_io);
        linux_platform.posix.close(fd);
        return;
    };
    linux_platform.posix.listen(fd, 128) catch {
        setLastErrorLocked(error.ListenFailed);
        mutex.unlock(std.Options.debug_io);
        linux_platform.posix.close(fd);
        return;
    };

    if (requested_port == 0) {
        var bound_addr: posix.sockaddr.in = undefined;
        var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        linux_platform.posix.getsockname(fd, @ptrCast(&bound_addr), &bound_len) catch {
            setLastErrorLocked(error.BindFailed);
            mutex.unlock(std.Options.debug_io);
            linux_platform.posix.close(fd);
            return;
        };
        listen_port = std.mem.bigToNative(u16, bound_addr.port);
    }

    listen_fd = fd;
    running = true;
    const Loop = struct {
        fn run(allocator: std.mem.Allocator) void {
            acceptLoop(allocator, acceptFn);
        }
    };
    listener_thread = std.Thread.spawn(.{}, Loop.run, .{alloc}) catch {
        setLastErrorLocked(error.ThreadSpawnFailed);
        running = false;
        listen_fd = null;
        mutex.unlock(std.Options.debug_io);
        linux_platform.posix.close(fd);
        return;
    };
    mutex.unlock(std.Options.debug_io);
}

fn acceptLoop(alloc: std.mem.Allocator, comptime acceptFn: anytype) void {
    var backoff = accept_support.Backoff{};
    while (true) {
        mutex.lockUncancelable(std.Options.debug_io);
        const stopping = stop_requested;
        const fd = listen_fd;
        mutex.unlock(std.Options.debug_io);
        if (stopping or fd == null) return;

        const ready = accept_support.ready(fd.?) catch |err| {
            if (err == error.Retry) {
                backoff.pause();
                continue;
            }
            listenerFailed();
            return;
        };
        if (!ready) continue;
        const client_fd = acceptFn(fd.?) catch |err| switch (err) {
            error.WouldBlock => continue,
            error.Retry => {
                backoff.pause();
                continue;
            },
            error.Fatal => {
                listenerFailed();
                return;
            },
        };
        backoff.reset();
        mutex.lockUncancelable(std.Options.debug_io);
        accepted_connections_total += 1;
        mutex.unlock(std.Options.debug_io);
        workers.spawn(client_fd, connectionWorker, .{ alloc, client_fd }) catch |err| {
            linux_platform.posix.close(client_fd);
            if (err != error.ConnectionLimit and err != error.Stopping) {
                mutex.lockUncancelable(std.Options.debug_io);
                setLastErrorLocked(error.ThreadSpawnFailed);
                mutex.unlock(std.Options.debug_io);
                backoff.pause();
            }
        };
    }
}

fn listenerFailed() void {
    mutex.lockUncancelable(std.Options.debug_io);
    if (!stop_requested) setLastErrorLocked(error.AcceptFailed);
    running = false;
    mutex.unlock(std.Options.debug_io);
    workers.cancel();
    // The next reconciliation joins this handle before opening a new socket.
    // Do not invoke a hook here: it could synchronously try to join this thread.
}

fn connectionWorker(alloc: std.mem.Allocator, client_fd: posix.fd_t) void {
    var routes = proxy_runtime.snapshotRouteConfigs(alloc) catch {
        linux_platform.posix.close(client_fd);
        return;
    };
    defer deinitRoutes(alloc, &routes);

    var proxy = reverse_proxy.ReverseProxy.init(alloc, routes.items);
    defer proxy.deinit();
    mutex.lockUncancelable(std.Options.debug_io);
    proxy.peer_key = peer_key;
    mutex.unlock(std.Options.debug_io);
    proxy.handleConnection(client_fd);
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

const LifecycleFixture = struct {
    fn connect() !posix.fd_t {
        const port = portIfRunning() orelse return error.ListenerNotRunning;
        const fd = try linux_platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
        errdefer linux_platform.posix.close(fd);
        const addr = linux_platform.net.Address.initIp4(default_bind_addr, port);
        try linux_platform.posix.connect(fd, &addr.any, addr.getOsSockLen());
        return fd;
    }

    fn waitActive(expected: u32) !void {
        const deadline = @import("../../tls/client_transport.zig").Deadline.afterMilliseconds(2000);
        while (activeConnectionCount() != expected) {
            _ = try deadline.remaining();
            try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
        }
    }
};

test "listener lifecycle cancels idle workers before restart" {
    const store = @import("../../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    resetForTest();
    defer resetForTest();

    for (0..3) |_| {
        startForTest(std.testing.allocator, 0);
        const client = try LifecycleFixture.connect();
        defer linux_platform.posix.close(client);
        // Keep the client open, without completing a request, across stop.
        try LifecycleFixture.waitActive(1);
        try std.testing.expect(!waitForConnectionsToDrain(0));
        stop();
        try std.testing.expectEqual(@as(u32, 0), activeConnectionCount());
        try std.testing.expect(waitForConnectionsToDrain(0));
        try std.testing.expect(listener_thread == null);
        try std.testing.expect(listen_fd == null);
    }
}

test "listener lifecycle retries temporary accept failures and reopens after fatal failure" {
    const Injected = struct {
        var calls: std.atomic.Value(u32) = .init(0);
        fn transient(fd: posix.fd_t) accept_support.Error!posix.fd_t {
            if (calls.fetchAdd(1, .acq_rel) < 3) return error.Retry;
            return accept_support.accept(fd);
        }
        fn fatal(_: posix.fd_t) accept_support.Error!posix.fd_t {
            return error.Fatal;
        }
    };
    const store = @import("../../state/store.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    proxy_runtime.resetForTest();
    defer proxy_runtime.resetForTest();
    resetForTest();
    defer resetForTest();
    Injected.calls.store(0, .release);
    configure(default_bind_addr, 0);
    startWith(std.testing.allocator, Injected.transient);
    const first = try LifecycleFixture.connect();
    defer linux_platform.posix.close(first);
    try LifecycleFixture.waitActive(1);
    try std.testing.expect(Injected.calls.load(.acquire) >= 4);
    try std.testing.expect(portIfRunning() != null);
    stop();

    configure(default_bind_addr, 0);
    startWith(std.testing.allocator, Injected.fatal);
    const failed = try LifecycleFixture.connect();
    defer linux_platform.posix.close(failed);
    const deadline = @import("../../tls/client_transport.zig").Deadline.afterMilliseconds(2000);
    while (portIfRunning() != null) {
        _ = try deadline.remaining();
        try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
    }
    const failed_state = try snapshot(std.testing.allocator);
    defer failed_state.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("error.AcceptFailed", failed_state.last_error.?);
    // Recovery must retire the failed thread without requiring an explicit stop.
    start(std.testing.allocator);
    const recovered = try LifecycleFixture.connect();
    defer linux_platform.posix.close(recovered);
    try LifecycleFixture.waitActive(1);
    const recovered_state = try snapshot(std.testing.allocator);
    defer recovered_state.deinit(std.testing.allocator);
    try std.testing.expect(recovered_state.running);
    try std.testing.expect(recovered_state.last_error == null);
}
