const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const log = @import("../../lib/log.zig");
const packet_support = @import("packet_support.zig");
const registry_support = @import("registry_support.zig");
const local_networks = @import("../local_networks.zig");
const runtime_wait = @import("../../lib/runtime_wait.zig");
const bridge = @import("../bridge.zig");

const listen_port: u16 = 53;
const upstream_port: u16 = 53;
const rate_limit_max_tokens: u32 = 100;
const rate_limit_refill_ms: i64 = 10;

const RateLimitEntry = struct {
    ip: u32,
    tokens: u32,
    last_refill: i64,
};

var upstream_dns: [4]u8 = .{ 8, 8, 8, 8 };
var upstream_initialized: bool = false;
const ListenerConfig = struct {
    address: [4]u8,
    device: [16]u8 = [_]u8{0} ** 16,
    device_len: usize,
    scope: [63]u8 = undefined,
    scope_len: usize = 0,

    fn init(address: [4]u8, device: []const u8, scope: ?[]const u8) ListenerConfig {
        var config: ListenerConfig = .{ .address = address, .device_len = device.len };
        @memcpy(config.device[0..device.len], device);
        if (scope) |name| {
            @memcpy(config.scope[0..name.len], name);
            config.scope_len = name.len;
        }
        return config;
    }
};
const Listener = struct {
    config: ListenerConfig,
    socket: ?linux_platform.posix.socket_t = null,
    thread: ?std.Thread = null,
    external: bool = false,
};
// Gateway sockets stay bound to their own bridge, including named networks.
var listeners: [256]?Listener = .{null} ** 256;
var retry_running = std.atomic.Value(bool).init(false);
var retry_thread: ?std.Thread = null;
var resolver_running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var resolver_mutex: std.Io.Mutex = .init;
var rate_limits: [256]RateLimitEntry = [_]RateLimitEntry{.{
    .ip = 0,
    .tokens = rate_limit_max_tokens,
    .last_refill = 0,
}} ** 256;
var rate_limit_mutex: std.Io.Mutex = .init;

pub fn startResolver() void {
    startResolverAt(bridge.gateway_ip);
}

pub fn startResolverAt(address: [4]u8) void {
    resolver_mutex.lockUncancelable(std.Options.debug_io);
    defer resolver_mutex.unlock(std.Options.debug_io);

    startResolverAtLocked(ListenerConfig.init(address, bridge.default_bridge, null));
}

pub fn startScopedResolverAt(address: [4]u8, device: []const u8, scope: []const u8) void {
    if (device.len >= 16 or scope.len == 0 or scope.len > 63) return;
    resolver_mutex.lockUncancelable(std.Options.debug_io);
    defer resolver_mutex.unlock(std.Options.debug_io);
    startResolverAtLocked(ListenerConfig.init(address, device, scope));
    // Every supervisor retries the shared listener. DNS survives when the
    // supervisor that first bound the gateway exits before its peers.
    if (retry_thread == null) {
        retry_running.store(true, .release);
        retry_thread = std.Thread.spawn(.{}, retryLoop, .{}) catch {
            retry_running.store(false, .release);
            return;
        };
    }
}

fn retryLoop() void {
    while (retry_running.load(.acquire)) {
        if (!runtime_wait.sleep(std.Io.Duration.fromSeconds(1), "named network dns retry")) return;
        if (retry_running.load(.acquire)) _ = refreshResolvers();
    }
}

fn startResolverAtLocked(config: ListenerConfig) void {
    const address = config.address;
    const device = config.device[0..config.device_len];
    var available: ?*?Listener = null;
    for (&listeners) |*entry| {
        if (entry.*) |listener| {
            if (std.mem.eql(u8, &listener.config.address, &address)) {
                if (listener.socket != null) return;
                available = entry;
                break;
            }
        } else {
            available = entry;
        }
    }
    const slot = available orelse {
        log.warn("dns: gateway listener limit reached", .{});
        return;
    };

    const was_external = if (slot.*) |listener| listener.external else false;
    // retain the requested gateway so an audit can retry a failed bind.
    slot.* = .{ .config = config };
    initUpstreamDns();

    const sock = linux_platform.posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0) catch |e| {
        log.warn("dns: failed to create socket: {}", .{e});
        return;
    };

    // Bind an explicit gateway so host DNS listeners on loopback can coexist.
    // Device binding also rejects packets arriving through unrelated interfaces.
    // Failure must close the socket, never expose an unrestricted DNS listener.
    linux_platform.posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.BINDTODEVICE, config.device[0 .. config.device_len + 1]) catch |e| {
        log.warn("dns: failed to bind socket to container bridge: {}", .{e});
        linux_platform.posix.close(sock);
        return;
    };
    const addr = posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, listen_port),
        .addr = @bitCast(address),
    };

    linux_platform.posix.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch |e| {
        if (e == error.AddressInUse) {
            slot.* = .{ .config = config, .external = true };
            if (!was_external) log.info("dns resolver already available on {s}:53", .{device});
        } else {
            log.warn("dns: failed to bind to {s}:53: {}", .{ device, e });
        }
        linux_platform.posix.close(sock);
        return;
    };

    const was_running = resolver_running.swap(true, .acq_rel);
    const thread = std.Thread.spawn(.{}, resolverLoop, .{ sock, config }) catch |e| {
        log.warn("dns: failed to spawn resolver thread: {}", .{e});
        resolver_running.store(was_running, .release);
        linux_platform.posix.close(sock);
        return;
    };
    slot.* = .{ .config = config, .socket = sock, .thread = thread };
    log.info("dns resolver started on {d}.{d}.{d}.{d}:53 via {s}", .{
        address[0], address[1], address[2], address[3], device,
    });
}

/// retry requested gateways without a local socket; return true after acquiring one.
pub fn refreshResolvers() bool {
    resolver_mutex.lockUncancelable(std.Options.debug_io);
    defer resolver_mutex.unlock(std.Options.debug_io);
    var acquired = false;
    for (&listeners) |*entry| {
        const listener = entry.* orelse continue;
        if (listener.socket != null) continue;
        startResolverAtLocked(listener.config);
        if (entry.*.?.socket != null) acquired = true;
    }
    return acquired;
}

pub fn isRunningAt(address: [4]u8) bool {
    resolver_mutex.lockUncancelable(std.Options.debug_io);
    defer resolver_mutex.unlock(std.Options.debug_io);
    for (listeners) |entry| {
        if (entry) |listener| {
            if (std.mem.eql(u8, &listener.config.address, &address)) return listener.socket != null or listener.external;
        }
    }
    return false;
}

pub fn isRunning() bool {
    resolver_mutex.lockUncancelable(std.Options.debug_io);
    defer resolver_mutex.unlock(std.Options.debug_io);
    for (listeners) |entry| {
        if (entry) |listener| {
            if (listener.socket != null or listener.external) return true;
        }
    }
    return false;
}

pub fn isOwnedByCurrentProcess() bool {
    return resolver_running.load(.acquire);
}

pub fn stopResolver() void {
    retry_running.store(false, .release);
    resolver_mutex.lockUncancelable(std.Options.debug_io);
    const retries = retry_thread;
    retry_thread = null;
    resolver_mutex.unlock(std.Options.debug_io);
    if (retries) |thread| thread.join();
    resolver_mutex.lockUncancelable(std.Options.debug_io);
    defer resolver_mutex.unlock(std.Options.debug_io);

    resolver_running.store(false, .release);
    // Resolver workers never take resolver_mutex. Hold it across joins so a
    // concurrent start cannot replace a socket while shutdown still owns it.
    for (listeners) |entry| {
        if (entry) |listener| {
            if (listener.socket) |sock| _ = std.os.linux.shutdown(sock, std.os.linux.SHUT.RDWR);
        }
    }
    for (&listeners) |*entry| {
        if (entry.*) |listener| {
            if (listener.thread) |thread| thread.join();
            if (listener.socket) |sock| linux_platform.posix.close(sock);
        }
        entry.* = null;
    }
}

fn initUpstreamDns() void {
    if (upstream_initialized) return;
    upstream_initialized = true;

    const content = std.Io.Dir.cwd().readFileAlloc(std.Options.debug_io, "/etc/resolv.conf", std.heap.page_allocator, .limited(4096)) catch {
        log.info("dns: /etc/resolv.conf not readable, using 8.8.8.8", .{});
        return;
    };
    defer std.heap.page_allocator.free(content);

    if (registry_support.parseResolvConf(content)) |addr| {
        upstream_dns = addr;
        log.info("dns: upstream resolver set to {d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] });
    } else {
        log.info("dns: no valid nameserver in resolv.conf, using 8.8.8.8", .{});
    }
}

fn checkRateLimit(client_ip: u32) bool {
    rate_limit_mutex.lockUncancelable(std.Options.debug_io);
    defer rate_limit_mutex.unlock(std.Options.debug_io);

    const now = std.Io.Clock.real.now(std.Options.debug_io).toMilliseconds();
    const idx = @as(usize, @intCast(client_ip % 256));
    var entry = &rate_limits[idx];

    if (entry.ip == client_ip) {
        const elapsed = now - entry.last_refill;
        const refill_amount = @divTrunc(elapsed, rate_limit_refill_ms);
        const max_new = rate_limit_max_tokens - entry.tokens;
        const new_tokens = @as(u32, @intCast(@min(refill_amount, max_new)));
        entry.tokens += new_tokens;
        entry.last_refill = now;

        if (entry.tokens > 0) {
            entry.tokens -= 1;
            return true;
        }
        return false;
    }

    entry.ip = client_ip;
    entry.tokens = rate_limit_max_tokens - 1;
    entry.last_refill = now;
    return true;
}

fn resolverLoop(sock: linux_platform.posix.socket_t, config: ListenerConfig) void {
    var recv_buf: [512]u8 = undefined;

    while (resolver_running.load(.acquire)) {
        var client_addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

        const recv_len = linux_platform.posix.recvfrom(sock, &recv_buf, 0, @ptrCast(&client_addr), &addr_len) catch {
            if (!resolver_running.load(.acquire)) break;
            continue;
        };

        if (recv_len < 12) continue;

        const client_ip = std.mem.nativeToBig(u32, client_addr.addr);
        if (!checkRateLimit(client_ip)) {
            log.debug("dns: rate limiting client {d}.{d}.{d}.{d}", .{
                (client_ip >> 24) & 0xFF,
                (client_ip >> 16) & 0xFF,
                (client_ip >> 8) & 0xFF,
                client_ip & 0xFF,
            });
            continue;
        }

        handleQuery(sock, recv_buf[0..recv_len], &client_addr, addr_len, config);
    }
}

fn handleQuery(
    sock: linux_platform.posix.socket_t,
    query: []const u8,
    client_addr: *const posix.sockaddr.in,
    addr_len: posix.socklen_t,
    config: ListenerConfig,
) void {
    const header = packet_support.parseHeader(query) orelse return;
    if (header.qdcount != 1) {
        log.debug("dns: rejecting query with QDCOUNT={d} (expected 1)", .{header.qdcount});
        return;
    }

    const qr = (header.flags >> 15) & 1;
    const opcode = (header.flags >> 11) & 0xF;
    if (qr != 0 or opcode != 0) {
        log.debug("dns: rejecting non-query packet (QR={d}, OPCODE={d})", .{ qr, opcode });
        return;
    }

    const question = packet_support.parseQuestion(query) orelse return;
    const name = question.name[0..question.name_len];
    if (config.scope_len != 0) {
        const address = local_networks.lookupDns(config.scope[0..config.scope_len], name);
        if (address != null or std.mem.indexOfScalar(u8, name, '.') == null) {
            var response_buf: [512]u8 = undefined;
            const length = if (address != null and question.qtype == packet_support.TYPE_A and question.qclass == packet_support.CLASS_IN)
                packet_support.buildResponse(query, query.len, address.?, &response_buf)
            else blk: {
                const length = packet_support.buildNxDomain(query, query.len, &response_buf);
                // Existing names without an A answer return NODATA, not NXDOMAIN.
                if (address != null) packet_support.writeU16(response_buf[2..4], 0x8400);
                break :blk length;
            };
            if (length) |n| _ = linux_platform.posix.sendto(sock, response_buf[0..n], 0, @ptrCast(client_addr), addr_len) catch {};
            return;
        }
        forwardQuery(sock, query, client_addr, addr_len);
        return;
    }
    if (question.qtype != packet_support.TYPE_A or question.qclass != packet_support.CLASS_IN) {
        forwardQuery(sock, query, client_addr, addr_len);
        return;
    }

    if (registry_support.lookupServiceForDns(name)) |service_ip| {
        var response_buf: [512]u8 = undefined;
        if (packet_support.buildResponse(query, query.len, service_ip, &response_buf)) |resp_len| {
            _ = linux_platform.posix.sendto(sock, response_buf[0..resp_len], 0, @ptrCast(client_addr), addr_len) catch |e| {
                log.warn("dns: failed to send response: {}", .{e});
            };
            return;
        }
    }

    forwardQuery(sock, query, client_addr, addr_len);
}

fn forwardQuery(
    sock: linux_platform.posix.socket_t,
    query: []const u8,
    client_addr: *const posix.sockaddr.in,
    addr_len: posix.socklen_t,
) void {
    const upstream_sock = linux_platform.posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
    defer linux_platform.posix.close(upstream_sock);

    const timeout = posix.timeval{ .sec = 2, .usec = 0 };
    posix.setsockopt(upstream_sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch |e| {
        log.warn("dns: failed to set upstream socket timeout: {}", .{e});
    };

    const expected_addr = packet_support.ipToU32(upstream_dns);
    const expected_port = std.mem.nativeToBig(u16, upstream_port);
    const upstream_addr = posix.sockaddr.in{
        .port = expected_port,
        .addr = std.mem.nativeToBig(u32, expected_addr),
    };

    _ = linux_platform.posix.sendto(upstream_sock, query, 0, @ptrCast(&upstream_addr), @sizeOf(posix.sockaddr.in)) catch return;

    var response_buf: [512]u8 = undefined;
    var resp_addr: posix.sockaddr.in = undefined;
    var resp_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

    const resp_n = linux_platform.posix.recvfrom(upstream_sock, &response_buf, 0, @ptrCast(&resp_addr), &resp_addr_len) catch return;

    if (resp_addr.addr != upstream_addr.addr or resp_addr.port != upstream_addr.port) {
        log.warn("dns: dropping response from unexpected source (expected {d}.{d}.{d}.{d}:{d})", .{
            upstream_dns[0], upstream_dns[1], upstream_dns[2], upstream_dns[3], upstream_port,
        });
        return;
    }

    if (resp_n < 2 or query.len < 2) return;
    if (response_buf[0] != query[0] or response_buf[1] != query[1]) return;

    const query_question = packet_support.parseQuestion(query) orelse return;
    const resp_question = packet_support.parseQuestion(response_buf[0..resp_n]) orelse return;

    if (query_question.name_len != resp_question.name_len) {
        log.warn("dns: response question name length mismatch (expected {d}, got {d})", .{ query_question.name_len, resp_question.name_len });
        return;
    }
    if (!std.mem.eql(u8, query_question.name[0..query_question.name_len], resp_question.name[0..resp_question.name_len])) {
        log.warn("dns: response question name mismatch", .{});
        return;
    }
    if (query_question.qtype != resp_question.qtype or query_question.qclass != resp_question.qclass) {
        log.warn("dns: response QTYPE/QCLASS mismatch", .{});
        return;
    }

    _ = linux_platform.posix.sendto(sock, response_buf[0..resp_n], 0, @ptrCast(client_addr), addr_len) catch |e| {
        log.warn("dns: failed to relay upstream response: {}", .{e});
    };
}
