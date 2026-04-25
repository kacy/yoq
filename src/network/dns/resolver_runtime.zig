const std = @import("std");
const platform = @import("platform");
const posix = std.posix;
const log = @import("../../lib/log.zig");
const packet_support = @import("packet_support.zig");
const registry_support = @import("registry_support.zig");

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
var resolver_thread: ?std.Thread = null;
var resolver_socket: ?platform.posix.socket_t = null;
var resolver_running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var external_resolver_available: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var resolver_mutex: std.Io.Mutex = .init;
var rate_limits: [256]RateLimitEntry = [_]RateLimitEntry{.{
    .ip = 0,
    .tokens = rate_limit_max_tokens,
    .last_refill = 0,
}} ** 256;
var rate_limit_mutex: std.Io.Mutex = .init;

pub fn startResolver() void {
    resolver_mutex.lockUncancelable(std.Options.debug_io);
    defer resolver_mutex.unlock(std.Options.debug_io);

    if (resolver_running.load(.acquire) or external_resolver_available.load(.acquire)) return;

    initUpstreamDns();

    const sock = platform.posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0) catch |e| {
        log.warn("dns: failed to create socket: {}", .{e});
        return;
    };

    const addr = posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, listen_port),
        .addr = std.mem.nativeToBig(u32, (@as(u32, 10) << 24) | (@as(u32, 42) << 16) | (@as(u32, 0) << 8) | 1),
    };

    platform.posix.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch |e| {
        if (e == error.AddressInUse) {
            external_resolver_available.store(true, .release);
            log.info("dns resolver already available on 10.42.0.1:53", .{});
        } else {
            log.warn("dns: failed to bind to 10.42.0.1:53: {}", .{e});
        }
        platform.posix.close(sock);
        return;
    };

    resolver_socket = sock;
    resolver_running.store(true, .release);
    external_resolver_available.store(false, .release);

    resolver_thread = std.Thread.spawn(.{}, resolverLoop, .{sock}) catch |e| {
        log.warn("dns: failed to spawn resolver thread: {}", .{e});
        resolver_running.store(false, .release);
        platform.posix.close(sock);
        resolver_socket = null;
        return;
    };

    log.info("dns resolver started on 10.42.0.1:53", .{});
}

pub fn isRunning() bool {
    return resolver_running.load(.acquire) or external_resolver_available.load(.acquire);
}

pub fn isOwnedByCurrentProcess() bool {
    return resolver_running.load(.acquire);
}

pub fn stopResolver() void {
    resolver_mutex.lockUncancelable(std.Options.debug_io);

    if (!resolver_running.load(.acquire)) {
        external_resolver_available.store(false, .release);
        resolver_mutex.unlock(std.Options.debug_io);
        return;
    }

    resolver_running.store(false, .release);

    // shut down the socket to unblock any recvfrom() in the resolver thread
    // before closing it, so the thread sees ENOTCONN instead of EBADF
    if (resolver_socket) |sock| {
        posix.shutdown(sock, .both) catch {};
    }

    const thread = resolver_thread;
    resolver_thread = null;
    resolver_mutex.unlock(std.Options.debug_io);

    if (thread) |t| {
        t.join();
    }

    // close socket after thread has exited
    resolver_mutex.lockUncancelable(std.Options.debug_io);
    if (resolver_socket) |sock| {
        platform.posix.close(sock);
        resolver_socket = null;
    }
    external_resolver_available.store(false, .release);
    resolver_mutex.unlock(std.Options.debug_io);
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

    const now = platform.milliTimestamp();
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

fn resolverLoop(sock: platform.posix.socket_t) void {
    var recv_buf: [512]u8 = undefined;

    while (resolver_running.load(.acquire)) {
        var client_addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

        const recv_len = platform.posix.recvfrom(sock, &recv_buf, 0, @ptrCast(&client_addr), &addr_len) catch {
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

        handleQuery(sock, recv_buf[0..recv_len], &client_addr, addr_len);
    }
}

fn handleQuery(
    sock: platform.posix.socket_t,
    query: []const u8,
    client_addr: *const posix.sockaddr.in,
    addr_len: posix.socklen_t,
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
    if (question.qtype != packet_support.TYPE_A or question.qclass != packet_support.CLASS_IN) {
        forwardQuery(sock, query, client_addr, addr_len);
        return;
    }

    const name = question.name[0..question.name_len];
    if (registry_support.lookupServiceForDns(name)) |service_ip| {
        var response_buf: [512]u8 = undefined;
        if (packet_support.buildResponse(query, query.len, service_ip, &response_buf)) |resp_len| {
            _ = platform.posix.sendto(sock, response_buf[0..resp_len], 0, @ptrCast(client_addr), addr_len) catch |e| {
                log.warn("dns: failed to send response: {}", .{e});
            };
            return;
        }
    }

    forwardQuery(sock, query, client_addr, addr_len);
}

fn forwardQuery(
    sock: platform.posix.socket_t,
    query: []const u8,
    client_addr: *const posix.sockaddr.in,
    addr_len: posix.socklen_t,
) void {
    const upstream_sock = platform.posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
    defer platform.posix.close(upstream_sock);

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

    _ = platform.posix.sendto(upstream_sock, query, 0, @ptrCast(&upstream_addr), @sizeOf(posix.sockaddr.in)) catch return;

    var response_buf: [512]u8 = undefined;
    var resp_addr: posix.sockaddr.in = undefined;
    var resp_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

    const resp_n = platform.posix.recvfrom(upstream_sock, &response_buf, 0, @ptrCast(&resp_addr), &resp_addr_len) catch return;

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

    _ = platform.posix.sendto(sock, response_buf[0..resp_n], 0, @ptrCast(client_addr), addr_len) catch |e| {
        log.warn("dns: failed to relay upstream response: {}", .{e});
    };
}
