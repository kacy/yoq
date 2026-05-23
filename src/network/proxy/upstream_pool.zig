//! bounded keep-alive connection pool for the L7 reverse proxy.
//!
//! the proxy opens TCP connections to upstream endpoints to forward requests.
//! without pooling every request pays a fresh connect; with it we keep a small
//! number of idle, kept-alive connections per endpoint and hand them back out.
//!
//! the pool is a process-wide singleton guarded by its own mutex (kept separate
//! from the metrics mutex in runtime.zig so the hot forward path does not
//! contend with status snapshots). connections are keyed per endpoint by
//! endpoint id + address + port, so a re-registered endpoint at a new address
//! can never be handed a socket from its previous incarnation.
//!
//! a checked-out connection is owned solely by the requesting thread until it
//! is released or discarded; the mutex only guards the map and counters and is
//! never held across socket I/O.

const std = @import("std");
const linux_platform = @import("linux_platform");
const socket_helpers = @import("socket_helpers.zig");

const socket_t = linux_platform.posix.socket_t;

/// most idle connections kept per endpoint. a small fixed array keeps the
/// checkout/release path allocation-free once an endpoint is known.
pub const max_idle_per_endpoint = 8;
/// global ceiling on idle connections across all endpoints, guarding against
/// file-descriptor exhaustion when many endpoints are in play.
pub const max_total_idle = 256;
/// idle connections older than this are evicted rather than reused.
pub const idle_timeout_ms = 30_000;

const PooledConn = struct {
    fd: socket_t,
    idle_since_ms: i64,
};

const EndpointPool = struct {
    conns: [max_idle_per_endpoint]PooledConn = undefined,
    len: usize = 0,
};

var mutex: std.Io.Mutex = .init;
var pool: std.StringHashMapUnmanaged(EndpointPool) = .{};

// counters surfaced as metrics. `active` and `idle_total` are gauges; the
// rest are monotonic totals.
var active: u64 = 0;
var idle_total: u64 = 0;
var reuse_total: u64 = 0;
var created_total: u64 = 0;
var evicted_idle_total: u64 = 0;
var evicted_broken_total: u64 = 0;
var evicted_overflow_total: u64 = 0;

pub const PoolSnapshot = struct {
    active: u64,
    idle: u64,
    reuse_total: u64,
    created_total: u64,
    evicted_idle_total: u64,
    evicted_broken_total: u64,
    evicted_overflow_total: u64,
};

fn nowMilliseconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toMilliseconds();
}

fn keyFor(endpoint_id: []const u8, address: []const u8, port: u16) ?[]u8 {
    return std.fmt.allocPrint(std.heap.page_allocator, "{s}\x1f{s}\x1f{d}", .{ endpoint_id, address, port }) catch null;
}

/// try to hand out a live idle connection for an endpoint. expired or
/// half-closed connections found along the way are closed and evicted. returns
/// null when no reusable connection is available, in which case the caller
/// should dial a fresh one and report it via `noteDialed`.
pub fn checkout(endpoint_id: []const u8, address: []const u8, port: u16) ?socket_t {
    const key = keyFor(endpoint_id, address, port) orelse return null;
    defer std.heap.page_allocator.free(key);

    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    const entry = pool.getPtr(key) orelse return null;
    const now = nowMilliseconds();

    // pop from the end (most-recently-released, warmest) toward the front.
    while (entry.len > 0) {
        entry.len -= 1;
        idle_total -|= 1;
        const conn = entry.conns[entry.len];

        if (now - conn.idle_since_ms >= idle_timeout_ms) {
            linux_platform.posix.close(conn.fd);
            evicted_idle_total += 1;
            continue;
        }
        if (!socket_helpers.peekConnAlive(conn.fd)) {
            linux_platform.posix.close(conn.fd);
            evicted_broken_total += 1;
            continue;
        }

        active += 1;
        reuse_total += 1;
        return conn.fd;
    }
    return null;
}

/// record that a fresh connection was dialed because no pooled one was reusable.
pub fn noteDialed() void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    active += 1;
    created_total += 1;
}

/// return a still-usable connection to the pool. if there is no room (per
/// endpoint or globally) the connection is closed and counted as an overflow
/// eviction instead.
pub fn release(endpoint_id: []const u8, address: []const u8, port: u16, fd: socket_t) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    active -|= 1;

    if (idle_total >= max_total_idle) {
        linux_platform.posix.close(fd);
        evicted_overflow_total += 1;
        return;
    }

    const key = keyFor(endpoint_id, address, port) orelse {
        linux_platform.posix.close(fd);
        evicted_overflow_total += 1;
        return;
    };

    const result = pool.getOrPut(std.heap.page_allocator, key) catch {
        std.heap.page_allocator.free(key);
        linux_platform.posix.close(fd);
        evicted_overflow_total += 1;
        return;
    };
    if (result.found_existing) {
        std.heap.page_allocator.free(key);
    } else {
        // the key the map stored is the one we allocated; keep it.
        result.value_ptr.* = .{};
    }

    const entry = result.value_ptr;
    if (entry.len >= max_idle_per_endpoint) {
        linux_platform.posix.close(fd);
        evicted_overflow_total += 1;
        return;
    }

    entry.conns[entry.len] = .{ .fd = fd, .idle_since_ms = nowMilliseconds() };
    entry.len += 1;
    idle_total += 1;
}

/// drop a checked-out connection that is broken or not reusable.
pub fn discard(fd: socket_t) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    active -|= 1;
    linux_platform.posix.close(fd);
}

/// evict idle connections that have outlived `idle_timeout_ms`. meant to be
/// called from the proxy control-plane periodic pass so connections do not
/// linger when traffic goes quiet.
pub fn sweepIdle(now_ms: i64) void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    var it = pool.iterator();
    while (it.next()) |kv| {
        const entry = kv.value_ptr;
        var i: usize = 0;
        while (i < entry.len) {
            if (now_ms - entry.conns[i].idle_since_ms >= idle_timeout_ms) {
                linux_platform.posix.close(entry.conns[i].fd);
                evicted_idle_total += 1;
                idle_total -|= 1;
                // compact by swapping the last live entry into this slot.
                entry.len -= 1;
                entry.conns[i] = entry.conns[entry.len];
            } else {
                i += 1;
            }
        }
    }
}

pub fn snapshot() PoolSnapshot {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);
    return .{
        .active = active,
        .idle = idle_total,
        .reuse_total = reuse_total,
        .created_total = created_total,
        .evicted_idle_total = evicted_idle_total,
        .evicted_broken_total = evicted_broken_total,
        .evicted_overflow_total = evicted_overflow_total,
    };
}

pub fn resetForTest() void {
    mutex.lockUncancelable(std.Options.debug_io);
    defer mutex.unlock(std.Options.debug_io);

    var it = pool.iterator();
    while (it.next()) |kv| {
        const entry = kv.value_ptr;
        for (entry.conns[0..entry.len]) |conn| linux_platform.posix.close(conn.fd);
        std.heap.page_allocator.free(kv.key_ptr.*);
    }
    pool.clearAndFree(std.heap.page_allocator);

    active = 0;
    idle_total = 0;
    reuse_total = 0;
    created_total = 0;
    evicted_idle_total = 0;
    evicted_broken_total = 0;
    evicted_overflow_total = 0;
}

// -- tests --

const posix = std.posix;

fn testPair() ![2]socket_t {
    var fds: [2]i32 = undefined;
    const rc = std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SkipZigTest;
    return .{ fds[0], fds[1] };
}

test "checkout returns null until a connection is released, then reuses it" {
    resetForTest();
    defer resetForTest();

    try std.testing.expect(checkout("api-1", "10.0.0.2", 8080) == null);

    const pair = try testPair();
    defer linux_platform.posix.close(pair[1]); // keep peer open so the conn stays alive

    noteDialed();
    release("api-1", "10.0.0.2", 8080, pair[0]);
    try std.testing.expectEqual(@as(u64, 1), snapshot().idle);

    const reused = checkout("api-1", "10.0.0.2", 8080) orelse return error.TestExpectedReuse;
    try std.testing.expectEqual(pair[0], reused);

    const snap = snapshot();
    try std.testing.expectEqual(@as(u64, 1), snap.reuse_total);
    try std.testing.expectEqual(@as(u64, 1), snap.created_total);
    try std.testing.expectEqual(@as(u64, 0), snap.idle);
    try std.testing.expectEqual(@as(u64, 1), snap.active);

    discard(reused);
    try std.testing.expectEqual(@as(u64, 0), snapshot().active);
}

test "release beyond the per-endpoint cap evicts as overflow" {
    resetForTest();
    defer resetForTest();

    var peers: [max_idle_per_endpoint + 1]socket_t = undefined;
    var i: usize = 0;
    while (i <= max_idle_per_endpoint) : (i += 1) {
        const pair = try testPair();
        peers[i] = pair[1];
        noteDialed();
        release("api-1", "10.0.0.2", 8080, pair[0]);
    }
    defer for (peers) |p| linux_platform.posix.close(p);

    const snap = snapshot();
    try std.testing.expectEqual(@as(u64, max_idle_per_endpoint), snap.idle);
    try std.testing.expectEqual(@as(u64, 1), snap.evicted_overflow_total);
}

test "sweepIdle evicts connections past the idle timeout" {
    resetForTest();
    defer resetForTest();

    const pair = try testPair();
    defer linux_platform.posix.close(pair[1]);

    noteDialed();
    release("api-1", "10.0.0.2", 8080, pair[0]);
    try std.testing.expectEqual(@as(u64, 1), snapshot().idle);

    // sweep with a clock far in the future so the entry is expired.
    sweepIdle(nowMilliseconds() + idle_timeout_ms + 1);

    const snap = snapshot();
    try std.testing.expectEqual(@as(u64, 0), snap.idle);
    try std.testing.expectEqual(@as(u64, 1), snap.evicted_idle_total);
}

test "checkout discards a connection whose peer has closed" {
    resetForTest();
    defer resetForTest();

    const pair = try testPair();
    noteDialed();
    release("api-1", "10.0.0.2", 8080, pair[0]);

    // peer closes: the pooled connection is now half-closed.
    linux_platform.posix.close(pair[1]);

    try std.testing.expect(checkout("api-1", "10.0.0.2", 8080) == null);
    const snap = snapshot();
    try std.testing.expectEqual(@as(u64, 1), snap.evicted_broken_total);
    try std.testing.expectEqual(@as(u64, 0), snap.idle);
}
