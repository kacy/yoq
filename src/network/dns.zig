// dns — userspace DNS resolver for container service discovery
//
// provides name resolution for containers on the yoq bridge network.
// runs a UDP listener on the bridge gateway (10.42.0.1:53) that answers
// A record queries for registered service names. unknown names are
// forwarded to an upstream DNS server read from /etc/resolv.conf
// (falls back to 8.8.8.8 if unavailable).
//
// security: upstream DNS responses are validated against the expected
// source address and port to prevent spoofing. service name reassignments
// are logged as warnings for conflict visibility.
//
// the in-memory registry is the hot path for lookups. the SQLite
// service_names table provides persistence across restarts.
//
// in cluster mode, lookups that miss the local registry fall through
// to the replicated service_names table (via cluster_db), providing
// transparent cross-node DNS resolution.
//
// thread model: single resolver thread, blocking recvfrom().
// the mutex around the registry is fine — critical section is
// an array scan + 4-byte IP copy.

const std = @import("std");
const posix = std.posix;
const sqlite = @import("sqlite");
const log = @import("../lib/log.zig");
const ip_mod = @import("ip.zig");
const ebpf = @import("ebpf.zig");

// -- service registry --
//
// fixed-size array of name→IP entries, protected by a mutex.
// capacity of 256 services is plenty for single-node use.
// names are stored as fixed-size buffers to avoid heap allocation.

const max_services = 256;
const max_name_len = 63; // max DNS label length

const ServiceEntry = struct {
    name: [max_name_len]u8,
    name_len: u8,
    container_id: [12]u8,
    container_id_len: u8,
    ip: [4]u8,
    active: bool,
};

var registry: [max_services]ServiceEntry = [_]ServiceEntry{.{
    .name = undefined,
    .name_len = 0,
    .container_id = undefined,
    .container_id_len = 0,
    .ip = .{ 0, 0, 0, 0 },
    .active = false,
}} ** max_services;
var registry_count: usize = 0;
var registry_mutex: std.Thread.Mutex = .{};

// -- cluster DNS --
//
// optional reference to the replicated state machine DB. when set,
// lookups that miss the local in-memory registry fall through to
// the service_names table, enabling cross-node name resolution.
// the DB is owned by the raft state machine — we just read from it.

var cluster_db: ?*sqlite.Db = null;

/// set the cluster database for cross-node DNS lookups.
/// called during agent startup after raft state machine is initialized.
/// pass null to disable cluster lookups (single-node mode).
pub fn setClusterDb(db: ?*sqlite.Db) void {
    cluster_db = db;
}

/// look up a service name in the replicated cluster database.
/// queries the service_names table for the IP address.
/// returns null if the name isn't found or the DB isn't available.
pub fn lookupClusterService(name: []const u8) ?[4]u8 {
    const db = cluster_db orelse return null;

    const Row = struct { ip_address: sqlite.Text };

    // query the service_names table for the most recently registered
    // entry with this name. multiple containers may share a name
    // (replicas), so we take the latest registration.
    var stmt = db.prepare(
        "SELECT ip_address FROM service_names WHERE name = ? ORDER BY registered_at DESC LIMIT 1;",
    ) catch return null;
    defer stmt.deinit();

    const row = stmt.oneAlloc(Row, std.heap.page_allocator, .{}, .{name}) catch return null;
    if (row) |r| {
        defer std.heap.page_allocator.free(r.ip_address.data);
        return ip_mod.parseIp(r.ip_address.data);
    }

    return null;
}

/// register a service name for a container IP.
/// if the same name already exists, the IP is updated (last-write-wins).
pub fn registerService(name: []const u8, container_id: []const u8, container_ip: [4]u8) void {
    if (name.len == 0 or name.len > max_name_len) return;

    registry_mutex.lock();
    defer registry_mutex.unlock();

    // check if this container already has an entry for this name
    for (&registry) |*entry| {
        if (entry.active and
            entry.name_len == name.len and
            std.mem.eql(u8, entry.name[0..entry.name_len], name) and
            entry.container_id_len == container_id.len and
            std.mem.eql(u8, entry.container_id[0..entry.container_id_len], container_id))
        {
            // update IP
            entry.ip = container_ip;
            updateBpfMap(name, container_ip);
            return;
        }
    }

    // check if the name already belongs to a different container.
    // this happens during replica scaling or container replacement.
    // we keep last-write-wins behavior but log the reassignment.
    if (detectNameConflict(name, container_id, container_ip)) |prev| {
        log.warn("dns: service name '{s}' reassigned from {d}.{d}.{d}.{d} ({s}) to {d}.{d}.{d}.{d} ({s})", .{
            name,
            prev.ip[0],   prev.ip[1],   prev.ip[2],   prev.ip[3],
            prev.container_id[0..prev.container_id_len],
            container_ip[0], container_ip[1], container_ip[2], container_ip[3],
            container_id[0..@min(container_id.len, 12)],
        });
    }

    // find a free slot
    for (&registry) |*entry| {
        if (!entry.active) {
            entry.active = true;
            entry.name_len = @intCast(name.len);
            @memcpy(entry.name[0..name.len], name);
            const cid_len: usize = @min(container_id.len, 12);
            entry.container_id_len = @intCast(cid_len);
            @memcpy(entry.container_id[0..cid_len], container_id[0..cid_len]);
            entry.ip = container_ip;
            registry_count += 1;
            updateBpfMap(name, container_ip);
            return;
        }
    }

    // registry full — log and drop
    log.warn("dns registry full, cannot register {s}", .{name});
}

/// unregister all service names for a container.
pub fn unregisterService(container_id: []const u8) void {
    registry_mutex.lock();
    defer registry_mutex.unlock();

    const cid_len = @min(container_id.len, 12);
    for (&registry) |*entry| {
        if (entry.active and
            entry.container_id_len == cid_len and
            std.mem.eql(u8, entry.container_id[0..entry.container_id_len], container_id[0..cid_len]))
        {
            deleteBpfMap(entry.name[0..entry.name_len]);
            entry.active = false;
            registry_count -= 1;
        }
    }
}

// -- BPF map sync --
//
// when a DNS interceptor is loaded, keep the BPF service_names map
// in sync with the in-memory registry. these are best-effort —
// if BPF isn't loaded, they're no-ops.

fn updateBpfMap(name: []const u8, ip_addr: [4]u8) void {
    if (ebpf.getDnsInterceptor()) |interceptor| {
        interceptor.updateService(name, ip_addr);
    }
}

fn deleteBpfMap(name: []const u8) void {
    if (ebpf.getDnsInterceptor()) |interceptor| {
        interceptor.deleteService(name);
    }
}

/// check if a service name is currently held by a different container.
/// returns the existing entry's info if it would be a reassignment, null otherwise.
/// caller must hold registry_mutex.
fn detectNameConflict(name: []const u8, new_container_id: []const u8, _: [4]u8) ?struct { ip: [4]u8, container_id: [12]u8, container_id_len: u8 } {
    const new_cid_len = @min(new_container_id.len, 12);

    // scan backwards to find the most recent entry with this name
    var i: usize = max_services;
    while (i > 0) {
        i -= 1;
        const entry = &registry[i];
        if (entry.active and
            entry.name_len == name.len and
            std.mem.eql(u8, entry.name[0..entry.name_len], name))
        {
            // same container — not a conflict (IP update is normal)
            if (entry.container_id_len == new_cid_len and
                std.mem.eql(u8, entry.container_id[0..entry.container_id_len], new_container_id[0..new_cid_len]))
            {
                return null;
            }

            // different container claiming the same name — reassignment
            return .{
                .ip = entry.ip,
                .container_id = entry.container_id,
                .container_id_len = entry.container_id_len,
            };
        }
    }

    return null;
}

/// look up the IP for a service name. returns null if not found.
/// checks the local in-memory registry first, then falls through to
/// the cluster database if available (cross-node resolution).
/// if multiple containers share a name, returns the last registered (last-write-wins).
pub fn lookupService(name: []const u8) ?[4]u8 {
    // check local in-memory registry first (hot path)
    {
        registry_mutex.lock();
        defer registry_mutex.unlock();

        // scan backwards to get the most recently registered entry
        var i: usize = max_services;
        while (i > 0) {
            i -= 1;
            const entry = &registry[i];
            if (entry.active and
                entry.name_len == name.len and
                std.mem.eql(u8, entry.name[0..entry.name_len], name))
            {
                return entry.ip;
            }
        }
    }

    // not found locally — try the cluster database for cross-node resolution
    return lookupClusterService(name);
}

// -- DNS wire format --
//
// minimal implementation of RFC 1035 for A record queries.
// only handles standard queries (opcode 0) with a single question.
// all parsing and building uses stack buffers — no heap allocation.

/// DNS header flags and fields
const DnsHeader = struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
};

/// parsed DNS question
const DnsQuestion = struct {
    name: [253]u8, // max DNS name length
    name_len: usize,
    qtype: u16,
    qclass: u16,
    /// byte offset where the question section ends in the packet
    end_offset: usize,
};

/// DNS record types
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

/// parse a DNS header from a packet buffer.
/// returns null if the buffer is too short.
pub fn parseHeader(buf: []const u8) ?DnsHeader {
    if (buf.len < 12) return null;

    return DnsHeader{
        .id = readU16(buf[0..2]),
        .flags = readU16(buf[2..4]),
        .qdcount = readU16(buf[4..6]),
        .ancount = readU16(buf[6..8]),
        .nscount = readU16(buf[8..10]),
        .arcount = readU16(buf[10..12]),
    };
}

/// parse the question section from a DNS packet.
/// handles the label-length encoding (e.g., 3www6google3com0).
/// returns null if the packet is malformed.
pub fn parseQuestion(buf: []const u8) ?DnsQuestion {
    if (buf.len < 13) return null; // header (12) + at least 1 byte

    var q = DnsQuestion{
        .name = undefined,
        .name_len = 0,
        .qtype = 0,
        .qclass = 0,
        .end_offset = 0,
    };

    var pos: usize = 12; // skip header
    var name_pos: usize = 0;

    // read labels
    while (pos < buf.len) {
        const label_len = buf[pos];
        pos += 1;

        if (label_len == 0) break; // end of name

        // sanity checks
        if (label_len > 63) return null; // label too long or compression pointer
        if (pos + label_len > buf.len) return null; // truncated

        // add dot separator between labels
        if (name_pos > 0) {
            if (name_pos >= q.name.len) return null;
            q.name[name_pos] = '.';
            name_pos += 1;
        }

        if (name_pos + label_len > q.name.len) return null; // name too long
        @memcpy(q.name[name_pos..][0..label_len], buf[pos..][0..label_len]);
        name_pos += label_len;
        pos += label_len;
    }

    q.name_len = name_pos;

    // read QTYPE and QCLASS
    if (pos + 4 > buf.len) return null;
    q.qtype = readU16(buf[pos..][0..2]);
    q.qclass = readU16(buf[pos + 2 ..][0..2]);
    q.end_offset = pos + 4;

    return q;
}

/// build a DNS A record response for a query.
/// copies the query ID and question section, adds an answer.
/// returns the response length, or null if building fails.
pub fn buildResponse(query_buf: []const u8, query_len: usize, response_ip: [4]u8, response_buf: *[512]u8) ?usize {
    const header = parseHeader(query_buf[0..@min(query_buf.len, query_len)]) orelse return null;
    const question = parseQuestion(query_buf[0..@min(query_buf.len, query_len)]) orelse return null;

    // response header
    writeU16(response_buf[0..2], header.id); // copy query ID
    writeU16(response_buf[2..4], 0x8400); // QR=1, AA=1, RA=0
    writeU16(response_buf[4..6], 1); // QDCOUNT = 1
    writeU16(response_buf[6..8], 1); // ANCOUNT = 1
    writeU16(response_buf[8..10], 0); // NSCOUNT = 0
    writeU16(response_buf[10..12], 0); // ARCOUNT = 0

    // copy question section from original query
    const question_bytes = question.end_offset - 12;
    if (12 + question_bytes > response_buf.len) return null;
    @memcpy(response_buf[12..][0..question_bytes], query_buf[12..][0..question_bytes]);

    var pos: usize = 12 + question_bytes;

    // answer section: pointer to name in question (compression)
    if (pos + 16 > response_buf.len) return null;
    writeU16(response_buf[pos..][0..2], 0xC00C); // pointer to name at offset 12
    pos += 2;
    writeU16(response_buf[pos..][0..2], TYPE_A); // TYPE
    pos += 2;
    writeU16(response_buf[pos..][0..2], CLASS_IN); // CLASS
    pos += 2;
    writeU32(response_buf[pos..][0..4], 5); // TTL = 5 seconds
    pos += 4;
    writeU16(response_buf[pos..][0..2], 4); // RDLENGTH = 4 (IPv4)
    pos += 2;
    response_buf[pos] = response_ip[0]; // RDATA
    response_buf[pos + 1] = response_ip[1];
    response_buf[pos + 2] = response_ip[2];
    response_buf[pos + 3] = response_ip[3];
    pos += 4;

    return pos;
}

/// build a "name not found" (NXDOMAIN) response.
pub fn buildNxDomain(query_buf: []const u8, query_len: usize, response_buf: *[512]u8) ?usize {
    const header = parseHeader(query_buf[0..@min(query_buf.len, query_len)]) orelse return null;
    const question = parseQuestion(query_buf[0..@min(query_buf.len, query_len)]) orelse return null;

    // response header — RCODE=3 (NXDOMAIN)
    writeU16(response_buf[0..2], header.id);
    writeU16(response_buf[2..4], 0x8403); // QR=1, AA=1, RCODE=3
    writeU16(response_buf[4..6], 1); // QDCOUNT
    writeU16(response_buf[6..8], 0); // ANCOUNT
    writeU16(response_buf[8..10], 0); // NSCOUNT
    writeU16(response_buf[10..12], 0); // ARCOUNT

    // copy question section
    const question_bytes = question.end_offset - 12;
    if (12 + question_bytes > response_buf.len) return null;
    @memcpy(response_buf[12..][0..question_bytes], query_buf[12..][0..question_bytes]);

    return 12 + question_bytes;
}

// -- resolver thread --

const listen_port: u16 = 53;
const upstream_port: u16 = 53;

// upstream DNS server, read from /etc/resolv.conf at startup.
// falls back to 8.8.8.8 if resolv.conf is missing or unparseable.
var upstream_dns: [4]u8 = .{ 8, 8, 8, 8 };
var upstream_initialized: bool = false;

/// read /etc/resolv.conf and extract the first nameserver address.
/// called once at resolver startup. idempotent.
fn initUpstreamDns() void {
    if (upstream_initialized) return;
    upstream_initialized = true;

    const content = std.fs.cwd().readFileAlloc(
        std.heap.page_allocator,
        "/etc/resolv.conf",
        4096,
    ) catch {
        log.info("dns: /etc/resolv.conf not readable, using 8.8.8.8", .{});
        return;
    };
    defer std.heap.page_allocator.free(content);

    if (parseResolvConf(content)) |addr| {
        upstream_dns = addr;
        log.info("dns: upstream resolver set to {d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] });
    } else {
        log.info("dns: no valid nameserver in resolv.conf, using 8.8.8.8", .{});
    }
}

/// parse the first nameserver line from resolv.conf content.
/// returns the IPv4 address as a 4-byte array, or null if none found.
pub fn parseResolvConf(content: []const u8) ?[4]u8 {
    var pos: usize = 0;
    while (pos < content.len) {
        // find end of current line
        const line_end = std.mem.indexOfPos(u8, content, pos, "\n") orelse content.len;
        const line = content[pos..line_end];
        pos = if (line_end < content.len) line_end + 1 else content.len;

        // skip comments and blank lines
        const trimmed = std.mem.trimLeft(u8, line, " \t");
        if (trimmed.len == 0 or trimmed[0] == '#' or trimmed[0] == ';') continue;

        // look for "nameserver" prefix
        const prefix = "nameserver";
        if (trimmed.len <= prefix.len) continue;
        if (!std.mem.eql(u8, trimmed[0..prefix.len], prefix)) continue;

        // must be followed by whitespace
        if (trimmed[prefix.len] != ' ' and trimmed[prefix.len] != '\t') continue;

        // extract the address string
        const addr_str = std.mem.trimLeft(u8, trimmed[prefix.len..], " \t");
        // trim trailing whitespace and carriage return
        const addr_clean = std.mem.trimRight(u8, addr_str, " \t\r");

        if (addr_clean.len == 0) continue;

        // parse dotted-quad IPv4 address
        if (ip_mod.parseIp(addr_clean)) |addr| return addr;
    }

    return null;
}


var resolver_thread: ?std.Thread = null;
var resolver_socket: ?posix.socket_t = null;
var resolver_running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var resolver_mutex: std.Thread.Mutex = .{};

/// start the DNS resolver thread. idempotent — safe to call multiple times.
pub fn startResolver() void {
    resolver_mutex.lock();
    defer resolver_mutex.unlock();

    if (resolver_running.load(.acquire)) return;

    // read upstream DNS from resolv.conf on first start
    initUpstreamDns();

    // create UDP socket with CLOEXEC so it isn't inherited by child
    // processes (e.g. iptables spawned during container setup)
    const sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0) catch |e| {
        log.warn("dns: failed to create socket: {}", .{e});
        return;
    };

    // bind to bridge gateway address
    const addr = posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, listen_port),
        .addr = std.mem.nativeToBig(u32, (@as(u32, 10) << 24) | (@as(u32, 42) << 16) | (@as(u32, 0) << 8) | 1),
    };

    posix.bind(sock, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch |e| {
        log.warn("dns: failed to bind to 10.42.0.1:53: {}", .{e});
        posix.close(sock);
        return;
    };

    resolver_socket = sock;
    resolver_running.store(true, .release);

    resolver_thread = std.Thread.spawn(.{}, resolverLoop, .{sock}) catch |e| {
        log.warn("dns: failed to spawn resolver thread: {}", .{e});
        resolver_running.store(false, .release);
        posix.close(sock);
        resolver_socket = null;
        return;
    };

    log.info("dns resolver started on 10.42.0.1:53", .{});
}

/// stop the DNS resolver thread.
pub fn stopResolver() void {
    resolver_mutex.lock();

    if (!resolver_running.load(.acquire)) {
        resolver_mutex.unlock();
        return;
    }

    resolver_running.store(false, .release);

    // close the socket to unblock recvfrom
    if (resolver_socket) |sock| {
        posix.close(sock);
        resolver_socket = null;
    }

    const thread = resolver_thread;
    resolver_thread = null;
    resolver_mutex.unlock();

    // join outside the lock to avoid deadlock
    if (thread) |t| {
        t.join();
    }
}

/// main loop for the resolver thread.
/// blocks on recvfrom, handles queries, and sends responses.
fn resolverLoop(sock: posix.socket_t) void {
    var recv_buf: [512]u8 = undefined;

    while (resolver_running.load(.acquire)) {
        var client_addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

        const n = posix.recvfrom(sock, &recv_buf, 0, @ptrCast(&client_addr), &addr_len) catch {
            // socket closed or error — check if we should stop
            if (!resolver_running.load(.acquire)) break;
            continue;
        };

        if (n < 12) continue; // too short for DNS header

        handleQuery(sock, recv_buf[0..n], &client_addr, addr_len);
    }
}

/// handle a single DNS query: check registry, respond or forward.
fn handleQuery(
    sock: posix.socket_t,
    query: []const u8,
    client_addr: *const posix.sockaddr.in,
    addr_len: posix.socklen_t,
) void {
    const question = parseQuestion(query) orelse return;

    // only handle A record queries for IN class
    if (question.qtype != TYPE_A or question.qclass != CLASS_IN) {
        forwardQuery(sock, query, client_addr, addr_len);
        return;
    }

    const name = question.name[0..question.name_len];

    // check the in-memory registry
    if (lookupService(name)) |service_ip| {
        var response_buf: [512]u8 = undefined;
        if (buildResponse(query, query.len, service_ip, &response_buf)) |resp_len| {
            _ = posix.sendto(sock, response_buf[0..resp_len], 0, @ptrCast(client_addr), addr_len) catch |e| {
                log.warn("dns: failed to send response: {}", .{e});
            };
            return;
        }
    }

    // not a known service — forward to upstream
    forwardQuery(sock, query, client_addr, addr_len);
}

/// forward a DNS query to the upstream resolver and relay the response.
/// validates that the response comes from the expected upstream address
/// to prevent DNS spoofing from unexpected sources.
fn forwardQuery(
    sock: posix.socket_t,
    query: []const u8,
    client_addr: *const posix.sockaddr.in,
    addr_len: posix.socklen_t,
) void {
    // create a temporary socket for the upstream query
    const upstream_sock = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch return;
    defer posix.close(upstream_sock);

    // set a timeout so we don't block forever
    const timeout = posix.timeval{ .sec = 2, .usec = 0 };
    posix.setsockopt(upstream_sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch |e| {
        log.warn("dns: failed to set upstream socket timeout: {}", .{e});
    };

    // build upstream address from the configured DNS server
    const expected_addr = ipToU32(upstream_dns);
    const expected_port = std.mem.nativeToBig(u16, upstream_port);

    const upstream_addr = posix.sockaddr.in{
        .port = expected_port,
        .addr = std.mem.nativeToBig(u32, expected_addr),
    };

    // send query to upstream
    _ = posix.sendto(upstream_sock, query, 0, @ptrCast(&upstream_addr), @sizeOf(posix.sockaddr.in)) catch return;

    // receive response with source address validation
    var response_buf: [512]u8 = undefined;
    var resp_addr: posix.sockaddr.in = undefined;
    var resp_addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

    const resp_n = posix.recvfrom(
        upstream_sock,
        &response_buf,
        0,
        @ptrCast(&resp_addr),
        &resp_addr_len,
    ) catch return;

    // validate source address matches the upstream server we queried.
    // drop responses from unexpected sources — could be spoofed.
    if (resp_addr.addr != upstream_addr.addr or resp_addr.port != upstream_addr.port) {
        log.warn("dns: dropping response from unexpected source (expected {d}.{d}.{d}.{d}:{d})", .{
            upstream_dns[0], upstream_dns[1], upstream_dns[2], upstream_dns[3], upstream_port,
        });
        return;
    }

    // verify the response's transaction ID matches our query.
    // drop mismatched responses — could be stale or spoofed.
    if (resp_n < 2 or query.len < 2) return;
    if (response_buf[0] != query[0] or response_buf[1] != query[1]) return;

    // relay response to original client
    _ = posix.sendto(sock, response_buf[0..resp_n], 0, @ptrCast(client_addr), addr_len) catch |e| {
        log.warn("dns: failed to relay upstream response: {}", .{e});
    };
}

/// convert a 4-byte IP to a u32 in host byte order.
fn ipToU32(ip: [4]u8) u32 {
    return (@as(u32, ip[0]) << 24) | (@as(u32, ip[1]) << 16) | (@as(u32, ip[2]) << 8) | @as(u32, ip[3]);
}

// -- helpers --

fn readU16(buf: *const [2]u8) u16 {
    return (@as(u16, buf[0]) << 8) | @as(u16, buf[1]);
}

fn writeU16(buf: *[2]u8, val: u16) void {
    const be = std.mem.nativeToBig(u16, val);
    buf[0] = @truncate(be >> 8);
    buf[1] = @truncate(be);
}

fn writeU32(buf: *[4]u8, val: u32) void {
    const be = std.mem.nativeToBig(u32, val);
    buf[0] = @truncate(be >> 24);
    buf[1] = @truncate(be >> 16);
    buf[2] = @truncate(be >> 8);
    buf[3] = @truncate(be);
}

// -- tests --

test "parse valid A record query" {
    // dig example.com A — minimal hand-crafted packet
    // header: ID=0x1234, flags=0x0100 (standard query), QDCOUNT=1
    var packet: [29]u8 = undefined;
    // header
    packet[0] = 0x12;
    packet[1] = 0x34; // ID
    packet[2] = 0x01;
    packet[3] = 0x00; // flags: standard query
    packet[4] = 0x00;
    packet[5] = 0x01; // QDCOUNT = 1
    packet[6] = 0x00;
    packet[7] = 0x00; // ANCOUNT = 0
    packet[8] = 0x00;
    packet[9] = 0x00; // NSCOUNT = 0
    packet[10] = 0x00;
    packet[11] = 0x00; // ARCOUNT = 0
    // question: "db" (2-byte label)
    packet[12] = 2; // label length
    packet[13] = 'd';
    packet[14] = 'b';
    packet[15] = 0; // end of name
    // QTYPE = A (1), QCLASS = IN (1)
    packet[16] = 0x00;
    packet[17] = 0x01;
    packet[18] = 0x00;
    packet[19] = 0x01;
    // padding (unused, but fills the array)
    @memset(packet[20..], 0);

    const header = parseHeader(&packet).?;
    try std.testing.expectEqual(@as(u16, 0x1234), header.id);
    try std.testing.expectEqual(@as(u16, 1), header.qdcount);

    const q = parseQuestion(&packet).?;
    try std.testing.expectEqualStrings("db", q.name[0..q.name_len]);
    try std.testing.expectEqual(TYPE_A, q.qtype);
    try std.testing.expectEqual(CLASS_IN, q.qclass);
}

test "parse multi-label name" {
    // query for "web.service.local"
    var packet: [40]u8 = undefined;
    // header
    @memset(packet[0..12], 0);
    packet[0] = 0xAB;
    packet[1] = 0xCD; // ID
    packet[4] = 0x00;
    packet[5] = 0x01; // QDCOUNT = 1
    // question: 3web7service5local0
    var pos: usize = 12;
    packet[pos] = 3;
    pos += 1;
    @memcpy(packet[pos..][0..3], "web");
    pos += 3;
    packet[pos] = 7;
    pos += 1;
    @memcpy(packet[pos..][0..7], "service");
    pos += 7;
    packet[pos] = 5;
    pos += 1;
    @memcpy(packet[pos..][0..5], "local");
    pos += 5;
    packet[pos] = 0;
    pos += 1; // end of name
    // QTYPE=A, QCLASS=IN
    packet[pos] = 0x00;
    packet[pos + 1] = 0x01;
    packet[pos + 2] = 0x00;
    packet[pos + 3] = 0x01;
    pos += 4;
    @memset(packet[pos..], 0);

    const q = parseQuestion(&packet).?;
    try std.testing.expectEqualStrings("web.service.local", q.name[0..q.name_len]);
}

test "parse non-A query returns valid question with different qtype" {
    // AAAA query (type 28)
    var packet: [20]u8 = undefined;
    @memset(packet[0..12], 0);
    packet[4] = 0x00;
    packet[5] = 0x01; // QDCOUNT = 1
    packet[12] = 2;
    packet[13] = 'd';
    packet[14] = 'b';
    packet[15] = 0;
    packet[16] = 0x00;
    packet[17] = 28; // AAAA
    packet[18] = 0x00;
    packet[19] = 0x01;

    const q = parseQuestion(&packet).?;
    try std.testing.expectEqual(@as(u16, 28), q.qtype);
}

test "build response produces valid DNS packet" {
    // build a query packet for "db"
    var query: [20]u8 = undefined;
    query[0] = 0x12;
    query[1] = 0x34; // ID
    query[2] = 0x01;
    query[3] = 0x00; // flags
    query[4] = 0x00;
    query[5] = 0x01; // QDCOUNT
    @memset(query[6..12], 0);
    query[12] = 2;
    query[13] = 'd';
    query[14] = 'b';
    query[15] = 0;
    query[16] = 0x00;
    query[17] = 0x01; // A
    query[18] = 0x00;
    query[19] = 0x01; // IN

    var response: [512]u8 = undefined;
    const resp_len = buildResponse(&query, query.len, .{ 10, 42, 0, 5 }, &response).?;

    // verify header
    try std.testing.expectEqual(@as(u16, 0x1234), readU16(response[0..2])); // ID preserved
    try std.testing.expectEqual(@as(u16, 0x8400), readU16(response[2..4])); // QR=1, AA=1
    try std.testing.expectEqual(@as(u16, 1), readU16(response[4..6])); // QDCOUNT
    try std.testing.expectEqual(@as(u16, 1), readU16(response[6..8])); // ANCOUNT

    // verify answer contains our IP
    // answer starts after header (12) + question (8) = 20
    // name pointer (2) + type (2) + class (2) + TTL (4) + rdlength (2) + rdata (4) = 16
    try std.testing.expectEqual(@as(usize, 36), resp_len);

    // IP is at the end of the response
    try std.testing.expectEqual(@as(u8, 10), response[resp_len - 4]);
    try std.testing.expectEqual(@as(u8, 42), response[resp_len - 3]);
    try std.testing.expectEqual(@as(u8, 0), response[resp_len - 2]);
    try std.testing.expectEqual(@as(u8, 5), response[resp_len - 1]);
}

test "registry register and lookup" {
    // clean up any previous test state
    resetRegistryForTest();

    registerService("mydb", "container001", .{ 10, 42, 0, 10 });

    const result = lookupService("mydb");
    try std.testing.expect(result != null);
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 10 }, result.?);
}

test "registry unregister removes entry" {
    resetRegistryForTest();

    registerService("web", "ctr_aaa", .{ 10, 42, 0, 20 });
    unregisterService("ctr_aaa");

    try std.testing.expect(lookupService("web") == null);
}

test "registry same name multiple containers — last wins" {
    resetRegistryForTest();

    registerService("api", "ctr_111", .{ 10, 42, 0, 30 });
    registerService("api", "ctr_222", .{ 10, 42, 0, 31 });

    // last registered should win (higher index in array)
    const result = lookupService("api").?;
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 31 }, result);
}

test "registry lookup unknown name returns null" {
    resetRegistryForTest();

    try std.testing.expect(lookupService("nonexistent") == null);
}

test "malformed packet — truncated header" {
    const short: [6]u8 = .{ 0, 0, 0, 0, 0, 0 };
    try std.testing.expect(parseHeader(&short) == null);
}

test "malformed packet — zero length name" {
    var packet: [20]u8 = undefined;
    @memset(packet[0..12], 0);
    packet[4] = 0x00;
    packet[5] = 0x01; // QDCOUNT = 1
    packet[12] = 0; // empty name (just the null terminator)
    packet[13] = 0x00;
    packet[14] = 0x01; // A
    packet[15] = 0x00;
    packet[16] = 0x01; // IN
    @memset(packet[17..], 0);

    // should parse successfully — empty name is valid in DNS (root)
    const q = parseQuestion(&packet).?;
    try std.testing.expectEqual(@as(usize, 0), q.name_len);
}

test "nxdomain response" {
    var query: [20]u8 = undefined;
    query[0] = 0x56;
    query[1] = 0x78;
    query[2] = 0x01;
    query[3] = 0x00;
    query[4] = 0x00;
    query[5] = 0x01;
    @memset(query[6..12], 0);
    query[12] = 2;
    query[13] = 'x';
    query[14] = 'y';
    query[15] = 0;
    query[16] = 0x00;
    query[17] = 0x01;
    query[18] = 0x00;
    query[19] = 0x01;

    var response: [512]u8 = undefined;
    const resp_len = buildNxDomain(&query, query.len, &response).?;

    try std.testing.expectEqual(@as(u16, 0x5678), readU16(response[0..2]));
    try std.testing.expectEqual(@as(u16, 0x8403), readU16(response[2..4])); // NXDOMAIN
    try std.testing.expectEqual(@as(u16, 0), readU16(response[6..8])); // no answers
    try std.testing.expect(resp_len > 12);
}

test "registerService ignores empty name" {
    resetRegistryForTest();

    registerService("", "ctr_001", .{ 10, 42, 0, 50 });
    // registry should still be empty
    try std.testing.expect(lookupService("") == null);
}

test "registerService ignores name exceeding max length" {
    resetRegistryForTest();

    // 64 chars — exceeds max_name_len (63)
    const long_name = "a" ** 64;
    registerService(long_name, "ctr_001", .{ 10, 42, 0, 50 });

    try std.testing.expect(lookupService(long_name) == null);
}

test "registerService updates IP for same container" {
    resetRegistryForTest();

    registerService("db", "ctr_001", .{ 10, 42, 0, 10 });
    registerService("db", "ctr_001", .{ 10, 42, 0, 99 });

    // should return updated IP, not the original
    const result = lookupService("db").?;
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 99 }, result);
}

test "unregisterService only removes matching container" {
    resetRegistryForTest();

    registerService("api", "ctr_aaa", .{ 10, 42, 0, 10 });
    registerService("api", "ctr_bbb", .{ 10, 42, 0, 11 });

    // remove only ctr_aaa
    unregisterService("ctr_aaa");

    // ctr_bbb's entry should still be resolvable
    const result = lookupService("api");
    try std.testing.expect(result != null);
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 11 }, result.?);
}

test "lookupService returns null after registry reset" {
    resetRegistryForTest();

    registerService("svc", "ctr_001", .{ 10, 42, 0, 5 });
    try std.testing.expect(lookupService("svc") != null);

    resetRegistryForTest();
    try std.testing.expect(lookupService("svc") == null);
}

/// reset registry state for test isolation.
/// only used in tests.
fn resetRegistryForTest() void {
    registry_mutex.lock();
    defer registry_mutex.unlock();
    for (&registry) |*entry| {
        entry.active = false;
    }
    registry_count = 0;
}

// -- resolv.conf parsing tests --

test "parseResolvConf — standard resolv.conf" {
    const content =
        \\# generated by NetworkManager
        \\nameserver 10.0.0.1
        \\nameserver 8.8.4.4
        \\search local
    ;
    const result = parseResolvConf(content).?;
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 1 }, result);
}

test "parseResolvConf — leading whitespace" {
    const content = "  nameserver 192.168.1.1\n";
    const result = parseResolvConf(content).?;
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 1 }, result);
}

test "parseResolvConf — tabs as separator" {
    const content = "nameserver\t172.16.0.1\n";
    const result = parseResolvConf(content).?;
    try std.testing.expectEqual([4]u8{ 172, 16, 0, 1 }, result);
}

test "parseResolvConf — empty file" {
    try std.testing.expect(parseResolvConf("") == null);
}

test "parseResolvConf — only comments" {
    const content =
        \\# this file has no nameservers
        \\; another comment style
    ;
    try std.testing.expect(parseResolvConf(content) == null);
}

test "parseResolvConf — no nameserver lines" {
    const content =
        \\search example.com
        \\domain example.com
    ;
    try std.testing.expect(parseResolvConf(content) == null);
}

test "parseResolvConf — skips IPv6 nameserver" {
    const content =
        \\nameserver ::1
        \\nameserver 10.0.0.1
    ;
    // ::1 is not valid IPv4, so it should be skipped
    const result = parseResolvConf(content).?;
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 1 }, result);
}

test "parseResolvConf — carriage return line endings" {
    const content = "nameserver 1.2.3.4\r\nnameserver 5.6.7.8\r\n";
    const result = parseResolvConf(content).?;
    try std.testing.expectEqual([4]u8{ 1, 2, 3, 4 }, result);
}

test "parseResolvConf — malformed IP address" {
    const content = "nameserver not.an.ip.address\nnameserver 10.0.0.1\n";
    // should skip the bad one and return the valid one
    const result = parseResolvConf(content).?;
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 1 }, result);
}

test "parseResolvConf — nameserver without space is not matched" {
    const content = "nameserver_extra 10.0.0.1\nnameserver 10.0.0.2\n";
    const result = parseResolvConf(content).?;
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 2 }, result);
}

// -- name conflict detection tests --

test "detectNameConflict — different container same name" {
    resetRegistryForTest();

    registerService("db", "ctr_old", .{ 10, 42, 0, 10 });

    // calling detectNameConflict directly requires holding the mutex
    registry_mutex.lock();
    defer registry_mutex.unlock();

    const conflict = detectNameConflict("db", "ctr_new", .{ 10, 42, 0, 20 });
    try std.testing.expect(conflict != null);
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 10 }, conflict.?.ip);
}

test "detectNameConflict — same container is not a conflict" {
    resetRegistryForTest();

    registerService("web", "ctr_001", .{ 10, 42, 0, 10 });

    registry_mutex.lock();
    defer registry_mutex.unlock();

    const conflict = detectNameConflict("web", "ctr_001", .{ 10, 42, 0, 20 });
    try std.testing.expect(conflict == null);
}

test "detectNameConflict — unknown name is not a conflict" {
    resetRegistryForTest();

    registry_mutex.lock();
    defer registry_mutex.unlock();

    const conflict = detectNameConflict("new_svc", "ctr_001", .{ 10, 42, 0, 10 });
    try std.testing.expect(conflict == null);
}


// -- ipToU32 tests --

test "ipToU32 — correct conversion" {
    try std.testing.expectEqual(@as(u32, 0x0A2A0001), ipToU32(.{ 10, 42, 0, 1 }));
    try std.testing.expectEqual(@as(u32, 0x08080808), ipToU32(.{ 8, 8, 8, 8 }));
    try std.testing.expectEqual(@as(u32, 0x00000000), ipToU32(.{ 0, 0, 0, 0 }));
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), ipToU32(.{ 255, 255, 255, 255 }));
}

// -- cluster DNS tests --

test "lookupClusterService returns null when no cluster db" {
    // ensure cluster_db is null (default state)
    const prev = cluster_db;
    cluster_db = null;
    defer cluster_db = prev;

    try std.testing.expect(lookupClusterService("anything") == null);
}

test "setClusterDb sets and clears the db reference" {
    const prev = cluster_db;
    defer cluster_db = prev;

    setClusterDb(null);
    try std.testing.expect(cluster_db == null);

    // we can't easily create a real sqlite.Db in tests without the
    // schema module, but we can verify the setter works with null
    setClusterDb(null);
    try std.testing.expect(cluster_db == null);
}

test "lookupClusterService resolves from service_names table" {
    const schema = @import("../state/schema.zig");

    var db = sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } }) catch return;
    defer db.deinit();
    schema.init(&db) catch return;

    // insert a service name entry
    db.exec(
        "INSERT INTO service_names (name, container_id, ip_address, registered_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "remote-db", "ctr_remote", "10.42.3.5", @as(i64, 1000) },
    ) catch return;

    // set up cluster db reference
    const prev = cluster_db;
    defer cluster_db = prev;
    cluster_db = &db;

    const result = lookupClusterService("remote-db");
    try std.testing.expect(result != null);
    try std.testing.expectEqual([4]u8{ 10, 42, 3, 5 }, result.?);
}

test "lookupClusterService returns null for unknown name" {
    const schema = @import("../state/schema.zig");

    var db = sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } }) catch return;
    defer db.deinit();
    schema.init(&db) catch return;

    const prev = cluster_db;
    defer cluster_db = prev;
    cluster_db = &db;

    try std.testing.expect(lookupClusterService("nonexistent") == null);
}

test "lookupService falls through to cluster db" {
    const schema = @import("../state/schema.zig");

    resetRegistryForTest();

    var db = sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } }) catch return;
    defer db.deinit();
    schema.init(&db) catch return;

    // register a service only in the cluster db, not locally
    db.exec(
        "INSERT INTO service_names (name, container_id, ip_address, registered_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "cluster-svc", "ctr_remote", "10.42.5.10", @as(i64, 1000) },
    ) catch return;

    const prev = cluster_db;
    defer cluster_db = prev;
    cluster_db = &db;

    // lookupService should find it via the cluster db fallback
    const result = lookupService("cluster-svc");
    try std.testing.expect(result != null);
    try std.testing.expectEqual([4]u8{ 10, 42, 5, 10 }, result.?);
}

test "lookupService prefers local registry over cluster db" {
    const schema = @import("../state/schema.zig");

    resetRegistryForTest();

    var db = sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } }) catch return;
    defer db.deinit();
    schema.init(&db) catch return;

    // register the same name locally and in the cluster db with different IPs
    registerService("web", "ctr_local", .{ 10, 42, 1, 10 });

    db.exec(
        "INSERT INTO service_names (name, container_id, ip_address, registered_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "web", "ctr_remote", "10.42.5.10", @as(i64, 1000) },
    ) catch return;

    const prev = cluster_db;
    defer cluster_db = prev;
    cluster_db = &db;

    // should return the local IP, not the cluster one
    const result = lookupService("web");
    try std.testing.expect(result != null);
    try std.testing.expectEqual([4]u8{ 10, 42, 1, 10 }, result.?);
}
