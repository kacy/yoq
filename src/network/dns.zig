// dns — userspace DNS resolver for container service discovery
//
// provides name resolution for containers on the yoq bridge network.
// runs a UDP listener on the bridge gateway (10.42.0.1:53) that answers
// A record queries for registered service names. unknown names are
// forwarded to an upstream DNS server (8.8.8.8).
//
// the in-memory registry is the hot path for lookups. the SQLite
// service_names table provides persistence across restarts.
//
// thread model: single resolver thread, blocking recvfrom().
// the mutex around the registry is fine — critical section is
// an array scan + 4-byte IP copy.

const std = @import("std");
const posix = std.posix;
const log = @import("../lib/log.zig");
const ip_mod = @import("ip.zig");

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
            return;
        }
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
            entry.active = false;
            registry_count -= 1;
        }
    }
}

/// look up the IP for a service name. returns null if not found.
/// if multiple containers share a name, returns the last registered (last-write-wins).
fn lookupService(name: []const u8) ?[4]u8 {
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

    return null;
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
const upstream_dns = [4]u8{ 8, 8, 8, 8 };
const upstream_port: u16 = 53;

var resolver_thread: ?std.Thread = null;
var resolver_socket: ?posix.socket_t = null;
var resolver_running: bool = false;
var resolver_mutex: std.Thread.Mutex = .{};

/// start the DNS resolver thread. idempotent — safe to call multiple times.
pub fn startResolver() void {
    resolver_mutex.lock();
    defer resolver_mutex.unlock();

    if (resolver_running) return;

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
    resolver_running = true;

    resolver_thread = std.Thread.spawn(.{}, resolverLoop, .{sock}) catch |e| {
        log.warn("dns: failed to spawn resolver thread: {}", .{e});
        resolver_running = false;
        posix.close(sock);
        resolver_socket = null;
        return;
    };

    log.info("dns resolver started on 10.42.0.1:53", .{});
}

/// stop the DNS resolver thread.
pub fn stopResolver() void {
    resolver_mutex.lock();

    if (!resolver_running) {
        resolver_mutex.unlock();
        return;
    }

    resolver_running = false;

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

    while (resolver_running) {
        var client_addr: posix.sockaddr.in = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);

        const n = posix.recvfrom(sock, &recv_buf, 0, @ptrCast(&client_addr), &addr_len) catch {
            // socket closed or error — check if we should stop
            if (!resolver_running) break;
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
            _ = posix.sendto(sock, response_buf[0..resp_len], 0, @ptrCast(client_addr), addr_len) catch {};
            return;
        }
    }

    // not a known service — forward to upstream
    forwardQuery(sock, query, client_addr, addr_len);
}

/// forward a DNS query to the upstream resolver and relay the response.
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
    posix.setsockopt(upstream_sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};

    const upstream_addr = posix.sockaddr.in{
        .port = std.mem.nativeToBig(u16, upstream_port),
        .addr = std.mem.nativeToBig(u32, (@as(u32, 8) << 24) | (@as(u32, 8) << 16) | (@as(u32, 8) << 8) | 8),
    };

    // send query to upstream
    _ = posix.sendto(upstream_sock, query, 0, @ptrCast(&upstream_addr), @sizeOf(posix.sockaddr.in)) catch return;

    // receive response
    var response_buf: [512]u8 = undefined;
    const resp_n = posix.recvfrom(upstream_sock, &response_buf, 0, null, null) catch return;

    // verify the response's transaction ID matches our query.
    // drop mismatched responses — could be stale or spoofed.
    if (resp_n < 2 or query.len < 2) return;
    if (response_buf[0] != query[0] or response_buf[1] != query[1]) return;

    // relay response to original client
    _ = posix.sendto(sock, response_buf[0..resp_n], 0, @ptrCast(client_addr), addr_len) catch {};
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
