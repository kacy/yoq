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
const sqlite = @import("sqlite");
const packet_support = @import("dns/packet_support.zig");
const registry_support = @import("dns/registry_support.zig");
const resolver_runtime = @import("dns/resolver_runtime.zig");

// -- service registry --
//
// fixed-size array of name→IP entries, protected by a mutex.
// capacity of 256 services is plenty for single-node use.
// names are stored as fixed-size buffers to avoid heap allocation.

// -- cluster DNS --
//
// optional reference to the replicated state machine DB. when set,
// lookups that miss the local in-memory registry fall through to
// the service_names table, enabling cross-node name resolution.
// the DB is owned by the raft state machine — we just read from it.

/// set the cluster database for cross-node DNS lookups.
/// called during agent startup after raft state machine is initialized.
/// pass null to disable cluster lookups (single-node mode).
pub fn setClusterDb(db: ?*sqlite.Db) void {
    registry_support.setClusterDb(db);
}

/// look up a service name in the replicated cluster database.
/// queries the service_names table for the IP address.
/// returns null if the name isn't found or the DB isn't available.
pub fn lookupClusterService(name: []const u8) ?[4]u8 {
    return registry_support.lookupClusterService(name);
}

/// register a service name for a container IP.
/// if the same name already exists, the IP is updated (last-write-wins).
pub fn registerService(name: []const u8, container_id: []const u8, container_ip: [4]u8) void {
    registry_support.registerService(name, container_id, container_ip);
}

/// unregister all service names for a container.
pub fn unregisterService(container_id: []const u8) void {
    registry_support.unregisterService(container_id);
}

/// look up the IP for a service name. returns null if not found.
/// checks the local in-memory registry first, then falls through to
/// the cluster database if available (cross-node resolution).
/// if multiple containers share a name, returns the last registered (last-write-wins).
pub fn lookupService(name: []const u8) ?[4]u8 {
    return registry_support.lookupService(name);
}

// -- DNS wire format --
//
// minimal implementation of RFC 1035 for A record queries.
// only handles standard queries (opcode 0) with a single question.
// all parsing and building uses stack buffers — no heap allocation.

/// DNS header flags and fields
const DnsHeader = packet_support.DnsHeader;
const DnsQuestion = packet_support.DnsQuestion;
const TYPE_A: u16 = packet_support.TYPE_A;
const CLASS_IN: u16 = packet_support.CLASS_IN;

/// parse a DNS header from a packet buffer.
/// returns null if the buffer is too short.
pub fn parseHeader(buf: []const u8) ?DnsHeader {
    return packet_support.parseHeader(buf);
}

/// parse the question section from a DNS packet.
/// handles the label-length encoding (e.g., 3www6google3com0).
/// returns null if the packet is malformed.
pub fn parseQuestion(buf: []const u8) ?DnsQuestion {
    return packet_support.parseQuestion(buf);
}

/// build a DNS A record response for a query.
/// copies the query ID and question section, adds an answer.
/// returns the response length, or null if building fails.
pub fn buildResponse(query_buf: []const u8, query_len: usize, response_ip: [4]u8, response_buf: *[512]u8) ?usize {
    return packet_support.buildResponse(query_buf, query_len, response_ip, response_buf);
}

/// build a "name not found" (NXDOMAIN) response.
pub fn buildNxDomain(query_buf: []const u8, query_len: usize, response_buf: *[512]u8) ?usize {
    return packet_support.buildNxDomain(query_buf, query_len, response_buf);
}

/// parse the first nameserver line from resolv.conf content.
/// returns the IPv4 address as a 4-byte array, or null if none found.
pub fn parseResolvConf(content: []const u8) ?[4]u8 {
    return registry_support.parseResolvConf(content);
}

/// start the DNS resolver thread. idempotent — safe to call multiple times.
pub fn startResolver() void {
    resolver_runtime.startResolver();
}

/// stop the DNS resolver thread.
pub fn stopResolver() void {
    resolver_runtime.stopResolver();
}

/// convert a 4-byte IP to a u32 in host byte order.
fn ipToU32(ip: [4]u8) u32 {
    return packet_support.ipToU32(ip);
}

// -- helpers --

fn readU16(buf: *const [2]u8) u16 {
    return packet_support.readU16(buf);
}

fn writeU16(buf: *[2]u8, val: u16) void {
    packet_support.writeU16(buf, val);
}

fn writeU32(buf: *[4]u8, val: u32) void {
    packet_support.writeU32(buf, val);
}

fn detectNameConflict(name: []const u8, new_container_id: []const u8, ip_addr: [4]u8) ?registry_support.ConflictInfo {
    return registry_support.detectNameConflict(name, new_container_id, ip_addr);
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

    const question = parseQuestion(&packet).?;
    try std.testing.expectEqualStrings("db", question.name[0..question.name_len]);
    try std.testing.expectEqual(TYPE_A, question.qtype);
    try std.testing.expectEqual(CLASS_IN, question.qclass);
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

    const question = parseQuestion(&packet).?;
    try std.testing.expectEqualStrings("web.service.local", question.name[0..question.name_len]);
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

    const question = parseQuestion(&packet).?;
    try std.testing.expectEqual(@as(u16, 28), question.qtype);
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
    const question = parseQuestion(&packet).?;
    try std.testing.expectEqual(@as(usize, 0), question.name_len);
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
    registry_support.resetRegistryForTest();
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

    const conflict = detectNameConflict("db", "ctr_new", .{ 10, 42, 0, 20 });
    try std.testing.expect(conflict != null);
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 10 }, conflict.?.ip);
}

test "detectNameConflict — same container is not a conflict" {
    resetRegistryForTest();

    registerService("web", "ctr_001", .{ 10, 42, 0, 10 });

    const conflict = detectNameConflict("web", "ctr_001", .{ 10, 42, 0, 20 });
    try std.testing.expect(conflict == null);
}

test "detectNameConflict — unknown name is not a conflict" {
    resetRegistryForTest();

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
    const prev = registry_support.currentClusterDb();
    setClusterDb(null);
    defer setClusterDb(prev);

    try std.testing.expect(lookupClusterService("anything") == null);
}

test "setClusterDb sets and clears the db reference" {
    const prev = registry_support.currentClusterDb();
    defer setClusterDb(prev);

    setClusterDb(null);
    try std.testing.expect(registry_support.currentClusterDb() == null);

    // we can't easily create a real sqlite.Db in tests without the
    // schema module, but we can verify the setter works with null
    setClusterDb(null);
    try std.testing.expect(registry_support.currentClusterDb() == null);
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
    const prev = registry_support.currentClusterDb();
    defer setClusterDb(prev);
    setClusterDb(&db);

    const result = lookupClusterService("remote-db");
    try std.testing.expect(result != null);
    try std.testing.expectEqual([4]u8{ 10, 42, 3, 5 }, result.?);
}

test "lookupClusterService returns null for unknown name" {
    const schema = @import("../state/schema.zig");

    var db = sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } }) catch return;
    defer db.deinit();
    schema.init(&db) catch return;

    const prev = registry_support.currentClusterDb();
    defer setClusterDb(prev);
    setClusterDb(&db);

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

    const prev = registry_support.currentClusterDb();
    defer setClusterDb(prev);
    setClusterDb(&db);

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

    const prev = registry_support.currentClusterDb();
    defer setClusterDb(prev);
    setClusterDb(&db);

    // should return the local IP, not the cluster one
    const result = lookupService("web");
    try std.testing.expect(result != null);
    try std.testing.expectEqual([4]u8{ 10, 42, 1, 10 }, result.?);
}

test "registerService rejects name with control characters" {
    resetRegistryForTest();

    registerService("bad\nname", "ctr_001", .{ 10, 42, 0, 50 });
    try std.testing.expect(lookupService("bad\nname") == null);
}

test "registerService rejects name with spaces" {
    resetRegistryForTest();

    registerService("bad name", "ctr_001", .{ 10, 42, 0, 50 });
    try std.testing.expect(lookupService("bad name") == null);
}
