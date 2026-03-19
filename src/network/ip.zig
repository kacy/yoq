// ip — container IP address allocation
//
// manages IPv4 addresses from the 10.42.0.0/16 subnet.
// 10.42.0.1 is reserved for the bridge gateway.
// allocates sequentially from 10.42.0.2, filling gaps left by
// released addresses.
//
// in multi-node (cluster) mode, each node gets a /24 subnet:
//   node 1: 10.42.1.0/24 (containers get 10.42.1.2 — 10.42.1.254)
//   node 2: 10.42.2.0/24 (containers get 10.42.2.2 — 10.42.2.254)
//   ...
// node_id 0 means single-node mode — uses the flat 10.42.0.0/16.
//
// all allocation state lives in the ip_allocations SQLite table,
// so it survives restarts and is consistent with the rest of
// the container state.

const std = @import("std");
const sqlite = @import("sqlite");
const schema = @import("../state/schema.zig");
const common = @import("ip/common.zig");
const parse_support = @import("ip/parse_support.zig");
const subnet_support = @import("ip/subnet_support.zig");
const allocation_runtime = @import("ip/allocation_runtime.zig");

pub const IpError = common.IpError;
pub const SubnetConfig = common.SubnetConfig;
const incrementIp = parse_support.incrementIp;
const incrementWithinRange = parse_support.incrementWithinRange;

/// return the subnet config for a given node.
///
/// node_id 0 is special: single-node mode, uses the full 10.42.0.0/16.
/// node_id 1-254: each gets 10.42.{node_id}.0/24 (backward compatible).
/// node_id 255+: extended scheme using 10.{42 + (node_id >> 8)}.{node_id & 0xFF}.0/24.
///   this supports up to ~54k nodes (second octet maxes at 255 when node_id >> 8 = 213).
///   returns error for node_ids that would overflow the second octet.
pub fn subnetForNode(node_id: u16) IpError!SubnetConfig {
    return subnet_support.subnetForNode(node_id);
}

/// allocate the next available IP for a container.
/// finds the lowest unused address in 10.42.0.2 — 10.42.255.254.
///
/// uses BEGIN IMMEDIATE to acquire a write lock before reading,
/// preventing concurrent allocations from seeing the same free IP.
///
/// fetches all allocated IPs in a single query and finds the first
/// gap using a bitset, rather than issuing one query per address.
pub fn allocate(db: *sqlite.Db, container_id: []const u8) IpError![4]u8 {
    return allocation_runtime.allocate(db, container_id);
}

/// allocate the next available IP from a specific subnet.
/// used in cluster mode where each node has its own /24 range.
/// walks the range from config.range_start to config.range_end,
/// skipping any IPs already in ip_allocations.
///
/// uses BEGIN IMMEDIATE for atomicity (same as allocate()).
///
/// fetches all IPs in the subnet with a single query (filtered by
/// the /24 prefix) and finds the first gap using a bitset.
pub fn allocateWithSubnet(db: *sqlite.Db, container_id: []const u8, config: SubnetConfig) IpError![4]u8 {
    return allocation_runtime.allocateWithSubnet(db, container_id, config);
}

/// release an IP allocation for a container
pub fn release(db: *sqlite.Db, container_id: []const u8) IpError!void {
    return allocation_runtime.release(db, container_id);
}

/// look up the IP address for a container
pub fn lookup(db: *sqlite.Db, alloc: std.mem.Allocator, container_id: []const u8) IpError![4]u8 {
    return allocation_runtime.lookup(db, alloc, container_id);
}

/// format an IP address as a dotted-quad string.
/// writes into the provided buffer and returns the used slice.
pub fn formatIp(ip: [4]u8, buf: *[16]u8) []const u8 {
    return parse_support.formatIp(ip, buf);
}

/// parse a dotted-quad IP string into 4 bytes
pub fn parseIp(str: []const u8) ?[4]u8 {
    return parse_support.parseIp(str);
}

// -- tests --

test "format and parse round-trip" {
    const ip = [4]u8{ 10, 42, 1, 100 };
    var buf: [16]u8 = undefined;
    const str = formatIp(ip, &buf);
    try std.testing.expectEqualStrings("10.42.1.100", str);

    const parsed = parseIp(str).?;
    try std.testing.expectEqual(ip, parsed);
}

test "parse basic IPs" {
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 1 }, parseIp("10.42.0.1").?);
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, parseIp("0.0.0.0").?);
    try std.testing.expectEqual([4]u8{ 255, 255, 255, 255 }, parseIp("255.255.255.255").?);
}

test "parse rejects invalid IPs" {
    try std.testing.expect(parseIp("not.an.ip") == null);
    try std.testing.expect(parseIp("10.42.0") == null);
    try std.testing.expect(parseIp("10.42.0.1.2") == null);
    try std.testing.expect(parseIp("999.0.0.1") == null);
    try std.testing.expect(parseIp("") == null);
}

test "increment ip within subnet" {
    var ip = [4]u8{ 10, 42, 0, 2 };
    try std.testing.expect(incrementIp(&ip));
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 3 }, ip);
}

test "increment ip rolls over to next block" {
    var ip = [4]u8{ 10, 42, 0, 254 };
    try std.testing.expect(incrementIp(&ip));
    try std.testing.expectEqual([4]u8{ 10, 42, 1, 1 }, ip);
}

test "increment ip exhausts subnet" {
    var ip = [4]u8{ 10, 42, 255, 254 };
    try std.testing.expect(!incrementIp(&ip));
}

test "allocate sequential IPs" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const ip1 = try allocate(&db, "container_1");
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 2 }, ip1);

    const ip2 = try allocate(&db, "container_2");
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 3 }, ip2);

    const ip3 = try allocate(&db, "container_3");
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 4 }, ip3);
}

test "allocate fills gaps after release" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    _ = try allocate(&db, "c1"); // .2
    _ = try allocate(&db, "c2"); // .3
    _ = try allocate(&db, "c3"); // .4

    // release the middle one
    try release(&db, "c2");

    // next allocation should fill the gap
    const ip4 = try allocate(&db, "c4");
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 3 }, ip4);
}

test "lookup returns allocated IP" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const alloc = std.testing.allocator;

    const ip = try allocate(&db, "lookup_test");
    const found = try lookup(&db, alloc, "lookup_test");
    try std.testing.expectEqual(ip, found);
}

test "parseIp rejects empty octets" {
    try std.testing.expect(parseIp("10..0.1") == null);
}

test "formatIp max values" {
    var buf: [16]u8 = undefined;
    const str = formatIp(.{ 255, 255, 255, 255 }, &buf);
    try std.testing.expectEqualStrings("255.255.255.255", str);
}

test "allocate and release round-trip" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const ip1 = try allocate(&db, "rt_test");
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 2 }, ip1);

    try release(&db, "rt_test");

    // re-allocating should get the same IP back (fills the gap)
    const ip2 = try allocate(&db, "rt_test2");
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 2 }, ip2);
}

test "lookup returns error for unknown container" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const alloc = std.testing.allocator;
    try std.testing.expectError(IpError.NotFound, lookup(&db, alloc, "nonexistent"));
}

test "subnetForNode(0) returns flat /16 for single-node mode" {
    const config = try subnetForNode(0);
    try std.testing.expectEqual(@as(u16, 0), config.node_id);
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 0 }, config.base);
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 1 }, config.gateway);
    try std.testing.expectEqual(@as(u8, 16), config.prefix_len);
    try std.testing.expectEqual([4]u8{ 10, 42, 0, 2 }, config.range_start);
    try std.testing.expectEqual([4]u8{ 10, 42, 255, 254 }, config.range_end);
}

test "subnetForNode(1) returns correct /24 subnet" {
    const config = try subnetForNode(1);
    try std.testing.expectEqual(@as(u16, 1), config.node_id);
    try std.testing.expectEqual([4]u8{ 10, 42, 1, 0 }, config.base);
    try std.testing.expectEqual([4]u8{ 10, 42, 1, 1 }, config.gateway);
    try std.testing.expectEqual(@as(u8, 24), config.prefix_len);
    try std.testing.expectEqual([4]u8{ 10, 42, 1, 2 }, config.range_start);
    try std.testing.expectEqual([4]u8{ 10, 42, 1, 254 }, config.range_end);
}

test "subnetForNode(254) returns correct /24 subnet" {
    const config = try subnetForNode(254);
    try std.testing.expectEqual(@as(u16, 254), config.node_id);
    try std.testing.expectEqual([4]u8{ 10, 42, 254, 0 }, config.base);
    try std.testing.expectEqual([4]u8{ 10, 42, 254, 1 }, config.gateway);
    try std.testing.expectEqual(@as(u8, 24), config.prefix_len);
    try std.testing.expectEqual([4]u8{ 10, 42, 254, 2 }, config.range_start);
    try std.testing.expectEqual([4]u8{ 10, 42, 254, 254 }, config.range_end);
}

test "subnetForNode(255) uses extended scheme" {
    const config = try subnetForNode(255);
    try std.testing.expectEqual(@as(u16, 255), config.node_id);
    // 42 + (255 >> 8) = 42 + 0 = 42, 255 & 0xFF = 255
    try std.testing.expectEqual([4]u8{ 10, 42, 255, 0 }, config.base);
    try std.testing.expectEqual([4]u8{ 10, 42, 255, 1 }, config.gateway);
    try std.testing.expectEqual(@as(u8, 24), config.prefix_len);
}

test "subnetForNode(256) uses extended scheme" {
    const config = try subnetForNode(256);
    try std.testing.expectEqual(@as(u16, 256), config.node_id);
    // 42 + (256 >> 8) = 43, 256 & 0xFF = 0
    try std.testing.expectEqual([4]u8{ 10, 43, 0, 0 }, config.base);
    try std.testing.expectEqual([4]u8{ 10, 43, 0, 1 }, config.gateway);
}

test "subnetForNode(1000) uses extended scheme" {
    const config = try subnetForNode(1000);
    try std.testing.expectEqual(@as(u16, 1000), config.node_id);
    // 42 + (1000 >> 8) = 42 + 3 = 45, 1000 & 0xFF = 232
    try std.testing.expectEqual([4]u8{ 10, 45, 232, 0 }, config.base);
}

test "subnetForNode backward compat: nodes 1-254 identical to old u8 scheme" {
    // verify every node in the original range produces the same result
    for (1..255) |i| {
        const nid: u16 = @intCast(i);
        const config = try subnetForNode(nid);
        const nid_u8: u8 = @intCast(i);
        try std.testing.expectEqual([4]u8{ 10, 42, nid_u8, 0 }, config.base);
        try std.testing.expectEqual([4]u8{ 10, 42, nid_u8, 1 }, config.gateway);
        try std.testing.expectEqual(@as(u8, 24), config.prefix_len);
    }
}

test "subnetForNode rejects node_id that would overflow second octet" {
    // node_id >> 8 = 214, 42 + 214 = 256 which overflows u8
    const max_valid: u16 = 54527; // (213 << 8) | 0xFF — last valid node_id
    _ = try subnetForNode(max_valid);

    // one past: (214 << 8) | 0 = 54784
    try std.testing.expectError(IpError.AllocationFailed, subnetForNode(54784));
    // max u16
    try std.testing.expectError(IpError.AllocationFailed, subnetForNode(65535));
}

test "allocateWithSubnet allocates from correct range" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const config = try subnetForNode(3);
    const ip1 = try allocateWithSubnet(&db, "c1", config);
    try std.testing.expectEqual([4]u8{ 10, 42, 3, 2 }, ip1);

    const ip2 = try allocateWithSubnet(&db, "c2", config);
    try std.testing.expectEqual([4]u8{ 10, 42, 3, 3 }, ip2);
}

test "allocateWithSubnet stays within node subnet" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    // use a tiny range for testing: only 2 addresses available
    const config = SubnetConfig{
        .node_id = 5,
        .base = .{ 10, 42, 5, 0 },
        .gateway = .{ 10, 42, 5, 1 },
        .prefix_len = 24,
        .range_start = .{ 10, 42, 5, 2 },
        .range_end = .{ 10, 42, 5, 3 },
    };

    const ip1 = try allocateWithSubnet(&db, "c1", config);
    try std.testing.expectEqual([4]u8{ 10, 42, 5, 2 }, ip1);

    const ip2 = try allocateWithSubnet(&db, "c2", config);
    try std.testing.expectEqual([4]u8{ 10, 42, 5, 3 }, ip2);

    // third allocation should fail — range exhausted
    try std.testing.expectError(IpError.SubnetExhausted, allocateWithSubnet(&db, "c3", config));
}

test "allocateWithSubnet fills gaps after release" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const config = try subnetForNode(7);

    _ = try allocateWithSubnet(&db, "c1", config); // .2
    _ = try allocateWithSubnet(&db, "c2", config); // .3
    _ = try allocateWithSubnet(&db, "c3", config); // .4

    try release(&db, "c2");

    // should fill the gap at .3
    const ip4 = try allocateWithSubnet(&db, "c4", config);
    try std.testing.expectEqual([4]u8{ 10, 42, 7, 3 }, ip4);
}

test "incrementWithinRange stops at range end" {
    var current = [4]u8{ 10, 42, 1, 254 };
    const range_end = [4]u8{ 10, 42, 1, 254 };
    try std.testing.expect(!incrementWithinRange(&current, range_end));
}

test "incrementWithinRange increments within range" {
    var current = [4]u8{ 10, 42, 1, 10 };
    const range_end = [4]u8{ 10, 42, 1, 254 };
    try std.testing.expect(incrementWithinRange(&current, range_end));
    try std.testing.expectEqual([4]u8{ 10, 42, 1, 11 }, current);
}
