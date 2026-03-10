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

pub const IpError = error{
    /// failed to allocate an IP address (db insert or transaction error)
    AllocationFailed,
    /// failed to delete an IP allocation from the database
    ReleaseFailed,
    /// no IP allocation exists for the given container
    NotFound,
    /// all addresses in the subnet have been allocated
    SubnetExhausted,
    /// failed to open or initialize the IP allocation database
    DbOpenFailed,
};

/// per-node subnet configuration.
/// each node in a cluster gets its own /24 within the 10.42.0.0/16 space,
/// so container IPs never collide across nodes.
pub const SubnetConfig = struct {
    node_id: u16,
    base: [4]u8,
    gateway: [4]u8,
    prefix_len: u8,
    range_start: [4]u8,
    range_end: [4]u8,
};

/// return the subnet config for a given node.
///
/// node_id 0 is special: single-node mode, uses the full 10.42.0.0/16.
/// node_id 1-254: each gets 10.42.{node_id}.0/24 (backward compatible).
/// node_id 255+: extended scheme using 10.{42 + (node_id >> 8)}.{node_id & 0xFF}.0/24.
///   this supports up to ~54k nodes (second octet maxes at 255 when node_id >> 8 = 213).
///   returns error for node_ids that would overflow the second octet.
pub fn subnetForNode(node_id: u16) IpError!SubnetConfig {
    if (node_id == 0) {
        // single-node mode — flat /16, same as the original behavior
        return .{
            .node_id = 0,
            .base = .{ 10, 42, 0, 0 },
            .gateway = .{ 10, 42, 0, 1 },
            .prefix_len = 16,
            .range_start = .{ 10, 42, 0, 2 },
            .range_end = .{ 10, 42, 255, 254 },
        };
    }

    if (node_id <= 254) {
        // original scheme: 10.42.{node_id}.0/24
        const nid: u8 = @intCast(node_id);
        return .{
            .node_id = node_id,
            .base = .{ 10, 42, nid, 0 },
            .gateway = .{ 10, 42, nid, 1 },
            .prefix_len = 24,
            .range_start = .{ 10, 42, nid, 2 },
            .range_end = .{ 10, 42, nid, 254 },
        };
    }

    // extended scheme for nodes 255+: 10.{42 + (node_id >> 8)}.{node_id & 0xFF}.0/24
    const offset = node_id >> 8;
    if (offset > (255 - 42)) return IpError.AllocationFailed;
    const high: u8 = @intCast(@as(u16, 42) + offset);
    const low: u8 = @intCast(node_id & 0xFF);
    return .{
        .node_id = node_id,
        .base = .{ 10, high, low, 0 },
        .gateway = .{ 10, high, low, 1 },
        .prefix_len = 24,
        .range_start = .{ 10, high, low, 2 },
        .range_end = .{ 10, high, low, 254 },
    };
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
    // validate container_id is not empty
    if (container_id.len == 0) return IpError.AllocationFailed;

    // acquire exclusive write lock before reading to prevent race conditions.
    // without this, two concurrent allocations could see the same IP as free.
    db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return IpError.AllocationFailed;
    errdefer db.exec("ROLLBACK;", .{}, .{}) catch {};

    // fetch all allocated IPs in one query and mark them in a bitset.
    // bitset maps the offset within 10.42.0.0/16: offset = ip[2]*256 + ip[3].
    // 65536 bits = 8KB on the stack — trivial.
    var allocated = std.StaticBitSet(65536).initEmpty();
    var count: usize = 0;

    const IpRow = struct { ip_address: sqlite.Text };
    var stmt = db.prepare("SELECT ip_address FROM ip_allocations;") catch
        return IpError.AllocationFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(IpRow, .{}) catch return IpError.AllocationFailed;
    while (iter.nextAlloc(std.heap.page_allocator, .{}) catch return IpError.AllocationFailed) |row| {
        defer std.heap.page_allocator.free(row.ip_address.data);
        if (parseIp(row.ip_address.data)) |addr| {
            if (addr[0] == 10 and addr[1] == 42) {
                const offset = @as(usize, addr[2]) * 256 + addr[3];
                allocated.set(offset);
            }
        }
        count += 1;
    }

    if (count >= 65533) return IpError.SubnetExhausted;

    // find the first gap starting at 10.42.0.2, following the same
    // increment logic as before: .2-.254, then .1-.254 per /24 block.
    var ip = [4]u8{ 10, 42, 0, 2 };
    while (true) {
        const offset = @as(usize, ip[2]) * 256 + ip[3];
        if (!allocated.isSet(offset)) break; // found a free one
        if (!incrementIp(&ip)) return IpError.SubnetExhausted;
    }

    // insert the allocation
    var ip_buf: [16]u8 = undefined;
    const ip_str = formatIp(ip, &ip_buf);

    db.exec(
        "INSERT INTO ip_allocations (container_id, ip_address, allocated_at) VALUES (?, ?, ?);",
        .{},
        .{ container_id, ip_str, @as(i64, std.time.timestamp()) },
    ) catch return IpError.AllocationFailed;

    db.exec("COMMIT;", .{}, .{}) catch return IpError.AllocationFailed;

    return ip;
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
    db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return IpError.AllocationFailed;
    errdefer db.exec("ROLLBACK;", .{}, .{}) catch {};

    // build a LIKE prefix to filter only IPs in this /24.
    // uses the actual base octets so it works for both the original
    // scheme (10.42.{node_id}.%) and the extended scheme (10.{high}.{low}.%).
    var prefix_buf: [16]u8 = undefined;
    const prefix = std.fmt.bufPrint(&prefix_buf, "{d}.{d}.{d}.%", .{
        config.base[0], config.base[1], config.base[2],
    }) catch return IpError.AllocationFailed;

    // bitset for a /24: 256 bits = 32 bytes. offset = last octet.
    var allocated = std.StaticBitSet(256).initEmpty();

    const IpRow = struct { ip_address: sqlite.Text };
    var stmt = db.prepare("SELECT ip_address FROM ip_allocations WHERE ip_address LIKE ?;") catch
        return IpError.AllocationFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(IpRow, .{prefix}) catch return IpError.AllocationFailed;
    while (iter.nextAlloc(std.heap.page_allocator, .{}) catch return IpError.AllocationFailed) |row| {
        defer std.heap.page_allocator.free(row.ip_address.data);
        if (parseIp(row.ip_address.data)) |addr| {
            allocated.set(addr[3]);
        }
    }

    // find first gap in the range
    var current = config.range_start;
    while (true) {
        if (!allocated.isSet(current[3])) {
            // found a free address — insert it
            var ip_buf: [16]u8 = undefined;
            const ip_str = formatIp(current, &ip_buf);

            db.exec(
                "INSERT INTO ip_allocations (container_id, ip_address, allocated_at) VALUES (?, ?, ?);",
                .{},
                .{ container_id, ip_str, @as(i64, std.time.timestamp()) },
            ) catch return IpError.AllocationFailed;

            db.exec("COMMIT;", .{}, .{}) catch return IpError.AllocationFailed;

            return current;
        }

        if (!incrementWithinRange(&current, config.range_end)) {
            return IpError.SubnetExhausted;
        }
    }
}

/// increment IP within a bounded range.
/// returns false if we've reached range_end (exhausted).
fn incrementWithinRange(current: *[4]u8, range_end: [4]u8) bool {
    // check if we're already at the end of the range
    if (std.mem.eql(u8, current, &range_end)) return false;

    // simple increment: bump last octet, roll over if needed
    if (current[3] < 254) {
        current[3] += 1;
        return true;
    }

    // for /24 subnets, we don't roll over to the next /24
    // (that would be a different node's subnet)
    return false;
}

/// release an IP allocation for a container
pub fn release(db: *sqlite.Db, container_id: []const u8) IpError!void {
    if (container_id.len == 0) return IpError.ReleaseFailed;

    db.exec(
        "DELETE FROM ip_allocations WHERE container_id = ?;",
        .{},
        .{container_id},
    ) catch return IpError.ReleaseFailed;
}

/// look up the IP address for a container
pub fn lookup(db: *sqlite.Db, alloc: std.mem.Allocator, container_id: []const u8) IpError![4]u8 {
    if (container_id.len == 0) return IpError.NotFound;

    const IpRow = struct { ip_address: sqlite.Text };
    const row = (db.oneAlloc(
        IpRow,
        alloc,
        "SELECT ip_address FROM ip_allocations WHERE container_id = ?;",
        .{},
        .{container_id},
    ) catch return IpError.NotFound) orelse return IpError.NotFound;
    defer alloc.free(row.ip_address.data);

    return parseIp(row.ip_address.data) orelse IpError.NotFound;
}

/// format an IP address as a dotted-quad string.
/// writes into the provided buffer and returns the used slice.
pub fn formatIp(ip: [4]u8, buf: *[16]u8) []const u8 {
    const result = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "0.0.0.0";
    return result;
}

/// parse a dotted-quad IP string into 4 bytes
pub fn parseIp(str: []const u8) ?[4]u8 {
    var ip: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var start: usize = 0;

    for (str, 0..) |c, i| {
        if (c == '.') {
            if (octet_idx >= 3) return null;
            ip[octet_idx] = std.fmt.parseInt(u8, str[start..i], 10) catch return null;
            octet_idx += 1;
            start = i + 1;
        }
    }

    if (octet_idx != 3) return null;
    ip[3] = std.fmt.parseInt(u8, str[start..], 10) catch return null;

    return ip;
}

/// increment IP within the 10.42.0.0/16 range.
/// returns false if we've exhausted the subnet.
fn incrementIp(ip: *[4]u8) bool {
    // increment the last two octets (10.42.x.y)
    if (ip[3] < 254) {
        ip[3] += 1;
        return true;
    }
    // roll over to next /24 block
    ip[3] = 1; // skip .0
    if (ip[2] < 255) {
        ip[2] += 1;
        return true;
    }
    return false; // exhausted 10.42.0.0/16
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
