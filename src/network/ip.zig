// ip — container IP address allocation
//
// manages IPv4 addresses from the 10.42.0.0/16 subnet.
// 10.42.0.1 is reserved for the bridge gateway.
// allocates sequentially from 10.42.0.2, filling gaps left by
// released addresses.
//
// all allocation state lives in the ip_allocations SQLite table,
// so it survives restarts and is consistent with the rest of
// the container state.

const std = @import("std");
const sqlite = @import("sqlite");
const schema = @import("../state/schema.zig");

pub const IpError = error{
    AllocationFailed,
    ReleaseFailed,
    NotFound,
    SubnetExhausted,
    DbOpenFailed,
};

/// allocate the next available IP for a container.
/// finds the lowest unused address in 10.42.0.2 — 10.42.255.254.
pub fn allocate(db: *sqlite.Db, container_id: []const u8) IpError![4]u8 {
    // get all currently allocated IPs, sorted
    const CountRow = struct { count: i64 };
    const count_result = (db.one(
        CountRow,
        "SELECT COUNT(*) AS count FROM ip_allocations;",
        .{},
        .{},
    ) catch return IpError.AllocationFailed) orelse return IpError.AllocationFailed;

    if (count_result.count >= 65533) return IpError.SubnetExhausted; // 10.42.0.2 to 10.42.255.254

    // find the lowest unused IP by trying sequentially.
    // start at 10.42.0.2 and check each address.
    var ip = [4]u8{ 10, 42, 0, 2 };

    // we iterate through the address space checking for gaps.
    // with <65k addresses this is fine.
    while (true) {
        var ip_buf: [16]u8 = undefined;
        const ip_str = formatIp(ip, &ip_buf);

        const ExistsRow = struct { count: i64 };
        const exists = (db.one(
            ExistsRow,
            "SELECT COUNT(*) AS count FROM ip_allocations WHERE ip_address = ?;",
            .{},
            .{ip_str},
        ) catch return IpError.AllocationFailed) orelse return IpError.AllocationFailed;

        if (exists.count == 0) break; // found a free one

        // increment IP
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

    return ip;
}

/// release an IP allocation for a container
pub fn release(db: *sqlite.Db, container_id: []const u8) IpError!void {
    db.exec(
        "DELETE FROM ip_allocations WHERE container_id = ?;",
        .{},
        .{container_id},
    ) catch return IpError.ReleaseFailed;
}

/// look up the IP address for a container
pub fn lookup(db: *sqlite.Db, alloc: std.mem.Allocator, container_id: []const u8) IpError![4]u8 {
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

test "lookup returns error for unknown container" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const alloc = std.testing.allocator;
    try std.testing.expectError(IpError.NotFound, lookup(&db, alloc, "nonexistent"));
}
