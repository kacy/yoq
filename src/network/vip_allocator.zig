const std = @import("std");
const sqlite = @import("sqlite");
const ip = @import("ip.zig");
const schema = @import("../state/schema.zig");

pub const VipError = error{
    AllocationFailed,
    SubnetExhausted,
};

pub const range_start = [4]u8{ 10, 43, 0, 2 };
pub const range_end = [4]u8{ 10, 43, 255, 254 };

const VipRow = struct {
    vip_address: sqlite.Text,
};

pub fn allocate(db: *sqlite.Db) VipError![4]u8 {
    var allocated = std.StaticBitSet(65536).initEmpty();
    var count: usize = 0;

    var stmt = db.prepare("SELECT vip_address FROM services;") catch return VipError.AllocationFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(VipRow, .{}) catch return VipError.AllocationFailed;
    while (iter.nextAlloc(std.heap.page_allocator, .{}) catch return VipError.AllocationFailed) |row| {
        defer std.heap.page_allocator.free(row.vip_address.data);
        if (ip.parseIp(row.vip_address.data)) |addr| {
            if (addr[0] == 10 and addr[1] == 43) {
                const offset = @as(usize, addr[2]) * 256 + addr[3];
                allocated.set(offset);
                count += 1;
            }
        }
    }

    if (count >= 65533) return VipError.SubnetExhausted;

    var current = range_start;
    while (true) {
        const offset = @as(usize, current[2]) * 256 + current[3];
        if (!allocated.isSet(offset)) return current;
        if (!incrementVip(&current)) return VipError.SubnetExhausted;
    }
}

fn incrementVip(current: *[4]u8) bool {
    if (std.mem.eql(u8, current, &range_end)) return false;

    if (current[3] < 254) {
        current[3] += 1;
        return true;
    }

    if (current[2] == 255) return false;
    current[2] += 1;
    current[3] = 0;
    return true;
}

test "allocate returns first VIP in empty service registry" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const vip = try allocate(&db);
    try std.testing.expectEqual([4]u8{ 10, 43, 0, 2 }, vip);
}

test "allocate skips existing VIPs and fills gaps" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO services (service_name, vip_address, lb_policy, created_at, updated_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "api", "10.43.0.2", "consistent_hash", @as(i64, 1000), @as(i64, 1000) },
    ) catch unreachable;
    db.exec(
        "INSERT INTO services (service_name, vip_address, lb_policy, created_at, updated_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ "web", "10.43.0.4", "consistent_hash", @as(i64, 1001), @as(i64, 1001) },
    ) catch unreachable;

    const vip = try allocate(&db);
    try std.testing.expectEqual([4]u8{ 10, 43, 0, 3 }, vip);
}

test "allocate rolls into the next third octet" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    var octet: usize = 2;
    while (octet <= 254) : (octet += 1) {
        var service_name_buf: [32]u8 = undefined;
        const service_name = try std.fmt.bufPrint(&service_name_buf, "svc-{d}", .{octet});
        var vip_buf: [16]u8 = undefined;
        const vip = try std.fmt.bufPrint(&vip_buf, "10.43.0.{d}", .{octet});
        db.exec(
            "INSERT INTO services (service_name, vip_address, lb_policy, created_at, updated_at) VALUES (?, ?, ?, ?, ?);",
            .{},
            .{ service_name, vip, "consistent_hash", @as(i64, 1000), @as(i64, 1000) },
        ) catch unreachable;
    }

    const allocated = try allocate(&db);
    try std.testing.expectEqual([4]u8{ 10, 43, 1, 0 }, allocated);
}

test "allocate returns exhausted when range is full" {
    var current = range_start;
    while (incrementVip(&current)) {}
    try std.testing.expectEqual(range_end, current);
}
