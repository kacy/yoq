const std = @import("std");
const platform = @import("platform");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const log = @import("../../lib/log.zig");
const parse_support = @import("parse_support.zig");

pub fn allocate(db: *sqlite.Db, container_id: []const u8) common.IpError![4]u8 {
    if (container_id.len == 0) return common.IpError.AllocationFailed;

    db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return common.IpError.AllocationFailed;
    errdefer db.exec("ROLLBACK;", .{}, .{}) catch {};

    var allocated = std.StaticBitSet(65536).initEmpty();
    var count: usize = 0;

    const IpRow = struct { ip_address: sqlite.Text };
    var stmt = db.prepare("SELECT ip_address FROM ip_allocations;") catch
        return common.IpError.AllocationFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(IpRow, .{}) catch return common.IpError.AllocationFailed;
    while (iter.nextAlloc(std.heap.page_allocator, .{}) catch return common.IpError.AllocationFailed) |row| {
        defer std.heap.page_allocator.free(row.ip_address.data);
        if (parse_support.parseIp(row.ip_address.data)) |addr| {
            if (addr[0] == 10 and addr[1] == 42) {
                const offset = @as(usize, addr[2]) * 256 + addr[3];
                allocated.set(offset);
            } else {
                log.warn("ip allocator: ignoring out-of-range IP {d}.{d}.{d}.{d} in allocation table", .{ addr[0], addr[1], addr[2], addr[3] });
            }
        }
        count += 1;
    }

    if (count >= 65533) return common.IpError.SubnetExhausted;

    var ip = [4]u8{ 10, 42, 0, 2 };
    while (true) {
        const offset = @as(usize, ip[2]) * 256 + ip[3];
        if (!allocated.isSet(offset)) break;
        if (!parse_support.incrementIp(&ip)) return common.IpError.SubnetExhausted;
    }

    var ip_buf: [16]u8 = undefined;
    const ip_str = parse_support.formatIp(ip, &ip_buf);
    db.exec(
        "INSERT INTO ip_allocations (container_id, ip_address, allocated_at) VALUES (?, ?, ?);",
        .{},
        .{ container_id, ip_str, @as(i64, platform.timestamp()) },
    ) catch return common.IpError.AllocationFailed;

    db.exec("COMMIT;", .{}, .{}) catch return common.IpError.AllocationFailed;
    return ip;
}

pub fn allocateWithSubnet(db: *sqlite.Db, container_id: []const u8, config: common.SubnetConfig) common.IpError![4]u8 {
    db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return common.IpError.AllocationFailed;
    errdefer db.exec("ROLLBACK;", .{}, .{}) catch {};

    var prefix_buf: [16]u8 = undefined;
    const prefix = std.fmt.bufPrint(&prefix_buf, "{d}.{d}.{d}.%", .{
        config.base[0], config.base[1], config.base[2],
    }) catch return common.IpError.AllocationFailed;

    var allocated = std.StaticBitSet(256).initEmpty();

    const IpRow = struct { ip_address: sqlite.Text };
    var stmt = db.prepare("SELECT ip_address FROM ip_allocations WHERE ip_address LIKE ?;") catch
        return common.IpError.AllocationFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(IpRow, .{prefix}) catch return common.IpError.AllocationFailed;
    while (iter.nextAlloc(std.heap.page_allocator, .{}) catch return common.IpError.AllocationFailed) |row| {
        defer std.heap.page_allocator.free(row.ip_address.data);
        if (parse_support.parseIp(row.ip_address.data)) |addr| {
            allocated.set(addr[3]);
        }
    }

    var current = config.range_start;
    while (true) {
        if (!allocated.isSet(current[3])) {
            var ip_buf: [16]u8 = undefined;
            const ip_str = parse_support.formatIp(current, &ip_buf);

            db.exec(
                "INSERT INTO ip_allocations (container_id, ip_address, allocated_at) VALUES (?, ?, ?);",
                .{},
                .{ container_id, ip_str, @as(i64, platform.timestamp()) },
            ) catch return common.IpError.AllocationFailed;

            db.exec("COMMIT;", .{}, .{}) catch return common.IpError.AllocationFailed;
            return current;
        }

        if (!parse_support.incrementWithinRange(&current, config.range_end)) {
            return common.IpError.SubnetExhausted;
        }
    }
}

pub fn release(db: *sqlite.Db, container_id: []const u8) common.IpError!void {
    if (container_id.len == 0) return common.IpError.ReleaseFailed;

    db.exec(
        "DELETE FROM ip_allocations WHERE container_id = ?;",
        .{},
        .{container_id},
    ) catch return common.IpError.ReleaseFailed;
}

pub fn lookup(db: *sqlite.Db, alloc: std.mem.Allocator, container_id: []const u8) common.IpError![4]u8 {
    if (container_id.len == 0) return common.IpError.NotFound;

    const IpRow = struct { ip_address: sqlite.Text };
    const row = (db.oneAlloc(
        IpRow,
        alloc,
        "SELECT ip_address FROM ip_allocations WHERE container_id = ?;",
        .{},
        .{container_id},
    ) catch return common.IpError.NotFound) orelse return common.IpError.NotFound;
    defer alloc.free(row.ip_address.data);

    return parse_support.parseIp(row.ip_address.data) orelse common.IpError.NotFound;
}
