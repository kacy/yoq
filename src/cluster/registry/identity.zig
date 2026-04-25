const std = @import("std");
const linux_platform = @import("linux_platform");
const sqlite = @import("sqlite");

const Allocator = std.mem.Allocator;

pub const NodeIdError = error{
    NoAvailableNodeId,
    QueryFailed,
};

pub fn findAgentIdByNodeId(alloc: Allocator, db: *sqlite.Db, node_id: u64) ?[]const u8 {
    const Row = struct { id: sqlite.Text };

    var stmt = db.prepare("SELECT id FROM agents WHERE node_id = ? LIMIT 1;") catch return null;
    defer stmt.deinit();

    var iter = stmt.iterator(Row, .{@as(i64, @intCast(node_id))}) catch return null;
    if (iter.nextAlloc(alloc, .{}) catch null) |row| return row.id.data;
    return null;
}

pub fn assignNodeId(db: *sqlite.Db) NodeIdError!u16 {
    const Row = struct { node_id: i64 };

    var stmt = db.prepare("SELECT node_id FROM agents WHERE node_id IS NOT NULL ORDER BY node_id;") catch return NodeIdError.QueryFailed;
    defer stmt.deinit();

    var iter = stmt.iterator(Row, .{}) catch return NodeIdError.QueryFailed;
    var next_id: u16 = 1;
    while (iter.next(.{}) catch null) |row| {
        const used: u16 = if (row.node_id >= 1 and row.node_id <= 65534) @intCast(row.node_id) else continue;
        if (next_id < used) return next_id;
        next_id = used +| 1;
    }

    if (next_id <= 65534) return next_id;
    return NodeIdError.NoAvailableNodeId;
}

pub fn getGossipSeeds(alloc: Allocator, db: *sqlite.Db, count: u32) ![][]const u8 {
    const Row = struct { node_id: i64, address: sqlite.Text };

    var stmt = db.prepare(
        "SELECT node_id, address FROM agents WHERE status = 'active' AND node_id IS NOT NULL AND (role = 'agent' OR role = 'both' OR role IS NULL) LIMIT ?;",
    ) catch return &[_][]const u8{};
    defer stmt.deinit();

    var results: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (results.items) |seed| alloc.free(seed);
        results.deinit(alloc);
    }

    const limit: i64 = @max(@as(i64, 0), @as(i64, @intCast(count)));
    var iter = stmt.iterator(Row, .{limit}) catch return &[_][]const u8{};

    while (iter.nextAlloc(alloc, .{}) catch null) |row| {
        defer alloc.free(row.address.data);
        var buf: [256]u8 = undefined;
        const seed = std.fmt.bufPrint(&buf, "{d}@{s}", .{ row.node_id, row.address.data }) catch continue;
        const duped = alloc.dupe(u8, seed) catch continue;
        results.append(alloc, duped) catch {
            alloc.free(duped);
            continue;
        };
    }

    return results.toOwnedSlice(alloc) catch return &[_][]const u8{};
}

pub fn freeGossipSeeds(alloc: Allocator, seeds: [][]const u8) void {
    for (seeds) |seed| alloc.free(seed);
    alloc.free(seeds);
}

pub fn validateToken(token: []const u8, expected: []const u8) bool {
    if (token.len != expected.len) return false;
    var diff: u8 = 0;
    for (token, expected) |a, b| diff |= a ^ b;
    return diff == 0;
}

pub fn generateAgentId(buf: *[12]u8) void {
    var random_bytes: [6]u8 = undefined;
    linux_platform.randomBytes(&random_bytes);
    const hex = "0123456789abcdef";
    for (random_bytes, 0..) |byte, i| {
        buf[i * 2] = hex[byte >> 4];
        buf[i * 2 + 1] = hex[byte & 0x0f];
    }
}
