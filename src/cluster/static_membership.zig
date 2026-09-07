// Raft voters are fixed for the lifetime of a cluster. Gossip and worker
// enrollment do not alter that quorum. Persist the startup voter set locally
// so changing flags on restart cannot silently create a different cluster.
const std = @import("std");
const sqlite = @import("sqlite");

pub fn validate(id: u64, peers: anytype) !void {
    if (id == 0 or id > std.math.maxInt(i64)) return error.InvalidNodeId;
    for (peers, 0..) |peer, i| {
        if (peer.id == 0 or peer.id > std.math.maxInt(i64) or peer.id == id) return error.InvalidPeerId;
        if (peer.port == 0) return error.InvalidPeerPort;
        for (peers[0..i]) |previous| {
            if (previous.id == peer.id) return error.DuplicatePeerId;
            if (previous.port == peer.port and std.mem.eql(u8, &previous.addr, &peer.addr))
                return error.DuplicatePeerAddress;
        }
    }
}

pub fn check(alloc: std.mem.Allocator, db: *sqlite.Db, id: u64, peers: anytype) !void {
    try validate(id, peers);
    const members = try alloc.alloc(u64, peers.len + 1);
    defer alloc.free(members);
    members[0] = id;
    for (peers, 1..) |peer, i| members[i] = peer.id;
    std.mem.sort(u64, members, {}, std.sort.asc(u64));
    var encoded = std.Io.Writer.Allocating.init(alloc);
    defer encoded.deinit();
    for (members) |member| try encoded.writer.print("{d},", .{member});

    try db.exec("CREATE TABLE IF NOT EXISTS static_membership (id INTEGER PRIMARY KEY CHECK (id = 1), node_id INTEGER NOT NULL, voters TEXT NOT NULL);", .{}, .{});
    try db.exec("INSERT OR IGNORE INTO static_membership (id, node_id, voters) VALUES (1, ?, ?);", .{}, .{ @as(i64, @intCast(id)), encoded.written() });
    const Row = struct { matches: i64 };
    const row = (try db.one(Row, "SELECT COUNT(*) AS matches FROM static_membership WHERE node_id = ? AND voters = ?;", .{}, .{ @as(i64, @intCast(id)), encoded.written() })).?;
    if (row.matches != 1) return error.MembershipChanged;
}

test "static membership accepts peer order changes and rejects changed voters" {
    const Peer = struct { id: u64, addr: [4]u8 = .{ 127, 0, 0, 1 }, port: u16 };
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    const peers = [_]Peer{ .{ .id = 2, .port = 9702 }, .{ .id = 3, .port = 9703 } };
    try check(std.testing.allocator, &db, 1, &peers);
    try check(std.testing.allocator, &db, 1, &[_]Peer{ peers[1], peers[0] });
    try std.testing.expectError(error.MembershipChanged, check(std.testing.allocator, &db, 1, peers[0..1]));
    try std.testing.expectError(error.MembershipChanged, check(std.testing.allocator, &db, 4, &peers));
    try std.testing.expectError(error.InvalidPeerId, validate(2, &peers));
    try std.testing.expectError(error.DuplicatePeerId, validate(1, &[_]Peer{ peers[0], peers[0] }));
}
