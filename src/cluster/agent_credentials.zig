const std = @import("std");
const sqlite = @import("sqlite");

pub fn issue() [64]u8 {
    var bytes: [32]u8 = undefined;
    @import("linux_platform").randomBytes(&bytes);
    defer std.crypto.secureZero(u8, &bytes);
    return std.fmt.bytesToHex(bytes, .lower);
}

pub fn hash(secret: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(secret, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// The enrollment secret never authenticates an operational worker request.
/// NULL hashes are legacy or revoked workers and deliberately fail closed.
pub fn authenticates(db: *sqlite.Db, secret: []const u8, agent_id: ?[]const u8) !bool {
    if (secret.len != 64) return false;
    const digest = hash(secret);
    const Row = struct { count: i64 };
    const row = if (agent_id) |id|
        try db.one(Row, "SELECT COUNT(*) AS count FROM agents WHERE id = ? AND credential_hash = ?;", .{}, .{ id, digest[0..] })
    else
        try db.one(Row, "SELECT COUNT(*) AS count FROM agents WHERE credential_hash = ?;", .{}, .{digest[0..]});
    return if (row) |value| value.count == 1 else false;
}

pub fn ownsAssignment(db: *sqlite.Db, agent_id: []const u8, assignment_id: []const u8) !bool {
    const row = try db.one(struct { count: i64 }, "SELECT COUNT(*) AS count FROM assignments WHERE id = ? AND agent_id = ?;", .{}, .{ assignment_id, agent_id });
    return if (row) |value| value.count == 1 else false;
}
