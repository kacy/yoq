const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const schema = @import("../schema.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

pub const TokenRecord = struct {
    name: []const u8,
    secret_hash: []const u8,
    scopes: []const u8,
    created_at: i64,
    expires_at: ?i64,
    revoked_at: ?i64,

    pub fn deinit(self: TokenRecord, alloc: Allocator) void {
        alloc.free(self.name);
        alloc.free(self.secret_hash);
        alloc.free(self.scopes);
    }
};

const token_columns = "name, secret_hash, scopes, created_at, expires_at, revoked_at";

const TokenRow = struct {
    name: sqlite.Text,
    secret_hash: sqlite.Text,
    scopes: sqlite.Text,
    created_at: i64,
    expires_at: ?i64,
    revoked_at: ?i64,
};

fn rowToRecord(row: TokenRow) TokenRecord {
    return .{
        .name = row.name.data,
        .secret_hash = row.secret_hash.data,
        .scopes = row.scopes.data,
        .created_at = row.created_at,
        .expires_at = row.expires_at,
        .revoked_at = row.revoked_at,
    };
}

/// create a named token. fails if the name already exists (PRIMARY KEY).
pub fn createToken(
    name: []const u8,
    secret_hash: []const u8,
    scopes: []const u8,
    created_at: i64,
    expires_at: ?i64,
) StoreError!void {
    var lease = try common.leaseDb();
    defer lease.deinit();
    return createTokenInDb(lease.db, name, secret_hash, scopes, created_at, expires_at);
}

pub fn createTokenInDb(
    db: *sqlite.Db,
    name: []const u8,
    secret_hash: []const u8,
    scopes: []const u8,
    created_at: i64,
    expires_at: ?i64,
) StoreError!void {
    // reject duplicates up front. the PRIMARY KEY is a backstop, but letting the
    // constraint fire inside db.exec leaves the prepared statement unfinalized
    // in this sqlite wrapper, so check first.
    if (tokenExistsInDb(db, name)) return StoreError.WriteFailed;

    db.exec(
        "INSERT INTO tokens (name, secret_hash, scopes, created_at, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, NULL);",
        .{},
        .{ name, secret_hash, scopes, created_at, expires_at },
    ) catch return StoreError.WriteFailed;
}

pub fn listTokens(alloc: Allocator) StoreError!std.ArrayList(TokenRecord) {
    var lease = try common.leaseDb();
    defer lease.deinit();
    return listTokensInDb(lease.db, alloc);
}

pub fn listTokensInDb(db: *sqlite.Db, alloc: Allocator) StoreError!std.ArrayList(TokenRecord) {
    var records: std.ArrayList(TokenRecord) = .empty;
    var stmt = db.prepare(
        "SELECT " ++ token_columns ++ " FROM tokens ORDER BY created_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(TokenRow, .{}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        records.append(alloc, rowToRecord(row)) catch return StoreError.ReadFailed;
    }
    return records;
}

/// find an active (not revoked, not expired) token by its secret hash. caller
/// owns the returned record. `now` is unix seconds.
pub fn findActiveTokenByHash(alloc: Allocator, secret_hash: []const u8, now: i64) StoreError!?TokenRecord {
    var lease = try common.leaseDb();
    defer lease.deinit();
    return findActiveTokenByHashInDb(lease.db, alloc, secret_hash, now);
}

pub fn findActiveTokenByHashInDb(db: *sqlite.Db, alloc: Allocator, secret_hash: []const u8, now: i64) StoreError!?TokenRecord {
    var stmt = db.prepare(
        "SELECT " ++ token_columns ++ " FROM tokens WHERE secret_hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?) LIMIT 1;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(TokenRow, .{ secret_hash, now }) catch return StoreError.ReadFailed;
    if (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        return rowToRecord(row);
    }
    return null;
}

/// existence check that needs no allocator (only a scalar column is read).
fn tokenExistsInDb(db: *sqlite.Db, name: []const u8) bool {
    var stmt = db.prepare("SELECT 1 FROM tokens WHERE name = ? LIMIT 1;") catch return false;
    defer stmt.deinit();
    var iter = stmt.iterator(struct { present: i64 }, .{name}) catch return false;
    const row = iter.next(.{}) catch return false;
    return row != null;
}

/// look up a token by name (active or not), or null if it does not exist.
pub fn findTokenByNameInDb(db: *sqlite.Db, alloc: Allocator, name: []const u8) StoreError!?TokenRecord {
    var stmt = db.prepare(
        "SELECT " ++ token_columns ++ " FROM tokens WHERE name = ? LIMIT 1;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(TokenRow, .{name}) catch return StoreError.ReadFailed;
    if (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        return rowToRecord(row);
    }
    return null;
}

/// revoke a token by name. returns false if no such token exists. idempotent.
pub fn revokeToken(alloc: Allocator, name: []const u8, now: i64) StoreError!bool {
    var lease = try common.leaseDb();
    defer lease.deinit();
    return revokeTokenInDb(lease.db, alloc, name, now);
}

pub fn revokeTokenInDb(db: *sqlite.Db, alloc: Allocator, name: []const u8, now: i64) StoreError!bool {
    const existing = try findTokenByNameInDb(db, alloc, name);
    if (existing) |rec| {
        rec.deinit(alloc);
    } else {
        return false;
    }
    db.exec(
        "UPDATE tokens SET revoked_at = ? WHERE name = ? AND revoked_at IS NULL;",
        .{},
        .{ now, name },
    ) catch return StoreError.WriteFailed;
    return true;
}

test "token create, find by hash, expiry and revocation filtering" {
    const alloc = std.testing.allocator;
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try createTokenInDb(&db, "deploy", "hash-deploy", "apps:write", 100, null);
    try createTokenInDb(&db, "temp", "hash-temp", "apps:read", 100, 500); // expires at 500
    try createTokenInDb(&db, "old", "hash-old", "secrets:read", 100, null);

    // active, no expiry → found
    {
        const found = (try findActiveTokenByHashInDb(&db, alloc, "hash-deploy", 1000)).?;
        defer found.deinit(alloc);
        try std.testing.expectEqualStrings("deploy", found.name);
        try std.testing.expectEqualStrings("apps:write", found.scopes);
    }
    // expired → not found
    try std.testing.expect((try findActiveTokenByHashInDb(&db, alloc, "hash-temp", 1000)) == null);
    // still valid before expiry → found
    {
        const found = (try findActiveTokenByHashInDb(&db, alloc, "hash-temp", 400)).?;
        defer found.deinit(alloc);
        try std.testing.expectEqualStrings("temp", found.name);
    }

    // revoke filters it out
    try std.testing.expect(try revokeTokenInDb(&db, alloc, "old", 600));
    try std.testing.expect((try findActiveTokenByHashInDb(&db, alloc, "hash-old", 1000)) == null);
    // revoking a missing token returns false
    try std.testing.expect(!(try revokeTokenInDb(&db, alloc, "nope", 600)));

    // list returns all three
    var all = try listTokensInDb(&db, alloc);
    defer {
        for (all.items) |t| t.deinit(alloc);
        all.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 3), all.items.len);
}

test "duplicate token name is rejected" {
    const alloc = std.testing.allocator;
    _ = alloc;
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    try createTokenInDb(&db, "dup", "h1", "*", 100, null);
    try std.testing.expectError(StoreError.WriteFailed, createTokenInDb(&db, "dup", "h2", "*", 100, null));
}
