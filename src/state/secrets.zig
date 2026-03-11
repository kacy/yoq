// secrets — encrypted-at-rest key-value store for sensitive data
//
// secrets are encrypted with XChaCha20-Poly1305 before being stored
// in SQLite. the master key lives at ~/.local/share/yoq/secrets.key
// and is auto-generated on first use. values are never logged or
// exposed in error messages.
//
// each secret gets its own random nonce, so the same plaintext
// stored twice produces different ciphertext.

const std = @import("std");
const sqlite = @import("sqlite");
const schema = @import("schema.zig");
const paths = @import("../lib/paths.zig");

const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const key_length = XChaCha20Poly1305.key_length; // 32
pub const nonce_length = XChaCha20Poly1305.nonce_length; // 24
pub const tag_length = XChaCha20Poly1305.tag_length; // 16

pub const SecretsError = error{
    /// the master key file exists but could not be read
    KeyLoadFailed,
    /// failed to generate or write a new master key file
    KeyCreateFailed,
    /// XChaCha20-Poly1305 encryption of a secret value failed
    EncryptionFailed,
    /// decryption failed — wrong key, tampered ciphertext, or invalid nonce/tag size
    DecryptionFailed,
    /// a database write (insert/update/delete) for secrets failed
    WriteFailed,
    /// a database read (select/query) for secrets failed
    ReadFailed,
    /// no secret exists with the given name
    NotFound,
    /// the constructed key file path exceeded the buffer size
    PathTooLong,
    /// could not determine the user's home directory for key storage
    HomeDirNotFound,
    /// memory allocation failed during a secrets operation
    AllocFailed,
};

pub const SecretsStore = struct {
    db: *sqlite.Db,
    key: [key_length]u8,
    allocator: std.mem.Allocator,

    /// initialize a secrets store backed by the given database.
    /// loads or creates the master key automatically.
    pub fn init(db: *sqlite.Db, allocator: std.mem.Allocator) SecretsError!SecretsStore {
        // ensure the secrets table exists (schema.init should have been called,
        // but this is a safety net)
        db.exec(schema.secrets_create_table_sql, .{}, .{}) catch return SecretsError.WriteFailed;

        const key = loadOrCreateKey() catch |err| return switch (err) {
            error.HomeDirNotFound => SecretsError.HomeDirNotFound,
            error.PathTooLong => SecretsError.PathTooLong,
            error.KeyCreateFailed => SecretsError.KeyCreateFailed,
            error.KeyLoadFailed => SecretsError.KeyLoadFailed,
        };

        return .{
            .db = db,
            .key = key,
            .allocator = allocator,
        };
    }

    /// initialize with an explicit key (for testing).
    /// skips file-based key loading entirely.
    pub fn initWithKey(db: *sqlite.Db, allocator: std.mem.Allocator, key: [key_length]u8) SecretsError!SecretsStore {
        db.exec(schema.secrets_create_table_sql, .{}, .{}) catch return SecretsError.WriteFailed;

        return .{
            .db = db,
            .key = key,
            .allocator = allocator,
        };
    }

    /// store a secret. encrypts the value and upserts into the database.
    /// if the secret already exists, it is overwritten.
    pub fn set(self: *SecretsStore, name: []const u8, value: []const u8) SecretsError!void {
        const encrypted = encrypt(self.allocator, value, self.key) catch
            return SecretsError.EncryptionFailed;
        defer self.allocator.free(encrypted.ciphertext);

        const now: i64 = std.time.timestamp();

        // check if the secret exists to decide created_at
        const existing = self.getTimestamp(name);
        const created_at = existing orelse now;

        try self.writeEncryptedValue(name, encrypted, created_at, now);
    }

    /// retrieve and decrypt a secret by name.
    /// caller owns the returned slice and must free it with the store's allocator.
    pub fn get(self: *SecretsStore, name: []const u8) SecretsError![]u8 {
        const SecretRow = struct {
            encrypted_value: sqlite.Blob,
            nonce: sqlite.Blob,
            tag: sqlite.Blob,
        };

        const row = (self.db.oneAlloc(
            SecretRow,
            self.allocator,
            "SELECT encrypted_value, nonce, tag FROM secrets WHERE name = ?;",
            .{},
            .{name},
        ) catch return SecretsError.ReadFailed) orelse return SecretsError.NotFound;
        defer {
            self.allocator.free(row.encrypted_value.data);
            self.allocator.free(row.nonce.data);
            self.allocator.free(row.tag.data);
        }

        // validate nonce and tag sizes
        if (row.nonce.data.len != nonce_length) return SecretsError.DecryptionFailed;
        if (row.tag.data.len != tag_length) return SecretsError.DecryptionFailed;

        const plaintext = decrypt(
            self.allocator,
            row.encrypted_value.data,
            row.nonce.data[0..nonce_length].*,
            row.tag.data[0..tag_length].*,
            self.key,
        ) catch return SecretsError.DecryptionFailed;

        return plaintext;
    }

    /// delete a secret by name.
    pub fn remove(self: *SecretsStore, name: []const u8) SecretsError!void {
        // check it exists first
        const existing = self.getTimestamp(name);
        if (existing == null) return SecretsError.NotFound;

        self.db.exec(
            "DELETE FROM secrets WHERE name = ?;",
            .{},
            .{name},
        ) catch return SecretsError.WriteFailed;
    }

    /// list all secret names (not values). caller owns the returned list
    /// and each string in it.
    pub fn list(self: *SecretsStore) SecretsError!std.ArrayList([]const u8) {
        const NameRow = struct {
            name: sqlite.Text,
        };

        var names: std.ArrayList([]const u8) = .empty;

        var stmt = self.db.prepare(
            "SELECT name FROM secrets ORDER BY name ASC;",
        ) catch return SecretsError.ReadFailed;
        defer stmt.deinit();

        var iter = stmt.iterator(NameRow, .{}) catch return SecretsError.ReadFailed;
        while (iter.nextAlloc(self.allocator, .{}) catch return SecretsError.ReadFailed) |row| {
            names.append(self.allocator, row.name.data) catch return SecretsError.AllocFailed;
        }

        return names;
    }

    /// rotate the master encryption key. decrypts all secrets with the
    /// current key, then re-encrypts them with the new key. updates
    /// the in-memory key to the new one.
    ///
    /// WARNING: callers should ensure the new key is persisted to disk
    /// before calling this, and the old key is securely erased after
    /// a successful rotation.
    pub fn rotateKey(self: *SecretsStore, new_key: [key_length]u8) SecretsError!void {
        try self.rotateKeyWithWriter(new_key, writeEncryptedValue);
    }

    fn rotateKeyWithWriter(
        self: *SecretsStore,
        new_key: [key_length]u8,
        write_fn: *const fn (*SecretsStore, []const u8, EncryptResult, i64, i64) SecretsError!void,
    ) SecretsError!void {
        // list all secret names
        var names = try self.list();
        defer {
            for (names.items) |n| self.allocator.free(n);
            names.deinit(self.allocator);
        }

        // decrypt all secrets with the current key, re-encrypt with new key.
        // we collect all plaintext first so a failure mid-rotation doesn't
        // leave secrets in a mixed-key state.
        var plaintexts: std.ArrayListUnmanaged([]u8) = .empty;
        defer {
            for (plaintexts.items) |pt| {
                secureZero(pt);
                self.allocator.free(pt);
            }
            plaintexts.deinit(self.allocator);
        }

        for (names.items) |name| {
            const pt = try self.get(name);
            plaintexts.append(self.allocator, pt) catch {
                secureZero(pt);
                self.allocator.free(pt);
                return SecretsError.AllocFailed;
            };
        }

        self.db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return SecretsError.WriteFailed;
        var transaction_open = true;
        errdefer if (transaction_open) self.db.exec("ROLLBACK;", .{}, .{}) catch {};

        // re-encrypt all secrets with the new key
        const now = std.time.timestamp();
        for (names.items, 0..) |name, i| {
            const created_at = self.getTimestamp(name) orelse now;
            const encrypted = encrypt(self.allocator, plaintexts.items[i], new_key) catch
                return SecretsError.EncryptionFailed;
            defer self.allocator.free(encrypted.ciphertext);

            try write_fn(self, name, encrypted, created_at, now);
        }

        self.db.exec("COMMIT;", .{}, .{}) catch return SecretsError.WriteFailed;
        transaction_open = false;

        secureZero(&self.key);
        self.key = new_key;
    }

    /// re-encrypt a secret with the current key. useful after key rotation:
    /// load the old key, decrypt, load the new key, re-encrypt.
    /// in the simple case (same key), this just generates a fresh nonce.
    pub fn rotate(self: *SecretsStore, name: []const u8) SecretsError!void {
        // decrypt with current key
        const plaintext = try self.get(name);
        defer {
            // zero the plaintext before freeing — defense in depth
            secureZero(plaintext);
            self.allocator.free(plaintext);
        }

        // re-encrypt (generates a new random nonce)
        try self.set(name, plaintext);
    }

    // -- internal helpers --

    /// look up the created_at timestamp for a secret, or null if it doesn't exist.
    fn getTimestamp(self: *SecretsStore, name: []const u8) ?i64 {
        const TimestampRow = struct {
            created_at: i64,
        };

        const row = (self.db.one(
            TimestampRow,
            "SELECT created_at FROM secrets WHERE name = ?;",
            .{},
            .{name},
        ) catch return null) orelse return null;

        return row.created_at;
    }

    fn writeEncryptedValue(
        self: *SecretsStore,
        name: []const u8,
        encrypted: EncryptResult,
        created_at: i64,
        updated_at: i64,
    ) SecretsError!void {
        self.db.exec(
            "INSERT OR REPLACE INTO secrets (name, encrypted_value, nonce, tag, created_at, updated_at)" ++
                " VALUES (?, ?, ?, ?, ?, ?);",
            .{},
            .{
                name,
                @as(sqlite.Blob, .{ .data = encrypted.ciphertext }),
                @as(sqlite.Blob, .{ .data = &encrypted.nonce }),
                @as(sqlite.Blob, .{ .data = &encrypted.tag }),
                created_at,
                updated_at,
            },
        ) catch return SecretsError.WriteFailed;
    }

};

// -- encryption primitives --

pub const EncryptResult = struct {
    ciphertext: []u8,
    nonce: [nonce_length]u8,
    tag: [tag_length]u8,
};

/// encrypt plaintext with XChaCha20-Poly1305.
/// returns owned ciphertext (caller must free) plus nonce and tag.
pub fn encrypt(allocator: std.mem.Allocator, plaintext: []const u8, key: [key_length]u8) !EncryptResult {
    const ciphertext = try allocator.alloc(u8, plaintext.len);
    errdefer allocator.free(ciphertext);

    // generate a random nonce — XChaCha20's 24-byte nonce is large enough
    // that random generation is safe (negligible collision probability)
    var nonce: [nonce_length]u8 = undefined;
    std.crypto.random.bytes(&nonce);

    var tag: [tag_length]u8 = undefined;

    XChaCha20Poly1305.encrypt(ciphertext, &tag, plaintext, "", nonce, key);

    return .{
        .ciphertext = ciphertext,
        .nonce = nonce,
        .tag = tag,
    };
}

/// decrypt ciphertext with XChaCha20-Poly1305.
/// returns owned plaintext (caller must free).
/// returns error if authentication fails (tampered data or wrong key).
pub fn decrypt(allocator: std.mem.Allocator, ciphertext: []const u8, nonce: [nonce_length]u8, tag: [tag_length]u8, key: [key_length]u8) ![]u8 {
    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);

    XChaCha20Poly1305.decrypt(plaintext, ciphertext, tag, "", nonce, key) catch
        return error.AuthenticationFailed;

    return plaintext;
}

// -- key management --

const KeyError = error{
    HomeDirNotFound,
    PathTooLong,
    KeyCreateFailed,
    KeyLoadFailed,
};

/// load the master key from disk, or create it if it doesn't exist.
/// key file: ~/.local/share/yoq/secrets.key
fn loadOrCreateKey() KeyError![key_length]u8 {
    var path_buf: [paths.max_path]u8 = undefined;
    const key_path = paths.dataPath(&path_buf, "secrets.key") catch |err| return switch (err) {
        error.HomeDirNotFound => KeyError.HomeDirNotFound,
        error.PathTooLong => KeyError.PathTooLong,
    };

    // ensure the data directory exists
    paths.ensureDataDir("") catch return KeyError.HomeDirNotFound;

    // refuse existing weak-permission key files rather than silently
    // replacing them. callers should fix permissions explicitly.
    if (keyFileExists(key_path)) {
        if (!keyFileHasOwnerOnlyPermissions(key_path)) return KeyError.KeyLoadFailed;
        if (readKeyFile(key_path)) |key| {
            return key;
        }
        return KeyError.KeyLoadFailed;
    }

    // key doesn't exist — generate and save
    var key: [key_length]u8 = undefined;
    std.crypto.random.bytes(&key);

    saveKeyFile(key_path, &key) catch return KeyError.KeyCreateFailed;
    return key;
}

/// read exactly key_length bytes from a file. returns null if the file
/// doesn't exist or has the wrong size.
fn readKeyFile(path: []const u8) ?[key_length]u8 {
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();

    const stat = file.stat() catch return null;
    if ((stat.mode & 0o077) != 0) return null;

    var key: [key_length]u8 = undefined;
    const n = file.readAll(&key) catch return null;
    if (n != key_length) return null;

    return key;
}

fn keyFileExists(path: []const u8) bool {
    std.fs.cwd().access(path, .{}) catch return false;
    return true;
}

fn keyFileHasOwnerOnlyPermissions(path: []const u8) bool {
    const file = std.fs.cwd().openFile(path, .{}) catch return false;
    defer file.close();

    const stat = file.stat() catch return false;
    return (stat.mode & 0o077) == 0;
}

/// write a key to a file with restrictive permissions (owner read/write only).
fn saveKeyFile(path: []const u8, key: *const [key_length]u8) !void {
    const file = std.fs.cwd().createFile(path, .{ .mode = 0o600 }) catch
        return error.KeyCreateFailed;
    defer file.close();

    file.writeAll(key) catch return error.KeyCreateFailed;
    file.sync() catch return error.KeyCreateFailed;
}

// -- utility --

/// overwrite memory with zeros. used to clear sensitive data before freeing.
fn secureZero(buf: []u8) void {
    // use the crypto library's secure zero to prevent optimizer from eliding
    std.crypto.secureZero(u8, buf);
}

// -- tests --

test "encrypt and decrypt round-trip" {
    const alloc = std.testing.allocator;
    const key = [_]u8{0x42} ** key_length;
    const plaintext = "super secret database password";

    const result = try encrypt(alloc, plaintext, key);
    defer alloc.free(result.ciphertext);

    const decrypted = try decrypt(alloc, result.ciphertext, result.nonce, result.tag, key);
    defer alloc.free(decrypted);

    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "encrypt produces different ciphertext each time" {
    const alloc = std.testing.allocator;
    const key = [_]u8{0x42} ** key_length;
    const plaintext = "same input";

    const r1 = try encrypt(alloc, plaintext, key);
    defer alloc.free(r1.ciphertext);

    const r2 = try encrypt(alloc, plaintext, key);
    defer alloc.free(r2.ciphertext);

    // nonces should differ (extremely high probability with 24 random bytes)
    try std.testing.expect(!std.mem.eql(u8, &r1.nonce, &r2.nonce));
}

test "decrypt fails with wrong key" {
    const alloc = std.testing.allocator;
    const key = [_]u8{0x42} ** key_length;
    const wrong_key = [_]u8{0x99} ** key_length;
    const plaintext = "secret";

    const result = try encrypt(alloc, plaintext, key);
    defer alloc.free(result.ciphertext);

    const decrypted = decrypt(alloc, result.ciphertext, result.nonce, result.tag, wrong_key);
    try std.testing.expectError(error.AuthenticationFailed, decrypted);
}

test "decrypt fails with tampered ciphertext" {
    const alloc = std.testing.allocator;
    const key = [_]u8{0x42} ** key_length;
    const plaintext = "important data";

    const result = try encrypt(alloc, plaintext, key);
    defer alloc.free(result.ciphertext);

    // flip a bit
    result.ciphertext[0] ^= 0x01;

    const decrypted = decrypt(alloc, result.ciphertext, result.nonce, result.tag, key);
    try std.testing.expectError(error.AuthenticationFailed, decrypted);
}

test "encrypt and decrypt empty plaintext" {
    const alloc = std.testing.allocator;
    const key = [_]u8{0x42} ** key_length;
    const plaintext = "";

    const result = try encrypt(alloc, plaintext, key);
    defer alloc.free(result.ciphertext);

    const decrypted = try decrypt(alloc, result.ciphertext, result.nonce, result.tag, key);
    defer alloc.free(decrypted);

    try std.testing.expectEqualStrings("", decrypted);
}

test "store set and get round-trip" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var store = try SecretsStore.initWithKey(&db, alloc, key);

    try store.set("db_password", "hunter2");

    const value = try store.get("db_password");
    defer alloc.free(value);

    try std.testing.expectEqualStrings("hunter2", value);
}

test "store set overwrites existing" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var store = try SecretsStore.initWithKey(&db, alloc, key);

    try store.set("api_key", "old_value");
    try store.set("api_key", "new_value");

    const value = try store.get("api_key");
    defer alloc.free(value);

    try std.testing.expectEqualStrings("new_value", value);
}

test "store get nonexistent returns not found" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var store = try SecretsStore.initWithKey(&db, alloc, key);

    const result = store.get("nonexistent");
    try std.testing.expectError(SecretsError.NotFound, result);
}

test "store remove" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var store = try SecretsStore.initWithKey(&db, alloc, key);

    try store.set("temp_secret", "value");
    try store.remove("temp_secret");

    const result = store.get("temp_secret");
    try std.testing.expectError(SecretsError.NotFound, result);
}

test "readKeyFile rejects weak permissions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file = try tmp.dir.createFile("secrets.key", .{ .mode = 0o644 });
    defer file.close();
    try file.writeAll(&([_]u8{0x11} ** key_length));

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try tmp.dir.realpath("secrets.key", &path_buf);
    try std.testing.expect(readKeyFile(path) == null);
}

test "store remove nonexistent returns not found" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var store = try SecretsStore.initWithKey(&db, alloc, key);

    const result = store.remove("ghost");
    try std.testing.expectError(SecretsError.NotFound, result);
}

test "store list returns sorted names" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var store = try SecretsStore.initWithKey(&db, alloc, key);

    try store.set("zebra", "z");
    try store.set("alpha", "a");
    try store.set("middle", "m");

    var names = try store.list();
    defer {
        for (names.items) |n| alloc.free(n);
        names.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 3), names.items.len);
    try std.testing.expectEqualStrings("alpha", names.items[0]);
    try std.testing.expectEqualStrings("middle", names.items[1]);
    try std.testing.expectEqualStrings("zebra", names.items[2]);
}

test "store list empty" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var store = try SecretsStore.initWithKey(&db, alloc, key);

    var names = try store.list();
    defer names.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 0), names.items.len);
}

test "store rotate re-encrypts with fresh nonce" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var store = try SecretsStore.initWithKey(&db, alloc, key);

    try store.set("rotate_me", "secret_value");

    // read the raw nonce before rotation
    const NonceRow = struct { nonce: sqlite.Blob };
    const before = (try db.oneAlloc(
        NonceRow,
        alloc,
        "SELECT nonce FROM secrets WHERE name = ?;",
        .{},
        .{"rotate_me"},
    )).?;
    const nonce_before = try alloc.dupe(u8, before.nonce.data);
    defer alloc.free(nonce_before);
    alloc.free(before.nonce.data);

    // rotate
    try store.rotate("rotate_me");

    // verify the value is still correct
    const value = try store.get("rotate_me");
    defer alloc.free(value);
    try std.testing.expectEqualStrings("secret_value", value);

    // verify the nonce changed
    const after = (try db.oneAlloc(
        NonceRow,
        alloc,
        "SELECT nonce FROM secrets WHERE name = ?;",
        .{},
        .{"rotate_me"},
    )).?;
    defer alloc.free(after.nonce.data);

    try std.testing.expect(!std.mem.eql(u8, nonce_before, after.nonce.data));
}

test "store rotate nonexistent returns not found" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var store = try SecretsStore.initWithKey(&db, alloc, key);

    const result = store.rotate("nope");
    try std.testing.expectError(SecretsError.NotFound, result);
}

test "store preserves created_at on update" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var store = try SecretsStore.initWithKey(&db, alloc, key);

    try store.set("ts_test", "first");

    const TimestampRow = struct { created_at: i64, updated_at: i64 };
    const before = (try db.one(
        TimestampRow,
        "SELECT created_at, updated_at FROM secrets WHERE name = ?;",
        .{},
        .{"ts_test"},
    )).?;

    // update — created_at should be preserved, updated_at should change (or stay same if instant)
    try store.set("ts_test", "second");

    const after = (try db.one(
        TimestampRow,
        "SELECT created_at, updated_at FROM secrets WHERE name = ?;",
        .{},
        .{"ts_test"},
    )).?;

    try std.testing.expectEqual(before.created_at, after.created_at);
    try std.testing.expect(after.updated_at >= before.updated_at);
}

test "secureZero clears buffer" {
    var buf = [_]u8{ 1, 2, 3, 4, 5 };
    secureZero(&buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0 }, &buf);
}

test "encrypt and decrypt large value" {
    const alloc = std.testing.allocator;
    const key = [_]u8{0x42} ** key_length;

    // 10KB of data
    const plaintext = try alloc.alloc(u8, 10240);
    defer alloc.free(plaintext);
    @memset(plaintext, 0x55);

    const result = try encrypt(alloc, plaintext, key);
    defer alloc.free(result.ciphertext);

    const decrypted = try decrypt(alloc, result.ciphertext, result.nonce, result.tag, key);
    defer alloc.free(decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "store rotateKey re-encrypts all secrets with new key" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const old_key = [_]u8{0xAA} ** key_length;
    const new_key = [_]u8{0xBB} ** key_length;
    var store_obj = try SecretsStore.initWithKey(&db, alloc, old_key);

    // store some secrets with the old key
    try store_obj.set("secret_a", "value_a");
    try store_obj.set("secret_b", "value_b");

    // rotate to new key
    try store_obj.rotateKey(new_key);

    // verify secrets are still readable with the new key
    const val_a = try store_obj.get("secret_a");
    defer alloc.free(val_a);
    try std.testing.expectEqualStrings("value_a", val_a);

    const val_b = try store_obj.get("secret_b");
    defer alloc.free(val_b);
    try std.testing.expectEqualStrings("value_b", val_b);

    // verify the store's key is now the new key
    try std.testing.expectEqualSlices(u8, &new_key, &store_obj.key);
}

test "store rotateKey with no secrets succeeds" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const old_key = [_]u8{0xAA} ** key_length;
    const new_key = [_]u8{0xBB} ** key_length;
    var store_obj = try SecretsStore.initWithKey(&db, alloc, old_key);

    // should succeed even with no secrets
    try store_obj.rotateKey(new_key);
    try std.testing.expectEqualSlices(u8, &new_key, &store_obj.key);
}

test "store rotateKey rolls back on write failure" {
    const FailingWriter = struct {
        var calls: usize = 0;

        fn write(
            self: *SecretsStore,
            name: []const u8,
            encrypted: EncryptResult,
            created_at: i64,
            updated_at: i64,
        ) SecretsError!void {
            calls += 1;
            if (calls == 2) return SecretsError.WriteFailed;
            return self.writeEncryptedValue(name, encrypted, created_at, updated_at);
        }
    };

    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const old_key = [_]u8{0x11} ** key_length;
    const new_key = [_]u8{0x22} ** key_length;
    var store_obj = try SecretsStore.initWithKey(&db, alloc, old_key);

    try store_obj.set("secret_a", "value_a");
    try store_obj.set("secret_b", "value_b");

    FailingWriter.calls = 0;
    try std.testing.expectError(
        SecretsError.WriteFailed,
        store_obj.rotateKeyWithWriter(new_key, FailingWriter.write),
    );

    try std.testing.expectEqualSlices(u8, &old_key, &store_obj.key);

    const val_a = try store_obj.get("secret_a");
    defer alloc.free(val_a);
    try std.testing.expectEqualStrings("value_a", val_a);

    const val_b = try store_obj.get("secret_b");
    defer alloc.free(val_b);
    try std.testing.expectEqualStrings("value_b", val_b);
}
