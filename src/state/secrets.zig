// secrets — encrypted-at-rest key-value store for sensitive data
//
// this file keeps the stable public API and tests while the
// implementation lives in smaller modules under `state/secrets/`.

const std = @import("std");
const sqlite = @import("sqlite");

const common = @import("secrets/common.zig");
const crypto_runtime = @import("secrets/crypto_runtime.zig");
const key_support = @import("secrets/key_support.zig");
const storage_runtime = @import("secrets/storage_runtime.zig");

pub const key_length = common.key_length;
pub const nonce_length = common.nonce_length;
pub const tag_length = common.tag_length;
pub const SecretsError = common.SecretsError;
pub const EncryptResult = common.EncryptResult;
pub const SecretsStore = storage_runtime.SecretsStore;
pub const encrypt = crypto_runtime.encrypt;
pub const decrypt = crypto_runtime.decrypt;

const readKeyFile = key_support.readKeyFile;
const secureZero = key_support.secureZero;

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

    var file = try tmp.dir.createFile(std.testing.io, "secrets.key", .{
        .permissions = std.Io.File.Permissions.fromMode(0o644),
    });
    defer file.close(std.testing.io);
    try file.writeStreamingAll(std.testing.io, &([_]u8{0x11} ** key_length));

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPathFile(std.testing.io, "secrets.key", &path_buf);
    const path = path_buf[0..path_len];
    try std.testing.expectError(error.KeyLoadFailed, readKeyFile(path));
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

    try store.rotate("rotate_me");

    const value = try store.get("rotate_me");
    defer alloc.free(value);
    try std.testing.expectEqualStrings("secret_value", value);

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

    try store_obj.set("secret_a", "value_a");
    try store_obj.set("secret_b", "value_b");

    try store_obj.rotateKey(new_key);

    const val_a = try store_obj.get("secret_a");
    defer alloc.free(val_a);
    try std.testing.expectEqualStrings("value_a", val_a);

    const val_b = try store_obj.get("secret_b");
    defer alloc.free(val_b);
    try std.testing.expectEqualStrings("value_b", val_b);

    try std.testing.expectEqualSlices(u8, &new_key, &store_obj.key);
}

test "store rotateKey with no secrets succeeds" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const old_key = [_]u8{0xAA} ** key_length;
    const new_key = [_]u8{0xBB} ** key_length;
    var store_obj = try SecretsStore.initWithKey(&db, alloc, old_key);

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
