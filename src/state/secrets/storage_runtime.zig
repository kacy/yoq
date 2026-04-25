const std = @import("std");
const sqlite = @import("sqlite");
const schema = @import("../schema.zig");
const common = @import("common.zig");
const crypto_runtime = @import("crypto_runtime.zig");
const key_support = @import("key_support.zig");

pub const SecretsStore = struct {
    db: *sqlite.Db,
    key: [common.key_length]u8,
    allocator: std.mem.Allocator,

    pub fn init(db: *sqlite.Db, allocator: std.mem.Allocator) common.SecretsError!SecretsStore {
        db.exec(schema.secrets_create_table_sql, .{}, .{}) catch return common.SecretsError.WriteFailed;

        const key = key_support.loadOrCreateKey() catch |err| return switch (err) {
            error.HomeDirNotFound => common.SecretsError.HomeDirNotFound,
            error.PathTooLong => common.SecretsError.PathTooLong,
            error.KeyCreateFailed => common.SecretsError.KeyCreateFailed,
            error.KeyLoadFailed => common.SecretsError.KeyLoadFailed,
        };

        return .{
            .db = db,
            .key = key,
            .allocator = allocator,
        };
    }

    pub fn initWithKey(db: *sqlite.Db, allocator: std.mem.Allocator, key: [common.key_length]u8) common.SecretsError!SecretsStore {
        db.exec(schema.secrets_create_table_sql, .{}, .{}) catch return common.SecretsError.WriteFailed;

        return .{
            .db = db,
            .key = key,
            .allocator = allocator,
        };
    }

    pub fn set(self: *SecretsStore, name: []const u8, value: []const u8) common.SecretsError!void {
        const encrypted = crypto_runtime.encrypt(self.allocator, value, self.key) catch
            return common.SecretsError.EncryptionFailed;
        defer self.allocator.free(encrypted.ciphertext);

        const now: i64 = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
        const existing = self.getTimestamp(name);
        const created_at = existing orelse now;

        try self.writeEncryptedValue(name, encrypted, created_at, now);
    }

    pub fn get(self: *SecretsStore, name: []const u8) common.SecretsError![]u8 {
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
        ) catch return common.SecretsError.ReadFailed) orelse return common.SecretsError.NotFound;
        defer {
            self.allocator.free(row.encrypted_value.data);
            self.allocator.free(row.nonce.data);
            self.allocator.free(row.tag.data);
        }

        if (row.nonce.data.len != common.nonce_length) return common.SecretsError.DecryptionFailed;
        if (row.tag.data.len != common.tag_length) return common.SecretsError.DecryptionFailed;

        return crypto_runtime.decrypt(
            self.allocator,
            row.encrypted_value.data,
            row.nonce.data[0..common.nonce_length].*,
            row.tag.data[0..common.tag_length].*,
            self.key,
        ) catch common.SecretsError.DecryptionFailed;
    }

    pub fn remove(self: *SecretsStore, name: []const u8) common.SecretsError!void {
        const existing = self.getTimestamp(name);
        if (existing == null) return common.SecretsError.NotFound;

        self.db.exec(
            "DELETE FROM secrets WHERE name = ?;",
            .{},
            .{name},
        ) catch return common.SecretsError.WriteFailed;
    }

    pub fn list(self: *SecretsStore) common.SecretsError!std.ArrayList([]const u8) {
        const NameRow = struct {
            name: sqlite.Text,
        };

        var names: std.ArrayList([]const u8) = .empty;

        var stmt = self.db.prepare(
            "SELECT name FROM secrets ORDER BY name ASC;",
        ) catch return common.SecretsError.ReadFailed;
        defer stmt.deinit();

        var iter = stmt.iterator(NameRow, .{}) catch return common.SecretsError.ReadFailed;
        while (iter.nextAlloc(self.allocator, .{}) catch return common.SecretsError.ReadFailed) |row| {
            names.append(self.allocator, row.name.data) catch return common.SecretsError.AllocFailed;
        }

        return names;
    }

    pub fn rotateKey(self: *SecretsStore, new_key: [common.key_length]u8) common.SecretsError!void {
        try self.rotateKeyWithWriter(new_key, writeEncryptedValue);
    }

    pub fn rotateKeyWithWriter(
        self: *SecretsStore,
        new_key: [common.key_length]u8,
        write_fn: *const fn (*SecretsStore, []const u8, common.EncryptResult, i64, i64) common.SecretsError!void,
    ) common.SecretsError!void {
        var names = try self.list();
        defer {
            for (names.items) |n| self.allocator.free(n);
            names.deinit(self.allocator);
        }

        var plaintexts: std.ArrayListUnmanaged([]u8) = .empty;
        defer {
            for (plaintexts.items) |pt| {
                key_support.secureZero(pt);
                self.allocator.free(pt);
            }
            plaintexts.deinit(self.allocator);
        }

        for (names.items) |name| {
            const pt = try self.get(name);
            plaintexts.append(self.allocator, pt) catch {
                key_support.secureZero(pt);
                self.allocator.free(pt);
                return common.SecretsError.AllocFailed;
            };
        }

        self.db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return common.SecretsError.WriteFailed;
        var transaction_open = true;
        errdefer if (transaction_open) self.db.exec("ROLLBACK;", .{}, .{}) catch {};

        const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
        for (names.items, 0..) |name, i| {
            const created_at = self.getTimestamp(name) orelse now;
            const encrypted = crypto_runtime.encrypt(self.allocator, plaintexts.items[i], new_key) catch
                return common.SecretsError.EncryptionFailed;
            defer self.allocator.free(encrypted.ciphertext);

            try write_fn(self, name, encrypted, created_at, now);
        }

        self.db.exec("COMMIT;", .{}, .{}) catch return common.SecretsError.WriteFailed;
        transaction_open = false;

        key_support.secureZero(&self.key);
        self.key = new_key;
    }

    pub fn rotate(self: *SecretsStore, name: []const u8) common.SecretsError!void {
        const plaintext = try self.get(name);
        defer {
            key_support.secureZero(plaintext);
            self.allocator.free(plaintext);
        }

        try self.set(name, plaintext);
    }

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

    pub fn writeEncryptedValue(
        self: *SecretsStore,
        name: []const u8,
        encrypted: common.EncryptResult,
        created_at: i64,
        updated_at: i64,
    ) common.SecretsError!void {
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
        ) catch return common.SecretsError.WriteFailed;
    }
};
