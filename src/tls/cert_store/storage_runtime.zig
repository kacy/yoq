const std = @import("std");
const platform = @import("platform");
const sqlite = @import("sqlite");
const secrets = @import("../../state/secrets.zig");
const common = @import("common.zig");
const key_support = @import("key_support.zig");
const x509_parse = @import("x509_parse.zig");

pub const CertStore = struct {
    db: *sqlite.Db,
    key: [common.key_length]u8,
    allocator: std.mem.Allocator,

    pub fn init(db: *sqlite.Db, allocator: std.mem.Allocator) common.CertError!CertStore {
        ensureTable(db) catch return common.CertError.WriteFailed;

        const key = key_support.loadOrCreateKey() catch |err| return switch (err) {
            error.HomeDirNotFound => common.CertError.HomeDirNotFound,
            error.PathTooLong => common.CertError.PathTooLong,
            error.KeyCreateFailed => common.CertError.KeyCreateFailed,
            error.KeyLoadFailed => common.CertError.KeyLoadFailed,
        };

        return .{
            .db = db,
            .key = key,
            .allocator = allocator,
        };
    }

    pub fn initWithKey(db: *sqlite.Db, allocator: std.mem.Allocator, key: [common.key_length]u8) common.CertError!CertStore {
        ensureTable(db) catch return common.CertError.WriteFailed;

        return .{
            .db = db,
            .key = key,
            .allocator = allocator,
        };
    }

    pub fn install(self: *CertStore, domain: []const u8, cert_pem: []const u8, key_pem: []const u8, source: []const u8) common.CertError!void {
        const not_after = x509_parse.parseExpiryFromPem(cert_pem) catch
            return common.CertError.InvalidCert;

        const now: i64 = platform.timestamp();
        if (not_after <= now) return common.CertError.InvalidCert;

        const encrypted = secrets.encrypt(self.allocator, key_pem, self.key) catch
            return common.CertError.EncryptionFailed;
        defer self.allocator.free(encrypted.ciphertext);

        const existing = self.getCreatedAt(domain);
        const created_at = existing orelse now;

        self.db.exec(
            "INSERT OR REPLACE INTO certificates (domain, cert_pem, encrypted_key, key_nonce, key_tag, not_after, source, created_at, updated_at)" ++
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
            .{},
            .{
                domain,
                @as(sqlite.Blob, .{ .data = cert_pem }),
                @as(sqlite.Blob, .{ .data = encrypted.ciphertext }),
                @as(sqlite.Blob, .{ .data = &encrypted.nonce }),
                @as(sqlite.Blob, .{ .data = &encrypted.tag }),
                not_after,
                source,
                created_at,
                now,
            },
        ) catch return common.CertError.WriteFailed;
    }

    pub fn get(self: *CertStore, domain: []const u8) common.CertError!struct { cert_pem: []u8, key_pem: []u8 } {
        const CertRow = struct {
            cert_pem: sqlite.Blob,
            encrypted_key: sqlite.Blob,
            key_nonce: sqlite.Blob,
            key_tag: sqlite.Blob,
        };

        const row = (self.db.oneAlloc(
            CertRow,
            self.allocator,
            "SELECT cert_pem, encrypted_key, key_nonce, key_tag FROM certificates WHERE domain = ?;",
            .{},
            .{domain},
        ) catch return common.CertError.ReadFailed) orelse return common.CertError.NotFound;
        defer {
            self.allocator.free(row.cert_pem.data);
            self.allocator.free(row.encrypted_key.data);
            self.allocator.free(row.key_nonce.data);
            self.allocator.free(row.key_tag.data);
        }

        if (row.key_nonce.data.len != common.nonce_length) return common.CertError.DecryptionFailed;
        if (row.key_tag.data.len != common.tag_length) return common.CertError.DecryptionFailed;

        const key_pem = secrets.decrypt(
            self.allocator,
            row.encrypted_key.data,
            row.key_nonce.data[0..common.nonce_length].*,
            row.key_tag.data[0..common.tag_length].*,
            self.key,
        ) catch return common.CertError.DecryptionFailed;
        errdefer {
            key_support.secureZero(key_pem);
            self.allocator.free(key_pem);
        }

        const cert_pem = self.allocator.dupe(u8, row.cert_pem.data) catch {
            key_support.secureZero(key_pem);
            self.allocator.free(key_pem);
            return common.CertError.AllocFailed;
        };

        return .{ .cert_pem = cert_pem, .key_pem = key_pem };
    }

    pub fn remove(self: *CertStore, domain: []const u8) common.CertError!void {
        const existing = self.getCreatedAt(domain);
        if (existing == null) return common.CertError.NotFound;

        self.db.exec(
            "DELETE FROM certificates WHERE domain = ?;",
            .{},
            .{domain},
        ) catch return common.CertError.WriteFailed;
    }

    pub fn list(self: *CertStore) common.CertError!std.ArrayList(common.CertInfo) {
        const InfoRow = struct {
            domain: sqlite.Text,
            not_after: i64,
            source: sqlite.Text,
            created_at: i64,
        };

        var results: std.ArrayList(common.CertInfo) = .empty;

        var stmt = self.db.prepare(
            "SELECT domain, not_after, source, created_at FROM certificates ORDER BY domain ASC;",
        ) catch return common.CertError.ReadFailed;
        defer stmt.deinit();

        var iter = stmt.iterator(InfoRow, .{}) catch return common.CertError.ReadFailed;
        while (iter.nextAlloc(self.allocator, .{}) catch return common.CertError.ReadFailed) |row| {
            results.append(self.allocator, .{
                .domain = row.domain.data,
                .not_after = row.not_after,
                .source = row.source.data,
                .created_at = row.created_at,
            }) catch return common.CertError.AllocFailed;
        }

        return results;
    }

    pub fn needsRenewal(self: *CertStore, domain: []const u8, days: i64) common.CertError!bool {
        const ExpiryRow = struct {
            not_after: i64,
        };

        const row = (self.db.one(
            ExpiryRow,
            "SELECT not_after FROM certificates WHERE domain = ?;",
            .{},
            .{domain},
        ) catch return common.CertError.ReadFailed) orelse return common.CertError.NotFound;

        const threshold = platform.timestamp() + (days * 86400);
        return row.not_after <= threshold;
    }

    pub fn listExpiringSoon(self: *CertStore, days: i64) common.CertError!std.ArrayList([]const u8) {
        const DomainRow = struct {
            domain: sqlite.Text,
        };

        const threshold = platform.timestamp() + (days * 86400);
        var results: std.ArrayList([]const u8) = .empty;

        var stmt = self.db.prepare(
            "SELECT domain FROM certificates WHERE not_after <= ? ORDER BY not_after ASC;",
        ) catch return common.CertError.ReadFailed;
        defer stmt.deinit();

        var iter = stmt.iterator(DomainRow, .{threshold}) catch return common.CertError.ReadFailed;
        while (iter.nextAlloc(self.allocator, .{}) catch return common.CertError.ReadFailed) |row| {
            results.append(self.allocator, row.domain.data) catch return common.CertError.AllocFailed;
        }

        return results;
    }

    fn getCreatedAt(self: *CertStore, domain: []const u8) ?i64 {
        const TimestampRow = struct {
            created_at: i64,
        };

        const row = (self.db.one(
            TimestampRow,
            "SELECT created_at FROM certificates WHERE domain = ?;",
            .{},
            .{domain},
        ) catch return null) orelse return null;

        return row.created_at;
    }

    fn ensureTable(db: *sqlite.Db) !void {
        db.exec(
            \\CREATE TABLE IF NOT EXISTS certificates (
            \\    domain TEXT PRIMARY KEY,
            \\    cert_pem BLOB NOT NULL,
            \\    encrypted_key BLOB NOT NULL,
            \\    key_nonce BLOB NOT NULL,
            \\    key_tag BLOB NOT NULL,
            \\    not_after INTEGER NOT NULL,
            \\    source TEXT NOT NULL DEFAULT 'manual',
            \\    created_at INTEGER NOT NULL,
            \\    updated_at INTEGER NOT NULL
            \\);
        , .{}, .{}) catch return error.TableCreationFailed;
    }
};
