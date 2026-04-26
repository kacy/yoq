const std = @import("std");
const sqlite = @import("sqlite");
const secrets = @import("../../state/secrets.zig");
const common = @import("common.zig");
const key_support = @import("key_support.zig");
const x509_parse = @import("x509_parse.zig");
const acme_config = @import("../acme/config.zig");

fn nowRealSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

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

        const now: i64 = nowRealSeconds();
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

        if (!std.mem.eql(u8, source, "acme")) {
            self.db.exec("DELETE FROM certificate_acme_config WHERE domain = ?;", .{}, .{domain}) catch {};
        }
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
            "DELETE FROM certificate_acme_config WHERE domain = ?;",
            .{},
            .{domain},
        ) catch return common.CertError.WriteFailed;

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

    pub fn setAcmeConfig(self: *CertStore, domain: []const u8, config: common.AcmeManagedConfig) common.CertError!void {
        var aw: std.Io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();
        try acme_config.ManagedConfig.writeJson(&aw.writer, config);

        const now: i64 = nowRealSeconds();
        const created_at = self.getAcmeConfigCreatedAt(domain) orelse now;
        self.db.exec(
            "INSERT OR REPLACE INTO certificate_acme_config (domain, config_json, created_at, updated_at) VALUES (?, ?, ?, ?);",
            .{},
            .{ domain, aw.writer.buffered(), created_at, now },
        ) catch return common.CertError.WriteFailed;
    }

    pub fn getAcmeConfig(self: *CertStore, domain: []const u8) common.CertError!common.AcmeManagedConfig {
        const Row = struct {
            config_json: sqlite.Text,
        };

        const row = (self.db.oneAlloc(
            Row,
            self.allocator,
            "SELECT config_json FROM certificate_acme_config WHERE domain = ?;",
            .{},
            .{domain},
        ) catch return common.CertError.ReadFailed) orelse return common.CertError.NotFound;
        defer self.allocator.free(row.config_json.data);

        return decodeManagedConfig(self.allocator, row.config_json.data) catch return common.CertError.ReadFailed;
    }

    pub fn removeAcmeConfig(self: *CertStore, domain: []const u8) common.CertError!void {
        self.db.exec(
            "DELETE FROM certificate_acme_config WHERE domain = ?;",
            .{},
            .{domain},
        ) catch return common.CertError.WriteFailed;
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

        const threshold = nowRealSeconds() + (days * 86400);
        return row.not_after <= threshold;
    }

    pub fn listExpiringSoon(self: *CertStore, days: i64) common.CertError!std.ArrayList([]const u8) {
        const DomainRow = struct {
            domain: sqlite.Text,
        };

        const threshold = nowRealSeconds() + (days * 86400);
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

    pub fn listExpiringManagedSoon(self: *CertStore, days: i64) common.CertError!std.ArrayList([]const u8) {
        const DomainRow = struct {
            domain: sqlite.Text,
        };

        const threshold = nowRealSeconds() + (days * 86400);
        var results: std.ArrayList([]const u8) = .empty;

        var stmt = self.db.prepare(
            "SELECT c.domain FROM certificates c " ++
                "JOIN certificate_acme_config a ON a.domain = c.domain " ++
                "WHERE c.not_after <= ? ORDER BY c.not_after ASC;",
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

    fn getAcmeConfigCreatedAt(self: *CertStore, domain: []const u8) ?i64 {
        const TimestampRow = struct {
            created_at: i64,
        };

        const row = (self.db.one(
            TimestampRow,
            "SELECT created_at FROM certificate_acme_config WHERE domain = ?;",
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
        db.exec(
            \\CREATE TABLE IF NOT EXISTS certificate_acme_config (
            \\    domain TEXT PRIMARY KEY,
            \\    config_json TEXT NOT NULL,
            \\    created_at INTEGER NOT NULL,
            \\    updated_at INTEGER NOT NULL,
            \\    FOREIGN KEY (domain) REFERENCES certificates(domain) ON DELETE CASCADE
            \\);
        , .{}, .{}) catch return error.TableCreationFailed;
    }
};

fn decodeManagedConfig(alloc: std.mem.Allocator, json: []const u8) !common.AcmeManagedConfig {
    const JsonKeyValue = struct {
        key: []const u8,
        value: []const u8,
    };
    const JsonChallenge = struct {
        type: []const u8,
        provider: ?[]const u8 = null,
        secret_refs: []const JsonKeyValue = &.{},
        config: []const JsonKeyValue = &.{},
        hook: []const []const u8 = &.{},
        propagation_timeout_secs: u32 = 300,
        poll_interval_secs: u32 = 5,
    };
    const JsonConfig = struct {
        email: []const u8,
        directory_url: []const u8,
        challenge: JsonChallenge,
    };

    const parsed = try std.json.parseFromSlice(JsonConfig, alloc, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    const challenge_type = acme_config.ChallengeType.parse(parsed.value.challenge.type) orelse
        return error.ReadFailed;
    const challenge: acme_config.ChallengeConfig = switch (challenge_type) {
        .http_01 => .http_01,
        .dns_01 => blk: {
            const provider_raw = parsed.value.challenge.provider orelse return error.ReadFailed;
            const provider = acme_config.DnsProvider.parse(provider_raw) orelse return error.ReadFailed;
            const secret_refs = try cloneJsonKeyValues(JsonKeyValue, alloc, parsed.value.challenge.secret_refs);
            errdefer acme_config.freeKeyValueRefs(alloc, secret_refs);
            const config_pairs = try cloneJsonKeyValues(JsonKeyValue, alloc, parsed.value.challenge.config);
            errdefer acme_config.freeKeyValueRefs(alloc, config_pairs);
            const hook = try cloneJsonStrings(alloc, parsed.value.challenge.hook);
            errdefer acme_config.freeStringArray(alloc, hook);

            break :blk .{ .dns_01 = .{
                .provider = provider,
                .secret_refs = secret_refs,
                .config = config_pairs,
                .hook = hook,
                .propagation_timeout_secs = parsed.value.challenge.propagation_timeout_secs,
                .poll_interval_secs = parsed.value.challenge.poll_interval_secs,
            } };
        },
    };
    errdefer challenge.deinit(alloc);
    const email = try alloc.dupe(u8, parsed.value.email);
    errdefer alloc.free(email);
    const directory_url = try alloc.dupe(u8, parsed.value.directory_url);
    errdefer alloc.free(directory_url);

    return .{
        .email = email,
        .directory_url = directory_url,
        .challenge = challenge,
    };
}

fn cloneJsonKeyValues(
    comptime T: type,
    alloc: std.mem.Allocator,
    values: []const T,
) ![]const acme_config.KeyValueRef {
    var result: std.ArrayListUnmanaged(acme_config.KeyValueRef) = .empty;
    errdefer {
        for (result.items) |entry| entry.deinit(alloc);
        result.deinit(alloc);
    }
    for (values) |entry| {
        const cloned = blk: {
            const key = try alloc.dupe(u8, entry.key);
            errdefer alloc.free(key);
            break :blk acme_config.KeyValueRef{
                .key = key,
                .value = try alloc.dupe(u8, entry.value),
            };
        };
        try result.append(alloc, cloned);
    }
    return try result.toOwnedSlice(alloc);
}

fn cloneJsonStrings(alloc: std.mem.Allocator, values: []const []const u8) ![]const []const u8 {
    var result: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (result.items) |entry| alloc.free(entry);
        result.deinit(alloc);
    }
    for (values) |entry| {
        try result.append(alloc, try alloc.dupe(u8, entry));
    }
    return try result.toOwnedSlice(alloc);
}
