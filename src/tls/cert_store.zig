// cert_store — encrypted certificate storage
//
// stores TLS certificates and their private keys in SQLite.
// private keys are encrypted with XChaCha20-Poly1305 using the same
// master key as the secrets store. cert PEM is stored as plaintext
// (it's public anyway). expiry dates are parsed from the certificate
// and stored for renewal checks.
//
// reuses the encrypt/decrypt primitives from secrets.zig and the
// same master key at ~/.local/share/yoq/secrets.key.

const std = @import("std");
const sqlite = @import("sqlite");
const secrets = @import("../state/secrets.zig");
const paths = @import("../lib/paths.zig");

const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;

pub const key_length = XChaCha20Poly1305.key_length;
pub const nonce_length = XChaCha20Poly1305.nonce_length;
pub const tag_length = XChaCha20Poly1305.tag_length;

pub const CertError = error{
    KeyLoadFailed,
    KeyCreateFailed,
    EncryptionFailed,
    DecryptionFailed,
    WriteFailed,
    ReadFailed,
    NotFound,
    PathTooLong,
    HomeDirNotFound,
    AllocFailed,
    InvalidCert,
};

pub const CertInfo = struct {
    domain: []const u8,
    not_after: i64,
    source: []const u8,
    created_at: i64,

    pub fn deinit(self: CertInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.domain);
        allocator.free(self.source);
    }
};

pub const CertStore = struct {
    db: *sqlite.Db,
    key: [key_length]u8,
    allocator: std.mem.Allocator,

    /// initialize a certificate store backed by the given database.
    /// loads or creates the master key automatically (shared with secrets store).
    pub fn init(db: *sqlite.Db, allocator: std.mem.Allocator) CertError!CertStore {
        ensureTable(db) catch return CertError.WriteFailed;

        const key = loadOrCreateKey() catch |err| return switch (err) {
            error.HomeDirNotFound => CertError.HomeDirNotFound,
            error.PathTooLong => CertError.PathTooLong,
            error.KeyCreateFailed => CertError.KeyCreateFailed,
            error.KeyLoadFailed => CertError.KeyLoadFailed,
        };

        return .{
            .db = db,
            .key = key,
            .allocator = allocator,
        };
    }

    /// initialize with an explicit key (for testing).
    pub fn initWithKey(db: *sqlite.Db, allocator: std.mem.Allocator, key: [key_length]u8) CertError!CertStore {
        ensureTable(db) catch return CertError.WriteFailed;

        return .{
            .db = db,
            .key = key,
            .allocator = allocator,
        };
    }

    /// store a certificate and its private key for a domain.
    /// the private key is encrypted before storage. the cert PEM is
    /// stored as plaintext. expiry is parsed from the certificate.
    /// source should be "manual" or "acme".
    pub fn install(self: *CertStore, domain: []const u8, cert_pem: []const u8, key_pem: []const u8, source: []const u8) CertError!void {
        const not_after = parseExpiryFromPem(cert_pem) catch
            return CertError.InvalidCert;

        const encrypted = secrets.encrypt(self.allocator, key_pem, self.key) catch
            return CertError.EncryptionFailed;
        defer self.allocator.free(encrypted.ciphertext);

        const now: i64 = std.time.timestamp();

        // preserve created_at if updating an existing cert
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
        ) catch return CertError.WriteFailed;
    }

    /// retrieve a certificate and decrypted private key for a domain.
    /// caller owns both returned slices and must free them.
    pub fn get(self: *CertStore, domain: []const u8) CertError!struct { cert_pem: []u8, key_pem: []u8 } {
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
        ) catch return CertError.ReadFailed) orelse return CertError.NotFound;
        defer {
            self.allocator.free(row.cert_pem.data);
            self.allocator.free(row.encrypted_key.data);
            self.allocator.free(row.key_nonce.data);
            self.allocator.free(row.key_tag.data);
        }

        if (row.key_nonce.data.len != nonce_length) return CertError.DecryptionFailed;
        if (row.key_tag.data.len != tag_length) return CertError.DecryptionFailed;

        const key_pem = secrets.decrypt(
            self.allocator,
            row.encrypted_key.data,
            row.key_nonce.data[0..nonce_length].*,
            row.key_tag.data[0..tag_length].*,
            self.key,
        ) catch return CertError.DecryptionFailed;
        errdefer {
            secureZero(key_pem);
            self.allocator.free(key_pem);
        }

        const cert_pem = self.allocator.dupe(u8, row.cert_pem.data) catch {
            secureZero(key_pem);
            self.allocator.free(key_pem);
            return CertError.AllocFailed;
        };

        return .{ .cert_pem = cert_pem, .key_pem = key_pem };
    }

    /// remove a certificate by domain.
    pub fn remove(self: *CertStore, domain: []const u8) CertError!void {
        const existing = self.getCreatedAt(domain);
        if (existing == null) return CertError.NotFound;

        self.db.exec(
            "DELETE FROM certificates WHERE domain = ?;",
            .{},
            .{domain},
        ) catch return CertError.WriteFailed;
    }

    /// list all stored certificates with metadata.
    /// caller owns the returned list and each CertInfo in it.
    pub fn list(self: *CertStore) CertError!std.ArrayList(CertInfo) {
        const InfoRow = struct {
            domain: sqlite.Text,
            not_after: i64,
            source: sqlite.Text,
            created_at: i64,
        };

        var results: std.ArrayList(CertInfo) = .empty;

        var stmt = self.db.prepare(
            "SELECT domain, not_after, source, created_at FROM certificates ORDER BY domain ASC;",
        ) catch return CertError.ReadFailed;
        defer stmt.deinit();

        var iter = stmt.iterator(InfoRow, .{}) catch return CertError.ReadFailed;
        while (iter.nextAlloc(self.allocator, .{}) catch return CertError.ReadFailed) |row| {
            results.append(self.allocator, .{
                .domain = row.domain.data,
                .not_after = row.not_after,
                .source = row.source.data,
                .created_at = row.created_at,
            }) catch return CertError.AllocFailed;
        }

        return results;
    }

    /// check if a domain's certificate needs renewal (expires within given days).
    pub fn needsRenewal(self: *CertStore, domain: []const u8, days: i64) CertError!bool {
        const ExpiryRow = struct {
            not_after: i64,
        };

        const row = (self.db.one(
            ExpiryRow,
            "SELECT not_after FROM certificates WHERE domain = ?;",
            .{},
            .{domain},
        ) catch return CertError.ReadFailed) orelse return CertError.NotFound;

        const threshold = std.time.timestamp() + (days * 86400);
        return row.not_after <= threshold;
    }

    /// list certificates expiring within the given number of days.
    /// caller owns the returned list and each string in it.
    pub fn listExpiringSoon(self: *CertStore, days: i64) CertError!std.ArrayList([]const u8) {
        const DomainRow = struct {
            domain: sqlite.Text,
        };

        const threshold = std.time.timestamp() + (days * 86400);
        var results: std.ArrayList([]const u8) = .empty;

        var stmt = self.db.prepare(
            "SELECT domain FROM certificates WHERE not_after <= ? ORDER BY not_after ASC;",
        ) catch return CertError.ReadFailed;
        defer stmt.deinit();

        var iter = stmt.iterator(DomainRow, .{threshold}) catch return CertError.ReadFailed;
        while (iter.nextAlloc(self.allocator, .{}) catch return CertError.ReadFailed) |row| {
            results.append(self.allocator, row.domain.data) catch return CertError.AllocFailed;
        }

        return results;
    }

    // -- internal helpers --

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

// -- X.509 expiry parsing --

/// parse the notAfter timestamp from a PEM-encoded certificate.
/// supports DER-encoded X.509 within the PEM wrapper.
/// returns unix timestamp of the expiry date.
pub fn parseExpiryFromPem(pem: []const u8) !i64 {
    const der = try pemToDer(pem);
    return parseExpiryFromDer(der);
}

/// decode a PEM block to raw DER bytes.
/// expects "-----BEGIN CERTIFICATE-----" markers.
fn pemToDer(pem: []const u8) ![]const u8 {
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    const begin_pos = std.mem.indexOf(u8, pem, begin_marker) orelse
        return error.InvalidPem;
    const data_start = begin_pos + begin_marker.len;

    const end_pos = std.mem.indexOfPos(u8, pem, data_start, end_marker) orelse
        return error.InvalidPem;

    // strip whitespace/newlines from the base64 content
    return pem[data_start..end_pos];
}

/// parse notAfter from DER-encoded X.509 certificate data (still base64).
/// walks the ASN.1 structure to find the validity sequence.
fn parseExpiryFromDer(base64_data: []const u8) !i64 {
    // decode base64
    var buf: [8192]u8 = undefined;
    var decoded_len: usize = 0;

    // strip whitespace from base64 input
    var clean: [8192]u8 = undefined;
    var clean_len: usize = 0;
    for (base64_data) |c| {
        if (c != '\n' and c != '\r' and c != ' ' and c != '\t') {
            if (clean_len >= clean.len) return error.CertTooLarge;
            clean[clean_len] = c;
            clean_len += 1;
        }
    }

    const decoder = std.base64.standard.Decoder;
    decoded_len = decoder.calcSizeForSlice(clean[0..clean_len]) catch return error.InvalidBase64;
    if (decoded_len > buf.len) return error.CertTooLarge;
    decoder.decode(&buf, clean[0..clean_len]) catch return error.InvalidBase64;

    const der = buf[0..decoded_len];

    // X.509 structure (simplified):
    // SEQUENCE (certificate)
    //   SEQUENCE (tbsCertificate)
    //     [0] EXPLICIT version (optional)
    //     INTEGER serialNumber
    //     SEQUENCE signature
    //     SEQUENCE issuer
    //     SEQUENCE validity
    //       UTCTime/GeneralizedTime notBefore
    //       UTCTime/GeneralizedTime notAfter
    //     ...

    // parse outer SEQUENCE
    var pos: usize = 0;
    const outer = try parseAsn1Tag(der, &pos);
    if (outer.tag != 0x30) return error.InvalidAsn1;

    // parse tbsCertificate SEQUENCE
    const tbs = try parseAsn1Tag(der, &pos);
    if (tbs.tag != 0x30) return error.InvalidAsn1;

    // outer and tbs lengths are consumed implicitly as we walk the fields
    _ = outer.length;
    _ = tbs.length;

    // skip version if present (context tag [0])
    if (pos < der.len and der[pos] == 0xA0) {
        _ = try parseAsn1Tag(der, &pos);
        // skip the version content
        const version_inner = try parseAsn1Tag(der, &pos);
        pos += version_inner.length;
    }

    // skip serialNumber (INTEGER)
    const serial = try parseAsn1Tag(der, &pos);
    if (serial.tag != 0x02) return error.InvalidAsn1;
    pos += serial.length;

    // skip signature algorithm (SEQUENCE)
    const sig_alg = try parseAsn1Tag(der, &pos);
    if (sig_alg.tag != 0x30) return error.InvalidAsn1;
    pos += sig_alg.length;

    // skip issuer (SEQUENCE)
    const issuer = try parseAsn1Tag(der, &pos);
    if (issuer.tag != 0x30) return error.InvalidAsn1;
    pos += issuer.length;

    // parse validity SEQUENCE
    const validity = try parseAsn1Tag(der, &pos);
    if (validity.tag != 0x30) return error.InvalidAsn1;
    _ = validity.length;

    // skip notBefore
    const not_before = try parseAsn1Tag(der, &pos);
    pos += not_before.length;

    // parse notAfter
    const not_after_tag = try parseAsn1Tag(der, &pos);
    if (pos + not_after_tag.length > der.len) return error.InvalidAsn1;

    const time_bytes = der[pos .. pos + not_after_tag.length];

    if (not_after_tag.tag == 0x17) {
        // UTCTime: YYMMDDHHMMSSZ
        return parseUtcTime(time_bytes);
    } else if (not_after_tag.tag == 0x18) {
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        return parseGeneralizedTime(time_bytes);
    }

    return error.UnsupportedTimeFormat;
}

const Asn1Header = struct {
    tag: u8,
    length: usize,
};

fn parseAsn1Tag(data: []const u8, pos: *usize) !Asn1Header {
    if (pos.* >= data.len) return error.InvalidAsn1;

    const tag = data[pos.*];
    pos.* += 1;

    if (pos.* >= data.len) return error.InvalidAsn1;

    var length: usize = 0;
    const len_byte = data[pos.*];
    pos.* += 1;

    if (len_byte & 0x80 == 0) {
        // short form
        length = len_byte;
    } else {
        // long form
        const num_bytes = len_byte & 0x7F;
        if (num_bytes > 4 or num_bytes == 0) return error.InvalidAsn1;
        for (0..num_bytes) |_| {
            if (pos.* >= data.len) return error.InvalidAsn1;
            length = (length << 8) | data[pos.*];
            pos.* += 1;
        }
    }

    return .{ .tag = tag, .length = length };
}

/// parse UTCTime (YYMMDDHHMMSSZ) to unix timestamp.
fn parseUtcTime(data: []const u8) !i64 {
    if (data.len < 13) return error.InvalidTime;

    const yy = parseDigits(data[0..2]) orelse return error.InvalidTime;
    const mm = parseDigits(data[2..4]) orelse return error.InvalidTime;
    const dd = parseDigits(data[4..6]) orelse return error.InvalidTime;
    const hh = parseDigits(data[6..8]) orelse return error.InvalidTime;
    const min = parseDigits(data[8..10]) orelse return error.InvalidTime;
    const ss = parseDigits(data[10..12]) orelse return error.InvalidTime;

    // RFC 5280: YY >= 50 means 19YY, YY < 50 means 20YY
    const year: u16 = if (yy >= 50) 1900 + yy else 2000 + yy;

    return dateToTimestamp(year, mm, dd, hh, min, ss);
}

/// parse GeneralizedTime (YYYYMMDDHHMMSSZ) to unix timestamp.
fn parseGeneralizedTime(data: []const u8) !i64 {
    if (data.len < 15) return error.InvalidTime;

    const yyyy_hi = parseDigits(data[0..2]) orelse return error.InvalidTime;
    const yyyy_lo = parseDigits(data[2..4]) orelse return error.InvalidTime;
    const year: u16 = yyyy_hi * 100 + yyyy_lo;
    const mm = parseDigits(data[4..6]) orelse return error.InvalidTime;
    const dd = parseDigits(data[6..8]) orelse return error.InvalidTime;
    const hh = parseDigits(data[8..10]) orelse return error.InvalidTime;
    const min = parseDigits(data[10..12]) orelse return error.InvalidTime;
    const ss = parseDigits(data[12..14]) orelse return error.InvalidTime;

    return dateToTimestamp(year, mm, dd, hh, min, ss);
}

fn parseDigits(data: []const u8) ?u16 {
    if (data.len != 2) return null;
    const hi = std.fmt.charToDigit(data[0], 10) catch return null;
    const lo = std.fmt.charToDigit(data[1], 10) catch return null;
    return @as(u16, hi) * 10 + lo;
}

/// convert a date to unix timestamp. basic implementation — no leap second
/// handling (close enough for certificate expiry checks).
fn dateToTimestamp(year: u16, month: u16, day: u16, hour: u16, minute: u16, second: u16) !i64 {
    if (month < 1 or month > 12) return error.InvalidTime;
    if (day < 1 or day > 31) return error.InvalidTime;
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidTime;

    // days from epoch (1970-01-01) to start of year
    var days: i64 = 0;
    var y: u16 = 1970;
    while (y < year) : (y += 1) {
        days += if (isLeapYear(y)) @as(i64, 366) else @as(i64, 365);
    }

    // days from start of year to start of month
    const month_days = [_]u16{ 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30 };
    var m: u16 = 1;
    while (m < month) : (m += 1) {
        days += month_days[m];
        if (m == 2 and isLeapYear(year)) days += 1;
    }

    days += @as(i64, day) - 1;

    return days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + @as(i64, second);
}

fn isLeapYear(year: u16) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}

// -- utility --

fn secureZero(buf: []u8) void {
    std.crypto.secureZero(u8, buf);
}

// -- key management (shared with secrets store) --

const KeyError = error{
    HomeDirNotFound,
    PathTooLong,
    KeyCreateFailed,
    KeyLoadFailed,
};

fn loadOrCreateKey() KeyError![key_length]u8 {
    var path_buf: [paths.max_path]u8 = undefined;
    const key_path = paths.dataPath(&path_buf, "secrets.key") catch |err| return switch (err) {
        error.HomeDirNotFound => KeyError.HomeDirNotFound,
        error.PathTooLong => KeyError.PathTooLong,
    };

    paths.ensureDataDir("") catch return KeyError.HomeDirNotFound;

    if (readKeyFile(key_path)) |key| {
        return key;
    }

    var key: [key_length]u8 = undefined;
    std.crypto.random.bytes(&key);

    saveKeyFile(key_path, &key) catch return KeyError.KeyCreateFailed;
    return key;
}

fn readKeyFile(path: []const u8) ?[key_length]u8 {
    const file = std.fs.cwd().openFile(path, .{}) catch return null;
    defer file.close();

    var key: [key_length]u8 = undefined;
    const n = file.readAll(&key) catch return null;
    if (n != key_length) return null;

    return key;
}

fn saveKeyFile(path: []const u8, key: *const [key_length]u8) !void {
    const file = std.fs.cwd().createFile(path, .{ .mode = 0o600 }) catch
        return error.KeyCreateFailed;
    defer file.close();

    file.writeAll(key) catch return error.KeyCreateFailed;
}

// -- tests --

test "install and get round-trip" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var cs = try CertStore.initWithKey(&db, alloc, key);

    const cert_pem = @embedFile("testdata/cert.pem");
    const key_pem = "-----BEGIN PRIVATE KEY-----\nfake-key-data\n-----END PRIVATE KEY-----\n";

    try cs.install("example.com", cert_pem, key_pem, "manual");

    const result = try cs.get("example.com");
    defer {
        alloc.free(result.cert_pem);
        secureZero(result.key_pem);
        alloc.free(result.key_pem);
    }

    try std.testing.expectEqualStrings(cert_pem, result.cert_pem);
    try std.testing.expectEqualStrings(key_pem, result.key_pem);
}

test "get nonexistent returns not found" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var cs = try CertStore.initWithKey(&db, alloc, key);

    const result = cs.get("nonexistent.com");
    try std.testing.expectError(CertError.NotFound, result);
}

test "remove certificate" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var cs = try CertStore.initWithKey(&db, alloc, key);

    const cert_pem = @embedFile("testdata/cert.pem");
    try cs.install("example.com", cert_pem, "key-data", "manual");
    try cs.remove("example.com");

    const result = cs.get("example.com");
    try std.testing.expectError(CertError.NotFound, result);
}

test "remove nonexistent returns not found" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var cs = try CertStore.initWithKey(&db, alloc, key);

    const result = cs.remove("ghost.com");
    try std.testing.expectError(CertError.NotFound, result);
}

test "list certificates sorted" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var cs = try CertStore.initWithKey(&db, alloc, key);

    const cert_pem = @embedFile("testdata/cert.pem");
    try cs.install("zebra.com", cert_pem, "k1", "manual");
    try cs.install("alpha.com", cert_pem, "k2", "acme");
    try cs.install("middle.com", cert_pem, "k3", "manual");

    var certs = try cs.list();
    defer {
        for (certs.items) |c| c.deinit(alloc);
        certs.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 3), certs.items.len);
    try std.testing.expectEqualStrings("alpha.com", certs.items[0].domain);
    try std.testing.expectEqualStrings("middle.com", certs.items[1].domain);
    try std.testing.expectEqualStrings("zebra.com", certs.items[2].domain);
    try std.testing.expectEqualStrings("acme", certs.items[0].source);
}

test "list empty" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var cs = try CertStore.initWithKey(&db, alloc, key);

    var certs = try cs.list();
    defer certs.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 0), certs.items.len);
}

test "encrypted key not readable without correct key" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var cs = try CertStore.initWithKey(&db, alloc, key);

    const cert_pem = @embedFile("testdata/cert.pem");
    try cs.install("example.com", cert_pem, "secret-key-data", "manual");

    // try to read with a different key
    const wrong_key = [_]u8{0x99} ** key_length;
    var cs2 = try CertStore.initWithKey(&db, alloc, wrong_key);

    const result = cs2.get("example.com");
    try std.testing.expectError(CertError.DecryptionFailed, result);
}

test "install overwrites existing" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var cs = try CertStore.initWithKey(&db, alloc, key);

    const cert_pem = @embedFile("testdata/cert.pem");
    try cs.install("example.com", cert_pem, "old-key", "manual");
    try cs.install("example.com", cert_pem, "new-key", "acme");

    const result = try cs.get("example.com");
    defer {
        alloc.free(result.cert_pem);
        secureZero(result.key_pem);
        alloc.free(result.key_pem);
    }

    try std.testing.expectEqualStrings("new-key", result.key_pem);
}

test "parseExpiryFromPem with test cert" {
    const cert_pem = @embedFile("testdata/cert.pem");
    const expiry = try parseExpiryFromPem(cert_pem);

    // the test cert should have a valid expiry in the future or past —
    // just verify we got a reasonable timestamp (after 2020)
    const year_2020: i64 = 1577836800;
    try std.testing.expect(expiry > year_2020);
}

test "needsRenewal checks expiry threshold" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var cs = try CertStore.initWithKey(&db, alloc, key);

    const cert_pem = @embedFile("testdata/cert.pem");
    try cs.install("example.com", cert_pem, "key", "manual");

    // the test cert expires in 2035 — so 30 days threshold should return false
    const needs = try cs.needsRenewal("example.com", 30);
    try std.testing.expect(!needs);

    // a threshold of 999999 days (way past expiry) should return true
    const needs_far = try cs.needsRenewal("example.com", 999999);
    try std.testing.expect(needs_far);
}

test "needsRenewal nonexistent returns not found" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var cs = try CertStore.initWithKey(&db, alloc, key);

    const result = cs.needsRenewal("ghost.com", 30);
    try std.testing.expectError(CertError.NotFound, result);
}

test "listExpiringSoon with distant expiry" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var cs = try CertStore.initWithKey(&db, alloc, key);

    const cert_pem = @embedFile("testdata/cert.pem");
    try cs.install("example.com", cert_pem, "key", "manual");

    // cert expires in 2035, 30 days should return empty
    var expiring = try cs.listExpiringSoon(30);
    defer {
        for (expiring.items) |d| alloc.free(d);
        expiring.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 0), expiring.items.len);
}

test "parseUtcTime" {
    // 250101120000Z = Jan 1, 2025, 12:00:00 UTC
    const result = try parseUtcTime("250101120000Z");
    // 2025-01-01 12:00:00 UTC
    const expected: i64 = 1735732800;
    try std.testing.expectEqual(expected, result);
}

test "parseGeneralizedTime" {
    // 20350101120000Z = Jan 1, 2035, 12:00:00 UTC
    const result = try parseGeneralizedTime("20350101120000Z");
    const expected: i64 = 2051265600;
    try std.testing.expectEqual(expected, result);
}

test "parseAsn1Tag short form" {
    const data = [_]u8{ 0x30, 0x0A }; // SEQUENCE, length 10
    var pos: usize = 0;
    const header = try parseAsn1Tag(&data, &pos);
    try std.testing.expectEqual(@as(u8, 0x30), header.tag);
    try std.testing.expectEqual(@as(usize, 10), header.length);
    try std.testing.expectEqual(@as(usize, 2), pos);
}

test "parseAsn1Tag long form" {
    const data = [_]u8{ 0x30, 0x82, 0x01, 0x22 }; // SEQUENCE, length 290
    var pos: usize = 0;
    const header = try parseAsn1Tag(&data, &pos);
    try std.testing.expectEqual(@as(u8, 0x30), header.tag);
    try std.testing.expectEqual(@as(usize, 290), header.length);
    try std.testing.expectEqual(@as(usize, 4), pos);
}

test "dateToTimestamp unix epoch" {
    const ts = try dateToTimestamp(1970, 1, 1, 0, 0, 0);
    try std.testing.expectEqual(@as(i64, 0), ts);
}

test "dateToTimestamp known date" {
    // 2025-06-15 10:30:00 UTC
    const ts = try dateToTimestamp(2025, 6, 15, 10, 30, 0);
    // verify it's reasonable (after 2025-01-01)
    try std.testing.expect(ts > 1735689600);
    try std.testing.expect(ts < 1768225600);
}

test "isLeapYear" {
    try std.testing.expect(isLeapYear(2000)); // divisible by 400
    try std.testing.expect(isLeapYear(2024)); // divisible by 4, not 100
    try std.testing.expect(!isLeapYear(1900)); // divisible by 100, not 400
    try std.testing.expect(!isLeapYear(2023)); // not divisible by 4
}
