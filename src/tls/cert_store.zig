// cert_store — encrypted certificate storage
//
// this file keeps the stable public cert-store API while the
// implementation lives in smaller modules under `tls/cert_store/`.

const std = @import("std");
const sqlite = @import("sqlite");

const common = @import("cert_store/common.zig");
const key_support = @import("cert_store/key_support.zig");
const storage_runtime = @import("cert_store/storage_runtime.zig");
const x509_parse = @import("cert_store/x509_parse.zig");

pub const key_length = common.key_length;
pub const nonce_length = common.nonce_length;
pub const tag_length = common.tag_length;

pub const CertError = common.CertError;
pub const CertInfo = common.CertInfo;
pub const CertStore = storage_runtime.CertStore;
pub const parseExpiryFromPem = x509_parse.parseExpiryFromPem;

const parseUtcTime = x509_parse.parseUtcTime;
const parseGeneralizedTime = x509_parse.parseGeneralizedTime;
const parseAsn1Tag = x509_parse.parseAsn1Tag;
const dateToTimestamp = x509_parse.dateToTimestamp;
const isLeapYear = x509_parse.isLeapYear;
const secureZero = key_support.secureZero;

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

test "install overwrite preserves created_at" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const alloc = std.testing.allocator;
    const key = [_]u8{0xAB} ** key_length;
    var cs = try CertStore.initWithKey(&db, alloc, key);

    const cert_pem = @embedFile("testdata/cert.pem");
    try cs.install("example.com", cert_pem, "old-key", "manual");
    const created_at: i64 = 1234567890;
    try db.exec(
        "UPDATE certificates SET created_at = ? WHERE domain = ?;",
        .{},
        .{ created_at, "example.com" },
    );

    try cs.install("example.com", cert_pem, "new-key", "acme");

    var second = try cs.list();
    defer {
        for (second.items) |c| c.deinit(alloc);
        second.deinit(alloc);
    }

    try std.testing.expectEqual(created_at, second.items[0].created_at);
}

test "parseExpiryFromPem with test cert" {
    const cert_pem = @embedFile("testdata/cert.pem");
    const expiry = try parseExpiryFromPem(cert_pem);

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

    const needs = try cs.needsRenewal("example.com", 30);
    try std.testing.expect(!needs);

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

    var expiring = try cs.listExpiringSoon(30);
    defer {
        for (expiring.items) |d| alloc.free(d);
        expiring.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 0), expiring.items.len);
}

test "parseUtcTime" {
    const result = try parseUtcTime("250101120000Z");
    const expected: i64 = 1735732800;
    try std.testing.expectEqual(expected, result);
}

test "parseGeneralizedTime" {
    const result = try parseGeneralizedTime("20350101120000Z");
    const expected: i64 = 2051265600;
    try std.testing.expectEqual(expected, result);
}

test "parseAsn1Tag short form" {
    const data = [_]u8{ 0x30, 0x0A };
    var pos: usize = 0;
    const header = try parseAsn1Tag(&data, &pos);
    try std.testing.expectEqual(@as(u8, 0x30), header.tag);
    try std.testing.expectEqual(@as(usize, 10), header.length);
    try std.testing.expectEqual(@as(usize, 2), pos);
}

test "parseAsn1Tag long form" {
    const data = [_]u8{ 0x30, 0x82, 0x01, 0x22 };
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
    const ts = try dateToTimestamp(2025, 6, 15, 10, 30, 0);
    try std.testing.expect(ts > 1735689600);
    try std.testing.expect(ts < 1768225600);
}

test "isLeapYear" {
    try std.testing.expect(isLeapYear(2000));
    try std.testing.expect(isLeapYear(2024));
    try std.testing.expect(!isLeapYear(1900));
    try std.testing.expect(!isLeapYear(2023));
}
