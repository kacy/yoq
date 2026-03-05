// sni — extract server name indication from TLS ClientHello
//
// pure parsing, no I/O. reads the SNI extension from a raw ClientHello
// message to determine which domain the client wants to connect to.
// this is used by the TLS reverse proxy to look up the right certificate
// before completing the handshake.
//
// references:
//   RFC 8446 §4.1.2 (ClientHello)
//   RFC 6066 §3 (SNI extension)

const std = @import("std");

pub const SniError = error{
    BufferTooShort,
    NotATlsRecord,
    NotAClientHello,
    InvalidLength,
    NoSniExtension,
};

/// extract the server name from a TLS ClientHello message.
/// `data` should contain the raw bytes starting from the TLS record header.
/// returns a slice into `data` — no allocation needed.
pub fn extractSni(data: []const u8) SniError![]const u8 {
    // TLS record header: type(1) + version(2) + length(2) = 5 bytes
    if (data.len < 5) return SniError.BufferTooShort;

    // content type 22 = handshake
    if (data[0] != 22) return SniError.NotATlsRecord;

    const record_len = readU16(data[3..5]);
    if (data.len < 5 + record_len) return SniError.BufferTooShort;

    const handshake = data[5 .. 5 + record_len];

    // handshake header: type(1) + length(3) = 4 bytes
    if (handshake.len < 4) return SniError.BufferTooShort;

    // handshake type 1 = ClientHello
    if (handshake[0] != 1) return SniError.NotAClientHello;

    const msg_len = readU24(handshake[1..4]);
    if (handshake.len < 4 + msg_len) return SniError.BufferTooShort;

    const msg = handshake[4 .. 4 + msg_len];
    return parseClientHello(msg);
}

/// walk the ClientHello fields to find the SNI extension.
fn parseClientHello(msg: []const u8) SniError![]const u8 {
    var pos: usize = 0;

    // client version (2 bytes) — ignored in TLS 1.3
    pos = skip(pos, 2, msg.len) orelse return SniError.BufferTooShort;

    // client random (32 bytes)
    pos = skip(pos, 32, msg.len) orelse return SniError.BufferTooShort;

    // session ID (variable: 1 byte length + data)
    if (pos >= msg.len) return SniError.BufferTooShort;
    const session_id_len = msg[pos];
    pos = skip(pos, 1 + @as(usize, session_id_len), msg.len) orelse return SniError.BufferTooShort;

    // cipher suites (variable: 2 byte length + data)
    if (pos + 2 > msg.len) return SniError.BufferTooShort;
    const cipher_suites_len = readU16(msg[pos .. pos + 2]);
    pos = skip(pos, 2 + cipher_suites_len, msg.len) orelse return SniError.BufferTooShort;

    // compression methods (variable: 1 byte length + data)
    if (pos >= msg.len) return SniError.BufferTooShort;
    const compression_len = msg[pos];
    pos = skip(pos, 1 + @as(usize, compression_len), msg.len) orelse return SniError.BufferTooShort;

    // extensions (variable: 2 byte total length + extension list)
    if (pos + 2 > msg.len) return SniError.BufferTooShort;
    const extensions_len = readU16(msg[pos .. pos + 2]);
    pos += 2;

    if (pos + extensions_len > msg.len) return SniError.BufferTooShort;
    const extensions_end = pos + extensions_len;

    // walk extensions looking for SNI (type 0x0000)
    while (pos + 4 <= extensions_end) {
        const ext_type = readU16(msg[pos .. pos + 2]);
        const ext_len = readU16(msg[pos + 2 .. pos + 4]);
        pos += 4;

        if (pos + ext_len > extensions_end) return SniError.InvalidLength;

        if (ext_type == 0x0000) {
            // SNI extension found — parse the server name list
            return parseSniExtension(msg[pos .. pos + ext_len]);
        }

        pos += ext_len;
    }

    return SniError.NoSniExtension;
}

/// parse the SNI extension value to extract the hostname.
/// SNI extension format:
///   server_name_list_length(2)
///     name_type(1) = 0 (host_name)
///     name_length(2)
///     name(variable)
fn parseSniExtension(data: []const u8) SniError![]const u8 {
    if (data.len < 2) return SniError.InvalidLength;

    const list_len = readU16(data[0..2]);
    if (data.len < 2 + list_len) return SniError.InvalidLength;

    var pos: usize = 2;
    const list_end = 2 + list_len;

    while (pos + 3 <= list_end) {
        const name_type = data[pos];
        const name_len = readU16(data[pos + 1 .. pos + 3]);
        pos += 3;

        if (pos + name_len > list_end) return SniError.InvalidLength;

        // name_type 0 = host_name
        if (name_type == 0 and name_len > 0) {
            return data[pos .. pos + name_len];
        }

        pos += name_len;
    }

    return SniError.NoSniExtension;
}

// -- helpers --

fn readU16(data: []const u8) usize {
    return (@as(usize, data[0]) << 8) | @as(usize, data[1]);
}

fn readU24(data: []const u8) usize {
    return (@as(usize, data[0]) << 16) | (@as(usize, data[1]) << 8) | @as(usize, data[2]);
}

/// advance position by `n` bytes, returning null if out of bounds.
fn skip(pos: usize, n: usize, limit: usize) ?usize {
    const new_pos = pos + n;
    if (new_pos > limit) return null;
    return new_pos;
}

// -- tests --

test "extract SNI from minimal ClientHello" {
    // construct a minimal ClientHello with SNI extension
    const sni_name = "example.com";
    const hello = buildTestClientHello(sni_name);
    const result = try extractSni(&hello);
    try std.testing.expectEqualStrings("example.com", result);
}

test "extract SNI from ClientHello with multiple extensions" {
    // SNI should be found even when other extensions come first
    const sni_name = "test.example.org";
    const hello = buildTestClientHelloWithExtraExtensions(sni_name);
    const result = try extractSni(&hello);
    try std.testing.expectEqualStrings("test.example.org", result);
}

test "not a TLS record" {
    const data = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04 };
    try std.testing.expectError(SniError.NotATlsRecord, extractSni(&data));
}

test "not a ClientHello" {
    // TLS record with handshake type 2 (ServerHello) instead of 1
    var data = buildTestClientHello("x.com");
    data[5] = 2; // change handshake type
    try std.testing.expectError(SniError.NotAClientHello, extractSni(&data));
}

test "buffer too short" {
    const data = [_]u8{ 22, 0x03, 0x01 };
    try std.testing.expectError(SniError.BufferTooShort, extractSni(&data));
}

test "no SNI extension" {
    const hello = buildTestClientHelloNoSni();
    try std.testing.expectError(SniError.NoSniExtension, extractSni(&hello));
}

test "readU16" {
    try std.testing.expectEqual(@as(usize, 0x0301), readU16(&[_]u8{ 0x03, 0x01 }));
    try std.testing.expectEqual(@as(usize, 0), readU16(&[_]u8{ 0x00, 0x00 }));
    try std.testing.expectEqual(@as(usize, 0xFFFF), readU16(&[_]u8{ 0xFF, 0xFF }));
}

test "readU24" {
    try std.testing.expectEqual(@as(usize, 0x010203), readU24(&[_]u8{ 0x01, 0x02, 0x03 }));
}

// -- test helpers --
//
// TLS ClientHello structure:
//   record header:  type(1) + version(2) + length(2)          = 5
//   handshake:      type(1) + length(3)                       = 4
//   hello body:
//     version:      2
//     random:       32
//     session_id:   len(1)                                    = 1
//     ciphers:      len(2) + suite(2)                         = 4
//     compression:  len(1) + null_method(1)                   = 2
//     extensions:   len(2) + ext_data                         = 2 + ext_data

/// build a minimal TLS ClientHello record with the given SNI.
fn buildTestClientHello(comptime hostname: []const u8) [61 + hostname.len]u8 {
    // SNI extension: type(2) + len(2) + list_len(2) + name_type(1) + name_len(2) + name
    const sni_data_len = hostname.len + 5;
    const extensions_len = 4 + sni_data_len; // type(2) + len(2) + data
    const body_len = 2 + 32 + 1 + 4 + 2 + 2 + extensions_len;
    const hs_len = 4 + body_len;

    var buf: [5 + hs_len]u8 = undefined;
    var p: usize = 0;

    // record header
    buf[p] = 22;
    p += 1;
    writeU16Be(buf[p..], 0x0301);
    p += 2;
    writeU16Be(buf[p..], @intCast(hs_len));
    p += 2;

    // handshake header
    buf[p] = 1;
    p += 1;
    writeU24Be(buf[p..], @intCast(body_len));
    p += 3;

    // version + random
    writeU16Be(buf[p..], 0x0303);
    p += 2;
    @memset(buf[p .. p + 32], 0);
    p += 32;

    // session ID (empty)
    buf[p] = 0;
    p += 1;

    // cipher suites (one: TLS_AES_256_GCM_SHA384 = 0x1302)
    writeU16Be(buf[p..], 2);
    p += 2;
    writeU16Be(buf[p..], 0x1302);
    p += 2;

    // compression methods (one: null = 0x00)
    buf[p] = 1;
    p += 1;
    buf[p] = 0;
    p += 1;

    // extensions
    writeU16Be(buf[p..], @intCast(extensions_len));
    p += 2;

    // SNI extension (type 0x0000)
    writeU16Be(buf[p..], 0x0000);
    p += 2;
    writeU16Be(buf[p..], @intCast(sni_data_len));
    p += 2;
    writeU16Be(buf[p..], @intCast(hostname.len + 3));
    p += 2;
    buf[p] = 0; // host_name type
    p += 1;
    writeU16Be(buf[p..], @intCast(hostname.len));
    p += 2;
    @memcpy(buf[p .. p + hostname.len], hostname);

    return buf;
}

/// build a ClientHello with two dummy extensions before SNI.
fn buildTestClientHelloWithExtraExtensions(comptime hostname: []const u8) [69 + hostname.len]u8 {
    const sni_data_len = hostname.len + 5;
    // two dummy extensions (4 bytes each: type+len, 0 data) + SNI
    const extensions_len = 4 + 4 + 4 + sni_data_len;
    const body_len = 2 + 32 + 1 + 4 + 2 + 2 + extensions_len;
    const hs_len = 4 + body_len;

    var buf: [5 + hs_len]u8 = undefined;
    var p: usize = 0;

    buf[p] = 22;
    p += 1;
    writeU16Be(buf[p..], 0x0301);
    p += 2;
    writeU16Be(buf[p..], @intCast(hs_len));
    p += 2;

    buf[p] = 1;
    p += 1;
    writeU24Be(buf[p..], @intCast(body_len));
    p += 3;

    writeU16Be(buf[p..], 0x0303);
    p += 2;
    @memset(buf[p .. p + 32], 0);
    p += 32;

    buf[p] = 0;
    p += 1;

    writeU16Be(buf[p..], 2);
    p += 2;
    writeU16Be(buf[p..], 0x1302);
    p += 2;

    buf[p] = 1;
    p += 1;
    buf[p] = 0;
    p += 1;

    writeU16Be(buf[p..], @intCast(extensions_len));
    p += 2;

    // dummy: supported_versions (0x002B), empty
    writeU16Be(buf[p..], 0x002B);
    p += 2;
    writeU16Be(buf[p..], 0);
    p += 2;

    // dummy: key_share (0x0033), empty
    writeU16Be(buf[p..], 0x0033);
    p += 2;
    writeU16Be(buf[p..], 0);
    p += 2;

    // SNI
    writeU16Be(buf[p..], 0x0000);
    p += 2;
    writeU16Be(buf[p..], @intCast(sni_data_len));
    p += 2;
    writeU16Be(buf[p..], @intCast(hostname.len + 3));
    p += 2;
    buf[p] = 0;
    p += 1;
    writeU16Be(buf[p..], @intCast(hostname.len));
    p += 2;
    @memcpy(buf[p .. p + hostname.len], hostname);

    return buf;
}

/// build a ClientHello with no extensions at all.
fn buildTestClientHelloNoSni() [52]u8 {
    const body_len = 2 + 32 + 1 + 4 + 2 + 2 + 0; // no extensions (but extensions length field still present)
    const hs_len = 4 + body_len;

    var buf: [5 + hs_len]u8 = undefined;
    var p: usize = 0;

    buf[p] = 22;
    p += 1;
    writeU16Be(buf[p..], 0x0301);
    p += 2;
    writeU16Be(buf[p..], @intCast(hs_len));
    p += 2;

    buf[p] = 1;
    p += 1;
    writeU24Be(buf[p..], @intCast(body_len));
    p += 3;

    writeU16Be(buf[p..], 0x0303);
    p += 2;
    @memset(buf[p .. p + 32], 0);
    p += 32;

    buf[p] = 0;
    p += 1;

    writeU16Be(buf[p..], 2);
    p += 2;
    writeU16Be(buf[p..], 0x1302);
    p += 2;

    buf[p] = 1;
    p += 1;
    buf[p] = 0;
    p += 1;

    // extensions length = 0
    writeU16Be(buf[p..], 0);

    return buf;
}

fn writeU16Be(dest: []u8, val: u16) void {
    dest[0] = @intCast(val >> 8);
    dest[1] = @intCast(val & 0xFF);
}

fn writeU24Be(dest: []u8, val: u24) void {
    dest[0] = @intCast(val >> 16);
    dest[1] = @intCast((val >> 8) & 0xFF);
    dest[2] = @intCast(val & 0xFF);
}
