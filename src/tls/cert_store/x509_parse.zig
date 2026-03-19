const std = @import("std");

pub fn parseExpiryFromPem(pem: []const u8) !i64 {
    const der = try pemToDer(pem);
    return parseExpiryFromDer(der);
}

fn pemToDer(pem: []const u8) ![]const u8 {
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";

    const begin_pos = std.mem.indexOf(u8, pem, begin_marker) orelse
        return error.InvalidPem;
    const data_start = begin_pos + begin_marker.len;

    const end_pos = std.mem.indexOfPos(u8, pem, data_start, end_marker) orelse
        return error.InvalidPem;

    return pem[data_start..end_pos];
}

fn parseExpiryFromDer(base64_data: []const u8) !i64 {
    var buf: [8192]u8 = undefined;
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
    const decoded_len = decoder.calcSizeForSlice(clean[0..clean_len]) catch
        return error.InvalidBase64;
    if (decoded_len > buf.len) return error.CertTooLarge;
    decoder.decode(&buf, clean[0..clean_len]) catch return error.InvalidBase64;

    const der = buf[0..decoded_len];

    var pos: usize = 0;
    const outer = try parseAsn1Tag(der, &pos);
    if (outer.tag != 0x30) return error.InvalidAsn1;

    const tbs = try parseAsn1Tag(der, &pos);
    if (tbs.tag != 0x30) return error.InvalidAsn1;

    _ = outer.length;
    _ = tbs.length;

    if (pos < der.len and der[pos] == 0xA0) {
        _ = try parseAsn1Tag(der, &pos);
        const version_inner = try parseAsn1Tag(der, &pos);
        pos += version_inner.length;
    }

    const serial = try parseAsn1Tag(der, &pos);
    if (serial.tag != 0x02) return error.InvalidAsn1;
    pos += serial.length;

    const sig_alg = try parseAsn1Tag(der, &pos);
    if (sig_alg.tag != 0x30) return error.InvalidAsn1;
    pos += sig_alg.length;

    const issuer = try parseAsn1Tag(der, &pos);
    if (issuer.tag != 0x30) return error.InvalidAsn1;
    pos += issuer.length;

    const validity = try parseAsn1Tag(der, &pos);
    if (validity.tag != 0x30) return error.InvalidAsn1;
    _ = validity.length;

    const not_before = try parseAsn1Tag(der, &pos);
    pos += not_before.length;

    const not_after_tag = try parseAsn1Tag(der, &pos);
    if (pos + not_after_tag.length > der.len) return error.InvalidAsn1;

    const time_bytes = der[pos .. pos + not_after_tag.length];

    if (not_after_tag.tag == 0x17) {
        return parseUtcTime(time_bytes);
    } else if (not_after_tag.tag == 0x18) {
        return parseGeneralizedTime(time_bytes);
    }

    return error.UnsupportedTimeFormat;
}

pub const Asn1Header = struct {
    tag: u8,
    length: usize,
};

pub fn parseAsn1Tag(data: []const u8, pos: *usize) !Asn1Header {
    if (pos.* >= data.len) return error.InvalidAsn1;

    const tag = data[pos.*];
    pos.* += 1;

    if (pos.* >= data.len) return error.InvalidAsn1;

    var length: usize = 0;
    const len_byte = data[pos.*];
    pos.* += 1;

    if (len_byte & 0x80 == 0) {
        length = len_byte;
    } else {
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

pub fn parseUtcTime(data: []const u8) !i64 {
    if (data.len < 13) return error.InvalidTime;

    const yy = parseDigits(data[0..2]) orelse return error.InvalidTime;
    const mm = parseDigits(data[2..4]) orelse return error.InvalidTime;
    const dd = parseDigits(data[4..6]) orelse return error.InvalidTime;
    const hh = parseDigits(data[6..8]) orelse return error.InvalidTime;
    const min = parseDigits(data[8..10]) orelse return error.InvalidTime;
    const ss = parseDigits(data[10..12]) orelse return error.InvalidTime;

    const year: u16 = if (yy >= 50) 1900 + yy else 2000 + yy;
    return dateToTimestamp(year, mm, dd, hh, min, ss);
}

pub fn parseGeneralizedTime(data: []const u8) !i64 {
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

pub fn dateToTimestamp(year: u16, month: u16, day: u16, hour: u16, minute: u16, second: u16) !i64 {
    if (month < 1 or month > 12) return error.InvalidTime;
    if (day < 1 or day > 31) return error.InvalidTime;
    if (hour > 23 or minute > 59 or second > 59) return error.InvalidTime;

    var days: i64 = 0;
    var yr: u16 = 1970;
    while (yr < year) : (yr += 1) {
        days += if (isLeapYear(yr)) @as(i64, 366) else @as(i64, 365);
    }

    const month_days = [_]u16{ 0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30 };
    var mo: u16 = 1;
    while (mo < month) : (mo += 1) {
        days += month_days[mo];
        if (mo == 2 and isLeapYear(year)) days += 1;
    }

    days += @as(i64, day) - 1;

    return days * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + @as(i64, second);
}

pub fn isLeapYear(year: u16) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}
