const std = @import("std");
const common = @import("common.zig");

pub const ClientHelloInfo = struct {
    client_random: [32]u8,
    session_id: []const u8,
    has_aes_256_gcm: bool,
    x25519_key_share: ?[32]u8,
    supported_versions_has_tls13: bool,
    offers_h2_alpn: bool,
    offers_http11_alpn: bool,
};

pub fn parseClientHelloFields(msg: []const u8) common.HandshakeError!ClientHelloInfo {
    var pos: usize = 0;

    if (pos + 2 > msg.len) return common.HandshakeError.InvalidClientHello;
    pos += 2;

    if (pos + 32 > msg.len) return common.HandshakeError.InvalidClientHello;
    var client_random: [32]u8 = undefined;
    @memcpy(&client_random, msg[pos .. pos + 32]);
    pos += 32;

    if (pos >= msg.len) return common.HandshakeError.InvalidClientHello;
    const sid_len = msg[pos];
    pos += 1;
    if (pos + sid_len > msg.len) return common.HandshakeError.InvalidClientHello;
    const session_id = msg[pos .. pos + sid_len];
    pos += sid_len;

    if (pos + 2 > msg.len) return common.HandshakeError.InvalidClientHello;
    const cs_len = common.readU16(msg[pos..]);
    pos += 2;
    if (pos + cs_len > msg.len) return common.HandshakeError.InvalidClientHello;
    var has_aes_256_gcm = false;
    var cs_pos: usize = pos;
    while (cs_pos + 2 <= pos + cs_len) : (cs_pos += 2) {
        if (common.readU16(msg[cs_pos..]) == common.cipher_suite_aes_256_gcm) {
            has_aes_256_gcm = true;
        }
    }
    pos += cs_len;

    if (pos >= msg.len) return common.HandshakeError.InvalidClientHello;
    const comp_len = msg[pos];
    pos += 1;
    if (pos + comp_len > msg.len) return common.HandshakeError.InvalidClientHello;
    pos += comp_len;

    var x25519_key_share: ?[32]u8 = null;
    var has_tls13 = false;
    var offers_h2_alpn = false;
    var offers_http11_alpn = false;

    if (pos + 2 <= msg.len) {
        const ext_len = common.readU16(msg[pos..]);
        pos += 2;
        const ext_end = @min(pos + ext_len, msg.len);

        while (pos + 4 <= ext_end) {
            const ext_type = common.readU16(msg[pos..]);
            const ext_data_len = common.readU16(msg[pos + 2 ..]);
            pos += 4;
            if (pos + ext_data_len > ext_end) break;

            if (ext_type == 0x002B) {
                has_tls13 = parseSupportedVersions(msg[pos .. pos + ext_data_len]);
            } else if (ext_type == 0x0033) {
                x25519_key_share = parseKeyShare(msg[pos .. pos + ext_data_len]);
            } else if (ext_type == 0x0010) {
                const alpn = parseAlpn(msg[pos .. pos + ext_data_len]);
                offers_h2_alpn = alpn.h2;
                offers_http11_alpn = alpn.http11;
            }

            pos += ext_data_len;
        }
    }

    return .{
        .client_random = client_random,
        .session_id = session_id,
        .has_aes_256_gcm = has_aes_256_gcm,
        .x25519_key_share = x25519_key_share,
        .supported_versions_has_tls13 = has_tls13,
        .offers_h2_alpn = offers_h2_alpn,
        .offers_http11_alpn = offers_http11_alpn,
    };
}

fn parseSupportedVersions(data: []const u8) bool {
    if (data.len < 1) return false;
    const list_len = data[0];
    var pos: usize = 1;
    while (pos + 2 <= 1 + @as(usize, list_len) and pos + 2 <= data.len) : (pos += 2) {
        if (common.readU16(data[pos..]) == 0x0304) return true;
    }
    return false;
}

fn parseKeyShare(data: []const u8) ?[32]u8 {
    if (data.len < 2) return null;
    const list_len = common.readU16(data[0..]);
    var pos: usize = 2;
    const end = @min(2 + list_len, data.len);
    while (pos + 4 <= end) {
        const group = common.readU16(data[pos..]);
        const key_len = common.readU16(data[pos + 2 ..]);
        pos += 4;
        if (pos + key_len > end) break;
        if (group == 0x001D and key_len == 32) {
            var key: [32]u8 = undefined;
            @memcpy(&key, data[pos .. pos + 32]);
            return key;
        }
        pos += key_len;
    }
    return null;
}

fn parseAlpn(data: []const u8) struct { h2: bool, http11: bool } {
    if (data.len < 2) return .{ .h2 = false, .http11 = false };

    const list_len = common.readU16(data[0..]);
    var pos: usize = 2;
    const end = @min(2 + list_len, data.len);
    var offers_h2 = false;
    var offers_http11 = false;

    while (pos < end) {
        const proto_len = data[pos];
        pos += 1;
        if (pos + proto_len > end) break;
        const proto = data[pos .. pos + proto_len];
        if (std.mem.eql(u8, proto, "h2")) offers_h2 = true;
        if (std.mem.eql(u8, proto, "http/1.1")) offers_http11 = true;
        pos += proto_len;
    }

    return .{ .h2 = offers_h2, .http11 = offers_http11 };
}
