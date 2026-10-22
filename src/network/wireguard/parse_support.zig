const std = @import("std");
const mem = std.mem;
const ip_mod = @import("../ip.zig");
const nl = @import("../netlink.zig");
const types = @import("types.zig");

pub fn decodeKey(encoded: []const u8) ?[32]u8 {
    if (encoded.len != types.encoded_key_len) return null;
    // the decoder requires the destination to match the decoded size. 44
    // characters without padding decode to 33 bytes and with "==" to 31,
    // so check the size before decoding into the fixed buffer.
    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(encoded) catch return null;
    if (size != 32) return null;
    var raw: [32]u8 = undefined;
    decoder.decode(&raw, encoded) catch return null;
    return raw;
}

pub fn parseEndpoint(endpoint: []const u8) ?[16]u8 {
    const colon = mem.lastIndexOfScalar(u8, endpoint, ':') orelse return null;
    if (colon == 0 or colon + 1 >= endpoint.len) return null;

    const addr = ip_mod.parseIp(endpoint[0..colon]) orelse return null;
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return null;

    var sa: [16]u8 = .{0} ** 16;
    sa[0] = nl.AF.INET;
    sa[2] = @intCast(port >> 8);
    sa[3] = @intCast(port & 0xff);
    sa[4] = addr[0];
    sa[5] = addr[1];
    sa[6] = addr[2];
    sa[7] = addr[3];
    return sa;
}

pub fn parseCidr(cidr: []const u8) ?types.ParsedCidr {
    const slash = mem.indexOfScalar(u8, cidr, '/') orelse return null;
    if (slash == 0 or slash + 1 >= cidr.len) return null;

    const prefix = std.fmt.parseInt(u8, cidr[slash + 1 ..], 10) catch return null;
    if (prefix > 32) return null;

    const addr = ip_mod.parseIp(cidr[0..slash]) orelse return null;
    return .{ .addr = addr, .prefix = prefix };
}
