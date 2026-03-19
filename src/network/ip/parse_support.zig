const std = @import("std");

pub fn formatIp(ip: [4]u8, buf: *[16]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch "0.0.0.0";
}

pub fn parseIp(str: []const u8) ?[4]u8 {
    var ip: [4]u8 = undefined;
    var octet_idx: usize = 0;
    var start: usize = 0;

    for (str, 0..) |c, i| {
        if (c == '.') {
            if (octet_idx >= 3) return null;
            ip[octet_idx] = std.fmt.parseInt(u8, str[start..i], 10) catch return null;
            octet_idx += 1;
            start = i + 1;
        }
    }

    if (octet_idx != 3) return null;
    ip[3] = std.fmt.parseInt(u8, str[start..], 10) catch return null;
    return ip;
}

pub fn incrementIp(ip: *[4]u8) bool {
    if (ip[3] < 254) {
        ip[3] += 1;
        return true;
    }
    ip[3] = 1;
    if (ip[2] < 255) {
        ip[2] += 1;
        return true;
    }
    return false;
}

pub fn incrementWithinRange(current: *[4]u8, range_end: [4]u8) bool {
    if (std.mem.eql(u8, current, &range_end)) return false;
    if (current[3] < 254) {
        current[3] += 1;
        return true;
    }
    return false;
}
