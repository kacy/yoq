const std = @import("std");

pub const Digest = struct {
    hash: [32]u8,

    pub fn string(self: Digest, buf: *[71]u8) []const u8 {
        const result = std.fmt.bufPrint(buf, "sha256:{s}", .{self.hex()}) catch unreachable;
        return result;
    }

    pub fn hex(self: Digest) [64]u8 {
        return std.fmt.bytesToHex(self.hash, .lower);
    }

    pub fn parse(s: []const u8) ?Digest {
        const prefix = "sha256:";
        if (!std.mem.startsWith(u8, s, prefix)) return null;
        return fromHex(s[prefix.len..]);
    }

    pub fn fromHex(hex_str: []const u8) ?Digest {
        if (hex_str.len != 64) return null;

        var hash: [32]u8 = undefined;
        for (0..32) |i| {
            hash[i] = std.fmt.parseInt(u8, hex_str[i * 2 ..][0..2], 16) catch return null;
        }
        return Digest{ .hash = hash };
    }

    pub fn eql(self: Digest, other: Digest) bool {
        return std.mem.eql(u8, &self.hash, &other.hash);
    }
};

pub fn computeDigest(data: []const u8) Digest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    return Digest{ .hash = hasher.finalResult() };
}
