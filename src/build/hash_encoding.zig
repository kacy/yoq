const std = @import("std");

/// Fields have explicit lengths; domains version independent build identities.
pub const Hasher = struct {
    hash: std.crypto.hash.sha2.Sha256,

    pub fn init(domain: []const u8) Hasher {
        var self = Hasher{ .hash = std.crypto.hash.sha2.Sha256.init(.{}) };
        self.bytes(domain);
        return self;
    }

    pub fn number(self: *Hasher, value: u64) void {
        var encoded: [8]u8 = undefined;
        std.mem.writeInt(u64, &encoded, value, .little);
        self.hash.update(&encoded);
    }

    pub fn bytes(self: *Hasher, value: []const u8) void {
        self.number(value.len);
        self.hash.update(value);
    }

    pub fn optional(self: *Hasher, value: ?[]const u8) void {
        self.number(if (value != null) 1 else 0);
        if (value) |present| self.bytes(present);
    }
};
