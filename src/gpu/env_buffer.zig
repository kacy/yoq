const std = @import("std");

pub const NullEnvWriter = struct {
    buf: []u8,
    pos: usize = 0,

    pub fn init(buf: []u8) NullEnvWriter {
        return .{ .buf = buf };
    }

    pub fn writeEntry(self: *NullEnvWriter, name: []const u8, value: []const u8) !void {
        try self.writeLiteral(name);
        try self.writeLiteral("=");
        try self.writeLiteral(value);
        try self.finishEntry();
    }

    pub fn writeLiteralEntry(self: *NullEnvWriter, entry: []const u8) !void {
        try self.writeLiteral(entry);
        try self.finishEntry();
    }

    pub fn writeEntryValueFmt(
        self: *NullEnvWriter,
        name: []const u8,
        comptime fmt: []const u8,
        args: anytype,
    ) !void {
        try self.writeLiteral(name);
        try self.writeLiteral("=");
        const written = std.fmt.bufPrint(self.remaining(), fmt, args) catch return error.BufferTooSmall;
        self.pos += written.len;
        try self.finishEntry();
    }

    pub fn finish(self: *const NullEnvWriter) []const u8 {
        return self.buf[0..self.pos];
    }

    fn writeLiteral(self: *NullEnvWriter, value: []const u8) !void {
        if (value.len > self.remaining().len) return error.BufferTooSmall;
        @memcpy(self.buf[self.pos..][0..value.len], value);
        self.pos += value.len;
    }

    fn finishEntry(self: *NullEnvWriter) !void {
        if (self.pos >= self.buf.len) return error.BufferTooSmall;
        self.buf[self.pos] = 0;
        self.pos += 1;
    }

    fn remaining(self: *NullEnvWriter) []u8 {
        return self.buf[self.pos..];
    }
};

test "NullEnvWriter writes null-separated entries" {
    var buf: [64]u8 = undefined;
    var writer = NullEnvWriter.init(&buf);
    try writer.writeEntry("FOO", "bar");
    try writer.writeLiteralEntry("BAZ=qux");

    const out = writer.finish();
    try std.testing.expectEqualStrings("FOO=bar", out[0.."FOO=bar".len]);
    try std.testing.expectEqual(@as(u8, 0), out["FOO=bar".len]);
    try std.testing.expect(std.mem.indexOf(u8, out, "BAZ=qux") != null);
}

test "NullEnvWriter returns BufferTooSmall" {
    var buf: [8]u8 = undefined;
    var writer = NullEnvWriter.init(&buf);
    try std.testing.expectError(error.BufferTooSmall, writer.writeEntry("TOO_LONG", "value"));
}

test "NullEnvWriter writes formatted values" {
    var buf: [64]u8 = undefined;
    var writer = NullEnvWriter.init(&buf);
    try writer.writeEntryValueFmt("PORT", "{d}", .{29500});

    const out = writer.finish();
    try std.testing.expectEqualStrings("PORT=29500", out[0.."PORT=29500".len]);
    try std.testing.expectEqual(@as(u8, 0), out["PORT=29500".len]);
}
