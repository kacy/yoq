const std = @import("std");

/// CPU lists are values so copied resource configurations do not borrow argv.
pub const CpuSet = struct {
    buffer: [512]u8 = undefined,
    len: u16 = 0,

    pub fn parse(value: []const u8) !CpuSet {
        if (value.len == 0 or value.len > 512) return error.InvalidLimit;
        var ranges = std.mem.splitScalar(u8, value, ',');
        while (ranges.next()) |range| _ = try parseRange(range);
        var result: CpuSet = .{ .len = @intCast(value.len) };
        @memcpy(result.buffer[0..value.len], value);
        return result;
    }

    pub fn text(self: *const CpuSet) []const u8 {
        return self.buffer[0..self.len];
    }

    pub fn isSubsetOf(self: *const CpuSet, available: *const CpuSet) bool {
        var requested = std.mem.splitScalar(u8, self.text(), ',');
        while (requested.next()) |part| {
            const range = parseRange(part) catch return false;
            var next = range.first;
            while (next <= range.last) {
                var covered_until: ?u32 = null;
                var allowed = std.mem.splitScalar(u8, available.text(), ',');
                while (allowed.next()) |allowed_part| {
                    const span = parseRange(allowed_part) catch return false;
                    if (span.first <= next and span.last >= next)
                        covered_until = @max(covered_until orelse span.last, span.last);
                }
                next = (covered_until orelse return false) + 1;
            }
        }
        return true;
    }
};

fn parseRange(value: []const u8) !struct { first: u32, last: u32 } {
    if (value.len == 0) return error.InvalidLimit;
    for (value) |char| if (!std.ascii.isDigit(char) and char != '-') return error.InvalidLimit;
    var parts = std.mem.splitScalar(u8, value, '-');
    const first = std.fmt.parseUnsigned(u20, parts.next().?, 10) catch return error.InvalidLimit;
    const last = if (parts.next()) |end| std.fmt.parseUnsigned(u20, end, 10) catch return error.InvalidLimit else first;
    if (parts.next() != null or first > last) return error.InvalidLimit;
    return .{ .first = first, .last = last };
}

test "cpuset lists validate ranges and reject unavailable cpus" {
    const available = try CpuSet.parse("0-3,8,10-12");
    const allowed = try CpuSet.parse("12,0-2,8,10-11");
    try std.testing.expect(allowed.isSubsetOf(&available));
    const gap = try CpuSet.parse("2-8");
    try std.testing.expect(!gap.isSubsetOf(&available));
    const adjacent = try CpuSet.parse("0-1,2-3");
    const merged = try CpuSet.parse("0-3");
    try std.testing.expect(merged.isSubsetOf(&adjacent));
    for ([_][]const u8{ "", "1,", ",1", "2-1", "-1", "1--2", "1-", "1 2", "1-2-3", "99999999999" }) |value|
        try std.testing.expectError(error.InvalidLimit, CpuSet.parse(value));
}
