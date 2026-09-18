const std = @import("std");
const http2 = @import("http2.zig");
const flow = @import("http2_flow.zig");
const hpack = @import("hpack.zig");

// a split frame header can add at most eight retained bytes to the next output.
pub const max_carry = http2.frame_header_len - 1;

/// cap the backend's header-table advertisement to the request decoder's limit.
/// other frames pass through incrementally, without buffering their payloads.
pub const Rewriter = struct {
    header: [http2.frame_header_len]u8 = undefined,
    header_count: usize = 0,
    payload_left: usize = 0,
    settings: bool = false,
    entry: [6]u8 = undefined,
    entry_count: usize = 0,

    pub fn rewrite(self: *Rewriter, alloc: std.mem.Allocator, input: []const u8) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(alloc);
        var pos: usize = 0;
        while (pos < input.len) {
            if (self.header_count < self.header.len) {
                const count = @min(self.header.len - self.header_count, input.len - pos);
                @memcpy(self.header[self.header_count..][0..count], input[pos..][0..count]);
                self.header_count += count;
                pos += count;
                if (self.header_count < self.header.len) break;
                const frame = http2.parseFrameHeader(&self.header) orelse return error.InvalidFrameSequence;
                self.settings = frame.frame_type == .settings;
                if (self.settings) try flow.validateSettings(frame);
                self.payload_left = frame.length;
                try out.appendSlice(alloc, &self.header);
                if (self.payload_left == 0) {
                    self.header_count = 0;
                    continue;
                }
            }
            const available = @min(self.payload_left, input.len - pos);
            if (!self.settings) {
                try out.appendSlice(alloc, input[pos..][0..available]);
                pos += available;
                self.payload_left -= available;
            } else {
                const count = @min(self.entry.len - self.entry_count, available);
                @memcpy(self.entry[self.entry_count..][0..count], input[pos..][0..count]);
                self.entry_count += count;
                pos += count;
                self.payload_left -= count;
                if (self.entry_count == self.entry.len) {
                    const id = std.mem.readInt(u16, self.entry[0..2], .big);
                    if (id == 1) {
                        const limit = std.mem.readInt(u32, self.entry[2..6], .big);
                        std.mem.writeInt(u32, self.entry[2..6], @min(limit, hpack.dynamic_table_default_max_size), .big);
                    }
                    try out.appendSlice(alloc, &self.entry);
                    self.entry_count = 0;
                }
            }
            if (self.payload_left == 0) self.header_count = 0;
        }
        return out.toOwnedSlice(alloc);
    }
};

test "http2 compression relay caps settings across every split and preserves data" {
    const alloc = std.testing.allocator;
    const settings = try http2.buildFrame(alloc, .{ .length = 12, .frame_type = .settings, .flags = 0, .stream_id = 0 }, &.{ 0, 1, 0, 0, 0x20, 0, 0, 4, 0, 0, 0xff, 0xff });
    defer alloc.free(settings);
    const data = try http2.buildFrame(alloc, .{ .length = 6, .frame_type = .data, .flags = 1, .stream_id = 3 }, &.{ 0, 1, 0, 0, 0x20, 0 });
    defer alloc.free(data);
    const zero = try http2.buildFrame(alloc, .{ .length = 6, .frame_type = .settings, .flags = 0, .stream_id = 0 }, &.{ 0, 1, 0, 0, 0, 0 });
    defer alloc.free(zero);
    const input = try std.mem.concat(alloc, u8, &.{ settings, data, zero });
    defer alloc.free(input);
    const expected = try alloc.dupe(u8, input);
    defer alloc.free(expected);
    expected[13] = 0x10;
    for (0..input.len + 1) |split| {
        var rewriter: Rewriter = .{};
        const first = try rewriter.rewrite(alloc, input[0..split]);
        defer alloc.free(first);
        const second = try rewriter.rewrite(alloc, input[split..]);
        defer alloc.free(second);
        try std.testing.expect(first.len <= split + max_carry);
        try std.testing.expect(second.len <= input.len - split + max_carry);
        const output = try std.mem.concat(alloc, u8, &.{ first, second });
        defer alloc.free(output);
        try std.testing.expectEqualSlices(u8, expected, output);
    }
}

test "http2 compression relay streams large data without buffering its frame" {
    const alloc = std.testing.allocator;
    var body: [32769]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @truncate(index);
    const frame = try http2.buildFrame(alloc, .{ .length = body.len, .frame_type = .data, .flags = 1, .stream_id = 7 }, &body);
    defer alloc.free(frame);
    var rewriter: Rewriter = .{};
    var offset: usize = 0;
    while (offset < frame.len) {
        const count = @min(@as(usize, 1024), frame.len - offset);
        const output = try rewriter.rewrite(alloc, frame[offset..][0..count]);
        defer alloc.free(output);
        // complete DATA bytes are returned on every call, including before EOF.
        try std.testing.expectEqualSlices(u8, frame[offset..][0..count], output);
        offset += count;
    }
}

test "http2 compression relay rejects malformed settings framing" {
    const alloc = std.testing.allocator;
    for ([_]http2.FrameHeader{
        .{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 1 },
        .{ .length = 6, .frame_type = .settings, .flags = 1, .stream_id = 0 },
        .{ .length = 7, .frame_type = .settings, .flags = 0, .stream_id = 0 },
    }) |header| {
        var bytes: [9]u8 = undefined;
        try http2.writeFrameHeader(&bytes, header);
        var rewriter: Rewriter = .{};
        try std.testing.expectError(error.InvalidFrameSequence, rewriter.rewrite(alloc, &bytes));
    }
}
