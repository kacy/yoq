const std = @import("std");
const http2 = @import("http2.zig");

pub const initial_window: i64 = 65535;
pub const max_window: i64 = 0x7fffffff;
pub const max_frame_payload = 16384;
pub const max_queue_bytes = 256 * 1024;

pub const Window = struct {
    value: i64 = initial_window,

    pub fn add(self: *Window, amount: u32) !void {
        if (amount == 0 or self.value + amount > max_window) return error.FlowControlError;
        self.value += amount;
    }

    pub fn adjust(self: *Window, delta: i64) !void {
        const next = self.value + delta;
        if (next > max_window or next < -max_window) return error.FlowControlError;
        self.value = next;
    }

    pub fn canSend(self: Window, count: usize) bool {
        return self.value >= @as(i64, @intCast(count));
    }

    pub fn consume(self: *Window, count: usize) !void {
        if (!self.canSend(count)) return error.FlowControlError;
        self.value -= @intCast(count);
    }
};

pub fn increment(payload: []const u8) !u32 {
    if (payload.len != 4) return error.InvalidFrameSequence;
    const value = std.mem.readInt(u32, payload[0..4], .big) & 0x7fffffff;
    if (value == 0) return error.FlowControlError;
    return value;
}

pub fn initialSetting(payload: []const u8) !?i64 {
    if (payload.len % 6 != 0) return error.InvalidFrameSequence;
    var value: ?i64 = null;
    var offset: usize = 0;
    while (offset < payload.len) : (offset += 6) {
        const id = std.mem.readInt(u16, payload[offset..][0..2], .big);
        const setting = std.mem.readInt(u32, payload[offset + 2 ..][0..4], .big);
        if (id == 2 and setting > 1) return error.InvalidFrameSequence;
        if (id == 5 and (setting < max_frame_payload or setting > 0x00ffffff)) return error.InvalidFrameSequence;
        if (id == 4) {
            if (setting > max_window) return error.FlowControlError;
            value = setting;
        }
    }
    return value;
}

pub fn validateSettings(frame: http2.FrameHeader) !void {
    if (frame.stream_id != 0) return error.InvalidFrameSequence;
    if (frame.flags & 1 != 0) {
        if (frame.length != 0) return error.InvalidFrameSequence;
    } else if (frame.length % 6 != 0) return error.InvalidFrameSequence;
}

pub fn windowUpdate(stream_id: u32, count: u32) [13]u8 {
    // this frame has a fixed four-byte payload and no flags.
    var frame = [_]u8{ 0, 0, 4, @intFromEnum(http2.FrameType.window_update), 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, frame[5..9], stream_id & 0x7fffffff, .big);
    std.mem.writeInt(u32, frame[9..13], count, .big);
    return frame;
}

/// queues contain complete frames or complete header sequences. one partially
/// written sequence stays at the front until its final byte is accepted.
pub const Queue = struct {
    bytes: std.ArrayList(u8) = .empty,
    offset: usize = 0,
    reserved: bool = false,

    pub fn deinit(self: *Queue, alloc: std.mem.Allocator) void {
        self.bytes.deinit(alloc);
    }

    pub fn append(self: *Queue, alloc: std.mem.Allocator, bytes: []const u8) !void {
        if (bytes.len > max_queue_bytes - self.bytes.items.len) return error.QueueFull;
        try self.bytes.appendSlice(alloc, bytes);
    }

    /// rewritten header blocks have no padding or priority prefix. keep every
    /// fragment adjacent so the queue cannot insert DATA or control frames in
    /// the middle of a HEADERS/CONTINUATION sequence.
    pub fn appendHeaders(self: *Queue, alloc: std.mem.Allocator, frame: []const u8) !void {
        const header = http2.parseFrameHeader(frame) orelse return error.BufferTooShort;
        if (header.frame_type != .headers or header.flags & 4 == 0 or header.flags & 0x28 != 0 or frame.len != 9 + header.length) return error.InvalidFrameSequence;
        const payload = frame[9..];
        const fragments = @max(@as(usize, 1), std.math.divCeil(usize, payload.len, max_frame_payload) catch return error.InvalidFrameSequence);
        const length = payload.len + fragments * http2.frame_header_len;
        if (length > max_queue_bytes - self.bytes.items.len) return error.QueueFull;
        try self.bytes.ensureUnusedCapacity(alloc, length);
        var offset: usize = 0;
        for (0..fragments) |index| {
            const count = @min(payload.len - offset, max_frame_payload);
            var encoded: [9]u8 = undefined;
            try http2.writeFrameHeader(&encoded, .{
                .length = @intCast(count),
                .frame_type = if (index == 0) .headers else .continuation,
                .flags = (if (index == 0) header.flags & 1 else @as(u8, 0)) | (if (index + 1 == fragments) @as(u8, 4) else 0),
                .stream_id = header.stream_id,
            });
            self.bytes.appendSliceAssumeCapacity(&encoded);
            self.bytes.appendSliceAssumeCapacity(payload[offset..][0..count]);
            offset += count;
        }
    }

    /// padding has no application meaning. discard it before queuing and return
    /// its receive credit immediately; the remaining bytes can use tiny windows.
    pub fn appendData(self: *Queue, alloc: std.mem.Allocator, frame: []const u8) !usize {
        var header = http2.parseFrameHeader(frame) orelse return error.BufferTooShort;
        if (header.frame_type != .data or frame.len != 9 + header.length) return error.InvalidFrameSequence;
        if (header.flags & 8 == 0) {
            try self.append(alloc, frame);
            return 0;
        }
        if (header.length == 0 or frame[9] >= header.length) return error.InvalidFrameSequence;
        const padding: usize = 1 + @as(usize, frame[9]);
        const payload = frame[10 .. frame.len - frame[9]];
        if (9 + payload.len > max_queue_bytes - self.bytes.items.len) return error.QueueFull;
        try self.bytes.ensureUnusedCapacity(alloc, 9 + payload.len);
        header.length = @intCast(payload.len);
        header.flags &= ~@as(u8, 8);
        var encoded: [9]u8 = undefined;
        try http2.writeFrameHeader(&encoded, header);
        self.bytes.appendSliceAssumeCapacity(&encoded);
        self.bytes.appendSliceAssumeCapacity(payload);
        return padding;
    }

    /// split only an untouched DATA frame. a partially written frame retains its
    /// reserved credit and must finish before any new frame can be emitted.
    pub fn limitData(self: *Queue, alloc: std.mem.Allocator, credit: usize) !void {
        var header = http2.parseFrameHeader(self.bytes.items) orelse return error.BufferTooShort;
        if (header.frame_type != .data or header.length <= credit or self.reserved) return;
        if (credit == 0 or self.offset != 0 or header.flags & 8 != 0) return error.FlowControlError;
        if (9 > max_queue_bytes - self.bytes.items.len) return error.QueueFull;
        var remainder = header;
        remainder.length -= @intCast(credit);
        var encoded: [9]u8 = undefined;
        try http2.writeFrameHeader(&encoded, remainder);
        try self.bytes.insertSlice(alloc, 9 + credit, &encoded);
        header.length = @intCast(credit);
        header.flags &= ~@as(u8, 1);
        try http2.writeFrameHeader(self.bytes.items[0..9], header);
    }

    pub fn front(self: *const Queue) !?[]const u8 {
        if (self.bytes.items.len == 0) return null;
        const length = try sequenceLength(self.bytes.items);
        return self.bytes.items[0..length];
    }

    pub fn remove(self: *Queue, length: usize) void {
        self.bytes.replaceRangeAssumeCapacity(0, length, &.{});
        self.offset = 0;
        self.reserved = false;
    }
};

pub fn sequenceLength(bytes: []const u8) !usize {
    const first = http2.parseFrameHeader(bytes) orelse return error.BufferTooShort;
    if (first.length > max_frame_payload) return error.InvalidFrameSequence;
    var length: usize = http2.frame_header_len + first.length;
    if (bytes.len < length) return error.BufferTooShort;
    if (first.frame_type == .headers and first.flags & 4 == 0) {
        while (true) {
            const next = http2.parseFrameHeader(bytes[length..]) orelse return error.BufferTooShort;
            if (next.length > max_frame_payload or next.frame_type != .continuation or next.stream_id != first.stream_id) return error.InvalidFrameSequence;
            length += http2.frame_header_len + next.length;
            if (bytes.len < length) return error.BufferTooShort;
            if (next.flags & 4 != 0) break;
        }
    }
    return length;
}

test "http2 flow settings permit zero and negative stream credit until updates arrive" {
    var window: Window = .{};
    try window.consume(100);
    try window.adjust(-initial_window);
    try std.testing.expectEqual(@as(i64, -100), window.value);
    try std.testing.expect(!window.canSend(1));
    try window.add(100);
    try std.testing.expect(!window.canSend(1));
    try window.add(1);
    try window.consume(1);
    try std.testing.expectError(error.FlowControlError, window.add(0));
    window.value = max_window;
    try std.testing.expectError(error.FlowControlError, window.add(1));
    try std.testing.expectEqual(@as(?i64, 0), try initialSetting(&.{ 0, 4, 0, 0, 0, 0 }));
    try std.testing.expectError(error.FlowControlError, initialSetting(&.{ 0, 4, 128, 0, 0, 0 }));
}

test "http2 frame queue enforces its bound and preserves a header continuation group" {
    const alloc = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(alloc);
    const header = try http2.buildFrame(alloc, .{ .length = 1, .frame_type = .headers, .flags = 0, .stream_id = 1 }, "x");
    defer alloc.free(header);
    const continuation = try http2.buildFrame(alloc, .{ .length = 1, .frame_type = .continuation, .flags = 4, .stream_id = 1 }, "y");
    defer alloc.free(continuation);
    try queue.append(alloc, header);
    try std.testing.expectError(error.BufferTooShort, queue.front());
    try queue.append(alloc, continuation);
    try std.testing.expectEqual(header.len + continuation.len, (try queue.front()).?.len);
    const oversized = try alloc.alloc(u8, max_queue_bytes);
    defer alloc.free(oversized);
    try std.testing.expectError(error.QueueFull, queue.append(alloc, oversized));
    try std.testing.expectEqual(header.len + continuation.len, queue.bytes.items.len);
}

pub const Upstream = struct {
    send_connection: Window = .{},
    send_stream: Window = .{},
    receive_connection: Window = .{},
    receive_stream: Window = .{},
    initial_send_window: i64 = initial_window,
    request: Queue = .{},
    control: Queue = .{},

    pub fn deinit(self: *Upstream, alloc: std.mem.Allocator) void {
        self.request.deinit(alloc);
        self.control.deinit(alloc);
    }

    pub fn settings(self: *Upstream, payload: []const u8) !void {
        if (try initialSetting(payload)) |next| {
            try self.send_stream.adjust(next - self.initial_send_window);
            self.initial_send_window = next;
        }
    }

    pub fn update(self: *Upstream, stream_id: u32, payload: []const u8) !void {
        const amount = try increment(payload);
        switch (stream_id) {
            0 => try self.send_connection.add(amount),
            1 => try self.send_stream.add(amount),
            else => return error.InvalidFrameSequence,
        }
    }

    pub fn acceptData(self: *Upstream, count: usize) !void {
        if (!self.receive_connection.canSend(count) or !self.receive_stream.canSend(count)) return error.FlowControlError;
        try self.receive_connection.consume(count);
        try self.receive_stream.consume(count);
    }

    pub fn returnCredit(self: *Upstream, alloc: std.mem.Allocator, count: usize) !void {
        if (count == 0) return;
        const connection = windowUpdate(0, @intCast(count));
        const stream = windowUpdate(1, @intCast(count));
        var updates: [26]u8 = undefined;
        @memcpy(updates[0..13], &connection);
        @memcpy(updates[13..], &stream);
        try self.control.append(alloc, &updates);
        try self.receive_connection.add(@intCast(count));
        try self.receive_stream.add(@intCast(count));
    }

    pub fn wantsWrite(self: *const Upstream) bool {
        if (self.control.bytes.items.len > 0 or self.request.offset > 0) return true;
        const frame = (self.request.front() catch return true) orelse return false;
        const header = http2.parseFrameHeader(frame).?;
        return header.frame_type != .data or self.request.reserved or
            (header.length == 0 or (self.send_connection.canSend(1) and self.send_stream.canSend(1)));
    }

    /// return the number of request DATA bytes accepted by the transport.
    /// the caller can then restore downstream receive credit for those bytes.
    pub fn flush(self: *Upstream, alloc: std.mem.Allocator, connection: anytype) !usize {
        var forwarded: usize = 0;
        var written: usize = 0;
        while (written < max_queue_bytes) {
            if (!try connection.flushAvailable()) break;
            // finish a partially written frame before choosing a control frame.
            const control = self.control.offset > 0 or (self.request.offset == 0 and self.control.bytes.items.len > 0);
            const queue = if (control) &self.control else &self.request;
            if (queue.bytes.items.len == 0) break;
            const pending = http2.parseFrameHeader(queue.bytes.items).?;
            if (!control and pending.frame_type == .data and pending.length > 0 and !queue.reserved) {
                const credit = @min(self.send_connection.value, self.send_stream.value);
                if (credit <= 0) break;
                try queue.limitData(alloc, @intCast(credit));
            }
            const frame = (try queue.front()).?;
            const header = http2.parseFrameHeader(frame).?;
            const cost: usize = if (header.frame_type == .data) header.length else 0;
            if (!control and cost > 0 and !queue.reserved) {
                if (!self.send_connection.canSend(cost) or !self.send_stream.canSend(cost)) break;
                try self.send_connection.consume(cost);
                try self.send_stream.consume(cost);
                queue.reserved = true;
            }
            const count = try connection.writeAvailable(frame[queue.offset..]);
            if (count == 0) break;
            written += count;
            queue.offset += count;
            if (queue.offset == frame.len) {
                if (!control) forwarded += cost;
                queue.remove(frame.len);
            }
        }
        return forwarded;
    }
};

test "http2 flow splits padded data for tiny windows and sends end stream only once" {
    const alloc = std.testing.allocator;
    var queue: Queue = .{};
    defer queue.deinit(alloc);
    const padded = try http2.buildFrame(alloc, .{ .length = 8, .frame_type = .data, .flags = 9, .stream_id = 1 }, &.{ 2, 'a', 'b', 'c', 'd', 'e', 0, 0 });
    defer alloc.free(padded);
    try std.testing.expectEqual(@as(usize, 3), try queue.appendData(alloc, padded));
    for ("abcde", 0..) |byte, index| {
        try queue.limitData(alloc, 1);
        const frame = (try queue.front()).?;
        const header = http2.parseFrameHeader(frame).?;
        try std.testing.expectEqual(@as(u24, 1), header.length);
        try std.testing.expectEqual(@as(u8, if (index == 4) 1 else 0), header.flags);
        try std.testing.expectEqual(byte, frame[9]);
        queue.remove(frame.len);
    }
    try std.testing.expectEqual(@as(usize, 0), queue.bytes.items.len);
}

test "http2 flow sends control frames while data waits for stream credit" {
    const alloc = std.testing.allocator;
    const Sink = struct {
        bytes: std.ArrayList(u8) = .empty,
        fn flushAvailable(_: *@This()) !bool {
            return true;
        }
        fn writeAvailable(self: *@This(), bytes: []const u8) !usize {
            // force a partial frame write on every call.
            const count = @min(bytes.len, 3);
            try self.bytes.appendSlice(std.testing.allocator, bytes[0..count]);
            return count;
        }
    };
    var sink: Sink = .{};
    defer sink.bytes.deinit(alloc);
    var upstream: Upstream = .{};
    defer upstream.deinit(alloc);
    try upstream.settings(&.{ 0, 4, 0, 0, 0, 0 });
    const data = try http2.buildFrame(alloc, .{ .length = 4, .frame_type = .data, .flags = 1, .stream_id = 1 }, "body");
    defer alloc.free(data);
    try upstream.request.append(alloc, data);
    try std.testing.expectEqual(@as(usize, 0), try upstream.flush(alloc, &sink));
    try std.testing.expect(!upstream.wantsWrite());
    const update = windowUpdate(0, 4);
    try upstream.control.append(alloc, &update);
    try std.testing.expectEqual(@as(usize, 0), try upstream.flush(alloc, &sink));
    try std.testing.expectEqualSlices(u8, &update, sink.bytes.items);
    for (0..4) |_| {
        try upstream.send_stream.add(1);
        try std.testing.expectEqual(@as(usize, 1), try upstream.flush(alloc, &sink));
    }
    try std.testing.expectEqual(@as(i64, initial_window - 4), upstream.send_connection.value);
    try std.testing.expectEqual(@as(i64, 0), upstream.send_stream.value);
    try std.testing.expectEqual(@as(usize, 0), upstream.request.bytes.items.len);
    var offset: usize = update.len;
    for ("body", 0..) |byte, index| {
        const header = http2.parseFrameHeader(sink.bytes.items[offset..]).?;
        try std.testing.expectEqual(@as(u24, 1), header.length);
        try std.testing.expectEqual(@as(u8, if (index == 3) 1 else 0), header.flags);
        try std.testing.expectEqual(byte, sink.bytes.items[offset + 9]);
        offset += 10;
    }
}

test "http2 flow rejects malformed settings and oversized continuation frames" {
    try std.testing.expectError(error.InvalidFrameSequence, validateSettings(.{ .length = 0, .frame_type = .settings, .flags = 0, .stream_id = 1 }));
    try std.testing.expectError(error.InvalidFrameSequence, validateSettings(.{ .length = 6, .frame_type = .settings, .flags = 1, .stream_id = 0 }));
    try std.testing.expectError(error.InvalidFrameSequence, initialSetting(&.{ 0, 5, 0, 0, 0, 1 }));
    try std.testing.expectError(error.InvalidFrameSequence, initialSetting(&.{ 0, 5, 1, 0, 0, 0 }));
    try std.testing.expectError(error.InvalidFrameSequence, initialSetting(&.{ 0, 2, 0, 0, 0, 2 }));
    var frames: [18]u8 = undefined;
    try http2.writeFrameHeader(frames[0..9], .{ .length = 0, .frame_type = .headers, .flags = 0, .stream_id = 1 });
    try http2.writeFrameHeader(frames[9..], .{ .length = max_frame_payload + 1, .frame_type = .continuation, .flags = 4, .stream_id = 1 });
    try std.testing.expectError(error.InvalidFrameSequence, sequenceLength(&frames));
    try http2.writeFrameHeader(frames[9..], .{ .length = 0, .frame_type = .continuation, .flags = 4, .stream_id = 3 });
    try std.testing.expectError(error.InvalidFrameSequence, sequenceLength(&frames));
    try http2.writeFrameHeader(frames[9..], .{ .length = 0, .frame_type = .continuation, .flags = 4, .stream_id = 1 });
    try std.testing.expectEqual(@as(usize, 18), try sequenceLength(&frames));
}

test "http2 flow fragments header blocks at the frame boundary and preserves sequence flags" {
    const alloc = std.testing.allocator;
    for ([_]usize{ 0, max_frame_payload, max_frame_payload + 1, 2 * max_frame_payload + 1 }) |length| {
        const payload = try alloc.alloc(u8, length);
        defer alloc.free(payload);
        @memset(payload, 0x6a);
        for ([_]u8{ 4, 5 }) |flags| {
            const frame = try http2.buildFrame(alloc, .{ .length = @intCast(length), .frame_type = .headers, .flags = flags, .stream_id = 3 }, payload);
            defer alloc.free(frame);
            var queue: Queue = .{};
            defer queue.deinit(alloc);
            try queue.appendHeaders(alloc, frame);
            const sequence_bytes = queue.bytes.items.len;
            const update = windowUpdate(0, 1);
            try queue.append(alloc, &update);
            const sequence = (try queue.front()).?;
            try std.testing.expectEqual(sequence_bytes, sequence.len);
            var offset: usize = 0;
            var payload_bytes: usize = 0;
            while (offset < sequence.len) {
                const header = http2.parseFrameHeader(sequence[offset..]).?;
                const final = offset + 9 + header.length == sequence.len;
                try std.testing.expect(header.length <= max_frame_payload);
                try std.testing.expectEqual(@as(u32, 3), header.stream_id);
                try std.testing.expectEqual(if (offset == 0) http2.FrameType.headers else http2.FrameType.continuation, header.frame_type);
                try std.testing.expectEqual((if (offset == 0) flags & 1 else @as(u8, 0)) | (if (final) @as(u8, 4) else 0), header.flags);
                try std.testing.expectEqualSlices(u8, payload[payload_bytes..][0..header.length], sequence[offset + 9 ..][0..header.length]);
                payload_bytes += header.length;
                offset += 9 + header.length;
            }
            try std.testing.expectEqual(length, payload_bytes);
            queue.remove(sequence_bytes);
            try std.testing.expectEqualSlices(u8, &update, (try queue.front()).?);
        }
    }
    const oversized = try alloc.alloc(u8, max_queue_bytes);
    defer alloc.free(oversized);
    try http2.writeFrameHeader(oversized[0..9], .{ .length = max_queue_bytes - 9, .frame_type = .headers, .flags = 4, .stream_id = 1 });
    var queue: Queue = .{};
    defer queue.deinit(alloc);
    try std.testing.expectError(error.QueueFull, queue.appendHeaders(alloc, oversized));
    try std.testing.expectEqual(@as(usize, 0), queue.bytes.items.len);
}
