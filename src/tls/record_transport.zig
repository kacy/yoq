//! Bounded TLS framing over a byte stream. Reading only the current record
//! leaves coalesced records in the socket, including application data that
//! arrives with Finished. The same deadline covers every fragment and write.
const std = @import("std");
const record = @import("record.zig");
const socket = @import("../lib/socket_stream.zig");
const handshake = @import("handshake.zig");

pub const Buffer = [record.record_header_size + record.max_ciphertext_size]u8;

pub fn read(wire: socket.Stream, buffer: *Buffer) ![]u8 {
    try readExactly(wire, buffer[0..5]);
    const header = try record.parseHeader(buffer[0..5]);
    try readExactly(wire, buffer[5..][0..header.length]);
    return buffer[0 .. 5 + @as(usize, header.length)];
}

fn readExactly(wire: anytype, bytes: []u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = try wire.read(bytes[offset..]);
        if (n == 0) return error.UnexpectedEof;
        offset += n;
    }
}

pub fn readEncrypted(wire: socket.Stream, buffer: *Buffer, keys: handshake.TrafficKeys, seq: *u64, allow_ccs: bool) !struct { plaintext: []u8, content_type: record.ContentType } {
    var full = try read(wire, buffer);
    if (allow_ccs and full[0] == @intFromEnum(record.ContentType.change_cipher_spec)) {
        if (!std.mem.eql(u8, full, &.{ 20, 3, 3, 0, 1, 1 })) return error.InvalidContentType;
        full = try read(wire, buffer);
    }
    if (full[0] != @intFromEnum(record.ContentType.application_data)) return error.InvalidContentType;
    const result = try record.decryptRecord(keys.key, keys.iv, seq.*, full[5..], full[0..5].*);
    seq.* += 1;
    return .{ .plaintext = result.plaintext, .content_type = result.content_type };
}

pub fn write(wire: socket.Stream, keys: handshake.TrafficKeys, seq: *u64, kind: record.ContentType, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = @min(bytes.len - offset, record.max_record_size);
        var buffer: Buffer = undefined;
        const len = try record.encryptRecord(keys.key, keys.iv, seq.*, bytes[offset..][0..n], kind, buffer[5..]);
        try record.writeHeader(&buffer, .application_data, @intCast(len));
        try wire.writeAll(buffer[0 .. 5 + len]);
        seq.* += 1;
        offset += n;
    }
}

test "record reader joins fragments and rejects premature eof" {
    const Fragmented = struct {
        data: []const u8,
        fn read(self: *@This(), out: []u8) !usize {
            const n = @min(1, @min(self.data.len, out.len));
            @memcpy(out[0..n], self.data[0..n]);
            self.data = self.data[n..];
            return n;
        }
    };
    var input = Fragmented{ .data = "headerpayload" };
    var out: [5]u8 = undefined;
    try readExactly(&input, &out);
    try std.testing.expectEqualStrings("heade", &out);
    try std.testing.expectEqualStrings("rpayload", input.data);
    var short = Fragmented{ .data = "x" };
    try std.testing.expectError(error.UnexpectedEof, readExactly(&short, &out));
}
