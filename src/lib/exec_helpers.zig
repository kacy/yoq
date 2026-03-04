// exec_helpers — shared utilities for post-fork exec setup
//
// these functions run after clone3() where the heap is invalid.
// everything here is pure stack-buffer, no allocator needed.

const std = @import("std");

/// copy a string into a buffer and null-terminate it.
/// returns a pointer suitable for execve argv/envp, or null if buffer is full.
pub fn packString(buf: *[65536]u8, pos: *usize, src: []const u8) ?[*:0]const u8 {
    if (pos.* + src.len + 1 > buf.len) return null;
    @memcpy(buf[pos.*..][0..src.len], src);
    buf[pos.* + src.len] = 0;
    const result: [*:0]const u8 = @ptrCast(&buf[pos.*]);
    pos.* += src.len + 1;
    return result;
}

// -- tests --

test "packString basic" {
    var buf: [65536]u8 = undefined;
    var pos: usize = 0;
    const ptr = packString(&buf, &pos, "hello").?;
    try std.testing.expectEqualStrings("hello", std.mem.span(ptr));
}

test "packString advances position" {
    var buf: [65536]u8 = undefined;
    var pos: usize = 0;
    _ = packString(&buf, &pos, "abc");
    // "abc" is 3 bytes + 1 null terminator = 4
    try std.testing.expectEqual(@as(usize, 4), pos);
}

test "packString returns null when buffer full" {
    var buf: [65536]u8 = undefined;
    var pos: usize = 65534;
    // only 2 bytes left (65536 - 65534), need 4 for "abc" + null
    try std.testing.expect(packString(&buf, &pos, "abc") == null);
}

test "packString empty string" {
    var buf: [65536]u8 = undefined;
    var pos: usize = 0;
    const ptr = packString(&buf, &pos, "").?;
    // empty string → just a null terminator
    try std.testing.expectEqual(@as(usize, 1), pos);
    try std.testing.expectEqualStrings("", std.mem.span(ptr));
}
