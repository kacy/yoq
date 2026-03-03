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
