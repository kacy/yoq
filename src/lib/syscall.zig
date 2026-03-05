// syscall — shared helpers for raw Linux syscall returns
//
// every module that calls linux.syscallN() needs to check if the
// return value is a negative errno. this centralizes that logic.

const std = @import("std");

/// check if a raw syscall return value indicates an error
/// (negative values in two's complement = errno)
pub fn isError(rc: usize) bool {
    const signed: isize = @bitCast(rc);
    return signed < 0;
}

/// extract the errno value from a failed syscall return.
/// only meaningful when isError(rc) is true.
pub fn getErrno(rc: usize) usize {
    const signed: isize = @bitCast(rc);
    return @bitCast(-signed);
}

/// convert a raw syscall return to a usable value or error.
/// returns the value on success, error.SyscallFailed on failure.
pub fn unwrap(rc: usize) !usize {
    if (isError(rc)) return error.SyscallFailed;
    return rc;
}

// -- tests --

test "isError: success" {
    try std.testing.expect(!isError(0));
    try std.testing.expect(!isError(42));
}

test "isError: failure" {
    const neg_one: usize = @bitCast(@as(isize, -1));
    try std.testing.expect(isError(neg_one));

    const neg_eperm: usize = @bitCast(@as(isize, -1));
    try std.testing.expect(isError(neg_eperm));
}

test "unwrap: success" {
    const val = try unwrap(42);
    try std.testing.expectEqual(@as(usize, 42), val);
}

test "unwrap: failure" {
    const neg: usize = @bitCast(@as(isize, -1));
    try std.testing.expectError(error.SyscallFailed, unwrap(neg));
}

test "getErrno: EINTR" {
    const eintr: usize = @bitCast(@as(isize, -4)); // EINTR = 4
    try std.testing.expectEqual(@as(usize, 4), getErrno(eintr));
}

test "getErrno: EPERM" {
    const eperm: usize = @bitCast(@as(isize, -1)); // EPERM = 1
    try std.testing.expectEqual(@as(usize, 1), getErrno(eperm));
}
