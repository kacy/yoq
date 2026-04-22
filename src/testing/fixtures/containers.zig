//! fixtures/containers.zig - Test fixtures for container records
//!
//! Provides helper functions to create test container records with
//! various configurations for use in API route tests.

const std = @import("std");
const platform = @import("platform");
const store = @import("../../state/store.zig");

pub const ContainerRecord = store.ContainerRecord;

/// Generate a valid 64-character hex container ID
pub fn generateContainerId(allocator: std.mem.Allocator, prefix: u8) ![]const u8 {
    var buf: [65]u8 = undefined;
    var i: usize = 0;

    // Fill with hex characters
    while (i < 64) : (i += 1) {
        const hex_digit = if (i < 32)
            (prefix + i) % 16
        else
            (prefix * 2 + i) % 16;

        if (hex_digit < 10) {
            buf[i] = '0' + @as(u8, @intCast(hex_digit));
        } else {
            buf[i] = 'a' + @as(u8, @intCast(hex_digit - 10));
        }
    }
    buf[64] = 0;

    return try allocator.dupe(u8, buf[0..64]);
}

/// Create a running container record
pub fn createRunningContainer(
    alloc: std.mem.Allocator,
    id_prefix: u8,
    pid: i32,
) !ContainerRecord {
    const id = try generateContainerId(alloc, id_prefix);
    errdefer alloc.free(id);

    return ContainerRecord{
        .id = id,
        .rootfs = try alloc.dupe(u8, "/tmp/test-rootfs-"),
        .command = try alloc.dupe(u8, "./app"),
        .hostname = try alloc.dupe(u8, "test-container"),
        .status = try alloc.dupe(u8, "running"),
        .pid = pid,
        .exit_code = null,
        .ip_address = try alloc.dupe(u8, "10.0.0.1"),
        .veth_host = try alloc.dupe(u8, "veth0"),
        .app_name = try alloc.dupe(u8, "test-app"),
        .created_at = platform.timestamp(),
    };
}

/// Create a stopped container record
pub fn createStoppedContainer(
    alloc: std.mem.Allocator,
    id_prefix: u8,
    exit_code: u8,
) !ContainerRecord {
    const id = try generateContainerId(alloc, id_prefix);
    errdefer alloc.free(id);

    return ContainerRecord{
        .id = id,
        .rootfs = try alloc.dupe(u8, "/tmp/test-rootfs-"),
        .command = try alloc.dupe(u8, "./app"),
        .hostname = try alloc.dupe(u8, "test-container"),
        .status = try alloc.dupe(u8, "exited"),
        .pid = null,
        .exit_code = exit_code,
        .ip_address = null,
        .veth_host = null,
        .app_name = try alloc.dupe(u8, "test-app"),
        .created_at = platform.timestamp(),
    };
}

/// Create a container with minimal fields
pub fn createMinimalContainer(
    alloc: std.mem.Allocator,
    id_prefix: u8,
    status: []const u8,
) !ContainerRecord {
    const id = try generateContainerId(alloc, id_prefix);
    errdefer alloc.free(id);

    return ContainerRecord{
        .id = id,
        .rootfs = try alloc.dupe(u8, "/tmp/rootfs"),
        .command = try alloc.dupe(u8, "sleep 1000"),
        .hostname = try alloc.dupe(u8, "host"),
        .status = try alloc.dupe(u8, status),
        .pid = null,
        .exit_code = null,
        .ip_address = null,
        .veth_host = null,
        .app_name = null,
        .created_at = platform.timestamp(),
    };
}

/// Array of valid test container IDs
pub const test_ids = [_][]const u8{
    "abc123def4567890123456789012345678901234567890123456789012345678",
    "def456789012345678901234567890123456789012345678901234567890123",
    "7890123456789012345678901234567890123456789012345678901234567890",
};

/// Array of invalid container IDs (for testing validation)
pub const invalid_ids = [_][]const u8{
    // Too short
    "abc123",
    // Too long
    "abc123def456789012345678901234567890123456789012345678901234567890",
    // Non-hex characters
    "xyz123def456789012345678901234567890123456789012345678901234567",
    // Empty
    "",
    // With uppercase (should we accept?)
    "ABC123DEF456789012345678901234567890123456789012345678901234567",
};

// -- Tests --

test "generateContainerId creates valid hex ID" {
    const id = try generateContainerId(std.testing.allocator, 0);
    defer std.testing.allocator.free(id);

    // Check length
    try std.testing.expectEqual(@as(usize, 64), id.len);

    // Check all characters are valid hex
    for (id) |c| {
        const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        try std.testing.expect(is_hex);
    }
}

test "createRunningContainer" {
    const container = try createRunningContainer(std.testing.allocator, 1, 1234);
    defer container.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("running", container.status);
    try std.testing.expectEqual(@as(i32, 1234), container.pid.?);
    try std.testing.expect(container.exit_code == null);
    try std.testing.expect(container.ip_address != null);
}

test "createStoppedContainer" {
    const container = try createStoppedContainer(std.testing.allocator, 2, 1);
    defer container.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("exited", container.status);
    try std.testing.expect(container.pid == null);
    try std.testing.expectEqual(@as(u8, 1), container.exit_code.?);
}

test "createMinimalContainer" {
    const container = try createMinimalContainer(std.testing.allocator, 3, "created");
    defer container.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("created", container.status);
    try std.testing.expect(container.ip_address == null);
    try std.testing.expect(container.app_name == null);
}

test "test_ids are all valid length" {
    for (test_ids) |id| {
        try std.testing.expectEqual(@as(usize, 64), id.len);
    }
}

test "invalid_ids are all invalid" {
    // These should fail validation (length != 64)
    for (invalid_ids[0..3]) |id| {
        try std.testing.expect(id.len != 64);
    }
}
