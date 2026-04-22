// oci — OCI image spec utilities
//
// provides helpers for working with OCI image configurations,
// including command resolution and image record management
// per the OCI runtime spec.

const std = @import("std");
const platform = @import("platform");
const image_spec = @import("spec.zig");
const state_store = @import("../state/store.zig");
const blob_store = @import("store.zig");

pub const ResolvedCommand = struct {
    command: []const u8,
    args: std.ArrayList([]const u8),
};

/// resolve effective command per OCI image spec.
/// user_args overrides default_cmd when non-empty.
/// entrypoint[0] is the command binary when set.
/// falls back to /bin/sh if nothing specified.
pub fn resolveCommand(
    alloc: std.mem.Allocator,
    entrypoint: []const []const u8,
    default_cmd: []const []const u8,
    user_args: []const []const u8,
) error{OutOfMemory}!ResolvedCommand {
    // effective_argv = user_override or default_cmd
    const effective_args: []const []const u8 = if (user_args.len > 0)
        user_args
    else
        default_cmd;

    // determine the command binary
    const effective_cmd: []const u8 = if (entrypoint.len > 0)
        entrypoint[0]
    else if (effective_args.len > 0)
        effective_args[0]
    else
        "/bin/sh";

    // build the full args list: entrypoint[1..] ++ effective_args
    // (or effective_args[1..] if no entrypoint)
    var full_args: std.ArrayList([]const u8) = .empty;
    errdefer full_args.deinit(alloc);

    if (entrypoint.len > 1) {
        try full_args.appendSlice(alloc, entrypoint[1..]);
    }

    if (entrypoint.len > 0) {
        // entrypoint is set — append all of effective_args
        try full_args.appendSlice(alloc, effective_args);
    } else if (effective_args.len > 1) {
        // no entrypoint — effective_args[0] is the command, rest are args
        try full_args.appendSlice(alloc, effective_args[1..]);
    }

    return .{
        .command = effective_cmd,
        .args = full_args,
    };
}

/// save an image record after a successful pull.
/// stores manifest and config blobs in the content-addressable store,
/// then records metadata in sqlite for later lookup (e.g. for push).
pub fn saveImageFromPull(
    ref: image_spec.ImageRef,
    manifest_digest: []const u8,
    manifest_bytes: []const u8,
    config_bytes: []const u8,
    config_digest: []const u8,
    total_size: usize,
) state_store.StoreError!void {
    // persist manifest and config blobs so they can be read back for push.
    // putBlob is idempotent — if the blob already exists, it's a no-op.
    _ = blob_store.putBlob(manifest_bytes) catch return state_store.StoreError.WriteFailed;
    _ = blob_store.putBlob(config_bytes) catch return state_store.StoreError.WriteFailed;

    return state_store.saveImage(.{
        .id = manifest_digest,
        .repository = ref.repository,
        .tag = ref.reference,
        .manifest_digest = manifest_digest,
        .config_digest = config_digest,
        .total_size = @intCast(total_size),
        .created_at = platform.timestamp(),
    });
}

// -- tests --

test "entrypoint with default cmd" {
    const alloc = std.testing.allocator;
    const ep: []const []const u8 = &.{"/usr/bin/python"};
    const cmd: []const []const u8 = &.{"app.py"};
    var result = try resolveCommand(alloc, ep, cmd, &.{});
    defer result.args.deinit(alloc);

    try std.testing.expectEqualStrings("/usr/bin/python", result.command);
    try std.testing.expectEqual(@as(usize, 1), result.args.items.len);
    try std.testing.expectEqualStrings("app.py", result.args.items[0]);
}

test "entrypoint with user override" {
    const alloc = std.testing.allocator;
    const ep: []const []const u8 = &.{"/usr/bin/python"};
    const cmd: []const []const u8 = &.{"app.py"};
    const user: []const []const u8 = &.{"test.py"};
    var result = try resolveCommand(alloc, ep, cmd, user);
    defer result.args.deinit(alloc);

    try std.testing.expectEqualStrings("/usr/bin/python", result.command);
    try std.testing.expectEqual(@as(usize, 1), result.args.items.len);
    try std.testing.expectEqualStrings("test.py", result.args.items[0]);
}

test "cmd only no entrypoint" {
    const alloc = std.testing.allocator;
    const cmd: []const []const u8 = &.{ "/bin/echo", "hello" };
    var result = try resolveCommand(alloc, &.{}, cmd, &.{});
    defer result.args.deinit(alloc);

    try std.testing.expectEqualStrings("/bin/echo", result.command);
    try std.testing.expectEqual(@as(usize, 1), result.args.items.len);
    try std.testing.expectEqualStrings("hello", result.args.items[0]);
}

test "user args only" {
    const alloc = std.testing.allocator;
    const user: []const []const u8 = &.{ "/bin/ls", "-la" };
    var result = try resolveCommand(alloc, &.{}, &.{}, user);
    defer result.args.deinit(alloc);

    try std.testing.expectEqualStrings("/bin/ls", result.command);
    try std.testing.expectEqual(@as(usize, 1), result.args.items.len);
    try std.testing.expectEqualStrings("-la", result.args.items[0]);
}

test "user args completely replace default cmd" {
    const alloc = std.testing.allocator;
    const ep: []const []const u8 = &.{"/entrypoint.sh"};
    const cmd: []const []const u8 = &.{ "default", "args" };
    const user: []const []const u8 = &.{ "custom", "override" };
    var result = try resolveCommand(alloc, ep, cmd, user);
    defer result.args.deinit(alloc);

    // entrypoint is still the command binary
    try std.testing.expectEqualStrings("/entrypoint.sh", result.command);
    // user args should completely replace default cmd
    try std.testing.expectEqual(@as(usize, 2), result.args.items.len);
    try std.testing.expectEqualStrings("custom", result.args.items[0]);
    try std.testing.expectEqualStrings("override", result.args.items[1]);
}

test "empty falls back to /bin/sh" {
    const alloc = std.testing.allocator;
    var result = try resolveCommand(alloc, &.{}, &.{}, &.{});
    defer result.args.deinit(alloc);

    try std.testing.expectEqualStrings("/bin/sh", result.command);
    try std.testing.expectEqual(@as(usize, 0), result.args.items.len);
}
