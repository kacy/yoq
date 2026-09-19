const std = @import("std");
const types = @import("types.zig");

pub fn free(alloc: std.mem.Allocator, args: []const []const u8) void {
    for (args) |arg| alloc.free(arg);
    alloc.free(args);
}

pub fn copy(alloc: std.mem.Allocator, args: []const []const u8) ![]const []const u8 {
    var owned: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (owned.items) |arg| alloc.free(arg);
        owned.deinit(alloc);
    }
    try owned.ensureTotalCapacity(alloc, args.len);
    for (args) |arg| owned.appendAssumeCapacity(try alloc.dupe(u8, arg));
    return owned.toOwnedSlice(alloc);
}

pub fn parse(alloc: std.mem.Allocator, args: []const u8, shell: ?[]const u8) types.BuildError![]const []const u8 {
    const trimmed = std.mem.trim(u8, args, " \t");
    if (std.mem.startsWith(u8, trimmed, "[")) {
        var parsed = std.json.parseFromSlice([]const []const u8, alloc, trimmed, .{}) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.MetadataFailed,
        };
        defer parsed.deinit();
        return copy(alloc, parsed.value);
    }
    const shell_json = shell orelse "[\"/bin/sh\",\"-c\"]";
    var parsed = std.json.parseFromSlice([]const []const u8, alloc, shell_json, .{}) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.MetadataFailed,
    };
    defer parsed.deinit();
    if (parsed.value.len == 0) return error.MetadataFailed;
    const combined = try alloc.alloc([]const u8, parsed.value.len + 1);
    defer alloc.free(combined);
    @memcpy(combined[0..parsed.value.len], parsed.value);
    combined[parsed.value.len] = args;
    return copy(alloc, combined);
}
