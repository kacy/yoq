const std = @import("std");
const log = @import("../../lib/log.zig");
const types = @import("types.zig");

pub fn processEnv(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    const owned = alloc.dupe(u8, args) catch return types.BuildError.OutOfMemory;
    errdefer alloc.free(owned);
    try state.env.append(alloc, owned);
}

pub fn processWorkdir(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    const owned = alloc.dupe(u8, args) catch return types.BuildError.OutOfMemory;
    if (!std.mem.eql(u8, state.workdir, "/")) alloc.free(state.workdir);
    state.workdir = owned;
}

pub fn processCmd(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    const owned = alloc.dupe(u8, args) catch return types.BuildError.OutOfMemory;
    if (state.cmd) |old| alloc.free(old);
    state.cmd = owned;
}

pub fn processEntrypoint(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    const owned = alloc.dupe(u8, args) catch return types.BuildError.OutOfMemory;
    if (state.entrypoint) |old| alloc.free(old);
    state.entrypoint = owned;
}

pub fn processExpose(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    const owned = alloc.dupe(u8, args) catch return types.BuildError.OutOfMemory;
    errdefer alloc.free(owned);
    try state.exposed_ports.append(alloc, owned);
}

pub fn processUser(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    const owned = alloc.dupe(u8, args) catch return types.BuildError.OutOfMemory;
    if (state.user) |old| alloc.free(old);
    state.user = owned;
}

pub fn processLabel(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    const owned = alloc.dupe(u8, args) catch return types.BuildError.OutOfMemory;
    errdefer alloc.free(owned);
    try state.labels.append(alloc, owned);
}

pub fn processArg(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    const trimmed = std.mem.trim(u8, args, " \t");
    if (std.mem.indexOfScalar(u8, trimmed, '=')) |eq| {
        const key = trimmed[0..eq];
        const val = trimmed[eq + 1 ..];
        if (state.build_args.get(key) != null) return;

        const owned_key = alloc.dupe(u8, key) catch return types.BuildError.OutOfMemory;
        errdefer alloc.free(owned_key);
        const owned_val = alloc.dupe(u8, val) catch return types.BuildError.OutOfMemory;
        errdefer alloc.free(owned_val);
        try state.build_args.put(alloc, owned_key, owned_val);
    } else {
        if (state.build_args.get(trimmed) != null) return;

        const owned_key = alloc.dupe(u8, trimmed) catch return types.BuildError.OutOfMemory;
        errdefer alloc.free(owned_key);
        const owned_val = alloc.dupe(u8, "") catch return types.BuildError.OutOfMemory;
        errdefer alloc.free(owned_val);
        try state.build_args.put(alloc, owned_key, owned_val);
    }
}

pub fn processVolume(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    if (std.mem.trim(u8, args, " \t").len == 0) return;

    if (std.mem.startsWith(u8, std.mem.trim(u8, args, " \t"), "[")) {
        const trimmed = std.mem.trim(u8, args, " \t[]");
        var iter = std.mem.splitScalar(u8, trimmed, ',');
        while (iter.next()) |entry| {
            const path = std.mem.trim(u8, entry, " \t\"");
            if (path.len == 0) continue;
            const owned = alloc.dupe(u8, path) catch return types.BuildError.OutOfMemory;
            errdefer alloc.free(owned);
            try state.volumes.append(alloc, owned);
        }
        return;
    }

    var iter = std.mem.tokenizeAny(u8, args, " \t");
    while (iter.next()) |path| {
        const owned = alloc.dupe(u8, path) catch return types.BuildError.OutOfMemory;
        errdefer alloc.free(owned);
        try state.volumes.append(alloc, owned);
    }
}

pub fn processShell(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    const owned = alloc.dupe(u8, args) catch return types.BuildError.OutOfMemory;
    if (state.shell) |old| alloc.free(old);
    state.shell = owned;
}

pub fn processHealthcheck(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    const owned = alloc.dupe(u8, args) catch return types.BuildError.OutOfMemory;
    if (state.healthcheck) |old| alloc.free(old);
    state.healthcheck = owned;
}

pub fn processStopsignal(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    const owned = alloc.dupe(u8, args) catch return types.BuildError.OutOfMemory;
    if (state.stop_signal) |old| alloc.free(old);
    state.stop_signal = owned;
}

pub fn processOnbuild(alloc: std.mem.Allocator, state: *types.BuildState, args: []const u8) types.BuildError!void {
    const owned = alloc.dupe(u8, args) catch return types.BuildError.OutOfMemory;
    errdefer alloc.free(owned);
    try state.onbuild_triggers.append(alloc, owned);
}

pub fn expandArgs(
    alloc: std.mem.Allocator,
    input: []const u8,
    args_map: *const std.StringHashMapUnmanaged([]const u8),
) ![]const u8 {
    if (std.mem.indexOfScalar(u8, input, '$') == null) return input;

    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(alloc);

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] != '$') {
            try result.append(alloc, input[i]);
            i += 1;
            continue;
        }

        i += 1;
        if (i >= input.len) {
            try result.append(alloc, '$');
            break;
        }

        if (input[i] == '{') {
            i += 1;
            const var_start = i;

            var default_start: ?usize = null;
            while (i < input.len and input[i] != '}') {
                if (i + 1 < input.len and input[i] == ':' and input[i + 1] == '-') {
                    default_start = i + 2;
                    i += 2;
                    continue;
                }
                i += 1;
            }

            if (i >= input.len) {
                try result.append(alloc, '$');
                try result.append(alloc, '{');
                try result.appendSlice(alloc, input[var_start..]);
                break;
            }

            const var_end = if (default_start) |ds| ds - 2 else i;
            const var_name = input[var_start..var_end];
            const default_val = if (default_start) |ds| input[ds..i] else null;

            i += 1;

            if (args_map.get(var_name)) |val| {
                if (val.len > 0) {
                    try result.appendSlice(alloc, val);
                } else if (default_val) |dv| {
                    try result.appendSlice(alloc, dv);
                }
            } else if (default_val) |dv| {
                try result.appendSlice(alloc, dv);
            }
        } else {
            if (!std.ascii.isAlphabetic(input[i]) and input[i] != '_') {
                try result.append(alloc, '$');
                continue;
            }

            const var_start = i;
            while (i < input.len and (std.ascii.isAlphanumeric(input[i]) or input[i] == '_')) {
                i += 1;
            }

            const var_name = input[var_start..i];
            if (args_map.get(var_name)) |val| {
                try result.appendSlice(alloc, val);
            }
        }
    }

    if (result.items.len == input.len and std.mem.eql(u8, result.items, input)) {
        result.deinit(alloc);
        return input;
    }

    return try result.toOwnedSlice(alloc);
}

test "processArg — key=value" {
    const alloc = std.testing.allocator;
    var state = types.BuildState.init(alloc);
    defer state.deinit();

    processArg(alloc, &state, "VERSION=1.0");
    try std.testing.expectEqualStrings("1.0", state.build_args.get("VERSION").?);
}

test "expandArgs — simple $VAR" {
    const alloc = std.testing.allocator;
    var args_map: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer args_map.deinit(alloc);

    const key = try alloc.dupe(u8, "NAME");
    const val = try alloc.dupe(u8, "world");
    defer alloc.free(key);
    defer alloc.free(val);
    try args_map.put(alloc, key, val);

    const result = try expandArgs(alloc, "hello $NAME", &args_map);
    defer alloc.free(result);
    try std.testing.expectEqualStrings("hello world", result);
}
