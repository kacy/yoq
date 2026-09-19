const std = @import("std");
const spec = @import("../../image/spec.zig");
const types = @import("types.zig");
const command_config = @import("command_config.zig");

pub fn inheritConfig(alloc: std.mem.Allocator, state: *types.BuildState, config: spec.ImageConfig) types.BuildError!void {
    if (config.architecture) |arch| try replaceString(alloc, &state.architecture, arch);
    if (config.os) |os| try replaceString(alloc, &state.os, os);
    if (config.config) |cc| {
        if (cc.Env) |envs| {
            for (envs) |env| {
                const owned = try alloc.dupe(u8, env);
                state.env.append(alloc, owned) catch {
                    alloc.free(owned);
                    return error.OutOfMemory;
                };
            }
        }

        if (cc.WorkingDir) |wd| {
            if (wd.len > 0) {
                var buf: [std.fs.max_path_bytes]u8 = undefined;
                const normalized = try @import("handlers_meta.zig").normalizeWorkdir("/", wd, &buf);
                const owned = if (std.mem.eql(u8, normalized, "/")) "/" else try alloc.dupe(u8, normalized);
                if (!std.mem.eql(u8, state.workdir, "/")) alloc.free(state.workdir);
                state.workdir = owned;
            }
        }

        if (cc.Cmd) |cmd| {
            const owned = try command_config.copy(alloc, cmd);
            if (state.cmd) |old| command_config.free(alloc, old);
            state.cmd = owned;
        }
        if (cc.Entrypoint) |ep| {
            const owned = try command_config.copy(alloc, ep);
            if (state.entrypoint) |old| command_config.free(alloc, old);
            state.entrypoint = owned;
        }
        if (cc.Shell) |shell| {
            const owned = try std.json.Stringify.valueAlloc(alloc, shell, .{});
            if (state.shell) |old| alloc.free(old);
            state.shell = owned;
        }
        if (cc.StopSignal) |signal| try replaceString(alloc, &state.stop_signal, signal);
        if (cc.Healthcheck) |healthcheck| {
            const owned = try std.json.Stringify.valueAlloc(alloc, healthcheck, .{ .emit_null_optional_fields = false });
            if (state.healthcheck) |old| alloc.free(old);
            state.healthcheck = owned;
        }
        try inheritKeys(alloc, &state.exposed_ports, cc.ExposedPorts);
        try inheritKeys(alloc, &state.volumes, cc.Volumes);
        if (cc.Labels) |labels| {
            if (labels != .object) return error.MetadataFailed;
            var iter = labels.object.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.* != .string) return error.MetadataFailed;
                try @import("handlers_meta.zig").setLabel(alloc, state, entry.key_ptr.*, entry.value_ptr.string);
            }
        }

        if (cc.User) |user| {
            if (user.len > 0) {
                @import("identity.zig").validate(user) catch return error.MetadataFailed;
                const owned = try alloc.dupe(u8, user);
                if (state.user) |old| alloc.free(old);
                state.user = owned;
            }
        }

        if (cc.OnBuild) |triggers| {
            for (triggers) |trigger| {
                const owned = try alloc.dupe(u8, trigger);
                state.pending_onbuild.append(alloc, owned) catch {
                    alloc.free(owned);
                    return error.OutOfMemory;
                };
            }
        }
    }
}

fn replaceString(alloc: std.mem.Allocator, field: *?[]const u8, value: []const u8) !void {
    const owned = try alloc.dupe(u8, value);
    if (field.*) |old| alloc.free(old);
    field.* = owned;
}

fn inheritKeys(alloc: std.mem.Allocator, target: *std.ArrayListUnmanaged([]const u8), value: ?std.json.Value) types.BuildError!void {
    const object = value orelse return;
    if (object != .object) return error.MetadataFailed;
    var iter = object.object.iterator();
    while (iter.next()) |entry| {
        const owned = try alloc.dupe(u8, entry.key_ptr.*);
        errdefer alloc.free(owned);
        try target.append(alloc, owned);
    }
}
