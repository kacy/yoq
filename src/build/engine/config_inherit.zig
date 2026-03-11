const std = @import("std");
const spec = @import("../../image/spec.zig");
const log = @import("../../lib/log.zig");
const types = @import("types.zig");

pub fn inheritConfig(alloc: std.mem.Allocator, state: *types.BuildState, config_bytes: []const u8) void {
    var parsed = spec.parseImageConfig(alloc, config_bytes) catch {
        log.warn("build: failed to parse base image config", .{});
        return;
    };
    defer parsed.deinit();

    if (parsed.value.config) |cc| {
        if (cc.Env) |envs| {
            for (envs) |env| {
                const owned = alloc.dupe(u8, env) catch continue;
                state.env.append(alloc, owned) catch alloc.free(owned);
            }
        }

        if (cc.WorkingDir) |wd| {
            if (wd.len > 0) {
                const owned = alloc.dupe(u8, wd) catch return;
                if (!std.mem.eql(u8, state.workdir, "/")) alloc.free(state.workdir);
                state.workdir = owned;
            }
        }

        if (cc.Cmd) |cmds| {
            if (cmds.len > 0) {
                const owned = alloc.dupe(u8, cmds[0]) catch return;
                if (state.cmd) |old| alloc.free(old);
                state.cmd = owned;
            }
        }

        if (cc.Entrypoint) |ep| {
            if (ep.len > 0) {
                const owned = alloc.dupe(u8, ep[0]) catch return;
                if (state.entrypoint) |old| alloc.free(old);
                state.entrypoint = owned;
            }
        }

        if (cc.User) |user| {
            if (user.len > 0) {
                const owned = alloc.dupe(u8, user) catch return;
                if (state.user) |old| alloc.free(old);
                state.user = owned;
            }
        }

        if (cc.OnBuild) |triggers| {
            for (triggers) |trigger| {
                const owned = alloc.dupe(u8, trigger) catch continue;
                state.pending_onbuild.append(alloc, owned) catch alloc.free(owned);
            }
        }
    }
}
