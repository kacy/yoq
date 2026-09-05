const std = @import("std");
const spec = @import("../../image/spec.zig");
const types = @import("types.zig");

pub fn inheritConfig(alloc: std.mem.Allocator, state: *types.BuildState, config: spec.ImageConfig) types.BuildError!void {
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

        if (cc.Cmd) |cmds| {
            if (cmds.len > 0) {
                const owned = try alloc.dupe(u8, cmds[0]);
                if (state.cmd) |old| alloc.free(old);
                state.cmd = owned;
            }
        }

        if (cc.Entrypoint) |ep| {
            if (ep.len > 0) {
                const owned = try alloc.dupe(u8, ep[0]);
                if (state.entrypoint) |old| alloc.free(old);
                state.entrypoint = owned;
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
