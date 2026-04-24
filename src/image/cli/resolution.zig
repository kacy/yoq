const std = @import("std");
const cli = @import("../../lib/cli.zig");
const spec = @import("../spec.zig");
const registry = @import("../registry.zig");
const layer = @import("../layer.zig");
const common = @import("common.zig");

const writeErr = cli.writeErr;

pub const ImageResolution = struct {
    rootfs: []const u8,
    entrypoint: []const []const u8 = &.{},
    default_cmd: []const []const u8 = &.{},
    image_env: []const []const u8 = &.{},
    working_dir: []const u8 = "/",
    layer_paths: []const []const u8 = &.{},
    pull_result: ?registry.PullResult = null,
    config_parsed: ?spec.ParseResult(spec.ImageConfig) = null,
    alloc: ?std.mem.Allocator = null,

    pub fn deinit(self: *ImageResolution) void {
        if (self.alloc) |a| {
            for (self.layer_paths) |p| a.free(p);
            a.free(self.layer_paths);
        }
        if (self.pull_result) |*r| r.deinit();
        if (self.config_parsed) |*c| c.deinit();
    }
};

pub fn pullAndResolveImage(io: std.Io, alloc: std.mem.Allocator, target: []const u8) common.ImageCommandsError!ImageResolution {
    const ref = spec.parseImageRef(target);

    writeErr("pulling {s}...\n", .{target});

    var result = ImageResolution{ .rootfs = target };

    result.pull_result = registry.pull(io, alloc, ref) catch |err| {
        common.writePullError(target, err);
        return common.ImageCommandsError.PullFailed;
    };

    result.config_parsed = spec.parseImageConfig(alloc, result.pull_result.?.config_bytes) catch |err| {
        writeErr("failed to parse image config: {}\n", .{err});
        return common.ImageCommandsError.PullFailed;
    };

    if (result.config_parsed.?.value.config) |cc| {
        if (cc.Entrypoint) |ep| result.entrypoint = ep;
        if (cc.Cmd) |cmd| result.default_cmd = cmd;
        if (cc.Env) |env| result.image_env = env;
        if (cc.WorkingDir) |wd| {
            if (wd.len > 0) result.working_dir = wd;
        }
    }

    result.layer_paths = layer.assembleRootfs(alloc, result.pull_result.?.layer_digests) catch |err| {
        writeErr("failed to extract image layers: {}\n", .{err});
        return common.ImageCommandsError.PullFailed;
    };
    result.alloc = alloc;

    if (result.layer_paths.len > 0) {
        result.rootfs = result.layer_paths[result.layer_paths.len - 1];
    }

    common.saveImageRecord(ref, result.pull_result.?);

    writeErr("image pulled and extracted\n", .{});
    return result;
}
