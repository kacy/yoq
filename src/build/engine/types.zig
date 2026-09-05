const std = @import("std");
const dockerfile = @import("../dockerfile.zig");

pub const BuildError = error{
    ParseFailed,
    PullFailed,
    RunStepFailed,
    CopyStepFailed,
    LayerFailed,
    ImageStoreFailed,
    NoFromInstruction,
    CacheFailed,
    OutOfMemory,
    MetadataFailed,
};

pub const BuildResult = struct {
    manifest_digest: []const u8,
    total_size: u64,
    layer_count: usize,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *BuildResult) void {
        self.alloc.free(self.manifest_digest);
    }
};

pub const Layer = struct {
    digest: []const u8,
    diff_id: []const u8,
    size: u64,
};

pub const BuildState = struct {
    layers: std.ArrayListUnmanaged(Layer) = .empty,
    total_size: u64 = 0,

    env: std.ArrayListUnmanaged([]const u8) = .empty,
    cmd: ?[]const u8 = null,
    entrypoint: ?[]const u8 = null,
    workdir: []const u8 = "/",
    user: ?[]const u8 = null,
    exposed_ports: std.ArrayListUnmanaged([]const u8) = .empty,
    labels: std.ArrayListUnmanaged([]const u8) = .empty,
    volumes: std.ArrayListUnmanaged([]const u8) = .empty,
    shell: ?[]const u8 = null,
    stop_signal: ?[]const u8 = null,
    healthcheck: ?[]const u8 = null,

    onbuild_triggers: std.ArrayListUnmanaged([]const u8) = .empty,
    pending_onbuild: std.ArrayListUnmanaged([]const u8) = .empty,

    build_args: std.StringHashMapUnmanaged([]const u8) = .empty,

    alloc: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) BuildState {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *BuildState) void {
        for (self.layers.items) |layer| {
            self.alloc.free(layer.digest);
            self.alloc.free(layer.diff_id);
        }
        self.layers.deinit(self.alloc);
        for (self.env.items) |env_var| self.alloc.free(env_var);
        self.env.deinit(self.alloc);
        for (self.exposed_ports.items) |port| self.alloc.free(port);
        self.exposed_ports.deinit(self.alloc);
        for (self.labels.items) |label| self.alloc.free(label);
        self.labels.deinit(self.alloc);
        for (self.volumes.items) |vol| self.alloc.free(vol);
        self.volumes.deinit(self.alloc);
        if (self.cmd) |cmd| self.alloc.free(cmd);
        if (self.entrypoint) |ep| self.alloc.free(ep);
        if (!std.mem.eql(u8, self.workdir, "/")) self.alloc.free(self.workdir);
        if (self.user) |user| self.alloc.free(user);
        if (self.shell) |sh| self.alloc.free(sh);
        if (self.stop_signal) |sig| self.alloc.free(sig);
        if (self.healthcheck) |hc| self.alloc.free(hc);
        for (self.onbuild_triggers.items) |trigger| self.alloc.free(trigger);
        self.onbuild_triggers.deinit(self.alloc);
        for (self.pending_onbuild.items) |trigger| self.alloc.free(trigger);
        self.pending_onbuild.deinit(self.alloc);
        var arg_it = self.build_args.iterator();
        while (arg_it.next()) |entry| {
            self.alloc.free(entry.key_ptr.*);
            self.alloc.free(entry.value_ptr.*);
        }
        self.build_args.deinit(self.alloc);
    }

    pub fn addLayer(self: *BuildState, compressed_digest: []const u8, diff_id: []const u8, size: u64) !void {
        const total_size = try std.math.add(u64, self.total_size, size);
        const owned_digest = try self.alloc.dupe(u8, compressed_digest);
        errdefer self.alloc.free(owned_digest);
        const owned_diff_id = try self.alloc.dupe(u8, diff_id);
        errdefer self.alloc.free(owned_diff_id);
        try self.layers.ensureUnusedCapacity(self.alloc, 1);

        self.layers.appendAssumeCapacity(.{ .digest = owned_digest, .diff_id = owned_diff_id, .size = size });
        self.total_size = total_size;
    }
};

pub const BuildStage = struct {
    name: ?[]const u8,
    index: usize,
    instructions: []const dockerfile.Instruction,
};

pub const CopyArgs = struct {
    src: []const u8,
    dest: []const u8,
    from_stage: ?[]const u8,
};

pub const TriggerInstruction = struct {
    kind: dockerfile.InstructionKind,
    args: []const u8,
};

test "build identity layer ownership survives every allocation failure" {
    const Fixture = struct {
        fn run(alloc: std.mem.Allocator) !void {
            var state = BuildState.init(alloc);
            defer state.deinit();
            for (0..12) |index| {
                state.addLayer("compressed", "uncompressed", 7) catch |err| {
                    try std.testing.expectEqual(index, state.layers.items.len);
                    try std.testing.expectEqual(@as(u64, index * 7), state.total_size);
                    for (state.layers.items) |item| {
                        try std.testing.expectEqualStrings("compressed", item.digest);
                        try std.testing.expectEqualStrings("uncompressed", item.diff_id);
                        try std.testing.expectEqual(@as(u64, 7), item.size);
                    }
                    return err;
                };
            }
            try std.testing.expectEqual(@as(usize, 12), state.layers.items.len);
            try std.testing.expectEqual(@as(u64, 84), state.total_size);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Fixture.run, .{});
}
