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

pub const BuildState = struct {
    layer_digests: std.ArrayListUnmanaged([]const u8) = .empty,
    layer_sizes: std.ArrayListUnmanaged(u64) = .empty,
    diff_ids: std.ArrayListUnmanaged([]const u8) = .empty,
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
    parent_digest: []const u8 = "",

    alloc: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) BuildState {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *BuildState) void {
        for (self.layer_digests.items) |d| self.alloc.free(d);
        self.layer_digests.deinit(self.alloc);
        for (self.diff_ids.items) |d| self.alloc.free(d);
        self.diff_ids.deinit(self.alloc);
        self.layer_sizes.deinit(self.alloc);
        for (self.env.items) |e| self.alloc.free(e);
        self.env.deinit(self.alloc);
        self.exposed_ports.deinit(self.alloc);
        self.labels.deinit(self.alloc);
        for (self.volumes.items) |v| self.alloc.free(v);
        self.volumes.deinit(self.alloc);
        if (self.cmd) |c| self.alloc.free(c);
        if (self.entrypoint) |e| self.alloc.free(e);
        if (!std.mem.eql(u8, self.workdir, "/")) self.alloc.free(self.workdir);
        if (self.user) |u| self.alloc.free(u);
        if (self.shell) |s| self.alloc.free(s);
        if (self.stop_signal) |s| self.alloc.free(s);
        if (self.healthcheck) |h| self.alloc.free(h);
        for (self.onbuild_triggers.items) |t| self.alloc.free(t);
        self.onbuild_triggers.deinit(self.alloc);
        for (self.pending_onbuild.items) |t| self.alloc.free(t);
        self.pending_onbuild.deinit(self.alloc);
        var arg_it = self.build_args.iterator();
        while (arg_it.next()) |entry| {
            self.alloc.free(entry.key_ptr.*);
            self.alloc.free(entry.value_ptr.*);
        }
        self.build_args.deinit(self.alloc);
        if (self.parent_digest.len > 0) self.alloc.free(self.parent_digest);
    }

    pub fn addLayer(self: *BuildState, compressed_digest: []const u8, diff_id: []const u8, size: u64) !void {
        const cd = try self.alloc.dupe(u8, compressed_digest);
        errdefer self.alloc.free(cd);
        const di = try self.alloc.dupe(u8, diff_id);
        errdefer self.alloc.free(di);

        try self.layer_digests.append(self.alloc, cd);
        try self.diff_ids.append(self.alloc, di);
        try self.layer_sizes.append(self.alloc, size);
        self.total_size += size;

        if (self.parent_digest.len > 0) self.alloc.free(self.parent_digest);
        self.parent_digest = try self.alloc.dupe(u8, compressed_digest);
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
