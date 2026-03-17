const std = @import("std");
const dockerfile = @import("../dockerfile.zig");

pub const LoadError = error{
    FileNotFound,
    ReadFailed,
    ParseFailed,
    MissingFrom,
    InvalidStep,
    EmptyManifest,
    CyclicDependency,
    OutOfMemory,
};

pub const LoadResult = struct {
    instructions: []dockerfile.Instruction,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *LoadResult) void {
        for (self.instructions) |inst| {
            self.alloc.free(inst.args);
        }
        self.alloc.free(self.instructions);
    }
};

pub const StageSpec = struct {
    name: []const u8,
    from: []const u8,
    workdir: ?[]const u8,
    env: ?[]const []const u8,
    arg: ?[]const []const u8,
    steps: ?[]const []const u8,
    expose: ?[]const []const u8,
    entrypoint: ?[]const []const u8,
    cmd: ?[]const []const u8,
    user: ?[]const u8,
    volume: ?[]const []const u8,
    shell: ?[]const []const u8,
    stopsignal: ?[]const u8,
    label: ?[]const []const u8,
    healthcheck: ?[]const u8,
};

pub const ParsedStep = struct {
    kind: dockerfile.InstructionKind,
    args: []const u8,
};
