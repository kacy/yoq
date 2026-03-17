const std = @import("std");
const spec = @import("../spec.zig");

pub const LoadError = error{
    FileNotFound,
    ReadFailed,
    ParseFailed,
    MissingImage,
    InvalidPortMapping,
    InvalidEnvVar,
    InvalidVolumeMount,
    InvalidHealthCheck,
    InvalidRestartPolicy,
    InvalidTlsConfig,
    InvalidVolumeConfig,
    UnknownDependency,
    CircularDependency,
    NoServices,
    InvalidSchedule,
    InvalidTrainingConfig,
    OutOfMemory,
};

pub const CommonFields = struct {
    image: []const u8,
    command: []const []const u8,
    env: []const []const u8,
    volumes: []const spec.VolumeMount,
    working_dir: ?[]const u8,

    pub fn deinit(self: CommonFields, alloc: std.mem.Allocator) void {
        alloc.free(self.image);
        for (self.command) |cmd| alloc.free(cmd);
        alloc.free(self.command);
        for (self.env) |env_var| alloc.free(env_var);
        alloc.free(self.env);
        for (self.volumes) |volume| volume.deinit(alloc);
        alloc.free(self.volumes);
        if (self.working_dir) |working_dir| alloc.free(working_dir);
    }
};
