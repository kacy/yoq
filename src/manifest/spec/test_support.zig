const std = @import("std");
const shared_types = @import("shared_types.zig");
const workloads = @import("workloads.zig");

pub fn testTrainingJob(alloc: std.mem.Allocator, name: []const u8) !workloads.TrainingJob {
    return .{
        .name = try alloc.dupe(u8, name),
        .image = try alloc.dupe(u8, "scratch"),
        .command = try alloc.alloc([]const u8, 0),
        .env = try alloc.alloc([]const u8, 0),
        .working_dir = null,
        .volumes = try alloc.alloc(shared_types.VolumeMount, 0),
        .gpus = 1,
    };
}

pub fn testService(alloc: std.mem.Allocator, name: []const u8) !workloads.Service {
    return .{
        .name = try alloc.dupe(u8, name),
        .image = try alloc.dupe(u8, "scratch"),
        .command = try alloc.alloc([]const u8, 0),
        .ports = try alloc.alloc(shared_types.PortMapping, 0),
        .env = try alloc.alloc([]const u8, 0),
        .depends_on = try alloc.alloc([]const u8, 0),
        .working_dir = null,
        .volumes = try alloc.alloc(shared_types.VolumeMount, 0),
        .health_check = null,
        .http_routes = try alloc.alloc(shared_types.HttpProxyRoute, 0),
    };
}
