const std = @import("std");
const json_helpers = @import("../../lib/json_helpers.zig");
const ip_mod = @import("../../network/ip.zig");
const agent_types = @import("../agent_types.zig");
const cluster_config = @import("../config.zig");

const Allocator = std.mem.Allocator;
const AgentResources = agent_types.AgentResources;

pub fn buildRegisterBody(
    alloc: Allocator,
    token: []const u8,
    address: []const u8,
    agent_api_port: u16,
    resources: AgentResources,
    pub_key: []const u8,
    wg_listen_port: u16,
    role: cluster_config.NodeRole,
    region: ?[]const u8,
    registration_key: ?[]const u8,
) ![]u8 {
    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();

    const writer = &json_buf_writer.writer;

    try writer.writeByte('{');
    try json_helpers.writeJsonStringField(writer, "token", token);
    if (registration_key) |key| {
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "registration_key", key);
    }
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "address", address);
    try writer.print(",\"agent_api_port\":{d}", .{agent_api_port});
    try writer.print(",\"cpu_cores\":{d}", .{resources.cpu_cores});
    try writer.print(",\"memory_mb\":{d}", .{resources.memory_mb});
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "wg_public_key", pub_key);
    try writer.print(",\"wg_listen_port\":{d}", .{wg_listen_port});
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "role", role.toString());

    if (region) |name| {
        try writer.writeByte(',');
        try json_helpers.writeJsonStringField(writer, "region", name);
    }

    // registration includes gpu details only when at least one gpu was detected.
    if (resources.gpu_count > 0) {
        try writer.print(",\"gpu_count\":{d}", .{resources.gpu_count});
        try writer.print(",\"gpu_vram_mb\":{d}", .{resources.gpu_vram_mb});

        if (resources.gpu_model) |model| {
            try writer.writeByte(',');
            try json_helpers.writeJsonStringField(writer, "gpu_model", model);
        }
    }

    try writer.writeByte('}');
    return try json_buf_writer.toOwnedSlice();
}

pub fn buildHeartbeatBody(alloc: Allocator, resources: AgentResources, gpu_health_label: []const u8) ![]u8 {
    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();

    const writer = &json_buf_writer.writer;

    try writer.writeByte('{');
    try writer.print("\"cpu_cores\":{d}", .{resources.cpu_cores});
    try writer.print(",\"memory_mb\":{d}", .{resources.memory_mb});
    try writer.print(",\"cpu_used\":{d}", .{resources.cpu_used});
    try writer.print(",\"memory_used_mb\":{d}", .{resources.memory_used_mb});
    try writer.print(",\"containers\":{d}", .{resources.containers});
    try writer.print(",\"gpu_count\":{d}", .{resources.gpu_count});
    try writer.print(",\"gpu_used\":{d}", .{resources.gpu_used});
    try writer.writeByte(',');
    try json_helpers.writeJsonStringField(writer, "gpu_health", gpu_health_label);
    try writer.writeByte('}');

    return try json_buf_writer.toOwnedSlice();
}

pub fn parseHostPort(s: []const u8) ?struct { addr: [4]u8, port: u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    const addr = ip_mod.parseIp(s[0..colon]) orelse return null;
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return null;
    return .{ .addr = addr, .port = port };
}
