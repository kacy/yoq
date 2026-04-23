const std = @import("std");
const platform = @import("platform");
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
) ![]u8 {
    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();

    const writer = &json_buf_writer.writer;

    try writer.writeAll("{\"token\":\"");
    try json_helpers.writeJsonEscaped(writer, token);
    try writer.writeAll("\",\"address\":\"");
    try json_helpers.writeJsonEscaped(writer, address);
    try writer.writeAll("\",\"agent_api_port\":");
    try writer.print("{d}", .{agent_api_port});
    try writer.writeAll(",\"cpu_cores\":");
    try writer.print("{d}", .{resources.cpu_cores});
    try writer.writeAll(",\"memory_mb\":");
    try writer.print("{d}", .{resources.memory_mb});
    try writer.writeAll(",\"wg_public_key\":\"");
    try json_helpers.writeJsonEscaped(writer, pub_key);
    try writer.writeAll("\",\"wg_listen_port\":");
    try writer.print("{d}", .{wg_listen_port});
    try writer.writeAll(",\"role\":\"");
    try json_helpers.writeJsonEscaped(writer, role.toString());
    try writer.writeByte('"');

    if (region) |reg| {
        try writer.writeAll(",\"region\":\"");
        try json_helpers.writeJsonEscaped(writer, reg);
        try writer.writeByte('"');
    }

    if (resources.gpu_count > 0) {
        try writer.writeAll(",\"gpu_count\":");
        try writer.print("{d}", .{resources.gpu_count});
        try writer.writeAll(",\"gpu_vram_mb\":");
        try writer.print("{d}", .{resources.gpu_vram_mb});

        if (resources.gpu_model) |model| {
            try writer.writeAll(",\"gpu_model\":\"");
            try json_helpers.writeJsonEscaped(writer, model);
            try writer.writeByte('"');
        }
    }

    try writer.writeByte('}');
    return try json_buf_writer.toOwnedSlice();
}

pub fn buildHeartbeatBody(alloc: Allocator, resources: AgentResources, gpu_health_label: []const u8) ![]u8 {
    var json_buf_writer = std.Io.Writer.Allocating.init(alloc);
    defer json_buf_writer.deinit();

    const writer = &json_buf_writer.writer;

    try writer.writeAll("{\"cpu_cores\":");
    try writer.print("{d}", .{resources.cpu_cores});
    try writer.writeAll(",\"memory_mb\":");
    try writer.print("{d}", .{resources.memory_mb});
    try writer.writeAll(",\"cpu_used\":");
    try writer.print("{d}", .{resources.cpu_used});
    try writer.writeAll(",\"memory_used_mb\":");
    try writer.print("{d}", .{resources.memory_used_mb});
    try writer.writeAll(",\"containers\":");
    try writer.print("{d}", .{resources.containers});
    try writer.writeAll(",\"gpu_count\":");
    try writer.print("{d}", .{resources.gpu_count});
    try writer.writeAll(",\"gpu_used\":");
    try writer.print("{d}", .{resources.gpu_used});
    try writer.writeAll(",\"gpu_health\":\"");
    try json_helpers.writeJsonEscaped(writer, gpu_health_label);
    try writer.writeAll("\"}");

    return try json_buf_writer.toOwnedSlice();
}

pub fn parseHostPort(s: []const u8) ?struct { addr: [4]u8, port: u16 } {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    const addr = ip_mod.parseIp(s[0..colon]) orelse return null;
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return null;
    return .{ .addr = addr, .port = port };
}
