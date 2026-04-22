const std = @import("std");
const platform = @import("platform");
const agent_registry = @import("../../../cluster/registry.zig");
const json_helpers = @import("../../../lib/json_helpers.zig");

pub fn writeAgentJson(writer: anytype, agent: agent_registry.AgentRecord) !void {
    try writer.writeAll("{\"id\":\"");
    try writer.writeAll(agent.id);
    try writer.writeAll("\",\"address\":\"");
    try json_helpers.writeJsonEscaped(writer, agent.address);
    try writer.writeAll("\",\"status\":\"");
    try writer.writeAll(agent.status);
    try writer.writeByte('"');
    if (agent.agent_api_port) |port| {
        try writer.writeAll(",\"agent_api_port\":");
        try platform.format(writer, "{d}", .{port});
    }
    try writer.writeAll(",\"cpu_cores\":");
    try platform.format(writer, "{d}", .{agent.cpu_cores});
    try writer.writeAll(",\"memory_mb\":");
    try platform.format(writer, "{d}", .{agent.memory_mb});
    try writer.writeAll(",\"cpu_used\":");
    try platform.format(writer, "{d}", .{agent.cpu_used});
    try writer.writeAll(",\"memory_used_mb\":");
    try platform.format(writer, "{d}", .{agent.memory_used_mb});
    try writer.writeAll(",\"containers\":");
    try platform.format(writer, "{d}", .{agent.containers});
    try writer.writeAll(",\"last_heartbeat\":");
    try platform.format(writer, "{d}", .{agent.last_heartbeat});

    if (agent.node_id) |nid| {
        try writer.writeAll(",\"node_id\":");
        try platform.format(writer, "{d}", .{nid});
    }
    if (agent.wg_public_key) |key| {
        try writer.writeAll(",\"wg_public_key\":\"");
        try json_helpers.writeJsonEscaped(writer, key);
        try writer.writeByte('"');
    }
    if (agent.overlay_ip) |oip| {
        try writer.writeAll(",\"overlay_ip\":\"");
        try json_helpers.writeJsonEscaped(writer, oip);
        try writer.writeByte('"');
    }
    if (agent.role) |r| {
        try writer.writeAll(",\"role\":\"");
        try json_helpers.writeJsonEscaped(writer, r);
        try writer.writeByte('"');
    }
    if (agent.region) |reg| {
        try writer.writeAll(",\"region\":\"");
        try json_helpers.writeJsonEscaped(writer, reg);
        try writer.writeByte('"');
    }
    if (agent.labels) |labels| {
        try writer.writeAll(",\"labels\":\"");
        try json_helpers.writeJsonEscaped(writer, labels);
        try writer.writeByte('"');
    }
    if (agent.gpu_count != 0) {
        try writer.writeAll(",\"gpu_count\":");
        try platform.format(writer, "{d}", .{agent.gpu_count});
    }
    if (agent.gpu_used != 0) {
        try writer.writeAll(",\"gpu_used\":");
        try platform.format(writer, "{d}", .{agent.gpu_used});
    }
    if (agent.gpu_model) |model| {
        try writer.writeAll(",\"gpu_model\":\"");
        try json_helpers.writeJsonEscaped(writer, model);
        try writer.writeByte('"');
    }
    if (agent.gpu_vram_mb) |vram| {
        try writer.writeAll(",\"gpu_vram_mb\":");
        try platform.format(writer, "{d}", .{vram});
    }
    if (agent.rdma_capable) {
        try writer.writeAll(",\"rdma_capable\":true");
    }

    try writer.writeByte('}');
}

pub fn writeAssignmentJson(writer: anytype, assignment: agent_registry.Assignment) !void {
    try writer.writeAll("{\"id\":\"");
    try writer.writeAll(assignment.id);
    try writer.writeAll("\",\"agent_id\":\"");
    try writer.writeAll(assignment.agent_id);
    try writer.writeAll("\",\"image\":\"");
    try json_helpers.writeJsonEscaped(writer, assignment.image);
    try writer.writeAll("\",\"command\":\"");
    try json_helpers.writeJsonEscaped(writer, assignment.command);
    try writer.writeAll("\",\"status\":\"");
    try writer.writeAll(assignment.status);
    if (assignment.status_reason) |status_reason| {
        try writer.writeAll("\",\"status_reason\":\"");
        try json_helpers.writeJsonEscaped(writer, status_reason);
    }
    try writer.writeAll("\",\"cpu_limit\":");
    try platform.format(writer, "{d}", .{assignment.cpu_limit});
    try writer.writeAll(",\"memory_limit_mb\":");
    try platform.format(writer, "{d}", .{assignment.memory_limit_mb});
    if (assignment.app_name) |app_name| {
        try writer.writeAll(",\"app_name\":\"");
        try json_helpers.writeJsonEscaped(writer, app_name);
        try writer.writeByte('"');
    }
    if (assignment.workload_kind) |workload_kind| {
        try writer.writeAll(",\"workload_kind\":\"");
        try json_helpers.writeJsonEscaped(writer, workload_kind);
        try writer.writeByte('"');
    }
    if (assignment.workload_name) |workload_name| {
        try writer.writeAll(",\"workload_name\":\"");
        try json_helpers.writeJsonEscaped(writer, workload_name);
        try writer.writeByte('"');
    }
    if (assignment.health_check_json) |health_check_json| {
        try writer.writeAll(",\"health_check\":");
        try writer.writeAll(health_check_json);
    }
    if (assignment.gang_rank) |rank| {
        try writer.writeAll(",\"gang_rank\":");
        try platform.format(writer, "{d}", .{rank});
    }
    if (assignment.gang_world_size) |ws| {
        try writer.writeAll(",\"gang_world_size\":");
        try platform.format(writer, "{d}", .{ws});
    }
    if (assignment.gang_master_addr) |addr| {
        try writer.writeAll(",\"gang_master_addr\":\"");
        try json_helpers.writeJsonEscaped(writer, addr);
        try writer.writeByte('"');
    }
    if (assignment.gang_master_port) |port| {
        try writer.writeAll(",\"gang_master_port\":");
        try platform.format(writer, "{d}", .{port});
    }
    try writer.writeByte('}');
}

pub fn writeWireguardPeerJson(writer: anytype, peer: agent_registry.WireguardPeer) !void {
    try writer.writeAll("{\"node_id\":");
    try platform.format(writer, "{d}", .{peer.node_id});
    try writer.writeAll(",\"agent_id\":\"");
    try json_helpers.writeJsonEscaped(writer, peer.agent_id);
    try writer.writeAll("\",\"public_key\":\"");
    try json_helpers.writeJsonEscaped(writer, peer.public_key);
    try writer.writeAll("\",\"endpoint\":\"");
    try json_helpers.writeJsonEscaped(writer, peer.endpoint);
    try writer.writeAll("\",\"overlay_ip\":\"");
    try json_helpers.writeJsonEscaped(writer, peer.overlay_ip);
    try writer.writeAll("\",\"container_subnet\":\"");
    try json_helpers.writeJsonEscaped(writer, peer.container_subnet);
    try writer.writeAll("\"}");
}
