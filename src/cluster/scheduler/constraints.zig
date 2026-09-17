const std = @import("std");
const agent_types = @import("../agent_types.zig");
const common = @import("common.zig");

pub const AgentRecord = agent_types.AgentRecord;
pub const VolumeConstraint = common.VolumeConstraint;

pub fn matchesLabels(agent_labels: []const u8, required: []const u8) bool {
    if (required.len == 0) return true;

    var required_labels = std.mem.splitScalar(u8, required, ',');
    while (required_labels.next()) |label| {
        const required_label = std.mem.trim(u8, label, " ");
        if (required_label.len == 0) continue;
        if (!containsLabel(agent_labels, required_label)) return false;
    }
    return true;
}

fn containsLabel(agent_labels: []const u8, required_label: []const u8) bool {
    var labels = std.mem.splitScalar(u8, agent_labels, ',');
    while (labels.next()) |label| {
        const agent_label = std.mem.trim(u8, label, " ");
        if (std.mem.eql(u8, agent_label, required_label)) return true;
    }
    return false;
}

pub fn matchesVolumeConstraints(agent: AgentRecord, constraints: []const VolumeConstraint) bool {
    for (constraints) |constraint| {
        const required_node = constraint.node_id orelse continue;
        const agent_node_id = agent.node_id orelse return false;
        var node_buf: [32]u8 = undefined;
        const node_text = std.fmt.bufPrint(&node_buf, "{d}", .{agent_node_id}) catch return false;
        if (!std.mem.eql(u8, node_text, required_node)) return false;
    }
    return true;
}
