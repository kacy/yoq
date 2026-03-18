const std = @import("std");
const agent_types = @import("../agent_types.zig");
const common = @import("common.zig");

pub const AgentRecord = agent_types.AgentRecord;
pub const VolumeConstraint = common.VolumeConstraint;

pub fn matchesLabels(agent_labels: []const u8, required: []const u8) bool {
    if (required.len == 0) return true;

    var req_iter = std.mem.splitScalar(u8, required, ',');
    while (req_iter.next()) |req_label| {
        const trimmed = std.mem.trim(u8, req_label, " ");
        if (trimmed.len == 0) continue;

        var found = false;
        var agent_iter = std.mem.splitScalar(u8, agent_labels, ',');
        while (agent_iter.next()) |agent_label| {
            const agent_trimmed = std.mem.trim(u8, agent_label, " ");
            if (std.mem.eql(u8, agent_trimmed, trimmed)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

pub fn matchesVolumeConstraints(agent: AgentRecord, constraints: []const VolumeConstraint) bool {
    for (constraints) |constraint| {
        const required_node = constraint.node_id orelse continue;
        if (agent.node_id) |agent_node_id| {
            var agent_node_buf: [32]u8 = undefined;
            const agent_node_str = std.fmt.bufPrint(&agent_node_buf, "{d}", .{agent_node_id}) catch return false;
            if (!std.mem.eql(u8, agent_node_str, required_node)) return false;
        } else {
            return false;
        }
    }
    return true;
}
