const common = @import("common.zig");

pub fn subnetForNode(node_id: u16) common.IpError!common.SubnetConfig {
    if (node_id == 0) {
        return .{
            .node_id = 0,
            .base = .{ 10, 42, 0, 0 },
            .gateway = .{ 10, 42, 0, 1 },
            .prefix_len = 16,
            .range_start = .{ 10, 42, 0, 2 },
            .range_end = .{ 10, 42, 255, 254 },
        };
    }

    if (node_id <= 254) {
        const nid: u8 = @intCast(node_id);
        return .{
            .node_id = node_id,
            .base = .{ 10, 42, nid, 0 },
            .gateway = .{ 10, 42, nid, 1 },
            .prefix_len = 24,
            .range_start = .{ 10, 42, nid, 2 },
            .range_end = .{ 10, 42, nid, 254 },
        };
    }

    const offset = node_id >> 8;
    if (offset > (255 - 42)) return common.IpError.AllocationFailed;
    const high: u8 = @intCast(@as(u16, 42) + offset);
    const low: u8 = @intCast(node_id & 0xFF);
    return .{
        .node_id = node_id,
        .base = .{ 10, high, low, 0 },
        .gateway = .{ 10, high, low, 1 },
        .prefix_len = 24,
        .range_start = .{ 10, high, low, 2 },
        .range_end = .{ 10, high, low, 254 },
    };
}
