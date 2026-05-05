const std = @import("std");
const sqlite = @import("sqlite");

const Allocator = std.mem.Allocator;

pub const NetworkPolicyRecord = struct {
    source_service: []const u8,
    target_service: []const u8,
    action: []const u8,
    created_at: i64,

    pub fn deinit(self: NetworkPolicyRecord, alloc: Allocator) void {
        alloc.free(self.source_service);
        alloc.free(self.target_service);
        alloc.free(self.action);
    }
};

pub const NetworkPolicyRow = struct {
    source_service: sqlite.Text,
    target_service: sqlite.Text,
    action: sqlite.Text,
    created_at: i64,
};

pub fn rowToNetworkPolicyRecord(row: NetworkPolicyRow) NetworkPolicyRecord {
    return .{
        .source_service = row.source_service.data,
        .target_service = row.target_service.data,
        .action = row.action.data,
        .created_at = row.created_at,
    };
}
