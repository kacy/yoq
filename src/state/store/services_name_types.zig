const std = @import("std");
const sqlite = @import("sqlite");

const Allocator = std.mem.Allocator;

pub const ServiceNameIpRow = struct {
    ip_address: sqlite.Text,
};

pub const ServiceNameRow = struct {
    name: sqlite.Text,
    container_id: sqlite.Text,
    ip_address: sqlite.Text,
    registered_at: i64,
};

pub const ServiceNameRecord = struct {
    name: []const u8,
    container_id: []const u8,
    ip_address: []const u8,
    registered_at: i64,

    pub fn deinit(self: ServiceNameRecord, alloc: Allocator) void {
        alloc.free(self.name);
        alloc.free(self.container_id);
        alloc.free(self.ip_address);
    }
};

pub fn rowToServiceNameRecord(row: ServiceNameRow) ServiceNameRecord {
    return .{
        .name = row.name.data,
        .container_id = row.container_id.data,
        .ip_address = row.ip_address.data,
        .registered_at = row.registered_at,
    };
}
