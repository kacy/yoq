const std = @import("std");
const sqlite = @import("sqlite");

const Allocator = std.mem.Allocator;

pub const ServiceEndpointRecord = struct {
    service_name: []const u8,
    endpoint_id: []const u8,
    container_id: []const u8,
    node_id: ?i64,
    ip_address: []const u8,
    port: i64,
    weight: i64,
    admin_state: []const u8,
    generation: i64,
    registered_at: i64,
    last_seen_at: i64,

    pub fn deinit(self: ServiceEndpointRecord, alloc: Allocator) void {
        alloc.free(self.service_name);
        alloc.free(self.endpoint_id);
        alloc.free(self.container_id);
        alloc.free(self.ip_address);
        alloc.free(self.admin_state);
    }
};

pub const endpoint_columns =
    "service_name, endpoint_id, container_id, node_id, ip_address, port, weight, admin_state, generation, registered_at, last_seen_at";

pub const ServiceEndpointRow = struct {
    service_name: sqlite.Text,
    endpoint_id: sqlite.Text,
    container_id: sqlite.Text,
    node_id: ?i64,
    ip_address: sqlite.Text,
    port: i64,
    weight: i64,
    admin_state: sqlite.Text,
    generation: i64,
    registered_at: i64,
    last_seen_at: i64,
};

pub fn rowToServiceEndpointRecord(row: ServiceEndpointRow) ServiceEndpointRecord {
    return .{
        .service_name = row.service_name.data,
        .endpoint_id = row.endpoint_id.data,
        .container_id = row.container_id.data,
        .node_id = row.node_id,
        .ip_address = row.ip_address.data,
        .port = row.port,
        .weight = row.weight,
        .admin_state = row.admin_state.data,
        .generation = row.generation,
        .registered_at = row.registered_at,
        .last_seen_at = row.last_seen_at,
    };
}
