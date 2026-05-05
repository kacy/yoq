const std = @import("std");
const common = @import("common.zig");
const service_core = @import("services_core.zig");
const service_endpoints = @import("services_endpoints.zig");
const service_names = @import("services_names.zig");
const service_policies = @import("services_policies.zig");
const service_types = @import("services_types.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

pub const ServiceNameRecord = service_types.ServiceNameRecord;
pub const ServiceRecord = service_types.ServiceRecord;
pub const ServiceHttpRouteRecord = service_types.ServiceHttpRouteRecord;
pub const ServiceHttpRouteMethodRecord = service_types.ServiceHttpRouteMethodRecord;
pub const ServiceHttpRouteHeaderRecord = service_types.ServiceHttpRouteHeaderRecord;
pub const ServiceHttpRouteInput = service_types.ServiceHttpRouteInput;
pub const ServiceHttpRouteMethodInput = service_types.ServiceHttpRouteMethodInput;
pub const ServiceHttpRouteHeaderInput = service_types.ServiceHttpRouteHeaderInput;
pub const ServiceHttpRouteBackendRecord = service_types.ServiceHttpRouteBackendRecord;
pub const ServiceHttpRouteBackendInput = service_types.ServiceHttpRouteBackendInput;
pub const ServiceEndpointRecord = service_types.ServiceEndpointRecord;
pub const NetworkPolicyRecord = service_types.NetworkPolicyRecord;

pub fn createService(record: ServiceRecord) StoreError!void {
    return service_core.create(record);
}

pub fn ensureService(alloc: Allocator, service_name: []const u8, lb_policy: []const u8) StoreError!ServiceRecord {
    return service_core.ensure(alloc, service_name, lb_policy);
}

pub fn syncServiceConfig(
    alloc: Allocator,
    service_name: []const u8,
    lb_policy: []const u8,
    routes: []const ServiceHttpRouteInput,
) StoreError!ServiceRecord {
    return service_core.syncConfig(alloc, service_name, lb_policy, routes);
}

pub fn getService(alloc: Allocator, service_name: []const u8) StoreError!ServiceRecord {
    return service_core.get(alloc, service_name);
}

pub fn listServices(alloc: Allocator) StoreError!std.ArrayList(ServiceRecord) {
    return service_core.list(alloc);
}

pub fn getServiceEndpoint(alloc: Allocator, service_name: []const u8, endpoint_id: []const u8) StoreError!ServiceEndpointRecord {
    return service_endpoints.get(alloc, service_name, endpoint_id);
}

pub fn upsertServiceEndpoint(record: ServiceEndpointRecord) StoreError!void {
    return service_endpoints.upsert(record);
}

pub fn removeServiceEndpoint(service_name: []const u8, endpoint_id: []const u8) StoreError!void {
    return service_endpoints.remove(service_name, endpoint_id);
}

pub fn markServiceEndpointAdminState(service_name: []const u8, endpoint_id: []const u8, admin_state: []const u8) StoreError!void {
    return service_endpoints.markAdminState(service_name, endpoint_id, admin_state);
}

pub fn listServiceEndpoints(alloc: Allocator, service_name: []const u8) StoreError!std.ArrayList(ServiceEndpointRecord) {
    return service_endpoints.list(alloc, service_name);
}

pub fn listServiceEndpointsByNode(alloc: Allocator, node_id: i64) StoreError!std.ArrayList(ServiceEndpointRecord) {
    return service_endpoints.listByNode(alloc, node_id);
}

pub fn removeServiceEndpointsByContainer(container_id: []const u8) StoreError!void {
    return service_endpoints.removeByContainer(container_id);
}

pub fn removeServiceEndpointsByNode(node_id: i64) StoreError!void {
    return service_endpoints.removeByNode(node_id);
}

pub fn registerServiceName(name: []const u8, container_id: []const u8, ip_address: []const u8) StoreError!void {
    return service_names.register(name, container_id, ip_address);
}

pub fn unregisterServiceName(container_id: []const u8) StoreError!void {
    return service_names.unregister(container_id);
}

pub fn removeServiceNamesByName(name: []const u8) StoreError!void {
    return service_names.removeByName(name);
}

pub fn lookupServiceNames(alloc: Allocator, name: []const u8) StoreError!std.ArrayList([]const u8) {
    return service_names.lookupNames(alloc, name);
}

pub fn lookupServiceAddresses(alloc: Allocator, name: []const u8) StoreError!std.ArrayList([]const u8) {
    return service_names.lookupAddresses(alloc, name);
}

pub fn listServiceNames(alloc: Allocator) StoreError!std.ArrayList(ServiceNameRecord) {
    return service_names.list(alloc);
}

pub fn addNetworkPolicy(source: []const u8, target: []const u8, action: []const u8) StoreError!void {
    return service_policies.add(source, target, action);
}

pub fn removeNetworkPolicy(source: []const u8, target: []const u8) StoreError!void {
    return service_policies.remove(source, target);
}

pub fn listNetworkPolicies(alloc: Allocator) StoreError!std.ArrayList(NetworkPolicyRecord) {
    return service_policies.list(alloc);
}

pub fn getServicePolicies(alloc: Allocator, source: []const u8) StoreError!std.ArrayList(NetworkPolicyRecord) {
    return service_policies.listForSource(alloc, source);
}
