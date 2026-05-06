const std = @import("std");
const sqlite = @import("sqlite");
const route_types = @import("services_route_types.zig");

const Allocator = std.mem.Allocator;
const ServiceHttpRouteRecord = route_types.ServiceHttpRouteRecord;

pub const ServiceRecord = struct {
    service_name: []const u8,
    vip_address: []const u8,
    lb_policy: []const u8,
    http_routes: []const ServiceHttpRouteRecord = &.{},
    http_proxy_host: ?[]const u8 = null,
    http_proxy_path_prefix: ?[]const u8 = null,
    http_proxy_rewrite_prefix: ?[]const u8 = null,
    http_proxy_retries: ?i64 = null,
    http_proxy_connect_timeout_ms: ?i64 = null,
    http_proxy_request_timeout_ms: ?i64 = null,
    http_proxy_http2_idle_timeout_ms: ?i64 = null,
    http_proxy_target_port: ?i64 = null,
    http_proxy_preserve_host: ?bool = null,
    http_proxy_retry_on_5xx: ?bool = null,
    http_proxy_circuit_breaker_threshold: ?i64 = null,
    http_proxy_circuit_breaker_timeout_ms: ?i64 = null,
    http_proxy_mirror_service: ?[]const u8 = null,
    created_at: i64,
    updated_at: i64,

    pub fn deinit(self: ServiceRecord, alloc: Allocator) void {
        alloc.free(self.service_name);
        alloc.free(self.vip_address);
        alloc.free(self.lb_policy);
        for (self.http_routes) |route| route.deinit(alloc);
        alloc.free(self.http_routes);
        if (self.http_proxy_host) |host| alloc.free(host);
        if (self.http_proxy_path_prefix) |path_prefix| alloc.free(path_prefix);
        if (self.http_proxy_rewrite_prefix) |rewrite_prefix| alloc.free(rewrite_prefix);
        if (self.http_proxy_mirror_service) |mirror_service| alloc.free(mirror_service);
    }
};

pub const service_columns =
    "service_name, vip_address, lb_policy, http_proxy_host, http_proxy_path_prefix, http_proxy_rewrite_prefix, http_proxy_retries, http_proxy_connect_timeout_ms, http_proxy_request_timeout_ms, http_proxy_http2_idle_timeout_ms, http_proxy_target_port, http_proxy_preserve_host, http_proxy_retry_on_5xx, http_proxy_circuit_breaker_threshold, http_proxy_circuit_breaker_timeout_ms, http_proxy_mirror_service, created_at, updated_at";

pub const ServiceRow = struct {
    service_name: sqlite.Text,
    vip_address: sqlite.Text,
    lb_policy: sqlite.Text,
    http_proxy_host: ?sqlite.Text,
    http_proxy_path_prefix: ?sqlite.Text,
    http_proxy_rewrite_prefix: ?sqlite.Text,
    http_proxy_retries: ?i64,
    http_proxy_connect_timeout_ms: ?i64,
    http_proxy_request_timeout_ms: ?i64,
    http_proxy_http2_idle_timeout_ms: ?i64,
    http_proxy_target_port: ?i64,
    http_proxy_preserve_host: ?i64,
    http_proxy_retry_on_5xx: ?i64,
    http_proxy_circuit_breaker_threshold: ?i64,
    http_proxy_circuit_breaker_timeout_ms: ?i64,
    http_proxy_mirror_service: ?sqlite.Text,
    created_at: i64,
    updated_at: i64,
};

pub fn rowToServiceRecord(row: ServiceRow, http_routes: []const ServiceHttpRouteRecord) ServiceRecord {
    return .{
        .service_name = row.service_name.data,
        .vip_address = row.vip_address.data,
        .lb_policy = row.lb_policy.data,
        .http_routes = http_routes,
        .http_proxy_host = if (row.http_proxy_host) |host| host.data else null,
        .http_proxy_path_prefix = if (row.http_proxy_path_prefix) |path_prefix| path_prefix.data else null,
        .http_proxy_rewrite_prefix = if (row.http_proxy_rewrite_prefix) |rewrite_prefix| rewrite_prefix.data else null,
        .http_proxy_retries = row.http_proxy_retries,
        .http_proxy_connect_timeout_ms = row.http_proxy_connect_timeout_ms,
        .http_proxy_request_timeout_ms = row.http_proxy_request_timeout_ms,
        .http_proxy_http2_idle_timeout_ms = row.http_proxy_http2_idle_timeout_ms,
        .http_proxy_target_port = row.http_proxy_target_port,
        .http_proxy_preserve_host = if (row.http_proxy_preserve_host) |preserve_host| preserve_host != 0 else null,
        .http_proxy_retry_on_5xx = if (row.http_proxy_retry_on_5xx) |retry_on_5xx| retry_on_5xx != 0 else null,
        .http_proxy_circuit_breaker_threshold = row.http_proxy_circuit_breaker_threshold,
        .http_proxy_circuit_breaker_timeout_ms = row.http_proxy_circuit_breaker_timeout_ms,
        .http_proxy_mirror_service = if (row.http_proxy_mirror_service) |mirror_service| mirror_service.data else null,
        .created_at = row.created_at,
        .updated_at = row.updated_at,
    };
}
