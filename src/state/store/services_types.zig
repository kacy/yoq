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

pub const ServiceHttpRouteRecord = struct {
    service_name: []const u8,
    route_name: []const u8,
    host: []const u8,
    path_prefix: []const u8,
    rewrite_prefix: ?[]const u8 = null,
    match_methods: []const ServiceHttpRouteMethodRecord = &.{},
    match_headers: []const ServiceHttpRouteHeaderRecord = &.{},
    backend_services: []const ServiceHttpRouteBackendRecord = &.{},
    mirror_service: ?[]const u8 = null,
    retries: i64,
    connect_timeout_ms: i64,
    request_timeout_ms: i64,
    http2_idle_timeout_ms: i64,
    target_port: ?i64 = null,
    preserve_host: bool = true,
    retry_on_5xx: bool = true,
    circuit_breaker_threshold: i64 = 3,
    circuit_breaker_timeout_ms: i64 = 30000,
    route_order: i64,
    created_at: i64,
    updated_at: i64,

    pub fn deinit(self: ServiceHttpRouteRecord, alloc: Allocator) void {
        alloc.free(self.service_name);
        alloc.free(self.route_name);
        alloc.free(self.host);
        alloc.free(self.path_prefix);
        if (self.rewrite_prefix) |rewrite_prefix| alloc.free(rewrite_prefix);
        for (self.match_methods) |method_match| method_match.deinit(alloc);
        if (self.match_methods.len > 0) alloc.free(self.match_methods);
        for (self.match_headers) |header_match| header_match.deinit(alloc);
        if (self.match_headers.len > 0) alloc.free(self.match_headers);
        for (self.backend_services) |backend| backend.deinit(alloc);
        if (self.backend_services.len > 0) alloc.free(self.backend_services);
        if (self.mirror_service) |mirror_service| alloc.free(mirror_service);
    }
};

pub const ServiceHttpRouteMethodRecord = struct {
    service_name: []const u8,
    route_name: []const u8,
    method: []const u8,
    match_order: i64,
    created_at: i64,
    updated_at: i64,

    pub fn deinit(self: ServiceHttpRouteMethodRecord, alloc: Allocator) void {
        alloc.free(self.service_name);
        alloc.free(self.route_name);
        alloc.free(self.method);
    }
};

pub const ServiceHttpRouteHeaderRecord = struct {
    service_name: []const u8,
    route_name: []const u8,
    header_name: []const u8,
    header_value: []const u8,
    match_order: i64,
    created_at: i64,
    updated_at: i64,

    pub fn deinit(self: ServiceHttpRouteHeaderRecord, alloc: Allocator) void {
        alloc.free(self.service_name);
        alloc.free(self.route_name);
        alloc.free(self.header_name);
        alloc.free(self.header_value);
    }
};

pub const ServiceHttpRouteInput = struct {
    route_name: []const u8,
    host: []const u8,
    path_prefix: []const u8 = "/",
    rewrite_prefix: ?[]const u8 = null,
    match_methods: []const ServiceHttpRouteMethodInput = &.{},
    match_headers: []const ServiceHttpRouteHeaderInput = &.{},
    backend_services: []const ServiceHttpRouteBackendInput = &.{},
    mirror_service: ?[]const u8 = null,
    retries: i64 = 0,
    connect_timeout_ms: i64 = 1000,
    request_timeout_ms: i64 = 5000,
    http2_idle_timeout_ms: i64 = 30000,
    target_port: ?i64 = null,
    preserve_host: bool = true,
    retry_on_5xx: bool = true,
    circuit_breaker_threshold: i64 = 3,
    circuit_breaker_timeout_ms: i64 = 30000,
};

pub const ServiceHttpRouteMethodInput = struct {
    method: []const u8,
};

pub const ServiceHttpRouteHeaderInput = struct {
    header_name: []const u8,
    header_value: []const u8,
};

pub const ServiceHttpRouteBackendRecord = struct {
    service_name: []const u8,
    route_name: []const u8,
    backend_service: []const u8,
    weight: i64,
    backend_order: i64,
    created_at: i64,
    updated_at: i64,

    pub fn deinit(self: ServiceHttpRouteBackendRecord, alloc: Allocator) void {
        alloc.free(self.service_name);
        alloc.free(self.route_name);
        alloc.free(self.backend_service);
    }
};

pub const ServiceHttpRouteBackendInput = struct {
    backend_service: []const u8,
    weight: i64,
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

pub const service_http_route_columns =
    "service_name, route_name, host, path_prefix, rewrite_prefix, mirror_service, retries, connect_timeout_ms, request_timeout_ms, http2_idle_timeout_ms, target_port, preserve_host, retry_on_5xx, circuit_breaker_threshold, circuit_breaker_timeout_ms, route_order, created_at, updated_at";

pub const ServiceHttpRouteRow = struct {
    service_name: sqlite.Text,
    route_name: sqlite.Text,
    host: sqlite.Text,
    path_prefix: sqlite.Text,
    rewrite_prefix: ?sqlite.Text,
    mirror_service: ?sqlite.Text,
    retries: i64,
    connect_timeout_ms: i64,
    request_timeout_ms: i64,
    http2_idle_timeout_ms: i64,
    target_port: ?i64,
    preserve_host: i64,
    retry_on_5xx: i64,
    circuit_breaker_threshold: i64,
    circuit_breaker_timeout_ms: i64,
    route_order: i64,
    created_at: i64,
    updated_at: i64,
};

pub const service_http_route_method_columns =
    "service_name, route_name, method, match_order, created_at, updated_at";

pub const ServiceHttpRouteMethodRow = struct {
    service_name: sqlite.Text,
    route_name: sqlite.Text,
    method: sqlite.Text,
    match_order: i64,
    created_at: i64,
    updated_at: i64,
};

pub const service_http_route_header_columns =
    "service_name, route_name, header_name, header_value, match_order, created_at, updated_at";

pub const ServiceHttpRouteHeaderRow = struct {
    service_name: sqlite.Text,
    route_name: sqlite.Text,
    header_name: sqlite.Text,
    header_value: sqlite.Text,
    match_order: i64,
    created_at: i64,
    updated_at: i64,
};

pub const service_http_route_backend_columns =
    "service_name, route_name, backend_service, weight, backend_order, created_at, updated_at";

pub const ServiceHttpRouteBackendRow = struct {
    service_name: sqlite.Text,
    route_name: sqlite.Text,
    backend_service: sqlite.Text,
    weight: i64,
    backend_order: i64,
    created_at: i64,
    updated_at: i64,
};

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

pub fn rowToServiceHttpRouteRecord(row: ServiceHttpRouteRow) ServiceHttpRouteRecord {
    return .{
        .service_name = row.service_name.data,
        .route_name = row.route_name.data,
        .host = row.host.data,
        .path_prefix = row.path_prefix.data,
        .rewrite_prefix = if (row.rewrite_prefix) |rewrite_prefix| rewrite_prefix.data else null,
        .match_methods = &.{},
        .match_headers = &.{},
        .backend_services = &.{},
        .mirror_service = if (row.mirror_service) |mirror_service| mirror_service.data else null,
        .retries = row.retries,
        .connect_timeout_ms = row.connect_timeout_ms,
        .request_timeout_ms = row.request_timeout_ms,
        .http2_idle_timeout_ms = row.http2_idle_timeout_ms,
        .target_port = row.target_port,
        .preserve_host = row.preserve_host != 0,
        .retry_on_5xx = row.retry_on_5xx != 0,
        .circuit_breaker_threshold = row.circuit_breaker_threshold,
        .circuit_breaker_timeout_ms = row.circuit_breaker_timeout_ms,
        .route_order = row.route_order,
        .created_at = row.created_at,
        .updated_at = row.updated_at,
    };
}

pub fn rowToServiceHttpRouteMethodRecord(row: ServiceHttpRouteMethodRow) ServiceHttpRouteMethodRecord {
    return .{
        .service_name = row.service_name.data,
        .route_name = row.route_name.data,
        .method = row.method.data,
        .match_order = row.match_order,
        .created_at = row.created_at,
        .updated_at = row.updated_at,
    };
}

pub fn rowToServiceHttpRouteHeaderRecord(row: ServiceHttpRouteHeaderRow) ServiceHttpRouteHeaderRecord {
    return .{
        .service_name = row.service_name.data,
        .route_name = row.route_name.data,
        .header_name = row.header_name.data,
        .header_value = row.header_value.data,
        .match_order = row.match_order,
        .created_at = row.created_at,
        .updated_at = row.updated_at,
    };
}

pub fn rowToServiceHttpRouteBackendRecord(row: ServiceHttpRouteBackendRow) ServiceHttpRouteBackendRecord {
    return .{
        .service_name = row.service_name.data,
        .route_name = row.route_name.data,
        .backend_service = row.backend_service.data,
        .weight = row.weight,
        .backend_order = row.backend_order,
        .created_at = row.created_at,
        .updated_at = row.updated_at,
    };
}

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

pub fn rowToServiceNameRecord(row: ServiceNameRow) ServiceNameRecord {
    return .{
        .name = row.name.data,
        .container_id = row.container_id.data,
        .ip_address = row.ip_address.data,
        .registered_at = row.registered_at,
    };
}

pub fn rowToNetworkPolicyRecord(row: NetworkPolicyRow) NetworkPolicyRecord {
    return .{
        .source_service = row.source_service.data,
        .target_service = row.target_service.data,
        .action = row.action.data,
        .created_at = row.created_at,
    };
}
