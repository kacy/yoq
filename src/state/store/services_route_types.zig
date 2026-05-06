const std = @import("std");
const sqlite = @import("sqlite");

const Allocator = std.mem.Allocator;

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

pub const ServiceHttpRouteBackendInput = struct {
    backend_service: []const u8,
    weight: i64,
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
