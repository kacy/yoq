const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const schema = @import("../schema.zig");
const service_observability = @import("../../network/service_observability.zig");
const vip_allocator = @import("../../network/vip_allocator.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

const ServiceNameIpRow = struct {
    ip_address: sqlite.Text,
};

const ServiceNameRow = struct {
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
    http_proxy_target_port: ?i64 = null,
    http_proxy_preserve_host: ?bool = null,
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
    }
};

pub const ServiceHttpRouteRecord = struct {
    service_name: []const u8,
    route_name: []const u8,
    host: []const u8,
    path_prefix: []const u8,
    rewrite_prefix: ?[]const u8 = null,
    retries: i64,
    connect_timeout_ms: i64,
    request_timeout_ms: i64,
    target_port: ?i64 = null,
    preserve_host: bool = true,
    route_order: i64,
    created_at: i64,
    updated_at: i64,

    pub fn deinit(self: ServiceHttpRouteRecord, alloc: Allocator) void {
        alloc.free(self.service_name);
        alloc.free(self.route_name);
        alloc.free(self.host);
        alloc.free(self.path_prefix);
        if (self.rewrite_prefix) |rewrite_prefix| alloc.free(rewrite_prefix);
    }
};

pub const ServiceHttpRouteInput = struct {
    route_name: []const u8,
    host: []const u8,
    path_prefix: []const u8 = "/",
    rewrite_prefix: ?[]const u8 = null,
    retries: i64 = 0,
    connect_timeout_ms: i64 = 1000,
    request_timeout_ms: i64 = 5000,
    target_port: ?i64 = null,
    preserve_host: bool = true,
};

const service_columns =
    "service_name, vip_address, lb_policy, http_proxy_host, http_proxy_path_prefix, http_proxy_rewrite_prefix, http_proxy_retries, http_proxy_connect_timeout_ms, http_proxy_request_timeout_ms, http_proxy_target_port, http_proxy_preserve_host, created_at, updated_at";

const ServiceRow = struct {
    service_name: sqlite.Text,
    vip_address: sqlite.Text,
    lb_policy: sqlite.Text,
    http_proxy_host: ?sqlite.Text,
    http_proxy_path_prefix: ?sqlite.Text,
    http_proxy_rewrite_prefix: ?sqlite.Text,
    http_proxy_retries: ?i64,
    http_proxy_connect_timeout_ms: ?i64,
    http_proxy_request_timeout_ms: ?i64,
    http_proxy_target_port: ?i64,
    http_proxy_preserve_host: ?i64,
    created_at: i64,
    updated_at: i64,
};

const service_http_route_columns =
    "service_name, route_name, host, path_prefix, rewrite_prefix, retries, connect_timeout_ms, request_timeout_ms, target_port, preserve_host, route_order, created_at, updated_at";

const ServiceHttpRouteRow = struct {
    service_name: sqlite.Text,
    route_name: sqlite.Text,
    host: sqlite.Text,
    path_prefix: sqlite.Text,
    rewrite_prefix: ?sqlite.Text,
    retries: i64,
    connect_timeout_ms: i64,
    request_timeout_ms: i64,
    target_port: ?i64,
    preserve_host: i64,
    route_order: i64,
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

const endpoint_columns =
    "service_name, endpoint_id, container_id, node_id, ip_address, port, weight, admin_state, generation, registered_at, last_seen_at";

const ServiceEndpointRow = struct {
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

const NetworkPolicyRow = struct {
    source_service: sqlite.Text,
    target_service: sqlite.Text,
    action: sqlite.Text,
    created_at: i64,
};

fn rowToServiceRecord(row: ServiceRow, http_routes: []const ServiceHttpRouteRecord) ServiceRecord {
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
        .http_proxy_target_port = row.http_proxy_target_port,
        .http_proxy_preserve_host = if (row.http_proxy_preserve_host) |preserve_host| preserve_host != 0 else null,
        .created_at = row.created_at,
        .updated_at = row.updated_at,
    };
}

fn rowToServiceHttpRouteRecord(row: ServiceHttpRouteRow) ServiceHttpRouteRecord {
    return .{
        .service_name = row.service_name.data,
        .route_name = row.route_name.data,
        .host = row.host.data,
        .path_prefix = row.path_prefix.data,
        .rewrite_prefix = if (row.rewrite_prefix) |rewrite_prefix| rewrite_prefix.data else null,
        .retries = row.retries,
        .connect_timeout_ms = row.connect_timeout_ms,
        .request_timeout_ms = row.request_timeout_ms,
        .target_port = row.target_port,
        .preserve_host = row.preserve_host != 0,
        .route_order = row.route_order,
        .created_at = row.created_at,
        .updated_at = row.updated_at,
    };
}

fn listServiceHttpRoutesForDb(alloc: Allocator, db: *sqlite.Db, service_name: []const u8) StoreError![]const ServiceHttpRouteRecord {
    var routes: std.ArrayList(ServiceHttpRouteRecord) = .empty;
    errdefer {
        for (routes.items) |route| route.deinit(alloc);
        routes.deinit(alloc);
    }
    var stmt = db.prepare(
        "SELECT " ++ service_http_route_columns ++ " FROM service_http_routes WHERE service_name = ? ORDER BY route_order, route_name;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(ServiceHttpRouteRow, .{service_name}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        routes.append(alloc, rowToServiceHttpRouteRecord(row)) catch return StoreError.ReadFailed;
    }
    return routes.toOwnedSlice(alloc) catch return StoreError.ReadFailed;
}

fn syncDerivedServiceProxyFields(
    db: *sqlite.Db,
    service_name: []const u8,
    now: i64,
    routes: []const ServiceHttpRouteInput,
) StoreError!void {
    const primary = if (routes.len > 0) routes[0] else null;
    db.exec(
        "UPDATE services SET lb_policy = lb_policy, http_proxy_host = ?, http_proxy_path_prefix = ?, http_proxy_rewrite_prefix = ?, http_proxy_retries = ?, http_proxy_connect_timeout_ms = ?, http_proxy_request_timeout_ms = ?, http_proxy_target_port = ?, http_proxy_preserve_host = ?, updated_at = ? WHERE service_name = ?;",
        .{},
        .{
            if (primary) |route| route.host else null,
            if (primary) |route| route.path_prefix else null,
            if (primary) |route| route.rewrite_prefix else null,
            if (primary) |route| route.retries else null,
            if (primary) |route| route.connect_timeout_ms else null,
            if (primary) |route| route.request_timeout_ms else null,
            if (primary) |route| route.target_port else null,
            if (primary) |route| @as(i64, @intFromBool(route.preserve_host)) else null,
            now,
            service_name,
        },
    ) catch return StoreError.WriteFailed;
}

fn replaceServiceHttpRoutes(
    db: *sqlite.Db,
    service_name: []const u8,
    now: i64,
    routes: []const ServiceHttpRouteInput,
) StoreError!void {
    db.exec(
        "DELETE FROM service_http_routes WHERE service_name = ?;",
        .{},
        .{service_name},
    ) catch return StoreError.WriteFailed;

    for (routes, 0..) |route, idx| {
        db.exec(
            "INSERT INTO service_http_routes (" ++ service_http_route_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            .{},
            .{
                service_name,
                route.route_name,
                route.host,
                route.path_prefix,
                route.rewrite_prefix,
                route.retries,
                route.connect_timeout_ms,
                route.request_timeout_ms,
                route.target_port,
                @as(i64, @intFromBool(route.preserve_host)),
                @as(i64, @intCast(idx)),
                now,
                now,
            },
        ) catch return StoreError.WriteFailed;
    }
}

fn rowToServiceEndpointRecord(row: ServiceEndpointRow) ServiceEndpointRecord {
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

fn rowToServiceNameRecord(row: ServiceNameRow) ServiceNameRecord {
    return .{
        .name = row.name.data,
        .container_id = row.container_id.data,
        .ip_address = row.ip_address.data,
        .registered_at = row.registered_at,
    };
}

pub fn createService(record: ServiceRecord) StoreError!void {
    const db = try common.getDb();
    db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return StoreError.WriteFailed;
    var committed = false;
    errdefer if (!committed) db.exec("ROLLBACK;", .{}, .{}) catch {};
    db.exec(
        "INSERT INTO services (" ++ service_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
        .{},
        .{
            record.service_name,
            record.vip_address,
            record.lb_policy,
            record.http_proxy_host,
            record.http_proxy_path_prefix,
            record.http_proxy_rewrite_prefix,
            record.http_proxy_retries,
            record.http_proxy_connect_timeout_ms,
            record.http_proxy_request_timeout_ms,
            record.http_proxy_target_port,
            if (record.http_proxy_preserve_host) |preserve_host| @as(?i64, @intFromBool(preserve_host)) else null,
            record.created_at,
            record.updated_at,
        },
    ) catch return StoreError.WriteFailed;
    if (record.http_routes.len > 0) {
        var route_inputs: std.ArrayListUnmanaged(ServiceHttpRouteInput) = .empty;
        defer route_inputs.deinit(std.heap.page_allocator);
        for (record.http_routes) |route| {
            route_inputs.append(std.heap.page_allocator, .{
                .route_name = route.route_name,
                .host = route.host,
                .path_prefix = route.path_prefix,
                .rewrite_prefix = route.rewrite_prefix,
                .retries = route.retries,
                .connect_timeout_ms = route.connect_timeout_ms,
                .request_timeout_ms = route.request_timeout_ms,
                .target_port = route.target_port,
                .preserve_host = route.preserve_host,
            }) catch return StoreError.WriteFailed;
        }
        try replaceServiceHttpRoutes(db, record.service_name, record.updated_at, route_inputs.items);
        try syncDerivedServiceProxyFields(db, record.service_name, record.updated_at, route_inputs.items);
    }
    db.exec("COMMIT;", .{}, .{}) catch return StoreError.WriteFailed;
    committed = true;
}

pub fn ensureService(alloc: Allocator, service_name: []const u8, lb_policy: []const u8) StoreError!ServiceRecord {
    const db = try common.getDb();
    db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return StoreError.WriteFailed;

    var committed = false;
    errdefer if (!committed) db.exec("ROLLBACK;", .{}, .{}) catch {};

    if (db.oneAlloc(
        ServiceRow,
        alloc,
        "SELECT " ++ service_columns ++ " FROM services WHERE service_name = ?;",
        .{},
        .{service_name},
    ) catch return StoreError.ReadFailed) |row| {
        const routes = try listServiceHttpRoutesForDb(alloc, db, service_name);
        const record = rowToServiceRecord(row, routes);
        db.exec("COMMIT;", .{}, .{}) catch {
            record.deinit(alloc);
            return StoreError.WriteFailed;
        };
        committed = true;
        return record;
    }

    const vip = vip_allocator.allocate(db) catch {
        service_observability.noteVipAllocFailure();
        return StoreError.WriteFailed;
    };
    var vip_buf: [16]u8 = undefined;
    const vip_address = @import("../../network/ip.zig").formatIp(vip, &vip_buf);
    const now = std.time.timestamp();

    db.exec(
        "INSERT INTO services (service_name, vip_address, lb_policy, created_at, updated_at) VALUES (?, ?, ?, ?, ?);",
        .{},
        .{ service_name, vip_address, lb_policy, now, now },
    ) catch return StoreError.WriteFailed;

    db.exec("COMMIT;", .{}, .{}) catch return StoreError.WriteFailed;
    committed = true;

    const service_name_copy = alloc.dupe(u8, service_name) catch return StoreError.ReadFailed;
    errdefer alloc.free(service_name_copy);
    const vip_copy = alloc.dupe(u8, vip_address) catch return StoreError.ReadFailed;
    errdefer alloc.free(vip_copy);
    const lb_policy_copy = alloc.dupe(u8, lb_policy) catch return StoreError.ReadFailed;

    return .{
        .service_name = service_name_copy,
        .vip_address = vip_copy,
        .lb_policy = lb_policy_copy,
        .http_routes = alloc.alloc(ServiceHttpRouteRecord, 0) catch return StoreError.ReadFailed,
        .http_proxy_host = null,
        .http_proxy_path_prefix = null,
        .http_proxy_rewrite_prefix = null,
        .http_proxy_retries = null,
        .http_proxy_connect_timeout_ms = null,
        .http_proxy_request_timeout_ms = null,
        .http_proxy_target_port = null,
        .http_proxy_preserve_host = null,
        .created_at = now,
        .updated_at = now,
    };
}

pub fn syncServiceConfig(
    alloc: Allocator,
    service_name: []const u8,
    lb_policy: []const u8,
    routes: []const ServiceHttpRouteInput,
) StoreError!ServiceRecord {
    var existing = try ensureService(alloc, service_name, lb_policy);
    defer existing.deinit(alloc);

    const db = try common.getDb();
    const now = std.time.timestamp();
    db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return StoreError.WriteFailed;
    var committed = false;
    errdefer if (!committed) db.exec("ROLLBACK;", .{}, .{}) catch {};
    db.exec(
        "UPDATE services SET lb_policy = ?, updated_at = ? WHERE service_name = ?;",
        .{},
        .{
            lb_policy,
            now,
            service_name,
        },
    ) catch return StoreError.WriteFailed;
    try replaceServiceHttpRoutes(db, service_name, now, routes);
    try syncDerivedServiceProxyFields(db, service_name, now, routes);
    db.exec("COMMIT;", .{}, .{}) catch return StoreError.WriteFailed;
    committed = true;

    return getService(alloc, service_name);
}

pub fn getService(alloc: Allocator, service_name: []const u8) StoreError!ServiceRecord {
    const db = try common.getDb();
    const row = (db.oneAlloc(
        ServiceRow,
        alloc,
        "SELECT " ++ service_columns ++ " FROM services WHERE service_name = ?;",
        .{},
        .{service_name},
    ) catch return StoreError.ReadFailed) orelse return StoreError.NotFound;
    const routes = try listServiceHttpRoutesForDb(alloc, db, service_name);
    return rowToServiceRecord(row, routes);
}

pub fn listServices(alloc: Allocator) StoreError!std.ArrayList(ServiceRecord) {
    const db = try common.getDb();
    var services: std.ArrayList(ServiceRecord) = .empty;
    var stmt = db.prepare(
        "SELECT " ++ service_columns ++ " FROM services ORDER BY service_name;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(ServiceRow, .{}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        const routes = try listServiceHttpRoutesForDb(alloc, db, row.service_name.data);
        services.append(alloc, rowToServiceRecord(row, routes)) catch return StoreError.ReadFailed;
    }
    return services;
}

pub fn getServiceEndpoint(alloc: Allocator, service_name: []const u8, endpoint_id: []const u8) StoreError!ServiceEndpointRecord {
    const db = try common.getDb();
    const row = (db.oneAlloc(
        ServiceEndpointRow,
        alloc,
        "SELECT " ++ endpoint_columns ++ " FROM service_endpoints WHERE service_name = ? AND endpoint_id = ?;",
        .{},
        .{ service_name, endpoint_id },
    ) catch return StoreError.ReadFailed) orelse return StoreError.NotFound;
    return rowToServiceEndpointRecord(row);
}

pub fn upsertServiceEndpoint(record: ServiceEndpointRecord) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "INSERT INTO service_endpoints (" ++ endpoint_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)" ++
            " ON CONFLICT(service_name, endpoint_id) DO UPDATE SET" ++
            " container_id = excluded.container_id," ++
            " node_id = excluded.node_id," ++
            " ip_address = excluded.ip_address," ++
            " port = excluded.port," ++
            " weight = excluded.weight," ++
            " admin_state = excluded.admin_state," ++
            " generation = excluded.generation," ++
            " registered_at = excluded.registered_at," ++
            " last_seen_at = excluded.last_seen_at;",
        .{},
        .{
            record.service_name,
            record.endpoint_id,
            record.container_id,
            record.node_id,
            record.ip_address,
            record.port,
            record.weight,
            record.admin_state,
            record.generation,
            record.registered_at,
            record.last_seen_at,
        },
    ) catch return StoreError.WriteFailed;
}

pub fn removeServiceEndpoint(service_name: []const u8, endpoint_id: []const u8) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "DELETE FROM service_endpoints WHERE service_name = ? AND endpoint_id = ?;",
        .{},
        .{ service_name, endpoint_id },
    ) catch return StoreError.WriteFailed;
}

pub fn markServiceEndpointAdminState(service_name: []const u8, endpoint_id: []const u8, admin_state: []const u8) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "UPDATE service_endpoints SET admin_state = ? WHERE service_name = ? AND endpoint_id = ?;",
        .{},
        .{ admin_state, service_name, endpoint_id },
    ) catch return StoreError.WriteFailed;
}

pub fn listServiceEndpoints(alloc: Allocator, service_name: []const u8) StoreError!std.ArrayList(ServiceEndpointRecord) {
    return queryServiceEndpoints(
        alloc,
        "SELECT " ++ endpoint_columns ++ " FROM service_endpoints WHERE service_name = ? ORDER BY registered_at DESC;",
        .{service_name},
    );
}

pub fn listServiceEndpointsByNode(alloc: Allocator, node_id: i64) StoreError!std.ArrayList(ServiceEndpointRecord) {
    return queryServiceEndpoints(
        alloc,
        "SELECT " ++ endpoint_columns ++ " FROM service_endpoints WHERE node_id = ? ORDER BY service_name, endpoint_id;",
        .{node_id},
    );
}

pub fn removeServiceEndpointsByContainer(container_id: []const u8) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "DELETE FROM service_endpoints WHERE container_id = ?;",
        .{},
        .{container_id},
    ) catch return StoreError.WriteFailed;
}

pub fn removeServiceEndpointsByNode(node_id: i64) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "DELETE FROM service_endpoints WHERE node_id = ?;",
        .{},
        .{node_id},
    ) catch return StoreError.WriteFailed;
}

fn queryServiceEndpoints(alloc: Allocator, comptime query: []const u8, args: anytype) StoreError!std.ArrayList(ServiceEndpointRecord) {
    const db = try common.getDb();
    var endpoints: std.ArrayList(ServiceEndpointRecord) = .empty;
    var stmt = db.prepare(query) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(ServiceEndpointRow, args) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        endpoints.append(alloc, rowToServiceEndpointRecord(row)) catch return StoreError.ReadFailed;
    }
    return endpoints;
}

pub fn registerServiceName(name: []const u8, container_id: []const u8, ip_address: []const u8) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "INSERT OR REPLACE INTO service_names (name, container_id, ip_address, registered_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ name, container_id, ip_address, @as(i64, std.time.timestamp()) },
    ) catch return StoreError.WriteFailed;
}

pub fn unregisterServiceName(container_id: []const u8) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "DELETE FROM service_names WHERE container_id = ?;",
        .{},
        .{container_id},
    ) catch return StoreError.WriteFailed;
}

pub fn removeServiceNamesByName(name: []const u8) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "DELETE FROM service_names WHERE name = ?;",
        .{},
        .{name},
    ) catch return StoreError.WriteFailed;
}

pub fn lookupServiceNames(alloc: Allocator, name: []const u8) StoreError!std.ArrayList([]const u8) {
    const db = try common.getDb();
    var ips: std.ArrayList([]const u8) = .empty;
    var stmt = db.prepare(
        "SELECT ip_address FROM service_names WHERE name = ? ORDER BY registered_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(ServiceNameIpRow, .{name}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        ips.append(alloc, row.ip_address.data) catch return StoreError.ReadFailed;
    }
    return ips;
}

pub fn lookupServiceAddresses(alloc: Allocator, name: []const u8) StoreError!std.ArrayList([]const u8) {
    const db = try common.getDb();
    var ips: std.ArrayList([]const u8) = .empty;

    var stmt = db.prepare(
        "SELECT vip_address FROM services WHERE service_name = ? LIMIT 1;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(struct { vip_address: sqlite.Text }, .{name}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        ips.append(alloc, row.vip_address.data) catch return StoreError.ReadFailed;
    }

    if (ips.items.len > 0) return ips;
    return lookupServiceNames(alloc, name);
}

pub fn listServiceNames(alloc: Allocator) StoreError!std.ArrayList(ServiceNameRecord) {
    const db = try common.getDb();
    var names: std.ArrayList(ServiceNameRecord) = .empty;
    var stmt = db.prepare(
        "SELECT name, container_id, ip_address, registered_at FROM service_names ORDER BY name, registered_at DESC;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(ServiceNameRow, .{}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        names.append(alloc, rowToServiceNameRecord(row)) catch return StoreError.ReadFailed;
    }
    return names;
}

pub fn addNetworkPolicy(source: []const u8, target: []const u8, action: []const u8) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "INSERT OR REPLACE INTO network_policies (source_service, target_service, action, created_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ source, target, action, @as(i64, std.time.timestamp()) },
    ) catch return StoreError.WriteFailed;
}

pub fn removeNetworkPolicy(source: []const u8, target: []const u8) StoreError!void {
    const db = try common.getDb();
    db.exec(
        "DELETE FROM network_policies WHERE source_service = ? AND target_service = ?;",
        .{},
        .{ source, target },
    ) catch return StoreError.WriteFailed;
}

pub fn listNetworkPolicies(alloc: Allocator) StoreError!std.ArrayList(NetworkPolicyRecord) {
    return queryNetworkPolicies(
        alloc,
        "SELECT source_service, target_service, action, created_at FROM network_policies ORDER BY created_at;",
        .{},
    );
}

pub fn getServicePolicies(alloc: Allocator, source: []const u8) StoreError!std.ArrayList(NetworkPolicyRecord) {
    return queryNetworkPolicies(
        alloc,
        "SELECT source_service, target_service, action, created_at FROM network_policies WHERE source_service = ? ORDER BY created_at;",
        .{source},
    );
}

fn queryNetworkPolicies(alloc: Allocator, comptime query: []const u8, args: anytype) StoreError!std.ArrayList(NetworkPolicyRecord) {
    const db = try common.getDb();
    var policies: std.ArrayList(NetworkPolicyRecord) = .empty;
    var stmt = db.prepare(query) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(NetworkPolicyRow, args) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        policies.append(alloc, .{
            .source_service = row.source_service.data,
            .target_service = row.target_service.data,
            .action = row.action.data,
            .created_at = row.created_at,
        }) catch return StoreError.ReadFailed;
    }
    return policies;
}

test "createService and getService round-trip" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .http_proxy_host = "api.internal",
        .http_proxy_path_prefix = "/v1",
        .http_proxy_retries = 2,
        .http_proxy_connect_timeout_ms = 1500,
        .http_proxy_request_timeout_ms = 5000,
        .http_proxy_target_port = 8080,
        .http_proxy_preserve_host = true,
        .created_at = 1000,
        .updated_at = 1000,
    });

    const alloc = std.testing.allocator;
    const service = try getService(alloc, "api");
    defer service.deinit(alloc);

    try std.testing.expectEqualStrings("api", service.service_name);
    try std.testing.expectEqualStrings("10.43.0.10", service.vip_address);
    try std.testing.expectEqualStrings("consistent_hash", service.lb_policy);
    try std.testing.expectEqualStrings("api.internal", service.http_proxy_host.?);
    try std.testing.expectEqualStrings("/v1", service.http_proxy_path_prefix.?);
    try std.testing.expectEqual(@as(?i64, 2), service.http_proxy_retries);
    try std.testing.expectEqual(@as(?i64, 1500), service.http_proxy_connect_timeout_ms);
    try std.testing.expectEqual(@as(?i64, 5000), service.http_proxy_request_timeout_ms);
    try std.testing.expectEqual(@as(?i64, 8080), service.http_proxy_target_port);
    try std.testing.expectEqual(@as(?bool, true), service.http_proxy_preserve_host);
    try std.testing.expectEqual(@as(i64, 1000), service.created_at);
}

test "listServices returns services ordered by name" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try createService(.{
        .service_name = "web",
        .vip_address = "10.43.0.20",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .created_at = 1001,
        .updated_at = 1001,
    });

    const alloc = std.testing.allocator;
    var services = try listServices(alloc);
    defer {
        for (services.items) |service| service.deinit(alloc);
        services.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 2), services.items.len);
    try std.testing.expectEqualStrings("api", services.items[0].service_name);
    try std.testing.expectEqualStrings("web", services.items[1].service_name);
}

test "ensureService allocates once and returns the existing VIP thereafter" {
    try common.initTestDb();
    defer common.deinitTestDb();

    const alloc = std.testing.allocator;

    const first = try ensureService(alloc, "api", "consistent_hash");
    defer first.deinit(alloc);
    try std.testing.expectEqualStrings("10.43.0.2", first.vip_address);

    const second = try ensureService(alloc, "api", "consistent_hash");
    defer second.deinit(alloc);
    try std.testing.expectEqualStrings("10.43.0.2", second.vip_address);

    var services = try listServices(alloc);
    defer {
        for (services.items) |service| service.deinit(alloc);
        services.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 1), services.items.len);
}

test "syncServiceConfig updates proxy policy without changing vip" {
    try common.initTestDb();
    defer common.deinitTestDb();

    const alloc = std.testing.allocator;

    const first = try ensureService(alloc, "api", "consistent_hash");
    defer first.deinit(alloc);

    const updated = try syncServiceConfig(
        alloc,
        "api",
        "consistent_hash",
        &.{
            .{
                .route_name = "default",
                .host = "api.internal",
                .path_prefix = "/v1",
                .retries = 2,
                .connect_timeout_ms = 1500,
                .request_timeout_ms = 5000,
                .target_port = 8080,
                .preserve_host = false,
            },
        },
    );
    defer updated.deinit(alloc);

    try std.testing.expectEqualStrings(first.vip_address, updated.vip_address);
    try std.testing.expectEqualStrings("api.internal", updated.http_proxy_host.?);
    try std.testing.expectEqualStrings("/v1", updated.http_proxy_path_prefix.?);
    try std.testing.expectEqual(@as(?i64, 8080), updated.http_proxy_target_port);
    try std.testing.expectEqual(@as(?bool, false), updated.http_proxy_preserve_host);
}

test "upsertServiceEndpoint updates an existing endpoint" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });

    try upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "ctr-1:8080",
        .container_id = "ctr-1",
        .node_id = 7,
        .ip_address = "10.42.0.9",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    try upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "ctr-1:8080",
        .container_id = "ctr-1b",
        .node_id = 8,
        .ip_address = "10.42.0.19",
        .port = 8080,
        .weight = 2,
        .admin_state = "draining",
        .generation = 2,
        .registered_at = 1001,
        .last_seen_at = 1002,
    });

    const alloc = std.testing.allocator;
    var endpoints = try listServiceEndpoints(alloc, "api");
    defer {
        for (endpoints.items) |endpoint| endpoint.deinit(alloc);
        endpoints.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), endpoints.items.len);
    try std.testing.expectEqualStrings("ctr-1b", endpoints.items[0].container_id);
    try std.testing.expectEqual(@as(?i64, 8), endpoints.items[0].node_id);
    try std.testing.expectEqualStrings("10.42.0.19", endpoints.items[0].ip_address);
    try std.testing.expectEqual(@as(i64, 2), endpoints.items[0].weight);
    try std.testing.expectEqualStrings("draining", endpoints.items[0].admin_state);
    try std.testing.expectEqual(@as(i64, 2), endpoints.items[0].generation);
}

test "service endpoint queries support service and node cleanup flows" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try createService(.{
        .service_name = "web",
        .vip_address = "10.43.0.20",
        .lb_policy = "consistent_hash",
        .created_at = 1001,
        .updated_at = 1001,
    });

    try upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = "api-1:8080",
        .container_id = "api-1",
        .node_id = 3,
        .ip_address = "10.42.0.11",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1000,
        .last_seen_at = 1000,
    });
    try upsertServiceEndpoint(.{
        .service_name = "web",
        .endpoint_id = "web-1:8080",
        .container_id = "web-1",
        .node_id = 3,
        .ip_address = "10.42.0.12",
        .port = 8080,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1001,
        .last_seen_at = 1001,
    });

    try markServiceEndpointAdminState("api", "api-1:8080", "removed");

    const alloc = std.testing.allocator;
    var node_endpoints = try listServiceEndpointsByNode(alloc, 3);
    defer {
        for (node_endpoints.items) |endpoint| endpoint.deinit(alloc);
        node_endpoints.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 2), node_endpoints.items.len);
    try std.testing.expectEqualStrings("removed", node_endpoints.items[0].admin_state);
    try std.testing.expectEqualStrings("active", node_endpoints.items[1].admin_state);

    try removeServiceEndpointsByContainer("api-1");

    var api_endpoints = try listServiceEndpoints(alloc, "api");
    defer {
        for (api_endpoints.items) |endpoint| endpoint.deinit(alloc);
        api_endpoints.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 0), api_endpoints.items.len);

    try removeServiceEndpointsByNode(3);

    var remaining = try listServiceEndpointsByNode(alloc, 3);
    defer {
        for (remaining.items) |endpoint| endpoint.deinit(alloc);
        remaining.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 0), remaining.items.len);
}

test "lookupServiceAddresses prefers service VIPs over legacy name rows" {
    try common.initTestDb();
    defer common.deinitTestDb();

    try createService(.{
        .service_name = "api",
        .vip_address = "10.43.0.10",
        .lb_policy = "consistent_hash",
        .created_at = 1000,
        .updated_at = 1000,
    });
    try registerServiceName("api", "ctr-1", "10.42.0.11");

    const alloc = std.testing.allocator;
    var addresses = try lookupServiceAddresses(alloc, "api");
    defer {
        for (addresses.items) |ip| alloc.free(ip);
        addresses.deinit(alloc);
    }

    try std.testing.expectEqual(@as(usize, 1), addresses.items.len);
    try std.testing.expectEqualStrings("10.43.0.10", addresses.items[0]);
}

test "service name register and lookup" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO service_names (name, container_id, ip_address, registered_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "web", "abc123", "10.42.0.2", @as(i64, 100) },
    ) catch unreachable;

    const alloc = std.testing.allocator;
    const row = (db.oneAlloc(ServiceNameIpRow, alloc, "SELECT ip_address FROM service_names WHERE name = ?;", .{}, .{"web"}) catch unreachable).?;
    defer alloc.free(row.ip_address.data);

    try std.testing.expectEqualStrings("10.42.0.2", row.ip_address.data);
}

test "service name unregister removes entries" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    db.exec(
        "INSERT INTO service_names (name, container_id, ip_address, registered_at) VALUES (?, ?, ?, ?);",
        .{},
        .{ "db", "xyz789", "10.42.0.3", @as(i64, 100) },
    ) catch unreachable;
    db.exec("DELETE FROM service_names WHERE container_id = ?;", .{}, .{"xyz789"}) catch unreachable;

    const CountRow = struct { count: i64 };
    const result = (db.one(CountRow, "SELECT COUNT(*) AS count FROM service_names;", .{}, .{}) catch unreachable).?;
    try std.testing.expectEqual(@as(i64, 0), result.count);
}

test "service name lookup returns empty for unknown" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);

    const alloc = std.testing.allocator;
    const row = db.oneAlloc(ServiceNameIpRow, alloc, "SELECT ip_address FROM service_names WHERE name = ?;", .{}, .{"nonexistent"}) catch unreachable;
    try std.testing.expect(row == null);
}
