const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");
const types = @import("services_types.zig");

const Allocator = std.mem.Allocator;
const StoreError = common.StoreError;

const ServiceHttpRouteRecord = types.ServiceHttpRouteRecord;
const ServiceHttpRouteMethodRecord = types.ServiceHttpRouteMethodRecord;
const ServiceHttpRouteHeaderRecord = types.ServiceHttpRouteHeaderRecord;
const ServiceHttpRouteBackendRecord = types.ServiceHttpRouteBackendRecord;
const ServiceHttpRouteInput = types.ServiceHttpRouteInput;
const ServiceHttpRouteMethodInput = types.ServiceHttpRouteMethodInput;
const ServiceHttpRouteHeaderInput = types.ServiceHttpRouteHeaderInput;
const ServiceHttpRouteBackendInput = types.ServiceHttpRouteBackendInput;

pub fn listForDb(alloc: Allocator, db: *sqlite.Db, service_name: []const u8) StoreError![]const ServiceHttpRouteRecord {
    var routes: std.ArrayList(ServiceHttpRouteRecord) = .empty;
    errdefer {
        for (routes.items) |route| route.deinit(alloc);
        routes.deinit(alloc);
    }
    var stmt = db.prepare(
        "SELECT " ++ types.service_http_route_columns ++ " FROM service_http_routes WHERE service_name = ? ORDER BY route_order, route_name;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(types.ServiceHttpRouteRow, .{service_name}) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        var route = types.rowToServiceHttpRouteRecord(row);
        route.match_methods = alloc.alloc(ServiceHttpRouteMethodRecord, 0) catch return StoreError.ReadFailed;
        route.match_headers = alloc.alloc(ServiceHttpRouteHeaderRecord, 0) catch return StoreError.ReadFailed;
        route.backend_services = alloc.alloc(ServiceHttpRouteBackendRecord, 0) catch return StoreError.ReadFailed;
        errdefer route.deinit(alloc);
        alloc.free(route.match_methods);
        alloc.free(route.match_headers);
        alloc.free(route.backend_services);
        route.match_methods = try listMethodsForDb(alloc, db, route.service_name, route.route_name);
        route.match_headers = try listHeadersForDb(alloc, db, route.service_name, route.route_name);
        route.backend_services = try listBackendsForDb(alloc, db, route.service_name, route.route_name);
        routes.append(alloc, route) catch return StoreError.ReadFailed;
    }
    return routes.toOwnedSlice(alloc) catch return StoreError.ReadFailed;
}

pub fn syncFromRecords(
    db: *sqlite.Db,
    service_name: []const u8,
    now: i64,
    routes: []const ServiceHttpRouteRecord,
) StoreError!void {
    if (routes.len == 0) return;

    var route_inputs: std.ArrayListUnmanaged(ServiceHttpRouteInput) = .empty;
    defer route_inputs.deinit(std.heap.page_allocator);
    for (routes) |route| {
        route_inputs.append(std.heap.page_allocator, .{
            .route_name = route.route_name,
            .host = route.host,
            .path_prefix = route.path_prefix,
            .rewrite_prefix = route.rewrite_prefix,
            .match_methods = try methodInputs(route),
            .match_headers = try headerInputs(route),
            .backend_services = try backendInputs(route),
            .mirror_service = route.mirror_service,
            .retries = route.retries,
            .connect_timeout_ms = route.connect_timeout_ms,
            .request_timeout_ms = route.request_timeout_ms,
            .http2_idle_timeout_ms = route.http2_idle_timeout_ms,
            .target_port = route.target_port,
            .preserve_host = route.preserve_host,
            .retry_on_5xx = route.retry_on_5xx,
            .circuit_breaker_threshold = route.circuit_breaker_threshold,
            .circuit_breaker_timeout_ms = route.circuit_breaker_timeout_ms,
        }) catch return StoreError.WriteFailed;
    }
    defer {
        for (route_inputs.items) |route_input| {
            if (route_input.match_methods.len > 0) std.heap.page_allocator.free(route_input.match_methods);
            if (route_input.match_headers.len > 0) std.heap.page_allocator.free(route_input.match_headers);
            if (route_input.backend_services.len > 0) std.heap.page_allocator.free(route_input.backend_services);
        }
    }

    try replaceInDb(db, service_name, now, route_inputs.items);
    try syncDerivedFields(db, service_name, now, route_inputs.items);
}

pub fn replaceInDb(
    db: *sqlite.Db,
    service_name: []const u8,
    now: i64,
    routes: []const ServiceHttpRouteInput,
) StoreError!void {
    db.exec(
        "DELETE FROM service_http_route_methods WHERE service_name = ?;",
        .{},
        .{service_name},
    ) catch return StoreError.WriteFailed;
    db.exec(
        "DELETE FROM service_http_route_backends WHERE service_name = ?;",
        .{},
        .{service_name},
    ) catch return StoreError.WriteFailed;
    db.exec(
        "DELETE FROM service_http_route_headers WHERE service_name = ?;",
        .{},
        .{service_name},
    ) catch return StoreError.WriteFailed;
    db.exec(
        "DELETE FROM service_http_routes WHERE service_name = ?;",
        .{},
        .{service_name},
    ) catch return StoreError.WriteFailed;

    for (routes, 0..) |route, idx| {
        db.exec(
            "INSERT INTO service_http_routes (" ++ types.service_http_route_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            .{},
            .{
                service_name,
                route.route_name,
                route.host,
                route.path_prefix,
                route.rewrite_prefix,
                route.mirror_service,
                route.retries,
                route.connect_timeout_ms,
                route.request_timeout_ms,
                route.http2_idle_timeout_ms,
                route.target_port,
                @as(i64, @intFromBool(route.preserve_host)),
                @as(i64, @intFromBool(route.retry_on_5xx)),
                route.circuit_breaker_threshold,
                route.circuit_breaker_timeout_ms,
                @as(i64, @intCast(idx)),
                now,
                now,
            },
        ) catch return StoreError.WriteFailed;

        for (route.match_methods, 0..) |method_match, method_idx| {
            db.exec(
                "INSERT INTO service_http_route_methods (" ++ types.service_http_route_method_columns ++ ") VALUES (?, ?, ?, ?, ?, ?);",
                .{},
                .{
                    service_name,
                    route.route_name,
                    method_match.method,
                    @as(i64, @intCast(method_idx)),
                    now,
                    now,
                },
            ) catch return StoreError.WriteFailed;
        }

        for (route.match_headers, 0..) |header_match, header_idx| {
            db.exec(
                "INSERT INTO service_http_route_headers (" ++ types.service_http_route_header_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?);",
                .{},
                .{
                    service_name,
                    route.route_name,
                    header_match.header_name,
                    header_match.header_value,
                    @as(i64, @intCast(header_idx)),
                    now,
                    now,
                },
            ) catch return StoreError.WriteFailed;
        }

        for (route.backend_services, 0..) |backend, backend_idx| {
            db.exec(
                "INSERT INTO service_http_route_backends (" ++ types.service_http_route_backend_columns ++ ") VALUES (?, ?, ?, ?, ?, ?, ?);",
                .{},
                .{
                    service_name,
                    route.route_name,
                    backend.backend_service,
                    backend.weight,
                    @as(i64, @intCast(backend_idx)),
                    now,
                    now,
                },
            ) catch return StoreError.WriteFailed;
        }
    }
}

pub fn syncDerivedFields(
    db: *sqlite.Db,
    service_name: []const u8,
    now: i64,
    routes: []const ServiceHttpRouteInput,
) StoreError!void {
    const primary = if (routes.len > 0) routes[0] else null;
    db.exec(
        "UPDATE services SET lb_policy = lb_policy, http_proxy_host = ?, http_proxy_path_prefix = ?, http_proxy_rewrite_prefix = ?, http_proxy_retries = ?, http_proxy_connect_timeout_ms = ?, http_proxy_request_timeout_ms = ?, http_proxy_http2_idle_timeout_ms = ?, http_proxy_target_port = ?, http_proxy_preserve_host = ?, http_proxy_retry_on_5xx = ?, http_proxy_circuit_breaker_threshold = ?, http_proxy_circuit_breaker_timeout_ms = ?, http_proxy_mirror_service = ?, updated_at = ? WHERE service_name = ?;",
        .{},
        .{
            if (primary) |route| route.host else null,
            if (primary) |route| route.path_prefix else null,
            if (primary) |route| route.rewrite_prefix else null,
            if (primary) |route| route.retries else null,
            if (primary) |route| route.connect_timeout_ms else null,
            if (primary) |route| route.request_timeout_ms else null,
            if (primary) |route| route.http2_idle_timeout_ms else null,
            if (primary) |route| route.target_port else null,
            if (primary) |route| @as(i64, @intFromBool(route.preserve_host)) else null,
            if (primary) |route| @as(i64, @intFromBool(route.retry_on_5xx)) else null,
            if (primary) |route| route.circuit_breaker_threshold else null,
            if (primary) |route| route.circuit_breaker_timeout_ms else null,
            if (primary) |route| route.mirror_service else null,
            now,
            service_name,
        },
    ) catch return StoreError.WriteFailed;
}

fn listMethodsForDb(
    alloc: Allocator,
    db: *sqlite.Db,
    service_name: []const u8,
    route_name: []const u8,
) StoreError![]const ServiceHttpRouteMethodRecord {
    var methods: std.ArrayList(ServiceHttpRouteMethodRecord) = .empty;
    errdefer {
        for (methods.items) |method_match| method_match.deinit(alloc);
        methods.deinit(alloc);
    }

    var stmt = db.prepare(
        "SELECT " ++ types.service_http_route_method_columns ++
            " FROM service_http_route_methods WHERE service_name = ? AND route_name = ? ORDER BY match_order, method;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(types.ServiceHttpRouteMethodRow, .{ service_name, route_name }) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        methods.append(alloc, types.rowToServiceHttpRouteMethodRecord(row)) catch return StoreError.ReadFailed;
    }
    return methods.toOwnedSlice(alloc) catch return StoreError.ReadFailed;
}

fn listHeadersForDb(
    alloc: Allocator,
    db: *sqlite.Db,
    service_name: []const u8,
    route_name: []const u8,
) StoreError![]const ServiceHttpRouteHeaderRecord {
    var headers: std.ArrayList(ServiceHttpRouteHeaderRecord) = .empty;
    errdefer {
        for (headers.items) |header| header.deinit(alloc);
        headers.deinit(alloc);
    }

    var stmt = db.prepare(
        "SELECT " ++ types.service_http_route_header_columns ++
            " FROM service_http_route_headers WHERE service_name = ? AND route_name = ? ORDER BY match_order, header_name;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(types.ServiceHttpRouteHeaderRow, .{ service_name, route_name }) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        headers.append(alloc, types.rowToServiceHttpRouteHeaderRecord(row)) catch return StoreError.ReadFailed;
    }
    return headers.toOwnedSlice(alloc) catch return StoreError.ReadFailed;
}

fn listBackendsForDb(
    alloc: Allocator,
    db: *sqlite.Db,
    service_name: []const u8,
    route_name: []const u8,
) StoreError![]const ServiceHttpRouteBackendRecord {
    var backends: std.ArrayList(ServiceHttpRouteBackendRecord) = .empty;
    errdefer {
        for (backends.items) |backend| backend.deinit(alloc);
        backends.deinit(alloc);
    }

    var stmt = db.prepare(
        "SELECT " ++ types.service_http_route_backend_columns ++
            " FROM service_http_route_backends WHERE service_name = ? AND route_name = ? ORDER BY backend_order, backend_service;",
    ) catch return StoreError.ReadFailed;
    defer stmt.deinit();
    var iter = stmt.iterator(types.ServiceHttpRouteBackendRow, .{ service_name, route_name }) catch return StoreError.ReadFailed;
    while (iter.nextAlloc(alloc, .{}) catch return StoreError.ReadFailed) |row| {
        backends.append(alloc, types.rowToServiceHttpRouteBackendRecord(row)) catch return StoreError.ReadFailed;
    }
    return backends.toOwnedSlice(alloc) catch return StoreError.ReadFailed;
}

fn methodInputs(route: ServiceHttpRouteRecord) StoreError![]const ServiceHttpRouteMethodInput {
    var methods: std.ArrayListUnmanaged(ServiceHttpRouteMethodInput) = .empty;
    for (route.match_methods) |method_match| {
        methods.append(std.heap.page_allocator, .{ .method = method_match.method }) catch return StoreError.WriteFailed;
    }
    return methods.toOwnedSlice(std.heap.page_allocator) catch return StoreError.WriteFailed;
}

fn headerInputs(route: ServiceHttpRouteRecord) StoreError![]const ServiceHttpRouteHeaderInput {
    var headers: std.ArrayListUnmanaged(ServiceHttpRouteHeaderInput) = .empty;
    for (route.match_headers) |header_match| {
        headers.append(std.heap.page_allocator, .{
            .header_name = header_match.header_name,
            .header_value = header_match.header_value,
        }) catch return StoreError.WriteFailed;
    }
    return headers.toOwnedSlice(std.heap.page_allocator) catch return StoreError.WriteFailed;
}

fn backendInputs(route: ServiceHttpRouteRecord) StoreError![]const ServiceHttpRouteBackendInput {
    var backends: std.ArrayListUnmanaged(ServiceHttpRouteBackendInput) = .empty;
    for (route.backend_services) |backend| {
        backends.append(std.heap.page_allocator, .{
            .backend_service = backend.backend_service,
            .weight = backend.weight,
        }) catch return StoreError.WriteFailed;
    }
    return backends.toOwnedSlice(std.heap.page_allocator) catch return StoreError.WriteFailed;
}
