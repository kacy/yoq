const std = @import("std");

const spec = @import("../spec.zig");
const store = @import("../../state/store.zig");
const log = @import("../../lib/log.zig");
const ip_mod = @import("../../network/ip.zig");
const proxy_control_plane = @import("../../network/proxy/control_plane.zig");
const listener_runtime = @import("../../network/proxy/listener_runtime.zig");
const health = @import("../health.zig");
const tls_proxy = @import("../../tls/proxy.zig");
const tls_backend = @import("../../tls/backend.zig");
const cert_store_mod = @import("../../tls/cert_store.zig");
const sqlite = @import("sqlite");
const cli = @import("../../lib/cli.zig");
const tls_support = @import("tls_support.zig");

const writeErr = cli.writeErr;

pub const TlsResources = struct {
    backend_registry: *tls_backend.BackendRegistry,
    proxy: *tls_proxy.TlsProxy,
    tls_certs: *cert_store_mod.CertStore,
    tls_db: *sqlite.Db,
};

pub fn registerHealthChecks(
    alloc: std.mem.Allocator,
    services: []const spec.Service,
    states: anytype,
    start_set: ?std.StringHashMapUnmanaged(void),
) void {
    var has_checks = false;

    for (services, 0..) |svc, i| {
        if (!shouldStart(start_set, svc.name)) continue;
        const hc = svc.health_check orelse continue;
        has_checks = true;

        const id = states[i].container_id;
        const record = store.load(alloc, id[0..]) catch {
            log.warn("orchestrator: failed to load container for health check registration: {s}", .{svc.name});
            continue;
        };
        defer record.deinit(alloc);

        const container_ip = if (record.ip_address) |ip_str|
            ip_mod.parseIp(ip_str) orelse [4]u8{ 0, 0, 0, 0 }
        else
            [4]u8{ 0, 0, 0, 0 };

        health.registerService(svc.name, id, container_ip, hc) catch |err| {
            writeErr("health: failed to register checks for {s}: {}\n", .{ svc.name, err });
        };
        states[i].health_status = .starting;
    }

    if (has_checks) health.startChecker();
}

pub fn syncServiceDefinitions(
    alloc: std.mem.Allocator,
    services: []const spec.Service,
    start_set: ?std.StringHashMapUnmanaged(void),
) void {
    for (services) |svc| {
        if (!shouldStart(start_set, svc.name)) continue;

        var route_inputs: std.ArrayList(store.ServiceHttpRouteInput) = .empty;
        defer route_inputs.deinit(alloc);
        var route_alloc_failed = false;
        for (svc.http_routes) |route| {
            var match_methods: std.ArrayList(store.ServiceHttpRouteMethodInput) = .empty;
            errdefer match_methods.deinit(alloc);
            for (route.match_methods) |method_match| {
                match_methods.append(alloc, .{
                    .method = method_match.method,
                }) catch {
                    log.warn("orchestrator: failed to allocate http route method matches for {s}", .{svc.name});
                    route_alloc_failed = true;
                    break;
                };
            }
            if (route_alloc_failed) {
                match_methods.deinit(alloc);
                break;
            }
            var match_headers: std.ArrayList(store.ServiceHttpRouteHeaderInput) = .empty;
            errdefer match_headers.deinit(alloc);
            for (route.match_headers) |header_match| {
                match_headers.append(alloc, .{
                    .header_name = header_match.name,
                    .header_value = header_match.value,
                }) catch {
                    log.warn("orchestrator: failed to allocate http route header matches for {s}", .{svc.name});
                    route_alloc_failed = true;
                    break;
                };
            }
            if (route_alloc_failed) {
                match_headers.deinit(alloc);
                break;
            }
            var backend_services: std.ArrayList(store.ServiceHttpRouteBackendInput) = .empty;
            errdefer backend_services.deinit(alloc);
            for (route.backend_services) |backend| {
                backend_services.append(alloc, .{
                    .backend_service = backend.service_name,
                    .weight = backend.weight,
                }) catch {
                    log.warn("orchestrator: failed to allocate http route backends for {s}", .{svc.name});
                    route_alloc_failed = true;
                    break;
                };
            }
            if (route_alloc_failed) {
                match_methods.deinit(alloc);
                match_headers.deinit(alloc);
                backend_services.deinit(alloc);
                break;
            }
            route_inputs.append(alloc, .{
                .route_name = route.name,
                .host = route.host,
                .path_prefix = route.path_prefix,
                .rewrite_prefix = route.rewrite_prefix,
                .match_methods = match_methods.toOwnedSlice(alloc) catch {
                    log.warn("orchestrator: failed to allocate http route method matches for {s}", .{svc.name});
                    route_alloc_failed = true;
                    break;
                },
                .match_headers = match_headers.toOwnedSlice(alloc) catch {
                    log.warn("orchestrator: failed to allocate http route header matches for {s}", .{svc.name});
                    route_alloc_failed = true;
                    break;
                },
                .backend_services = backend_services.toOwnedSlice(alloc) catch {
                    log.warn("orchestrator: failed to allocate http route backends for {s}", .{svc.name});
                    route_alloc_failed = true;
                    break;
                },
                .mirror_service = route.mirror_service,
                .retries = route.retries,
                .connect_timeout_ms = route.connect_timeout_ms,
                .request_timeout_ms = route.request_timeout_ms,
                .target_port = if (svc.ports.len > 0) svc.ports[0].container_port else null,
                .preserve_host = route.preserve_host,
                .retry_on_5xx = route.retry_on_5xx,
                .circuit_breaker_threshold = route.circuit_breaker_threshold,
                .circuit_breaker_timeout_ms = route.circuit_breaker_timeout_ms,
            }) catch {
                alloc.free(match_methods.items);
                alloc.free(match_headers.items);
                alloc.free(backend_services.items);
                log.warn("orchestrator: failed to allocate http routes for {s}", .{svc.name});
                route_alloc_failed = true;
                break;
            };
        }
        defer {
            for (route_inputs.items) |route| if (route.match_methods.len > 0) alloc.free(route.match_methods);
            for (route_inputs.items) |route| if (route.match_headers.len > 0) alloc.free(route.match_headers);
            for (route_inputs.items) |route| if (route.backend_services.len > 0) alloc.free(route.backend_services);
        }
        if (route_alloc_failed) continue;
        const record = store.syncServiceConfig(
            alloc,
            svc.name,
            "consistent_hash",
            route_inputs.items,
        ) catch |err| {
            log.warn("orchestrator: failed to sync service definition for {s}: {}", .{ svc.name, err });
            continue;
        };
        defer record.deinit(alloc);

        @import("../../network/service_registry_runtime.zig").syncServiceFromStore(svc.name);
    }

    proxy_control_plane.refreshIfEnabled();
}

pub fn refreshServiceRuntimeBindings(
    alloc: std.mem.Allocator,
    svc: spec.Service,
    state: anytype,
    backend_registry: ?*tls_backend.BackendRegistry,
) void {
    const id = state.container_id;
    const record = store.load(alloc, id[0..]) catch {
        log.warn("orchestrator: failed to load container for runtime binding refresh: {s}", .{svc.name});
        return;
    };
    defer record.deinit(alloc);

    const container_ip = if (record.ip_address) |ip_str|
        ip_mod.parseIp(ip_str) orelse [4]u8{ 0, 0, 0, 0 }
    else
        [4]u8{ 0, 0, 0, 0 };

    if (svc.health_check) |hc| {
        health.unregisterService(svc.name);
        health.registerService(svc.name, id, container_ip, hc) catch |err| {
            writeErr("health: failed to register checks for {s}: {}\n", .{ svc.name, err });
        };
        state.health_status = .starting;
        health.startChecker();
    }

    if (svc.tls) |tls| {
        const reg = backend_registry orelse return;
        const target = tlsBackendTargetForService(alloc, svc, tls.domain, record.ip_address) orelse return;
        defer alloc.free(target.ip);
        reg.register(tls.domain, target.ip, target.port) catch {
            log.warn("failed to refresh backend for {s}", .{tls.domain});
            return;
        };
    }
}

pub fn startTlsProxy(
    alloc: std.mem.Allocator,
    services: []const spec.Service,
    states: anytype,
    start_set: ?std.StringHashMapUnmanaged(void),
) ?TlsResources {
    if (!hasTlsServices(services, start_set)) return null;

    const reg = alloc.create(tls_backend.BackendRegistry) catch {
        writeErr("failed to allocate backend registry\n", .{});
        return null;
    };
    reg.* = tls_backend.BackendRegistry.init(alloc);
    errdefer {
        reg.deinit();
        alloc.destroy(reg);
    }

    registerTlsBackends(alloc, reg, services, states, start_set);

    const db_ptr = alloc.create(sqlite.Db) catch {
        writeErr("failed to allocate database for cert store\n", .{});
        return null;
    };
    errdefer alloc.destroy(db_ptr);
    db_ptr.* = store.openDb() catch {
        writeErr("failed to open database for cert store\n", .{});
        return null;
    };
    errdefer db_ptr.deinit();

    const certs = alloc.create(cert_store_mod.CertStore) catch {
        writeErr("failed to allocate cert store\n", .{});
        return null;
    };
    errdefer alloc.destroy(certs);
    certs.* = cert_store_mod.CertStore.init(db_ptr, alloc) catch {
        writeErr("failed to init cert store (is the master key set?)\n", .{});
        return null;
    };
    errdefer std.crypto.secureZero(u8, &certs.key);

    const proxy = alloc.create(tls_proxy.TlsProxy) catch {
        writeErr("failed to allocate TLS proxy\n", .{});
        return null;
    };
    errdefer alloc.destroy(proxy);
    proxy.* = tls_proxy.TlsProxy.init(alloc, reg, certs, 443, 80) catch {
        writeErr("failed to bind TLS proxy ports (443/80)\n", .{});
        return null;
    };

    if (hasManagedAcmeService(services, start_set)) {
        proxy.setRenewalConfig(.{});
    }

    proxy.start();
    provisionAcmeCerts(alloc, certs, &proxy.challenges, services, start_set);
    return .{
        .backend_registry = reg,
        .proxy = proxy,
        .tls_certs = certs,
        .tls_db = db_ptr,
    };
}

fn shouldStart(start_set: ?std.StringHashMapUnmanaged(void), name: []const u8) bool {
    const set = start_set orelse return true;
    return set.contains(name);
}

fn hasTlsServices(services: []const spec.Service, start_set: ?std.StringHashMapUnmanaged(void)) bool {
    for (services) |svc| {
        if (!shouldStart(start_set, svc.name)) continue;
        if (svc.tls != null) return true;
    }
    return false;
}

fn registerTlsBackends(
    alloc: std.mem.Allocator,
    reg: *tls_backend.BackendRegistry,
    services: []const spec.Service,
    states: anytype,
    start_set: ?std.StringHashMapUnmanaged(void),
) void {
    for (services, 0..) |svc, i| {
        if (!shouldStart(start_set, svc.name)) continue;
        const tls = svc.tls orelse continue;

        const id = states[i].container_id;
        const record = store.load(alloc, id[0..]) catch {
            log.warn("could not find container for {s}, skipping TLS backend", .{svc.name});
            continue;
        };
        defer record.deinit(alloc);

        const target = tlsBackendTargetForService(alloc, svc, tls.domain, record.ip_address) orelse continue;
        defer alloc.free(target.ip);

        reg.register(tls.domain, target.ip, target.port) catch {
            log.warn("failed to register backend for {s}", .{tls.domain});
            continue;
        };
        writeErr("  tls: {s} -> {s}:{d}\n", .{ tls.domain, target.ip, target.port });
    }
}

const TlsBackendTarget = struct {
    ip: []u8,
    port: u16,
};

fn tlsBackendTargetForService(
    alloc: std.mem.Allocator,
    svc: spec.Service,
    tls_domain: []const u8,
    container_ip: ?[]const u8,
) ?TlsBackendTarget {
    if (serviceUsesTlsRoutedListener(svc, tls_domain)) {
        if (listener_runtime.connectTargetIfRunning()) |target| {
            return .{
                .ip = std.fmt.allocPrint(alloc, "{d}.{d}.{d}.{d}", .{
                    target.addr[0],
                    target.addr[1],
                    target.addr[2],
                    target.addr[3],
                }) catch return null,
                .port = target.port,
            };
        }
        log.warn("http listener not running for routed TLS domain {s}; falling back to direct backend", .{tls_domain});
    }

    const ip = container_ip orelse {
        log.warn("no IP for {s}, skipping TLS backend", .{svc.name});
        return null;
    };
    return .{
        .ip = alloc.dupe(u8, ip) catch return null,
        .port = if (svc.ports.len > 0) svc.ports[0].container_port else 80,
    };
}

fn serviceUsesTlsRoutedListener(svc: spec.Service, tls_domain: []const u8) bool {
    if (svc.http_routes.len == 0) return false;
    for (svc.http_routes) |route| {
        if (std.mem.eql(u8, route.host, tls_domain)) return true;
    }
    return false;
}

fn provisionAcmeCerts(
    alloc: std.mem.Allocator,
    certs: *cert_store_mod.CertStore,
    challenges: *tls_proxy.ChallengeStore,
    services: []const spec.Service,
    start_set: ?std.StringHashMapUnmanaged(void),
) void {
    var threaded_io: ?std.Io.Threaded = null;
    defer if (threaded_io) |*io| io.deinit();

    for (services) |svc| {
        if (!shouldStart(start_set, svc.name)) continue;
        const tls = svc.tls orelse continue;
        if (!tls.acme) continue;

        const needs = certs.needsRenewal(tls.domain, 30) catch |err| blk: {
            if (err == cert_store_mod.CertError.NotFound) break :blk true;
            break :blk false;
        };
        if (!needs) {
            writeErr("  tls: {s} has valid certificate\n", .{tls.domain});
            continue;
        }

        writeErr("  tls: provisioning certificate for {s}...\n", .{tls.domain});
        if (threaded_io == null) {
            threaded_io = std.Io.Threaded.init(alloc, .{});
        }
        const acme_io = if (threaded_io) |*io| io.io() else unreachable;
        tls_support.provisionAcmeCertWithIo(
            acme_io,
            alloc,
            certs,
            challenges,
            tls,
        );
    }
}

fn hasManagedAcmeService(
    services: []const spec.Service,
    start_set: ?std.StringHashMapUnmanaged(void),
) bool {
    for (services) |svc| {
        if (!shouldStart(start_set, svc.name)) continue;
        const tls = svc.tls orelse continue;
        if (!tls.acme) continue;
        return true;
    }
    return false;
}

test "syncServiceDefinitions persists http proxy config for started services" {
    const rollout = @import("../../network/service_rollout.zig");
    const service_registry_runtime = @import("../../network/service_registry_runtime.zig");
    const shared_types = @import("../spec/shared_types.zig");
    const test_support = @import("../spec/test_support.zig");

    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();

    const alloc = std.testing.allocator;
    const services = try alloc.alloc(spec.Service, 2);
    defer alloc.free(services);

    services[0] = try test_support.testService(alloc, "api");
    defer services[0].deinit(alloc);
    alloc.free(services[0].ports);
    alloc.free(services[0].http_routes);
    services[0].ports = try alloc.dupe(shared_types.PortMapping, &.{
        .{
            .host_port = 18080,
            .container_port = 8080,
        },
    });
    services[0].http_routes = try alloc.dupe(shared_types.HttpProxyRoute, &.{
        .{
            .name = try alloc.dupe(u8, "default"),
            .host = try alloc.dupe(u8, "api.internal"),
            .path_prefix = try alloc.dupe(u8, "/v1"),
            .retries = 2,
            .connect_timeout_ms = 1500,
            .request_timeout_ms = 5000,
            .preserve_host = false,
        },
    });

    services[1] = try test_support.testService(alloc, "worker");
    defer services[1].deinit(alloc);

    var start_set: std.StringHashMapUnmanaged(void) = .empty;
    defer start_set.deinit(alloc);
    try start_set.put(alloc, "api", {});

    syncServiceDefinitions(alloc, services, start_set);

    const api = try store.getService(alloc, "api");
    defer api.deinit(alloc);
    try std.testing.expectEqualStrings("api.internal", api.http_proxy_host.?);
    try std.testing.expectEqualStrings("/v1", api.http_proxy_path_prefix.?);
    try std.testing.expectEqual(@as(?i64, 8080), api.http_proxy_target_port);

    const api_snapshot = try service_registry_runtime.snapshotService(alloc, "api");
    defer api_snapshot.deinit(alloc);
    try std.testing.expectEqualStrings("api.internal", api_snapshot.http_proxy_host.?);
    try std.testing.expectEqual(@as(?u16, 8080), api_snapshot.http_proxy_target_port);
    try std.testing.expectEqual(@as(usize, 1), api_snapshot.http_routes.len);

    try std.testing.expectError(store.StoreError.NotFound, store.getService(alloc, "worker"));
}

test "tls backend target uses local listener for routed domains" {
    const shared_types = @import("../spec/shared_types.zig");
    const test_support = @import("../spec/test_support.zig");

    const alloc = std.testing.allocator;
    listener_runtime.resetForTest();
    defer listener_runtime.resetForTest();
    try listener_runtime.startOrSkipForTest(alloc, 0);

    var svc = try test_support.testService(alloc, "api");
    defer svc.deinit(alloc);
    alloc.free(svc.http_routes);
    svc.http_routes = try alloc.dupe(shared_types.HttpProxyRoute, &.{
        .{
            .name = try alloc.dupe(u8, "default"),
            .host = try alloc.dupe(u8, "api.example.test"),
            .path_prefix = try alloc.dupe(u8, "/"),
        },
    });

    const listener_target = listener_runtime.connectTargetIfRunning().?;
    const target = tlsBackendTargetForService(alloc, svc, "api.example.test", "10.42.0.9").?;
    defer alloc.free(target.ip);
    try std.testing.expectEqualStrings("127.0.0.1", target.ip);
    try std.testing.expectEqual(listener_target.port, target.port);
}
