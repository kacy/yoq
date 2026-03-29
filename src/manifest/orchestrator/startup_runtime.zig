const std = @import("std");

const spec = @import("../spec.zig");
const store = @import("../../state/store.zig");
const log = @import("../../lib/log.zig");
const ip_mod = @import("../../network/ip.zig");
const proxy_control_plane = @import("../../network/proxy/control_plane.zig");
const health = @import("../health.zig");
const tls_proxy = @import("../../tls/proxy.zig");
const tls_backend = @import("../../tls/backend.zig");
const cert_store_mod = @import("../../tls/cert_store.zig");
const acme_mod = @import("../../tls/acme.zig");
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
            route_inputs.append(alloc, .{
                .route_name = route.name,
                .host = route.host,
                .path_prefix = route.path_prefix,
                .retries = route.retries,
                .connect_timeout_ms = route.connect_timeout_ms,
                .request_timeout_ms = route.request_timeout_ms,
                .target_port = if (svc.ports.len > 0) svc.ports[0].container_port else null,
                .preserve_host = route.preserve_host,
            }) catch {
                log.warn("orchestrator: failed to allocate http routes for {s}", .{svc.name});
                route_alloc_failed = true;
                break;
            };
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
        const ip = record.ip_address orelse {
            log.warn("no IP for {s}, skipping TLS backend refresh", .{svc.name});
            return;
        };
        const port: u16 = if (svc.ports.len > 0) svc.ports[0].container_port else 80;
        reg.register(tls.domain, ip, port) catch {
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

    const acme_email = provisionAcmeCerts(alloc, certs, services, start_set);

    const proxy = alloc.create(tls_proxy.TlsProxy) catch {
        writeErr("failed to allocate TLS proxy\n", .{});
        return null;
    };
    errdefer alloc.destroy(proxy);
    proxy.* = tls_proxy.TlsProxy.init(alloc, reg, certs, 443, 80) catch {
        writeErr("failed to bind TLS proxy ports (443/80)\n", .{});
        return null;
    };

    if (acme_email) |email| {
        proxy.setRenewalConfig(.{
            .email = email,
            .directory_url = acme_mod.letsencrypt_production,
        });
    }

    proxy.start();
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

        const ip = record.ip_address orelse {
            log.warn("no IP for {s}, skipping TLS backend", .{svc.name});
            continue;
        };

        const port: u16 = if (svc.ports.len > 0) svc.ports[0].container_port else 80;
        reg.register(tls.domain, ip, port) catch {
            log.warn("failed to register backend for {s}", .{tls.domain});
            continue;
        };
        writeErr("  tls: {s} -> {s}:{d}\n", .{ tls.domain, ip, port });
    }
}

fn provisionAcmeCerts(
    alloc: std.mem.Allocator,
    certs: *cert_store_mod.CertStore,
    services: []const spec.Service,
    start_set: ?std.StringHashMapUnmanaged(void),
) ?[]const u8 {
    var acme_email: ?[]const u8 = null;

    for (services) |svc| {
        if (!shouldStart(start_set, svc.name)) continue;
        const tls = svc.tls orelse continue;
        if (!tls.acme) continue;

        if (acme_email == null) acme_email = tls.email;

        const needs = certs.needsRenewal(tls.domain, 30) catch |err| blk: {
            if (err == cert_store_mod.CertError.NotFound) break :blk true;
            break :blk false;
        };
        if (!needs) {
            writeErr("  tls: {s} has valid certificate\n", .{tls.domain});
            continue;
        }

        writeErr("  tls: provisioning certificate for {s}...\n", .{tls.domain});
        tls_support.provisionAcmeCert(alloc, certs, tls.domain, tls.email orelse "admin@localhost");
    }

    return acme_email;
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
