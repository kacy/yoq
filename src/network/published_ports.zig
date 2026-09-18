// shared host ports belong to a service, with one durable claim per container.
// rebuilding only our chains preserves administrator rules and established
// connections. a stopped supervisor can release its claims without touching
// the replacement's containers.
const std = @import("std");
const sqlite = @import("sqlite");
const platform = @import("linux_platform");
const store = @import("../state/store.zig");
const common = @import("../state/store/common.zig");
const registry = @import("service_registry_runtime.zig");
const spec = @import("../manifest/spec.zig");
const paths = @import("../lib/paths.zig");
const ip = @import("ip.zig");
const firewall = @import("published_ports_firewall.zig");
const log = @import("../lib/log.zig");
const io = std.Options.debug_io;
const Allocator = std.mem.Allocator;

const Claim = struct {
    app: []const u8,
    service: []const u8,
    container: []const u8,
    host_port: u16,
    target_port: u16,
    address: [4]u8 = .{ 0, 0, 0, 0 },
    eligible: bool = false,
};
const Claims = std.ArrayList(Claim);
const Apply = *const fn (Allocator, []const Claim) anyerror!void;
var mutex: std.Io.Mutex = .init;

pub fn publishInstance(alloc: Allocator, app_name: ?[]const u8, service_name: []const u8, container_id: []const u8, ports: []const spec.PortMapping) !void {
    if (ports.len == 0) return;
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    const lock = try acquireLock();
    defer platform.posix.close(lock);
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    try change(arena.allocator(), .{ .publish = .{
        .app = app_name orelse "",
        .service = service_name,
        .container = container_id,
        .ports = ports,
    } }, applyRules);
}

pub fn removeInstance(alloc: Allocator, container_id: []const u8) !void {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    const lock = try acquireLock();
    defer platform.posix.close(lock);
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    try change(arena.allocator(), .{ .remove = container_id }, applyRules);
}

/// called after registry events, once registry and store locks are released.
pub fn refreshAll() void {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    // most commands do not publish ports. avoid creating lock files or running
    // privileged commands when there is no published service on this host.
    const claims = loadClaims(alloc) catch return;
    if (claims.items.len == 0) return;
    const lock = acquireLock() catch |err| {
        log.warn("published ports: cannot lock host rules: {}", .{err});
        return;
    };
    defer platform.posix.close(lock);
    change(alloc, .refresh, applyRules) catch |err| {
        log.warn("published ports: cannot refresh host rules: {}", .{err});
    };
}

const Change = union(enum) {
    publish: struct { app: []const u8, service: []const u8, container: []const u8, ports: []const spec.PortMapping },
    remove: []const u8,
    refresh,
};

fn change(alloc: Allocator, operation: Change, apply: Apply) !void {
    const previous = try loadClaims(alloc);
    if (previous.items.len == 0 and operation != .publish) return;
    try resolveBackends(alloc, previous.items);
    var next: Claims = .empty;
    for (previous.items) |claim| {
        const record = store.load(alloc, claim.container) catch |err| switch (err) {
            error.NotFound => continue,
            else => return err,
        };
        if (!std.mem.eql(u8, record.status, "running")) continue;
        if (operation == .remove and std.mem.eql(u8, claim.container, operation.remove)) continue;
        if (operation == .publish and std.mem.eql(u8, claim.container, operation.publish.container)) continue;
        try next.append(alloc, claim);
    }
    if (operation == .publish) {
        const request = operation.publish;
        const record = try store.load(alloc, request.container);
        if (!std.mem.eql(u8, record.status, "running")) return error.ContainerNotRunning;
        if (!std.mem.eql(u8, record.app_name orelse "", request.app) or
            !std.mem.eql(u8, record.hostname, request.service)) return error.ContainerOwnerMismatch;
        for (request.ports) |port| {
            if (port.host_port == 0 or port.container_port == 0) return error.InvalidPort;
            try appendClaim(alloc, &next, .{ .app = request.app, .service = request.service, .container = request.container, .host_port = port.host_port, .target_port = port.container_port });
        }
    }
    try resolveBackends(alloc, next.items);
    // a failed database commit or partial table update restores the prior
    // dataplane. the durable claims remain the source for the next retry.
    apply(alloc, next.items) catch |err| {
        apply(alloc, previous.items) catch |restore_err| log.err("published ports: rollback failed: {}", .{restore_err});
        return err;
    };
    saveClaims(next.items) catch |err| {
        apply(alloc, previous.items) catch |restore_err| log.err("published ports: rollback failed: {}", .{restore_err});
        return err;
    };
}

fn appendClaim(alloc: Allocator, claims: *Claims, claim: Claim) !void {
    for (claims.items) |existing| {
        if (existing.host_port != claim.host_port) continue;
        if (!std.mem.eql(u8, existing.app, claim.app) or
            !std.mem.eql(u8, existing.service, claim.service) or
            existing.target_port != claim.target_port) return error.PortAlreadyPublished;
        if (std.mem.eql(u8, existing.container, claim.container)) return;
    }
    try claims.append(alloc, claim);
}

fn resolveBackends(alloc: Allocator, claims: []Claim) !void {
    for (claims) |*claim| {
        claim.eligible = false;
        const endpoints = registry.snapshotServiceEndpoints(alloc, claim.service) catch |err| switch (err) {
            error.ServiceNotFound => continue,
            else => return err,
        };
        for (endpoints.items) |endpoint| {
            if (!endpoint.eligible or !std.mem.eql(u8, endpoint.container_id, claim.container)) continue;
            claim.address = ip.parseIp(endpoint.ip_address) orelse return error.InvalidAddress;
            claim.eligible = true;
            break;
        }
    }
}

const schema_sql =
    "CREATE TABLE IF NOT EXISTS published_port_claims (" ++
    "app TEXT NOT NULL, service TEXT NOT NULL, container TEXT NOT NULL, " ++
    "host_port INTEGER NOT NULL, target_port INTEGER NOT NULL, PRIMARY KEY(container, host_port));";

// callers use a temporary arena so row strings and snapshots have one lifetime.
fn loadClaims(alloc: Allocator) !Claims {
    var lease = try common.leaseDb();
    defer lease.deinit();
    try lease.db.exec(schema_sql, .{}, .{});
    var stmt = try lease.db.prepare("SELECT app, service, container, host_port, target_port FROM published_port_claims ORDER BY host_port, container;");
    defer stmt.deinit();
    const Row = struct { app: sqlite.Text, service: sqlite.Text, container: sqlite.Text, host_port: i64, target_port: i64 };
    var iter = try stmt.iterator(Row, .{});
    var claims: Claims = .empty;
    while (try iter.nextAlloc(alloc, .{})) |row| {
        if (row.host_port < 1 or row.host_port > 65535 or row.target_port < 1 or row.target_port > 65535) return error.InvalidPort;
        try claims.append(alloc, .{ .app = row.app.data, .service = row.service.data, .container = row.container.data, .host_port = @intCast(row.host_port), .target_port = @intCast(row.target_port) });
    }
    return claims;
}

fn saveClaims(claims: []const Claim) !void {
    var lease = try common.leaseDb();
    defer lease.deinit();
    try lease.db.exec("BEGIN IMMEDIATE;", .{}, .{});
    errdefer lease.db.exec("ROLLBACK;", .{}, .{}) catch {};
    try lease.db.exec("DELETE FROM published_port_claims;", .{}, .{});
    for (claims) |claim| try lease.db.exec("INSERT INTO published_port_claims (app, service, container, host_port, target_port) VALUES (?, ?, ?, ?, ?);", .{}, .{ claim.app, claim.service, claim.container, claim.host_port, claim.target_port });
    try lease.db.exec("COMMIT;", .{}, .{});
}

fn acquireLock() !std.posix.fd_t {
    var buf: [paths.max_path]u8 = undefined;
    const owner = try paths.dataPath(&buf, "");
    return @import("published_ports_lock.zig").acquire(owner);
}

fn renderRules(alloc: Allocator, claims: []const Claim) ![]const u8 {
    return firewall.renderRules(alloc, try backends(alloc, claims));
}

fn backends(alloc: Allocator, claims: []const Claim) ![]firewall.Backend {
    const result = try alloc.alloc(firewall.Backend, claims.len);
    for (claims, result) |claim, *backend| backend.* = .{
        .host_port = claim.host_port,
        .target_port = claim.target_port,
        .address = claim.address,
        .eligible = claim.eligible,
    };
    return result;
}

fn applyRules(alloc: Allocator, claims: []const Claim) !void {
    try firewall.apply(alloc, try backends(alloc, claims));
}

test "published ports reject another service and retain sibling ownership" {
    const alloc = std.testing.allocator;
    var claims: Claims = .empty;
    defer claims.deinit(alloc);
    const first: Claim = .{ .app = "shop", .service = "web", .container = "one", .host_port = 8080, .target_port = 80 };
    try appendClaim(alloc, &claims, first);
    var second = first;
    second.container = "two";
    try appendClaim(alloc, &claims, second);
    try std.testing.expectEqual(@as(usize, 2), claims.items.len);
    second.app = "other";
    try std.testing.expectError(error.PortAlreadyPublished, appendClaim(alloc, &claims, second));
    second.app = "shop";
    second.target_port = 90;
    try std.testing.expectError(error.PortAlreadyPublished, appendClaim(alloc, &claims, second));
}

test "published ports balance eligible replicas and reject an empty service" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const claims = [_]Claim{
        .{ .app = "a", .service = "web", .container = "one", .host_port = 8080, .target_port = 80, .address = .{ 10, 42, 0, 2 }, .eligible = true },
        .{ .app = "a", .service = "web", .container = "two", .host_port = 8080, .target_port = 80, .address = .{ 10, 42, 0, 3 }, .eligible = true },
        .{ .app = "a", .service = "web", .container = "bad", .host_port = 8080, .target_port = 80, .address = .{ 10, 42, 0, 4 } },
        .{ .app = "a", .service = "empty", .container = "pending", .host_port = 9090, .target_port = 90 },
    };
    const rules = try renderRules(arena.allocator(), &claims);
    try std.testing.expect(std.mem.indexOf(u8, rules, "--probability 0.5000000000") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "10.42.0.2:80") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "10.42.0.3:80") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "10.42.0.4") == null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "--dport 9090 -j REJECT") != null);
}

test "published ports preserve durable sibling claims after removal and apply failure" {
    try store.initTestDb();
    defer store.deinitTestDb();
    registry.resetForTest();
    defer registry.resetForTest();
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    for ([_][]const u8{ "one", "two", "replacement" }) |id| try store.save(.{
        .id = id,
        .rootfs = "/rootfs",
        .command = "server",
        .hostname = "web",
        .status = "running",
        .pid = 1,
        .exit_code = null,
        .app_name = "shop",
        .created_at = 0,
    });
    const Fake = struct {
        var fail_next: bool = false;
        var calls: usize = 0;
        fn apply(_: Allocator, _: []const Claim) !void {
            calls += 1;
            if (fail_next) {
                fail_next = false;
                return error.InjectedFirewallFailure;
            }
        }
    };
    Fake.fail_next = false;
    Fake.calls = 0;
    const ports = [_]spec.PortMapping{.{ .host_port = 8080, .container_port = 80 }};
    for ([_][]const u8{ "one", "two" }) |id| try change(alloc, .{ .publish = .{
        .app = "shop",
        .service = "web",
        .container = id,
        .ports = &ports,
    } }, Fake.apply);
    try std.testing.expectEqual(@as(usize, 2), (try loadClaims(alloc)).items.len);
    try change(alloc, .{ .remove = "one" }, Fake.apply);
    // an old supervisor can repeat cleanup after its replacement has started.
    try change(alloc, .{ .remove = "one" }, Fake.apply);
    var saved = try loadClaims(alloc);
    try std.testing.expectEqual(@as(usize, 1), saved.items.len);
    try std.testing.expectEqualStrings("two", saved.items[0].container);
    Fake.fail_next = true;
    const before = Fake.calls;
    try std.testing.expectError(error.InjectedFirewallFailure, change(alloc, .{ .publish = .{
        .app = "shop",
        .service = "web",
        .container = "replacement",
        .ports = &ports,
    } }, Fake.apply));
    try std.testing.expectEqual(before + 2, Fake.calls);
    saved = try loadClaims(alloc);
    try std.testing.expectEqual(@as(usize, 1), saved.items.len);
    try std.testing.expectEqualStrings("two", saved.items[0].container);
    try store.updateStatus("two", "stopped", null, 0);
    try change(alloc, .refresh, Fake.apply);
    try std.testing.expectEqual(@as(usize, 0), (try loadClaims(alloc)).items.len);
}
