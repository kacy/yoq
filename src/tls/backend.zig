// tls routes retain either a fixed listener address or a logical service name.
// service endpoints are selected when a connection arrives, so health changes
// and container restarts do not leave the proxy pinned to an old replica.

const std = @import("std");
const spec = @import("../manifest/spec.zig");
const service_registry = @import("../network/service_registry_runtime.zig");

pub const Backend = struct {
    ip: []const u8,
    port: u16,
    peer_mode: spec.TlsConfig.PeerMode = .off,
};

const Route = struct {
    target: union(enum) { address: []const u8, service: []const u8 },
    port: u16,
    peer_mode: spec.TlsConfig.PeerMode,
    next_endpoint: usize = 0,

    fn deinit(self: Route, alloc: std.mem.Allocator) void {
        switch (self.target) {
            inline else => |value| alloc.free(value),
        }
    }
};

pub const BackendRegistry = struct {
    mutex: std.Io.Mutex = .init,
    backends: std.StringHashMapUnmanaged(Route) = .empty,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) BackendRegistry {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *BackendRegistry) void {
        var iter = self.backends.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.backends.deinit(self.allocator);
    }

    /// register a fixed address, such as the local http route listener.
    pub fn register(self: *BackendRegistry, domain: []const u8, ip: []const u8, port: u16, peer_mode: spec.TlsConfig.PeerMode) !void {
        try self.replace(domain, .{ .target = .{ .address = ip }, .port = port, .peer_mode = peer_mode });
    }

    /// preserve raw tls traffic while choosing an eligible service replica.
    pub fn registerService(self: *BackendRegistry, domain: []const u8, service_name: []const u8, port: u16, peer_mode: spec.TlsConfig.PeerMode) !void {
        try self.replace(domain, .{ .target = .{ .service = service_name }, .port = port, .peer_mode = peer_mode });
    }

    fn replace(self: *BackendRegistry, domain: []const u8, route: Route) !void {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        var owned = route;
        owned.target = switch (route.target) {
            .address => |ip| .{ .address = try self.allocator.dupe(u8, ip) },
            .service => |name| .{ .service = try self.allocator.dupe(u8, name) },
        };
        errdefer owned.deinit(self.allocator);

        // keep the prior route usable if allocating its replacement fails.
        if (self.backends.getEntry(domain)) |entry| {
            entry.value_ptr.deinit(self.allocator);
            entry.value_ptr.* = owned;
            return;
        }
        const owned_domain = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(owned_domain);
        try self.backends.put(self.allocator, owned_domain, owned);
    }

    pub fn unregister(self: *BackendRegistry, domain: []const u8) void {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        if (self.backends.fetchRemove(domain)) |kv| {
            self.allocator.free(kv.key);
            kv.value.deinit(self.allocator);
        }
    }

    /// borrowed fixed-address lookup for callers that exclude concurrent updates.
    /// service routes require lookupOwned to retain the selected endpoint safely.
    pub fn lookup(self: *BackendRegistry, domain: []const u8) ?Backend {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        const route = self.backends.get(domain) orelse return null;
        return switch (route.target) {
            .address => |ip| .{ .ip = ip, .port = route.port, .peer_mode = route.peer_mode },
            .service => null,
        };
    }

    pub fn lookupOwned(self: *BackendRegistry, alloc: std.mem.Allocator, domain: []const u8) !?Backend {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);
        const route = self.backends.getPtr(domain) orelse return null;
        switch (route.target) {
            .address => |ip| return .{ .ip = try alloc.dupe(u8, ip), .port = route.port, .peer_mode = route.peer_mode },
            .service => |name| {
                var endpoints = try service_registry.snapshotServiceEndpoints(alloc, name);
                defer {
                    for (endpoints.items) |endpoint| endpoint.deinit(alloc);
                    endpoints.deinit(alloc);
                }
                return selectEndpoint(alloc, route, endpoints.items);
            },
        }
    }
};

fn selectEndpoint(alloc: std.mem.Allocator, route: *Route, endpoints: []const service_registry.EndpointSnapshot) !?Backend {
    var eligible_count: usize = 0;
    for (endpoints) |endpoint| {
        if (endpoint.eligible) eligible_count += 1;
    }
    if (eligible_count == 0) return null;

    var remaining = route.next_endpoint % eligible_count;
    for (endpoints) |endpoint| {
        if (!endpoint.eligible) continue;
        if (remaining > 0) {
            remaining -= 1;
            continue;
        }
        const backend: Backend = .{
            .ip = try alloc.dupe(u8, endpoint.ip_address),
            .port = route.port,
            .peer_mode = route.peer_mode,
        };
        route.next_endpoint +%= 1;
        return backend;
    }
    unreachable;
}

// -- tests --

test "register and lookup" {
    const alloc = std.testing.allocator;
    var reg = BackendRegistry.init(alloc);
    defer reg.deinit();

    try reg.register("example.com", "10.42.0.5", 8080, .off);

    const backend = reg.lookup("example.com");
    try std.testing.expect(backend != null);
    try std.testing.expectEqualStrings("10.42.0.5", backend.?.ip);
    try std.testing.expectEqual(@as(u16, 8080), backend.?.port);
}

test "lookup nonexistent returns null" {
    const alloc = std.testing.allocator;
    var reg = BackendRegistry.init(alloc);
    defer reg.deinit();

    try std.testing.expect(reg.lookup("ghost.com") == null);
}

test "register overwrites existing" {
    const alloc = std.testing.allocator;
    var reg = BackendRegistry.init(alloc);
    defer reg.deinit();

    try reg.register("example.com", "10.42.0.5", 8080, .off);
    try reg.register("example.com", "10.42.0.10", 9090, .off);

    const backend = reg.lookup("example.com");
    try std.testing.expect(backend != null);
    try std.testing.expectEqualStrings("10.42.0.10", backend.?.ip);
    try std.testing.expectEqual(@as(u16, 9090), backend.?.port);
}

test "unregister removes backend" {
    const alloc = std.testing.allocator;
    var reg = BackendRegistry.init(alloc);
    defer reg.deinit();

    try reg.register("example.com", "10.42.0.5", 8080, .off);
    reg.unregister("example.com");

    try std.testing.expect(reg.lookup("example.com") == null);
}

test "register and lookup carry peer_mode through" {
    const alloc = std.testing.allocator;
    var reg = BackendRegistry.init(alloc);
    defer reg.deinit();

    try reg.register("api.example", "10.0.0.1", 8443, .require);

    const got = reg.lookup("api.example").?;
    try std.testing.expectEqual(spec.TlsConfig.PeerMode.require, got.peer_mode);

    const owned = (try reg.lookupOwned(alloc, "api.example")).?;
    defer alloc.free(owned.ip);
    try std.testing.expectEqual(spec.TlsConfig.PeerMode.require, owned.peer_mode);
}

test "register without peer_mode defaults to off via overwrite path" {
    const alloc = std.testing.allocator;
    var reg = BackendRegistry.init(alloc);
    defer reg.deinit();

    try reg.register("api.example", "10.0.0.1", 8443, .require);
    try reg.register("api.example", "10.0.0.2", 9090, .off);

    const got = reg.lookup("api.example").?;
    try std.testing.expectEqual(spec.TlsConfig.PeerMode.off, got.peer_mode);
    try std.testing.expectEqualStrings("10.0.0.2", got.ip);
}

test "unregister nonexistent is safe" {
    const alloc = std.testing.allocator;
    var reg = BackendRegistry.init(alloc);
    defer reg.deinit();

    reg.unregister("ghost.com"); // should not crash
}

test "multiple domains" {
    const alloc = std.testing.allocator;
    var reg = BackendRegistry.init(alloc);
    defer reg.deinit();

    try reg.register("a.com", "10.42.0.1", 80, .off);
    try reg.register("b.com", "10.42.0.2", 443, .off);

    const a = reg.lookup("a.com");
    const b = reg.lookup("b.com");
    try std.testing.expect(a != null);
    try std.testing.expect(b != null);
    try std.testing.expectEqualStrings("10.42.0.1", a.?.ip);
    try std.testing.expectEqualStrings("10.42.0.2", b.?.ip);
}

test "lookupOwned returns stable backend copy" {
    const alloc = std.testing.allocator;
    var reg = BackendRegistry.init(alloc);
    defer reg.deinit();

    try reg.register("example.com", "10.42.0.5", 8080, .off);
    const owned = (try reg.lookupOwned(alloc, "example.com")).?;
    defer alloc.free(owned.ip);

    reg.unregister("example.com");
    try std.testing.expectEqualStrings("10.42.0.5", owned.ip);
    try std.testing.expectEqual(@as(u16, 8080), owned.port);
}

test "backend replacement allocation failure preserves original routing" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var registry = BackendRegistry.init(failing.allocator());
    defer registry.deinit();
    try registry.register("api.example", "10.0.0.1", 8443, .require);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, registry.register("api.example", "10.0.0.2", 80, .off));
    const backend = (try registry.lookupOwned(std.testing.allocator, "api.example")).?;
    defer std.testing.allocator.free(backend.ip);
    try std.testing.expectEqualStrings("10.0.0.1", backend.ip);
    try std.testing.expectEqual(@as(u16, 8443), backend.port);
    try std.testing.expectEqual(spec.TlsConfig.PeerMode.require, backend.peer_mode);
}

test "tls service routes select every eligible replica and fail closed" {
    const store = @import("../state/store.zig");
    const rollout = @import("../network/service_rollout.zig");
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();
    service_registry.resetForTest();
    defer service_registry.resetForTest();
    rollout.setForTest(.{ .service_registry_v2 = true });
    defer rollout.resetForTest();

    try store.createService(.{ .service_name = "api", .vip_address = "10.43.0.2", .lb_policy = "round_robin", .created_at = 1, .updated_at = 1 });
    const ids = [_][]const u8{ "replica-one", "replica-two", "replica-three" };
    const addresses = [_][]const u8{ "10.42.0.2", "10.42.0.3", "10.42.0.4" };
    for (ids, addresses) |id, address| try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = id,
        .container_id = id,
        .node_id = null,
        .ip_address = address,
        .port = 0,
        .weight = 1,
        .admin_state = "active",
        .generation = 1,
        .registered_at = 1,
        .last_seen_at = 1,
    });
    service_registry.syncServiceFromStore("api");

    var registry = BackendRegistry.init(alloc);
    defer registry.deinit();
    try registry.registerService("api.example", "api", 5432, .require);
    var seen = [_]bool{false} ** 3;
    for (0..3) |_| {
        const backend = (try registry.lookupOwned(alloc, "api.example")).?;
        defer alloc.free(backend.ip);
        for (addresses, 0..) |address, index| {
            if (std.mem.eql(u8, address, backend.ip)) seen[index] = true;
        }
        try std.testing.expectEqual(@as(u16, 5432), backend.port);
        try std.testing.expectEqual(spec.TlsConfig.PeerMode.require, backend.peer_mode);
    }
    for (seen) |was_seen| try std.testing.expect(was_seen);

    service_registry.noteProbeResult("api", ids[0], false);
    try store.upsertServiceEndpoint(.{
        .service_name = "api",
        .endpoint_id = ids[1],
        .container_id = ids[1],
        .node_id = null,
        .ip_address = addresses[1],
        .port = 0,
        .weight = 1,
        .admin_state = "draining",
        .generation = 1,
        .registered_at = 1,
        .last_seen_at = 1,
    });
    service_registry.syncServiceFromStore("api");
    for (0..3) |_| {
        const backend = (try registry.lookupOwned(alloc, "api.example")).?;
        defer alloc.free(backend.ip);
        try std.testing.expectEqualStrings(addresses[2], backend.ip);
    }

    const retained = (try registry.lookupOwned(alloc, "api.example")).?;
    defer alloc.free(retained.ip);
    service_registry.noteProbeResult("api", ids[2], false);
    try std.testing.expect((try registry.lookupOwned(alloc, "api.example")) == null);
    registry.unregister("api.example");
    try std.testing.expectEqualStrings(addresses[2], retained.ip);
}

test "tls service registration failure preserves a fixed route" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var registry = BackendRegistry.init(failing.allocator());
    defer registry.deinit();
    try registry.register("api.example", "127.0.0.1", 8080, .off);
    failing.fail_index = failing.alloc_index;
    try std.testing.expectError(error.OutOfMemory, registry.registerService("api.example", "api", 5432, .require));
    const backend = (try registry.lookupOwned(std.testing.allocator, "api.example")).?;
    defer std.testing.allocator.free(backend.ip);
    try std.testing.expectEqualStrings("127.0.0.1", backend.ip);
    try std.testing.expectEqual(@as(u16, 8080), backend.port);
}
