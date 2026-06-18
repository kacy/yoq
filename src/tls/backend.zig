// backend — domain-to-container routing for TLS proxy
//
// maps domain names to container backends (IP:port pairs). updated
// when containers start and stop. the TLS proxy uses this to route
// decrypted traffic after completing the TLS handshake.
//
// thread-safe: protected by a mutex since the proxy accept loop
// and the orchestrator lifecycle run on different threads.

const std = @import("std");
const spec = @import("../manifest/spec.zig");

pub const Backend = struct {
    ip: []const u8,
    port: u16,
    /// service-to-service mTLS posture for inbound traffic to this
    /// backend's service. `.off` keeps the legacy (TLS-terminate only)
    /// behavior; `.warn` and `.require` flip the listener to mTLS.
    peer_mode: spec.TlsConfig.PeerMode = .off,
};

pub const BackendRegistry = struct {
    mutex: std.Io.Mutex,
    backends: std.StringHashMapUnmanaged(Backend),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) BackendRegistry {
        return .{
            .mutex = .init,
            .backends = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BackendRegistry) void {
        var iter = self.backends.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.ip);
        }
        self.backends.deinit(self.allocator);
    }

    /// register a backend for a domain. overwrites any existing mapping.
    pub fn register(
        self: *BackendRegistry,
        domain: []const u8,
        ip: []const u8,
        port: u16,
        peer_mode: spec.TlsConfig.PeerMode,
    ) !void {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        // if domain already exists, free old values
        if (self.backends.getEntry(domain)) |entry| {
            self.allocator.free(entry.value_ptr.ip);
            const new_ip = try self.allocator.dupe(u8, ip);
            entry.value_ptr.* = .{ .ip = new_ip, .port = port, .peer_mode = peer_mode };
            return;
        }

        const owned_domain = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(owned_domain);
        const owned_ip = try self.allocator.dupe(u8, ip);
        errdefer self.allocator.free(owned_ip);

        try self.backends.put(self.allocator, owned_domain, .{ .ip = owned_ip, .port = port, .peer_mode = peer_mode });
    }

    /// remove a backend for a domain.
    pub fn unregister(self: *BackendRegistry, domain: []const u8) void {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        if (self.backends.fetchRemove(domain)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.ip);
        }
    }

    /// look up the backend for a domain. returns null if not registered.
    /// the returned Backend is only valid while the mutex is not held —
    /// callers should copy what they need.
    pub fn lookup(self: *BackendRegistry, domain: []const u8) ?Backend {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        return self.backends.get(domain);
    }

    pub fn lookupOwned(self: *BackendRegistry, alloc: std.mem.Allocator, domain: []const u8) !?Backend {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        const backend = self.backends.get(domain) orelse return null;
        return .{
            .ip = try alloc.dupe(u8, backend.ip),
            .port = backend.port,
            .peer_mode = backend.peer_mode,
        };
    }
};

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
