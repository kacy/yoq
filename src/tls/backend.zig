// backend — domain-to-container routing for TLS proxy
//
// maps domain names to container backends (IP:port pairs). updated
// when containers start and stop. the TLS proxy uses this to route
// decrypted traffic after completing the TLS handshake.
//
// thread-safe: protected by a mutex since the proxy accept loop
// and the orchestrator lifecycle run on different threads.

const std = @import("std");

pub const Backend = struct {
    ip: []const u8,
    port: u16,
};

pub const BackendRegistry = struct {
    mutex: std.Thread.Mutex,
    backends: std.StringHashMapUnmanaged(Backend),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) BackendRegistry {
        return .{
            .mutex = .{},
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
    pub fn register(self: *BackendRegistry, domain: []const u8, ip: []const u8, port: u16) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        // if domain already exists, free old values
        if (self.backends.getEntry(domain)) |entry| {
            self.allocator.free(entry.value_ptr.ip);
            const new_ip = try self.allocator.dupe(u8, ip);
            entry.value_ptr.* = .{ .ip = new_ip, .port = port };
            return;
        }

        const owned_domain = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(owned_domain);
        const owned_ip = try self.allocator.dupe(u8, ip);
        errdefer self.allocator.free(owned_ip);

        try self.backends.put(self.allocator, owned_domain, .{ .ip = owned_ip, .port = port });
    }

    /// remove a backend for a domain.
    pub fn unregister(self: *BackendRegistry, domain: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.backends.fetchRemove(domain)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value.ip);
        }
    }

    /// look up the backend for a domain. returns null if not registered.
    /// the returned Backend is only valid while the mutex is not held —
    /// callers should copy what they need.
    pub fn lookup(self: *BackendRegistry, domain: []const u8) ?Backend {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.backends.get(domain);
    }
};

// -- tests --

test "register and lookup" {
    const alloc = std.testing.allocator;
    var reg = BackendRegistry.init(alloc);
    defer reg.deinit();

    try reg.register("example.com", "10.42.0.5", 8080);

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

    try reg.register("example.com", "10.42.0.5", 8080);
    try reg.register("example.com", "10.42.0.10", 9090);

    const backend = reg.lookup("example.com");
    try std.testing.expect(backend != null);
    try std.testing.expectEqualStrings("10.42.0.10", backend.?.ip);
    try std.testing.expectEqual(@as(u16, 9090), backend.?.port);
}

test "unregister removes backend" {
    const alloc = std.testing.allocator;
    var reg = BackendRegistry.init(alloc);
    defer reg.deinit();

    try reg.register("example.com", "10.42.0.5", 8080);
    reg.unregister("example.com");

    try std.testing.expect(reg.lookup("example.com") == null);
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

    try reg.register("a.com", "10.42.0.1", 80);
    try reg.register("b.com", "10.42.0.2", 443);

    const a = reg.lookup("a.com");
    const b = reg.lookup("b.com");
    try std.testing.expect(a != null);
    try std.testing.expect(b != null);
    try std.testing.expectEqualStrings("10.42.0.1", a.?.ip);
    try std.testing.expectEqualStrings("10.42.0.2", b.?.ip);
}
