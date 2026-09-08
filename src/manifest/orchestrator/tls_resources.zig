const std = @import("std");
const sqlite = @import("sqlite");
const store = @import("../../state/store.zig");
const tls_proxy = @import("../../tls/proxy.zig");
const tls_backend = @import("../../tls/backend.zig");
const cert_store = @import("../../tls/cert_store.zig");

pub const InitError = store.OwnedDbError || error{
    AllocateRegistryFailed,
    AllocateCertStoreFailed,
    InitCertStoreFailed,
    AllocateProxyFailed,
    BindProxyFailed,
};

const InitDeps = struct {
    open_db: *const fn (std.mem.Allocator) store.OwnedDbError!*sqlite.Db = store.openOwnedDb,
    init_certs: *const fn (*sqlite.Db, std.mem.Allocator) cert_store.CertError!cert_store.CertStore = cert_store.CertStore.init,
    init_proxy: *const fn (std.mem.Allocator, *tls_backend.BackendRegistry, *cert_store.CertStore, u16, u16) tls_proxy.ProxyError!tls_proxy.TlsProxy = tls_proxy.TlsProxy.init,
};

/// the proxy borrows its registry and certificate store, so stop it before
/// releasing either. the certificate store in turn borrows the database.
pub const TlsResources = struct {
    backend_registry: *tls_backend.BackendRegistry,
    proxy: *tls_proxy.TlsProxy,
    tls_certs: *cert_store.CertStore,
    tls_db: *sqlite.Db,

    /// bind both listeners without starting workers. callers register backends
    /// and configure renewal before starting the proxy.
    pub fn init(alloc: std.mem.Allocator) InitError!TlsResources {
        return initWithDeps(alloc, .{});
    }

    fn initWithDeps(alloc: std.mem.Allocator, deps: InitDeps) InitError!TlsResources {
        const registry = alloc.create(tls_backend.BackendRegistry) catch return error.AllocateRegistryFailed;
        registry.* = tls_backend.BackendRegistry.init(alloc);
        errdefer {
            registry.deinit();
            alloc.destroy(registry);
        }

        const db = try deps.open_db(alloc);
        errdefer store.closeOwnedDb(alloc, db);

        const certs = alloc.create(cert_store.CertStore) catch return error.AllocateCertStoreFailed;
        errdefer alloc.destroy(certs);
        certs.* = deps.init_certs(db, alloc) catch return error.InitCertStoreFailed;
        errdefer std.crypto.secureZero(u8, &certs.key);

        const proxy = alloc.create(tls_proxy.TlsProxy) catch return error.AllocateProxyFailed;
        errdefer alloc.destroy(proxy);
        proxy.* = deps.init_proxy(alloc, registry, certs, 443, 80) catch return error.BindProxyFailed;

        return .{ .backend_registry = registry, .proxy = proxy, .tls_certs = certs, .tls_db = db };
    }

    pub fn deinit(self: *TlsResources, alloc: std.mem.Allocator) void {
        self.proxy.deinit();
        alloc.destroy(self.proxy);
        std.crypto.secureZero(u8, &self.tls_certs.key);
        alloc.destroy(self.tls_certs);
        store.closeOwnedDb(alloc, self.tls_db);
        self.backend_registry.deinit();
        alloc.destroy(self.backend_registry);
    }
};

const FailureStage = enum { database, certificates, listener };

const TestDeps = struct {
    fn openMemory(alloc: std.mem.Allocator) store.OwnedDbError!*sqlite.Db {
        const db = alloc.create(sqlite.Db) catch return error.AllocateDbFailed;
        errdefer alloc.destroy(db);
        db.* = sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } }) catch return error.DbOpenFailed;
        return db;
    }

    fn failOpen(_: std.mem.Allocator) store.OwnedDbError!*sqlite.Db {
        return error.DbOpenFailed;
    }

    fn initCerts(db: *sqlite.Db, alloc: std.mem.Allocator) cert_store.CertError!cert_store.CertStore {
        return cert_store.CertStore.initWithKey(db, alloc, [_]u8{0x42} ** cert_store.key_length);
    }

    fn failCerts(_: *sqlite.Db, _: std.mem.Allocator) cert_store.CertError!cert_store.CertStore {
        return error.KeyLoadFailed;
    }

    fn failProxy(_: std.mem.Allocator, _: *tls_backend.BackendRegistry, _: *cert_store.CertStore, _: u16, _: u16) tls_proxy.ProxyError!tls_proxy.TlsProxy {
        return error.SocketFailed;
    }
};

fn checkTlsRollback(alloc: std.mem.Allocator, stage: FailureStage) !void {
    var resources = TlsResources.initWithDeps(alloc, .{
        .open_db = if (stage == .database) TestDeps.failOpen else TestDeps.openMemory,
        .init_certs = if (stage == .certificates) TestDeps.failCerts else TestDeps.initCerts,
        .init_proxy = TestDeps.failProxy,
    }) catch |err| {
        switch (err) {
            error.AllocateRegistryFailed, error.AllocateDbFailed, error.AllocateCertStoreFailed, error.AllocateProxyFailed => return error.OutOfMemory,
            else => {},
        }
        const expected: InitError = switch (stage) {
            .database => error.DbOpenFailed,
            .certificates => error.InitCertStoreFailed,
            .listener => error.BindProxyFailed,
        };
        try std.testing.expectEqual(expected, err);
        return;
    };
    defer resources.deinit(alloc);
    return error.ExpectedStartupFailure;
}

test "tls resources release partial state on allocation and initialization failures" {
    inline for (.{ FailureStage.database, FailureStage.certificates, FailureStage.listener }) |stage| {
        try std.testing.checkAllAllocationFailures(std.testing.allocator, checkTlsRollback, .{stage});
    }
}
