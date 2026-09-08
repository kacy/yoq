const std = @import("std");
const store = @import("../../../state/store.zig");
const secrets = @import("../../../state/secrets.zig");
const cert_store = @import("../../../tls/cert_store.zig");

pub fn openSecretsStore(alloc: std.mem.Allocator) ?secrets.SecretsStore {
    const db = store.openOwnedDb(alloc) catch return null;
    return secrets.SecretsStore.init(db, alloc) catch {
        store.closeOwnedDb(alloc, db);
        return null;
    };
}

pub fn closeSecretsStore(alloc: std.mem.Allocator, sec: *secrets.SecretsStore) void {
    store.closeOwnedDb(alloc, sec.db);
}

pub fn openCertStore(alloc: std.mem.Allocator) ?cert_store.CertStore {
    const db = store.openOwnedDb(alloc) catch return null;
    return cert_store.CertStore.init(db, alloc) catch {
        store.closeOwnedDb(alloc, db);
        return null;
    };
}

pub fn closeCertStore(alloc: std.mem.Allocator, cs: *cert_store.CertStore) void {
    store.closeOwnedDb(alloc, cs.db);
}
