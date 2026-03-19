const std = @import("std");
const sqlite = @import("sqlite");
const store = @import("../../../state/store.zig");
const secrets = @import("../../../state/secrets.zig");
const cert_store = @import("../../../tls/cert_store.zig");

pub fn openSecretsStore(alloc: std.mem.Allocator) ?secrets.SecretsStore {
    const db_ptr = alloc.create(sqlite.Db) catch return null;
    db_ptr.* = store.openDb() catch {
        alloc.destroy(db_ptr);
        return null;
    };
    return secrets.SecretsStore.init(db_ptr, alloc) catch {
        db_ptr.deinit();
        alloc.destroy(db_ptr);
        return null;
    };
}

pub fn closeSecretsStore(alloc: std.mem.Allocator, sec: *secrets.SecretsStore) void {
    sec.db.deinit();
    alloc.destroy(sec.db);
}

pub fn openCertStore(alloc: std.mem.Allocator) ?cert_store.CertStore {
    const db_ptr = alloc.create(sqlite.Db) catch return null;
    db_ptr.* = store.openDb() catch {
        alloc.destroy(db_ptr);
        return null;
    };
    return cert_store.CertStore.init(db_ptr, alloc) catch {
        db_ptr.deinit();
        alloc.destroy(db_ptr);
        return null;
    };
}

pub fn closeCertStore(alloc: std.mem.Allocator, cs: *cert_store.CertStore) void {
    cs.db.deinit();
    alloc.destroy(cs.db);
}
