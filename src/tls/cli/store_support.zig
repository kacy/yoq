const std = @import("std");
const cli = @import("../../lib/cli.zig");
const cert_store = @import("../cert_store.zig");
const store = @import("../../state/store.zig");
const sqlite = @import("sqlite");
const common = @import("common.zig");

const writeErr = cli.writeErr;

pub const OpenStoreError = error{
    AllocateDbFailed,
    DbOpenFailed,
    HomeDirNotFound,
    StoreInitFailed,
};

pub const OpenedStore = struct {
    db: *sqlite.Db,
    store: cert_store.CertStore,
};

pub fn openCertStore(alloc: std.mem.Allocator) OpenStoreError!OpenedStore {
    const db_ptr = alloc.create(sqlite.Db) catch return OpenStoreError.AllocateDbFailed;
    errdefer alloc.destroy(db_ptr);

    db_ptr.* = store.openDb() catch return OpenStoreError.DbOpenFailed;
    errdefer db_ptr.deinit();

    const opened_store = cert_store.CertStore.init(db_ptr, alloc) catch |err| return switch (err) {
        cert_store.CertError.HomeDirNotFound => OpenStoreError.HomeDirNotFound,
        else => OpenStoreError.StoreInitFailed,
    };

    return .{
        .db = db_ptr,
        .store = opened_store,
    };
}

pub fn closeCertStore(alloc: std.mem.Allocator, opened: *OpenedStore) void {
    opened.store.db.deinit();
    alloc.destroy(opened.store.db);
}

pub fn reportOpenStoreError(err: OpenStoreError) common.TlsCommandsError {
    switch (err) {
        OpenStoreError.AllocateDbFailed => writeErr("failed to allocate database\n", .{}),
        OpenStoreError.DbOpenFailed => writeErr("failed to open database\n", .{}),
        OpenStoreError.HomeDirNotFound => writeErr("HOME directory not found\n", .{}),
        OpenStoreError.StoreInitFailed => writeErr("failed to initialize certificate store\n", .{}),
    }
    return common.TlsCommandsError.StoreFailed;
}
