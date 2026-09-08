const std = @import("std");
const secrets = @import("secrets.zig");
const store = @import("store.zig");
const cli = @import("../lib/cli.zig");

const writeErr = cli.writeErr;

pub fn open(alloc: std.mem.Allocator) secrets.SecretsStore {
    const db_ptr = store.openOwnedDb(alloc) catch |err| {
        switch (err) {
            error.AllocateDbFailed => writeErr("failed to allocate database\n", .{}),
            error.DbOpenFailed => writeErr("failed to open database\n", .{}),
        }
        std.process.exit(1);
    };

    return secrets.SecretsStore.init(db_ptr, alloc) catch |err| {
        store.closeOwnedDb(alloc, db_ptr);
        if (err == secrets.SecretsError.HomeDirNotFound) {
            writeErr("HOME directory not found\n", .{});
        } else {
            writeErr("failed to initialize secrets store\n", .{});
        }
        std.process.exit(1);
    };
}

pub fn close(alloc: std.mem.Allocator, sec: *secrets.SecretsStore) void {
    store.closeOwnedDb(alloc, sec.db);
}
