const std = @import("std");
const sqlite = @import("sqlite");
const secrets = @import("secrets.zig");
const store = @import("store.zig");
const cli = @import("../lib/cli.zig");

const writeErr = cli.writeErr;

pub fn open(alloc: std.mem.Allocator) secrets.SecretsStore {
    const db_ptr = alloc.create(sqlite.Db) catch {
        writeErr("failed to allocate database\n", .{});
        std.process.exit(1);
    };
    db_ptr.* = store.openDb() catch {
        alloc.destroy(db_ptr);
        writeErr("failed to open database\n", .{});
        std.process.exit(1);
    };

    return secrets.SecretsStore.init(db_ptr, alloc) catch |err| {
        db_ptr.deinit();
        alloc.destroy(db_ptr);
        if (err == secrets.SecretsError.HomeDirNotFound) {
            writeErr("HOME directory not found\n", .{});
        } else {
            writeErr("failed to initialize secrets store\n", .{});
        }
        std.process.exit(1);
    };
}

pub fn close(alloc: std.mem.Allocator, sec: *secrets.SecretsStore) void {
    sec.db.deinit();
    alloc.destroy(sec.db);
}
