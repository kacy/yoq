// certificate reads follow the cluster database while a server owns it.
// local commands keep their ordinary store; registering a cluster never
// redirects container, secret, token, or other local state.
const std = @import("std");
const sqlite = @import("sqlite");
const common = @import("common.zig");

const Source = struct { db: *sqlite.Db, mutex: *std.Io.Mutex };
var source: ?Source = null;
var source_mutex: std.Io.Mutex = .init;

pub const Binding = struct {
    db: *sqlite.Db,

    pub fn init(db: *sqlite.Db, mutex: *std.Io.Mutex) error{AlreadyBound}!Binding {
        source_mutex.lockUncancelable(std.Options.debug_io);
        defer source_mutex.unlock(std.Options.debug_io);
        if (source != null) return error.AlreadyBound;
        source = .{ .db = db, .mutex = mutex };
        return .{ .db = db };
    }

    // waiting for this lock joins every in-flight read before the owner
    // closes or replaces the database. callers must release the node lock.
    pub fn deinit(self: Binding) void {
        source_mutex.lockUncancelable(std.Options.debug_io);
        defer source_mutex.unlock(std.Options.debug_io);
        std.debug.assert(source != null and source.?.db == self.db);
        source = null;
    }
};

pub const Lease = struct {
    db: *sqlite.Db,
    owner: union(enum) { cluster: *std.Io.Mutex, local: common.DbLease },

    pub fn deinit(self: *Lease) void {
        switch (self.owner) {
            .cluster => |mutex| mutex.unlock(std.Options.debug_io),
            .local => |*local| local.deinit(),
        }
        source_mutex.unlock(std.Options.debug_io);
    }
};

// never call while holding the node mutex. records returned by the store
// own copies, so callers release this lease before decrypting or using them.
pub fn leaseDb() common.StoreError!Lease {
    source_mutex.lockUncancelable(std.Options.debug_io);
    errdefer source_mutex.unlock(std.Options.debug_io);
    if (source) |cluster| {
        cluster.mutex.lockUncancelable(std.Options.debug_io);
        return .{ .db = cluster.db, .owner = .{ .cluster = cluster.mutex } };
    }
    const local = try common.leaseDb();
    return .{ .db = local.db, .owner = .{ .local = local } };
}

test "cluster certificate binding reads replicated records without redirecting local state" {
    const store = @import("../store.zig");
    const schema = @import("../schema.zig");
    const ca = @import("cluster_ca.zig");
    const mtls = @import("certificates_mtls.zig");
    const alloc = std.testing.allocator;
    try store.initTestDb();
    defer store.deinitTestDb();
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    try schema.init(&db);
    var mutex: std.Io.Mutex = .init;
    const nonce = [_]u8{0} ** 12;
    const tag = [_]u8{0} ** 16;
    const seed = try ca.buildInsertSql(alloc, "replicated ca", "private key", &nonce, &tag, 1, 100);
    defer alloc.free(seed);
    try db.execDynamic(seed, .{}, .{});
    const proxy = try mtls.buildProxyUpsertSql(alloc, "replicated proxy", "private key", &nonce, &tag, 100, 1);
    defer alloc.free(proxy);
    try db.execDynamic(proxy, .{}, .{});

    {
        const binding = try Binding.init(&db, &mutex);
        defer binding.deinit();
        try std.testing.expectError(error.AlreadyBound, Binding.init(&db, &mutex));
        const cert = (try ca.getClusterCa(alloc)).?;
        defer cert.deinit(alloc);
        try std.testing.expectEqualStrings("replicated ca", cert.cert_pem);
        const identity = (try mtls.getProxy(alloc)).?;
        defer identity.deinit(alloc);
        try std.testing.expectEqualStrings("replicated proxy", identity.cert_pem);
        var local = try common.leaseDb();
        defer local.deinit();
        try std.testing.expect((try ca.getClusterCaInDb(local.db, alloc)) == null);
    }
    try std.testing.expect((try ca.getClusterCa(alloc)) == null);
    try std.testing.expect((try mtls.getProxy(alloc)) == null);
}

test "cluster certificate binding waits for readers before database teardown" {
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    var mutex: std.Io.Mutex = .init;
    const binding = try Binding.init(&db, &mutex);
    var lease = try leaseDb();
    const Stop = struct {
        entered: std.Io.Event = .unset,
        done: std.atomic.Value(bool) = .init(false),
        binding: Binding,
        fn run(self: *@This()) void {
            self.entered.set(std.Options.debug_io);
            self.binding.deinit();
            self.done.store(true, .release);
        }
    };
    var stop = Stop{ .binding = binding };
    const thread = std.Thread.spawn(.{}, Stop.run, .{&stop}) catch |err| {
        lease.deinit();
        binding.deinit();
        return err;
    };
    stop.entered.waitUncancelable(std.Options.debug_io);
    const stopped_early = stop.done.load(.acquire);
    lease.deinit();
    thread.join();
    try std.testing.expect(!stopped_early);
    try std.testing.expect(stop.done.load(.acquire));
}
