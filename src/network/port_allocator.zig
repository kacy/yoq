const std = @import("std");
const platform = @import("linux_platform");
const sqlite = @import("sqlite");
const store = @import("../state/store/common.zig");
const run_state = @import("../runtime/run_state.zig");
const ids = @import("../runtime/container/id_paths.zig");
const common = @import("setup/common.zig");
const posix = std.posix;

pub const Error = error{ InvalidMapping, PortInUse, AddressUnavailable, AllocationFailed, DbError, OutOfMemory };

pub const PortLeases = struct {
    sockets: std.ArrayList(posix.fd_t) = .empty,

    pub fn deinit(self: *PortLeases) void {
        for (self.sockets.items) |fd| platform.posix.close(fd);
        self.sockets.deinit(std.heap.page_allocator);
        self.* = .{};
    }
};

fn bindPort(mapping: common.PortMap) Error!struct { fd: posix.fd_t, port: u16 } {
    if (mapping.container_port == 0) return error.InvalidMapping;
    const socket_type: u32 = if (mapping.protocol == .tcp) posix.SOCK.STREAM else posix.SOCK.DGRAM;
    const fd = platform.posix.socket(posix.AF.INET, socket_type | posix.SOCK.CLOEXEC, 0) catch return error.AllocationFailed;
    errdefer platform.posix.close(fd);
    var address = platform.net.Address.initIp4(mapping.bindIp() orelse .{ 0, 0, 0, 0 }, mapping.host_port);
    platform.posix.bind(fd, &address.any, address.getOsSockLen()) catch |err| return switch (err) {
        error.AddressInUse => error.PortInUse,
        error.AddressNotAvailable => error.AddressUnavailable,
        else => error.AllocationFailed,
    };
    var length = address.getOsSockLen();
    platform.posix.getsockname(fd, &address.any, &length) catch return error.AllocationFailed;
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, address.in.port) };
}

/// Hold sockets in the supervisor until NAT teardown finishes. Database
/// reservations outlive these sockets so stopped containers retain their ports.
pub fn hold(mappings: []const common.PortMap) Error!PortLeases {
    var leases: PortLeases = .{};
    errdefer leases.deinit();
    leases.sockets.ensureTotalCapacity(std.heap.page_allocator, mappings.len) catch return error.OutOfMemory;
    for (mappings) |mapping| {
        if (mapping.host_port == 0) return error.InvalidMapping;
        const bound = try bindPort(mapping);
        leases.sockets.appendAssumeCapacity(bound.fd);
    }
    return leases;
}

fn addressNumber(mapping: common.PortMap) u32 {
    const address = mapping.bindIp() orelse return 0;
    return std.mem.readInt(u32, &address, .big);
}

fn overlaps(left: common.PortMap, right: common.PortMap) bool {
    if (left.protocol != right.protocol or left.host_port != right.host_port) return false;
    const a = addressNumber(left);
    const b = addressNumber(right);
    return a == 0 or b == 0 or a == b;
}

fn reserved(db: *sqlite.Db, mapping: common.PortMap) Error!bool {
    const address = addressNumber(mapping);
    const count = db.one(
        i64,
        "SELECT COUNT(*) FROM local_port_reservations WHERE host_port = ? AND protocol = ? " ++
            "AND (host_ip = 0 OR ? = 0 OR host_ip = ?);",
        .{},
        .{ mapping.host_port, @as(i64, @intFromEnum(mapping.protocol)), address, address },
    ) catch return error.DbError;
    return (count orelse 0) != 0;
}

/// Called by manifest publication while its existing database write transaction
/// is held. App ports currently publish TCP on every host address.
pub fn checkAppPort(db: *sqlite.Db, port: u16) Error!void {
    if (try reserved(db, .{ .host_port = port, .container_port = port })) return error.PortInUse;
}

fn appPortReserved(db: *sqlite.Db, mapping: common.PortMap) Error!bool {
    if (mapping.protocol != .tcp) return false;
    const has_table = db.one(i64, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'published_port_claims';", .{}, .{}) catch return error.DbError;
    if ((has_table orelse 0) == 0) return false;
    const count = db.one(i64, "SELECT COUNT(*) FROM published_port_claims WHERE host_port = ?;", .{}, .{mapping.host_port}) catch return error.DbError;
    return (count orelse 0) != 0;
}

fn loadLegacyMappings(alloc: std.mem.Allocator, db: *sqlite.Db, id: []const u8) Error![]common.PortMap {
    var result: std.ArrayList(common.PortMap) = .empty;
    errdefer result.deinit(alloc);
    var stmt = db.prepare(
        "SELECT id FROM containers WHERE id != ? AND id NOT IN (SELECT container_id FROM local_port_reservations);",
    ) catch return error.DbError;
    defer stmt.deinit();
    var iter = stmt.iterator(struct { id: sqlite.Text }, .{sqlite.Text{ .data = id }}) catch return error.DbError;
    while (iter.nextAlloc(alloc, .{}) catch return error.DbError) |row| {
        defer alloc.free(row.id.data);
        const saved = run_state.loadConfig(alloc, row.id.data) catch |err| switch (err) {
            error.NotFound => continue,
            else => return error.DbError,
        };
        defer saved.deinit(alloc);
        result.appendSlice(alloc, saved.port_maps) catch return error.OutOfMemory;
    }
    return result.toOwnedSlice(alloc) catch return error.OutOfMemory;
}

/// Assign ephemeral host ports and reserve the effective mappings before saving
/// container configuration. A failed transaction leaves the caller unchanged.
pub fn reserve(id: []const u8, mappings: []common.PortMap) Error!void {
    if (!ids.isValidContainerId(id) or mappings.len > 256) return error.InvalidMapping;
    const alloc = std.heap.page_allocator;
    const assigned = alloc.dupe(common.PortMap, mappings) catch return error.OutOfMemory;
    defer alloc.free(assigned);
    var sockets: PortLeases = .{};
    defer sockets.deinit();
    sockets.sockets.ensureTotalCapacity(alloc, mappings.len) catch return error.OutOfMemory;
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    lease.db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return error.DbError;
    errdefer lease.db.exec("ROLLBACK;", .{}, .{}) catch {};
    const legacy = try loadLegacyMappings(alloc, lease.db, id);
    defer alloc.free(legacy);
    lease.db.exec("DELETE FROM local_port_reservations WHERE container_id = ?;", .{}, .{sqlite.Text{ .data = id }}) catch return error.DbError;
    for (assigned, 0..) |*mapping, ordinal| {
        const ephemeral = mapping.host_port == 0;
        var attempts: usize = 0;
        while (true) : (attempts += 1) {
            if (attempts == 256) return error.AllocationFailed;
            const bound = try bindPort(mapping.*);
            errdefer platform.posix.close(bound.fd);
            var candidate = mapping.*;
            candidate.host_port = bound.port;
            var busy = try reserved(lease.db, candidate);
            if (!busy) busy = try appPortReserved(lease.db, candidate);
            if (!busy) for (legacy) |existing| {
                if (overlaps(candidate, existing)) {
                    busy = true;
                    break;
                }
            };
            if (busy) {
                if (!ephemeral) return error.PortInUse;
                platform.posix.close(bound.fd);
                continue;
            }
            sockets.sockets.appendAssumeCapacity(bound.fd);
            mapping.* = candidate;
            break;
        }
        lease.db.exec("INSERT INTO local_port_reservations (container_id, ordinal, host_ip, host_port, protocol) VALUES (?, ?, ?, ?, ?);", .{}, .{
            sqlite.Text{ .data = id }, ordinal, addressNumber(mapping.*), mapping.host_port, @as(i64, @intFromEnum(mapping.protocol)),
        }) catch return error.DbError;
    }
    lease.db.exec("COMMIT;", .{}, .{}) catch return error.DbError;
    @memcpy(mappings, assigned);
}

pub fn release(id: []const u8) Error!void {
    if (!ids.isValidContainerId(id)) return error.InvalidMapping;
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    lease.db.exec("DELETE FROM local_port_reservations WHERE container_id = ?;", .{}, .{sqlite.Text{ .data = id }}) catch return error.DbError;
}

test "port reservations assign distinct ports and keep ownership after sockets close" {
    try store.initTestDb();
    defer store.deinitTestDb();
    var mappings = [_]common.PortMap{
        .{ .host_ip = .{ 127, 0, 0, 1 }, .host_port = 0, .container_port = 80 },
        .{ .host_ip = .{ 127, 0, 0, 1 }, .host_port = 0, .container_port = 81 },
    };
    try reserve("aabbccddeeff", &mappings);
    defer release("aabbccddeeff") catch {};
    try std.testing.expect(mappings[0].host_port != 0 and mappings[1].host_port != 0);
    try std.testing.expect(mappings[0].host_port != mappings[1].host_port);
    var conflict = [_]common.PortMap{mappings[0]};
    try std.testing.expectError(error.PortInUse, reserve("112233445566", &conflict));
    try std.testing.expectEqual(mappings[0].host_port, conflict[0].host_port);
    try release("aabbccddeeff");
    try reserve("112233445566", &conflict);
    try release("112233445566");
}

test "port leases block external bind until teardown and permit distinct addresses" {
    var mapping = common.PortMap{ .host_ip = .{ 127, 0, 0, 1 }, .host_port = 0, .container_port = 53, .protocol = .udp };
    const chosen = try bindPort(mapping);
    platform.posix.close(chosen.fd);
    mapping.host_port = chosen.port;
    var leases = try hold(&.{mapping});
    defer leases.deinit();
    try std.testing.expectError(error.PortInUse, bindPort(mapping));
    var other = mapping;
    other.host_ip = .{ 127, 0, 0, 2 };
    const distinct = try bindPort(other);
    platform.posix.close(distinct.fd);
    leases.deinit();
    const available = try bindPort(mapping);
    platform.posix.close(available.fd);
}

test "port reservation overlap includes wildcard addresses but separates protocols" {
    const first: common.PortMap = .{ .host_ip = .{ 127, 0, 0, 1 }, .host_port = 8080, .container_port = 80 };
    var other = first;
    other.host_ip = .{ 127, 0, 0, 2 };
    try std.testing.expect(!overlaps(first, other));
    other.host_ip = null;
    try std.testing.expect(overlaps(first, other));
    other.protocol = .udp;
    try std.testing.expect(!overlaps(first, other));
}
