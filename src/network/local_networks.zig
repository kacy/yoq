const std = @import("std");
const sqlite = @import("sqlite");
const store = @import("../state/store/common.zig");
const cli = @import("../lib/cli.zig");
const ids = @import("../runtime/container/id_paths.zig");
const ip = @import("ip.zig");
const bridge = @import("bridge.zig");
const firewall = @import("local_network_rules.zig");
const platform = @import("linux_platform");
const paths = @import("../lib/paths.zig");

pub const Error = error{ InvalidName, InvalidSubnet, SubnetInUse, SubnetExhausted, AlreadyExists, NotFound, InUse, DbError, CleanupFailed, OutOfMemory };

pub const Record = struct {
    name: []const u8,
    bridge_name: []const u8,
    subnet: ip.SubnetConfig,
    references: u64,
    provisioned: bool,
    created_at: i64,

    pub fn deinit(self: Record, alloc: std.mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.bridge_name);
    }
};

pub fn parseSubnet(value: []const u8) ?[4]u8 {
    const slash = std.mem.indexOfScalar(u8, value, '/') orelse return null;
    if (!std.mem.eql(u8, value[slash + 1 ..], "24")) return null;
    const address = ip.parseIp(value[0..slash]) orelse return null;
    if (address[3] != 0) return null;
    const private = address[0] == 10 or (address[0] == 172 and address[1] >= 16 and address[1] <= 31) or
        (address[0] == 192 and address[1] == 168);
    if (!private or (address[0] == 10 and address[1] == 42)) return null;
    return address;
}

fn subnetFromBase(base: [4]u8) ip.SubnetConfig {
    return .{
        .node_id = 0,
        .base = base,
        .gateway = .{ base[0], base[1], base[2], 1 },
        .prefix_len = 24,
        .range_start = .{ base[0], base[1], base[2], 2 },
        .range_end = .{ base[0], base[1], base[2], 254 },
    };
}

fn routeOverlaps(base: [4]u8, routes: []const u8) bool {
    const proposed = std.mem.readInt(u32, &base, .big);
    var lines = std.mem.splitScalar(u8, routes, '\n');
    _ = lines.next();
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t");
        _ = fields.next() orelse continue;
        const destination = fields.next() orelse continue;
        for (0..5) |_| _ = fields.next() orelse break;
        const mask_text = fields.next() orelse continue;
        const destination_raw = std.fmt.parseUnsigned(u32, destination, 16) catch continue;
        const mask_raw = std.fmt.parseUnsigned(u32, mask_text, 16) catch continue;
        const route = std.mem.bigToNative(u32, destination_raw);
        const mask = std.mem.bigToNative(u32, mask_raw);
        if (mask == 0) continue; // default routes must remain usable for egress.
        const common_mask = mask & 0xffffff00;
        if ((proposed & common_mask) == (route & common_mask)) return true;
    }
    return false;
}

fn readHostRoutes(alloc: std.mem.Allocator) ![]u8 {
    const io = std.Options.debug_io;
    const file = try std.Io.Dir.cwd().openFile(io, "/proc/net/route", .{});
    defer file.close(io);
    // Proc route tables report size zero and must be read as streams.
    var reader = file.readerStreaming(io, &.{});
    return reader.interface.allocRemaining(alloc, .limited(1024 * 1024));
}

pub fn create(alloc: std.mem.Allocator, name: []const u8, requested_subnet: ?[]const u8) Error!Record {
    if (!cli.isValidContainerName(name) or std.mem.eql(u8, name, "default") or std.mem.eql(u8, name, "none")) return error.InvalidName;
    const routes = readHostRoutes(alloc) catch return error.InvalidSubnet;
    defer alloc.free(routes);
    return createWithRoutes(alloc, name, requested_subnet, routes);
}

fn createWithRoutes(alloc: std.mem.Allocator, name: []const u8, requested_subnet: ?[]const u8, routes: []const u8) Error!Record {
    if (!cli.isValidContainerName(name) or std.mem.eql(u8, name, "default") or std.mem.eql(u8, name, "none")) return error.InvalidName;
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    lease.db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return error.DbError;
    errdefer lease.db.exec("ROLLBACK;", .{}, .{}) catch {};
    const exists = lease.db.one(i64, "SELECT COUNT(*) FROM local_networks WHERE name = ?;", .{}, .{sqlite.Text{ .data = name }}) catch return error.DbError;
    if ((exists orelse 0) != 0) return error.AlreadyExists;
    const base = if (requested_subnet) |value| blk: {
        const selected = parseSubnet(value) orelse return error.InvalidSubnet;
        if (routeOverlaps(selected, routes) or try subnetUsed(lease.db, selected)) return error.SubnetInUse;
        break :blk selected;
    } else blk: {
        for (0..256) |index| {
            const selected = [4]u8{ 172, 30, @intCast(index), 0 };
            if (!routeOverlaps(selected, routes) and !try subnetUsed(lease.db, selected)) break :blk selected;
        }
        return error.SubnetExhausted;
    };
    var random: [4]u8 = undefined;
    platform.randomBytes(&random);
    const random_id = std.fmt.bytesToHex(random, .lower);
    const bridge_buf = "yoqn-".* ++ random_id;
    const bridge_name: []const u8 = &bridge_buf;
    lease.db.exec("INSERT INTO local_networks (name, bridge, subnet, created_at) VALUES (?, ?, ?, ?);", .{}, .{
        sqlite.Text{ .data = name }, sqlite.Text{ .data = bridge_name }, std.mem.readInt(u32, &base, .big), std.Io.Clock.real.now(std.Options.debug_io).toSeconds(),
    }) catch return error.DbError;
    const record = try inspectInDb(alloc, lease.db, name);
    errdefer record.deinit(alloc);
    lease.db.exec("COMMIT;", .{}, .{}) catch return error.DbError;
    return record;
}

fn subnetUsed(db: *sqlite.Db, base: [4]u8) Error!bool {
    const count = db.one(i64, "SELECT COUNT(*) FROM local_networks WHERE subnet = ?;", .{}, .{std.mem.readInt(u32, &base, .big)}) catch return error.DbError;
    return (count orelse 0) != 0;
}

const Row = struct { name: sqlite.Text, bridge: sqlite.Text, subnet: u32, references: i64, provisioned: i64, created_at: i64 };
const select_records = "SELECT n.name, n.bridge, n.subnet, (SELECT COUNT(*) FROM local_network_refs r WHERE r.network_name = n.name), n.provisioned, n.created_at FROM local_networks n ";

fn recordFromRow(row: Row) Record {
    var base: [4]u8 = undefined;
    std.mem.writeInt(u32, &base, row.subnet, .big);
    return .{ .name = row.name.data, .bridge_name = row.bridge.data, .subnet = subnetFromBase(base), .references = @intCast(row.references), .provisioned = row.provisioned != 0, .created_at = row.created_at };
}

fn inspectInDb(alloc: std.mem.Allocator, db: *sqlite.Db, name: []const u8) Error!Record {
    const row = (db.oneAlloc(Row, alloc, select_records ++ "WHERE n.name = ?;", .{}, .{sqlite.Text{ .data = name }}) catch return error.DbError) orelse return error.NotFound;
    return recordFromRow(row);
}

pub fn inspect(alloc: std.mem.Allocator, name: []const u8) Error!Record {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    return inspectInDb(alloc, lease.db, name);
}

pub fn list(alloc: std.mem.Allocator) Error![]Record {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    var result: std.ArrayList(Record) = .empty;
    errdefer {
        for (result.items) |record| record.deinit(alloc);
        result.deinit(alloc);
    }
    var stmt = lease.db.prepare(select_records ++ "ORDER BY n.name;") catch return error.DbError;
    defer stmt.deinit();
    var iter = stmt.iterator(Row, .{}) catch return error.DbError;
    while (iter.nextAlloc(alloc, .{}) catch return error.DbError) |row| {
        const record = recordFromRow(row);
        result.append(alloc, record) catch {
            record.deinit(alloc);
            return error.OutOfMemory;
        };
    }
    return result.toOwnedSlice(alloc) catch return error.OutOfMemory;
}

pub const Attachment = struct {
    container_id: []const u8,
    dns_name: []const u8,
    address: ?[]const u8,
    pub fn deinit(self: Attachment, alloc: std.mem.Allocator) void {
        alloc.free(self.container_id);
        alloc.free(self.dns_name);
        if (self.address) |value| alloc.free(value);
    }
};

pub fn attachments(alloc: std.mem.Allocator, name: []const u8) Error![]Attachment {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    const AttachmentRow = struct { container_id: sqlite.Text, dns_name: sqlite.Text, address: ?sqlite.Text };
    var result: std.ArrayList(Attachment) = .empty;
    errdefer {
        for (result.items) |ref| ref.deinit(alloc);
        result.deinit(alloc);
    }
    var stmt = lease.db.prepare("SELECT container_id, dns_name, ip_address FROM local_network_refs WHERE network_name = ? ORDER BY dns_name;") catch return error.DbError;
    defer stmt.deinit();
    var iter = stmt.iterator(AttachmentRow, .{sqlite.Text{ .data = name }}) catch return error.DbError;
    while (iter.nextAlloc(alloc, .{}) catch return error.DbError) |row| {
        const ref: Attachment = .{ .container_id = row.container_id.data, .dns_name = row.dns_name.data, .address = if (row.address) |value| value.data else null };
        result.append(alloc, ref) catch {
            ref.deinit(alloc);
            return error.OutOfMemory;
        };
    }
    return result.toOwnedSlice(alloc) catch return error.OutOfMemory;
}

pub fn listAliases(alloc: std.mem.Allocator, id: []const u8) Error![]const []const u8 {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    var result: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (result.items) |name| alloc.free(name);
        result.deinit(alloc);
    }
    var stmt = lease.db.prepare("SELECT name FROM local_network_aliases WHERE container_id = ? ORDER BY name;") catch return error.DbError;
    defer stmt.deinit();
    var iter = stmt.iterator(struct { name: sqlite.Text }, .{sqlite.Text{ .data = id }}) catch return error.DbError;
    while (iter.nextAlloc(alloc, .{}) catch return error.DbError) |row| {
        result.append(alloc, row.name.data) catch {
            alloc.free(row.name.data);
            return error.OutOfMemory;
        };
    }
    return result.toOwnedSlice(alloc) catch return error.OutOfMemory;
}

pub fn requireReference(name: []const u8, id: []const u8) Error!void {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    const count = lease.db.one(i64, "SELECT COUNT(*) FROM local_network_refs WHERE container_id = ? AND network_name = ?;", .{}, .{ sqlite.Text{ .data = id }, sqlite.Text{ .data = name } }) catch return error.DbError;
    if ((count orelse 0) != 1) return error.NotFound;
}

pub fn reserve(name: []const u8, id: []const u8, dns_name: []const u8) Error!void {
    if (!ids.isValidContainerId(id) or !cli.isValidContainerName(dns_name)) return error.InvalidName;
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    lease.db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return error.DbError;
    errdefer lease.db.exec("ROLLBACK;", .{}, .{}) catch {};
    const network = try inspectInDb(std.heap.page_allocator, lease.db, name);
    defer network.deinit(std.heap.page_allocator);
    const exists = lease.db.one(i64, "SELECT COUNT(*) FROM local_network_refs WHERE container_id = ? OR (network_name = ? AND dns_name = ? COLLATE NOCASE);", .{}, .{ sqlite.Text{ .data = id }, sqlite.Text{ .data = name }, sqlite.Text{ .data = dns_name } }) catch return error.DbError;
    if ((exists orelse 0) != 0 or try aliasTaken(lease.db, name, dns_name)) return error.AlreadyExists;
    lease.db.exec("INSERT INTO local_network_refs (container_id, network_name, dns_name) VALUES (?, ?, ?);", .{}, .{ sqlite.Text{ .data = id }, sqlite.Text{ .data = name }, sqlite.Text{ .data = dns_name } }) catch return error.DbError;
    lease.db.exec("COMMIT;", .{}, .{}) catch return error.DbError;
}

fn aliasTaken(db: *sqlite.Db, network_name: []const u8, name: []const u8) Error!bool {
    const count = db.one(i64, "SELECT COUNT(*) FROM local_network_aliases WHERE network_name = ? AND name = ? COLLATE NOCASE;", .{}, .{ sqlite.Text{ .data = network_name }, sqlite.Text{ .data = name } }) catch return error.DbError;
    return (count orelse 0) != 0;
}

pub fn reserveAliases(id: []const u8, aliases: []const []const u8) Error!void {
    if (aliases.len == 0) return;
    for (aliases) |name| if (!cli.isValidContainerName(name)) return error.InvalidName;
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    lease.db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return error.DbError;
    errdefer lease.db.exec("ROLLBACK;", .{}, .{}) catch {};
    const network = (lease.db.oneAlloc(struct { name: sqlite.Text }, std.heap.page_allocator, "SELECT network_name FROM local_network_refs WHERE container_id = ?;", .{}, .{sqlite.Text{ .data = id }}) catch return error.DbError) orelse return error.NotFound;
    defer std.heap.page_allocator.free(network.name.data);
    for (aliases) |name| {
        const existing = (lease.db.one(i64, "SELECT COUNT(*) FROM local_network_refs WHERE network_name = ? AND dns_name = ? COLLATE NOCASE;", .{}, .{ sqlite.Text{ .data = network.name.data }, sqlite.Text{ .data = name } }) catch return error.DbError) orelse 0;
        if (existing != 0 or try aliasTaken(lease.db, network.name.data, name)) return error.AlreadyExists;
        lease.db.exec("INSERT INTO local_network_aliases (container_id, network_name, name) VALUES (?, ?, ?);", .{}, .{ sqlite.Text{ .data = id }, sqlite.Text{ .data = network.name.data }, sqlite.Text{ .data = name } }) catch return error.DbError;
    }
    lease.db.exec("COMMIT;", .{}, .{}) catch return error.DbError;
}

pub fn release(id: []const u8) Error!void {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    lease.db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return error.DbError;
    errdefer lease.db.exec("ROLLBACK;", .{}, .{}) catch {};
    lease.db.exec("DELETE FROM local_network_aliases WHERE container_id = ?;", .{}, .{sqlite.Text{ .data = id }}) catch return error.DbError;
    lease.db.exec("DELETE FROM local_network_refs WHERE container_id = ?;", .{}, .{sqlite.Text{ .data = id }}) catch return error.DbError;
    lease.db.exec("COMMIT;", .{}, .{}) catch return error.DbError;
}

pub fn activate(id: []const u8, address: [4]u8) Error!void {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    var buf: [16]u8 = undefined;
    lease.db.exec("UPDATE local_network_refs SET active = 1, ip_address = ? WHERE container_id = ?;", .{}, .{ sqlite.Text{ .data = ip.formatIp(address, &buf) }, sqlite.Text{ .data = id } }) catch return error.DbError;
}

pub fn deactivate(id: []const u8) Error!void {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    lease.db.exec("UPDATE local_network_refs SET active = 0, ip_address = NULL WHERE container_id = ?;", .{}, .{sqlite.Text{ .data = id }}) catch return error.DbError;
}

pub fn lookupDns(network_name: []const u8, name: []const u8) ?[4]u8 {
    var lease = store.leaseDb() catch return null;
    defer lease.deinit();
    const row = (lease.db.oneAlloc(
        struct { address: sqlite.Text },
        std.heap.page_allocator,
        "SELECT r.ip_address FROM local_network_refs r JOIN containers c ON c.id = r.container_id " ++
            "WHERE r.network_name = ? AND (r.dns_name = ? COLLATE NOCASE OR EXISTS " ++
            "(SELECT 1 FROM local_network_aliases a WHERE a.container_id = r.container_id AND a.name = ? COLLATE NOCASE)) " ++
            "AND r.active = 1 AND c.status = 'running' LIMIT 1;",
        .{},
        .{ sqlite.Text{ .data = network_name }, sqlite.Text{ .data = name }, sqlite.Text{ .data = name } },
    ) catch return null) orelse return null;
    defer std.heap.page_allocator.free(row.address.data);
    return ip.parseIp(row.address.data);
}

pub fn markProvisioned(name: []const u8) Error!void {
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    lease.db.exec("UPDATE local_networks SET provisioned = 1 WHERE name = ?;", .{}, .{sqlite.Text{ .data = name }}) catch return error.DbError;
}

pub const Lock = struct {
    fd: std.posix.fd_t,
    pub fn deinit(self: Lock) void {
        platform.posix.close(self.fd);
    }
};

pub fn lock(name: []const u8) Error!Lock {
    if (!cli.isValidContainerName(name)) return error.InvalidName;
    paths.ensureDataDirStrict("local-network-locks") catch return error.DbError;
    var path_buf: [paths.max_path]u8 = undefined;
    const path = paths.dataPathFmt(&path_buf, "local-network-locks/{s}", .{name}) catch return error.DbError;
    const file = std.Io.Dir.cwd().createFile(std.Options.debug_io, path, .{ .read = true, .truncate = false }) catch return error.DbError;
    errdefer file.close(std.Options.debug_io);
    while (true) switch (std.os.linux.errno(std.os.linux.flock(file.handle, 2))) {
        .SUCCESS => return .{ .fd = file.handle },
        .INTR => continue,
        else => return error.DbError,
    };
}

const KernelCleanup = struct {
    fn run(_: KernelCleanup, record: Record) !void {
        try firewall.remove(record.bridge_name, record.subnet.base);
        try bridge.deleteBridgeChecked(record.bridge_name);
    }
};

pub fn remove(name: []const u8) Error!void {
    return removeWith(name, KernelCleanup{});
}

fn removeWith(name: []const u8, cleanup: anytype) Error!void {
    const owned_lock = try lock(name);
    defer owned_lock.deinit();
    var lease = store.leaseDb() catch return error.DbError;
    defer lease.deinit();
    lease.db.exec("BEGIN IMMEDIATE;", .{}, .{}) catch return error.DbError;
    errdefer lease.db.exec("ROLLBACK;", .{}, .{}) catch {};
    const record = try inspectInDb(std.heap.page_allocator, lease.db, name);
    defer record.deinit(std.heap.page_allocator);
    if (record.references != 0) return error.InUse;
    if (record.provisioned) {
        cleanup.run(record) catch return error.CleanupFailed;
    }
    lease.db.exec("DELETE FROM local_networks WHERE name = ?;", .{}, .{sqlite.Text{ .data = name }}) catch return error.DbError;
    lease.db.exec("COMMIT;", .{}, .{}) catch return error.DbError;
}

test "named networks accept private aligned /24 subnets outside the default pool" {
    try std.testing.expectEqual([4]u8{ 172, 30, 1, 0 }, parseSubnet("172.30.1.0/24").?);
    for ([_][]const u8{ "10.42.1.0/24", "172.30.1.1/24", "172.30.0.0/16", "8.8.8.0/24", "10.0.0.0" }) |value| try std.testing.expect(parseSubnet(value) == null);
    const routes = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\neth0 00001EAC 00000000 0001 0 0 0 0000FFFF 0 0 0\neth0 00000000 010011AC 0003 0 0 0 00000000 0 0 0\n";
    try std.testing.expect(routeOverlaps(.{ 172, 30, 9, 0 }, routes));
    try std.testing.expect(!routeOverlaps(.{ 192, 168, 9, 0 }, routes));
}

test "named networks allocate disjoint subnets and retain stopped container references" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    const one = try createWithRoutes(alloc, "one", null, "");
    defer one.deinit(alloc);
    const two = try createWithRoutes(alloc, "two", null, "");
    defer two.deinit(alloc);
    try std.testing.expect(!std.mem.eql(u8, &one.subnet.base, &two.subnet.base));
    try std.testing.expectError(error.SubnetInUse, createWithRoutes(alloc, "three", "172.30.0.0/24", ""));
    try reserve("one", "111111111111", "web");
    try std.testing.expectError(error.InUse, remove("one"));
    try deactivate("111111111111");
    try std.testing.expectError(error.InUse, remove("one"));
    const refs = try attachments(alloc, "one");
    defer {
        for (refs) |ref| ref.deinit(alloc);
        alloc.free(refs);
    }
    try std.testing.expectEqual(@as(usize, 1), refs.len);
    try std.testing.expect(refs[0].address == null);
    try release("111111111111");
    try remove("one");
    try std.testing.expectError(error.NotFound, inspect(alloc, "one"));
}

test "named network DNS isolates names and aliases and excludes stopped containers" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    const one = try createWithRoutes(alloc, "one", null, "");
    defer one.deinit(alloc);
    const two = try createWithRoutes(alloc, "two", null, "");
    defer two.deinit(alloc);
    const first = "111111111111";
    const second = "222222222222";
    {
        var lease = try store.leaseDb();
        defer lease.deinit();
        for ([_][]const u8{ first, second }) |id| try lease.db.exec("INSERT INTO containers (id, rootfs, command, status, created_at) VALUES (?, '/', '/bin/sh', 'running', 1);", .{}, .{sqlite.Text{ .data = id }});
    }
    try reserve("one", first, "web");
    try reserve("two", second, "web");
    try reserveAliases(first, &.{"database"});
    try reserveAliases(second, &.{"database"});
    try std.testing.expectError(error.AlreadyExists, reserveAliases(first, &.{ "fresh", "WEB" }));
    try std.testing.expectError(error.AlreadyExists, reserve("one", "333333333333", "DATABASE"));
    const address_one: [4]u8 = .{ 172, 30, 0, 2 };
    const address_two: [4]u8 = .{ 172, 30, 1, 2 };
    try activate(first, address_one);
    try activate(second, address_two);
    try std.testing.expectEqual(address_one, lookupDns("one", "WEB").?);
    try std.testing.expectEqual(address_two, lookupDns("two", "web").?);
    try std.testing.expectEqual(address_one, lookupDns("one", "database").?);
    try std.testing.expect(lookupDns("one", "fresh") == null); // aliases roll back as one transaction.
    try std.testing.expect(lookupDns("other", "web") == null);
    {
        var lease = try store.leaseDb();
        defer lease.deinit();
        try lease.db.exec("UPDATE containers SET status = 'stopped' WHERE id = ?;", .{}, .{sqlite.Text{ .data = first }});
    }
    try std.testing.expect(lookupDns("one", "database") == null);
    try deactivate(second);
    try std.testing.expect(lookupDns("two", "database") == null);
    try release(first);
    try reserve("one", "333333333333", "database");
}

test "named network removal keeps metadata when kernel cleanup fails" {
    try store.initTestDb();
    defer store.deinitTestDb();
    const alloc = std.testing.allocator;
    const record = try createWithRoutes(alloc, "cleanup-fixture", null, "");
    defer record.deinit(alloc);
    try markProvisioned(record.name);
    const Cleanup = struct {
        fail: bool,
        fn run(self: @This(), _: Record) !void {
            if (self.fail) return error.InjectedFailure;
        }
    };
    try std.testing.expectError(error.CleanupFailed, removeWith(record.name, Cleanup{ .fail = true }));
    const retained = try inspect(alloc, record.name);
    defer retained.deinit(alloc);
    try std.testing.expect(retained.provisioned);
    try removeWith(record.name, Cleanup{ .fail = false });
    try std.testing.expectError(error.NotFound, inspect(alloc, record.name));
}

test "named networks read routes from the zero-size proc table" {
    if (@import("builtin").os.tag != .linux) return error.SkipZigTest;
    const routes = try readHostRoutes(std.testing.allocator);
    defer std.testing.allocator.free(routes);
    try std.testing.expect(std.mem.startsWith(u8, routes, "Iface"));
    try std.testing.expect(std.mem.indexOf(u8, routes, "Destination") != null);
    try std.testing.expect(std.mem.indexOf(u8, routes, "Mask") != null);
}
