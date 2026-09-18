// shared host ports belong to a service, with one durable claim per container.
// rebuilding only our chains preserves administrator rules and established
// connections. a stopped supervisor can release its claims without touching
// the replacement's containers.
const std = @import("std");
const sqlite = @import("sqlite");
const platform = @import("linux_platform");
const store = @import("../state/store.zig");
const common = @import("../state/store/common.zig");
const registry = @import("service_registry_runtime.zig");
const spec = @import("../manifest/spec.zig");
const paths = @import("../lib/paths.zig");
const ip = @import("ip.zig");
const nat = @import("nat.zig");
const log = @import("../lib/log.zig");
const io = std.Options.debug_io;
const Allocator = std.mem.Allocator;

const Claim = struct {
    app: []const u8,
    service: []const u8,
    container: []const u8,
    host_port: u16,
    target_port: u16,
    address: [4]u8 = .{ 0, 0, 0, 0 },
    eligible: bool = false,
};
const Claims = std.ArrayList(Claim);
const Apply = *const fn (Allocator, []const Claim) anyerror!void;
var mutex: std.Io.Mutex = .init;

pub fn publishInstance(alloc: Allocator, app_name: ?[]const u8, service_name: []const u8, container_id: []const u8, ports: []const spec.PortMapping) !void {
    if (ports.len == 0) return;
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    const lock = try acquireLock();
    defer platform.posix.close(lock);
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    try change(arena.allocator(), .{ .publish = .{
        .app = app_name orelse "",
        .service = service_name,
        .container = container_id,
        .ports = ports,
    } }, applyRules);
}

pub fn removeInstance(alloc: Allocator, container_id: []const u8) !void {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    const lock = try acquireLock();
    defer platform.posix.close(lock);
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    try change(arena.allocator(), .{ .remove = container_id }, applyRules);
}

/// called after registry events, once registry and store locks are released.
pub fn refreshAll() void {
    mutex.lockUncancelable(io);
    defer mutex.unlock(io);
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    // most commands do not publish ports. avoid creating lock files or running
    // privileged commands when there is no published service on this host.
    const claims = loadClaims(alloc) catch return;
    if (claims.items.len == 0) return;
    const lock = acquireLock() catch |err| {
        log.warn("published ports: cannot lock host rules: {}", .{err});
        return;
    };
    defer platform.posix.close(lock);
    change(alloc, .refresh, applyRules) catch |err| {
        log.warn("published ports: cannot refresh host rules: {}", .{err});
    };
}

const Change = union(enum) {
    publish: struct { app: []const u8, service: []const u8, container: []const u8, ports: []const spec.PortMapping },
    remove: []const u8,
    refresh,
};

fn change(alloc: Allocator, operation: Change, apply: Apply) !void {
    var previous = try loadClaims(alloc);
    if (previous.items.len == 0 and operation != .publish) return;
    try resolveBackends(alloc, previous.items);
    var next: Claims = .empty;
    for (previous.items) |claim| {
        const record = store.load(alloc, claim.container) catch |err| switch (err) {
            error.NotFound => continue,
            else => return err,
        };
        if (!std.mem.eql(u8, record.status, "running")) continue;
        if (operation == .remove and std.mem.eql(u8, claim.container, operation.remove)) continue;
        if (operation == .publish and std.mem.eql(u8, claim.container, operation.publish.container)) continue;
        try next.append(alloc, claim);
    }
    if (operation == .publish) {
        const request = operation.publish;
        const record = try store.load(alloc, request.container);
        if (!std.mem.eql(u8, record.status, "running")) return error.ContainerNotRunning;
        if (!std.mem.eql(u8, record.app_name orelse "", request.app) or
            !std.mem.eql(u8, record.hostname, request.service)) return error.ContainerOwnerMismatch;
        for (request.ports) |port| {
            if (port.host_port == 0 or port.container_port == 0) return error.InvalidPort;
            try appendClaim(alloc, &next, .{ .app = request.app, .service = request.service, .container = request.container, .host_port = port.host_port, .target_port = port.container_port });
        }
    }
    try resolveBackends(alloc, next.items);
    // a failed database commit or partial table update restores the prior
    // dataplane. the durable claims remain the source for the next retry.
    apply(alloc, next.items) catch |err| {
        apply(alloc, previous.items) catch |restore_err| log.err("published ports: rollback failed: {}", .{restore_err});
        return err;
    };
    saveClaims(next.items) catch |err| {
        apply(alloc, previous.items) catch |restore_err| log.err("published ports: rollback failed: {}", .{restore_err});
        return err;
    };
}

fn appendClaim(alloc: Allocator, claims: *Claims, claim: Claim) !void {
    for (claims.items) |existing| {
        if (existing.host_port != claim.host_port) continue;
        if (!std.mem.eql(u8, existing.app, claim.app) or
            !std.mem.eql(u8, existing.service, claim.service) or
            existing.target_port != claim.target_port) return error.PortAlreadyPublished;
        if (std.mem.eql(u8, existing.container, claim.container)) return;
    }
    try claims.append(alloc, claim);
}

fn resolveBackends(alloc: Allocator, claims: []Claim) !void {
    for (claims) |*claim| {
        claim.eligible = false;
        const endpoints = registry.snapshotServiceEndpoints(alloc, claim.service) catch |err| switch (err) {
            error.ServiceNotFound => continue,
            else => return err,
        };
        for (endpoints.items) |endpoint| {
            if (!endpoint.eligible or !std.mem.eql(u8, endpoint.container_id, claim.container)) continue;
            claim.address = ip.parseIp(endpoint.ip_address) orelse return error.InvalidAddress;
            claim.eligible = true;
            break;
        }
    }
}

const schema_sql =
    "CREATE TABLE IF NOT EXISTS published_port_claims (" ++
    "app TEXT NOT NULL, service TEXT NOT NULL, container TEXT NOT NULL, " ++
    "host_port INTEGER NOT NULL, target_port INTEGER NOT NULL, PRIMARY KEY(container, host_port));";

// callers use a temporary arena so row strings and snapshots have one lifetime.
fn loadClaims(alloc: Allocator) !Claims {
    var lease = try common.leaseDb();
    defer lease.deinit();
    try lease.db.exec(schema_sql, .{}, .{});
    var stmt = try lease.db.prepare("SELECT app, service, container, host_port, target_port FROM published_port_claims ORDER BY host_port, container;");
    defer stmt.deinit();
    const Row = struct { app: sqlite.Text, service: sqlite.Text, container: sqlite.Text, host_port: i64, target_port: i64 };
    var iter = try stmt.iterator(Row, .{});
    var claims: Claims = .empty;
    while (try iter.nextAlloc(alloc, .{})) |row| {
        if (row.host_port < 1 or row.host_port > 65535 or row.target_port < 1 or row.target_port > 65535) return error.InvalidPort;
        try claims.append(alloc, .{ .app = row.app.data, .service = row.service.data, .container = row.container.data, .host_port = @intCast(row.host_port), .target_port = @intCast(row.target_port) });
    }
    return claims;
}

fn saveClaims(claims: []const Claim) !void {
    var lease = try common.leaseDb();
    defer lease.deinit();
    try lease.db.exec("BEGIN IMMEDIATE;", .{}, .{});
    errdefer lease.db.exec("ROLLBACK;", .{}, .{}) catch {};
    try lease.db.exec("DELETE FROM published_port_claims;", .{}, .{});
    for (claims) |claim| try lease.db.exec("INSERT INTO published_port_claims (app, service, container, host_port, target_port) VALUES (?, ?, ?, ?, ?);", .{}, .{ claim.app, claim.service, claim.container, claim.host_port, claim.target_port });
    try lease.db.exec("COMMIT;", .{}, .{});
}

fn acquireLock() !std.posix.fd_t {
    try paths.ensureDataDirStrict("network");
    var buf: [paths.max_path]u8 = undefined;
    const path = try paths.dataPath(&buf, "network/published-ports.lock");
    var zbuf: [paths.max_path]u8 = undefined;
    const name = try std.fmt.bufPrintZ(&zbuf, "{s}", .{path});
    const linux = std.os.linux;
    const rc = linux.open(name, .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true }, 0o600);
    if (linux.errno(rc) != .SUCCESS) return error.LockFailed;
    const fd: std.posix.fd_t = @intCast(rc);
    errdefer platform.posix.close(fd);
    while (true) switch (linux.errno(linux.flock(fd, 2))) {
        .SUCCESS => return fd,
        .INTR => continue,
        else => return error.LockFailed,
    };
}

fn firstForPort(claims: []const Claim, index: usize) bool {
    for (claims[0..index]) |earlier| if (earlier.host_port == claims[index].host_port) return false;
    return true;
}

/// each DNAT rule ends traversal. conditional probabilities give every healthy
/// replica the same share of new connections; conntrack pins subsequent packets.
fn renderRules(alloc: Allocator, claims: []const Claim) ![]const u8 {
    var output: std.Io.Writer.Allocating = .init(alloc);
    const writer = &output.writer;
    try writer.writeAll("*filter\n:YOQ-PUBLISHED-FWD - [0:0]\n:YOQ-PUBLISHED-IN - [0:0]\n-F YOQ-PUBLISHED-FWD\n-F YOQ-PUBLISHED-IN\n");
    for (claims, 0..) |claim, index| {
        if (firstForPort(claims, index)) try writer.print("-A YOQ-PUBLISHED-IN -p tcp --dport {d} -j REJECT --reject-with tcp-reset\n", .{claim.host_port});
        if (!claim.eligible) continue;
        var buf: [16]u8 = undefined;
        try writer.print("-A YOQ-PUBLISHED-FWD -p tcp -d {s} --dport {d} -j ACCEPT\n", .{ ip.formatIp(claim.address, &buf), claim.target_port });
    }
    try writer.writeAll("COMMIT\n*nat\n:YOQ-PUBLISHED - [0:0]\n:YOQ-PUBLISHED-SNAT - [0:0]\n-F YOQ-PUBLISHED\n-F YOQ-PUBLISHED-SNAT\n");
    for (claims, 0..) |claim, index| {
        if (!claim.eligible) continue;
        var remaining: usize = 0;
        for (claims[index..]) |later| if (later.eligible and later.host_port == claim.host_port) {
            remaining += 1;
        };
        try writer.print("-A YOQ-PUBLISHED -p tcp --dport {d}", .{claim.host_port});
        if (remaining > 1) try writer.print(" -m statistic --mode random --probability {d:.10}", .{1.0 / @as(f64, @floatFromInt(remaining))});
        var buf: [16]u8 = undefined;
        const address = ip.formatIp(claim.address, &buf);
        try writer.print(" -j DNAT --to-destination {s}:{d}\n", .{ address, claim.target_port });
        try writer.print("-A YOQ-PUBLISHED-SNAT -s 127.0.0.0/8 -p tcp -d {s} --dport {d} -j MASQUERADE\n", .{ address, claim.target_port });
    }
    try writer.writeAll("COMMIT\n");
    return output.toOwnedSlice();
}

fn run(argv: []const []const u8, input: ?std.Io.File) !void {
    var child = try std.process.spawn(io, .{ .argv = argv, .stdin = if (input) |file| .{ .file = file } else .ignore, .stdout = .ignore, .stderr = .ignore });
    const term = try child.wait(io);
    if (term != .exited or term.exited != 0) return error.FirewallFailed;
}

fn ensureJump(table: []const u8, source: []const u8, target: []const u8, local_only: bool) !void {
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(std.heap.page_allocator);
    try args.appendSlice(std.heap.page_allocator, &.{ "iptables", "--wait", "5", "-t", table, "-C", source });
    if (local_only) try args.appendSlice(std.heap.page_allocator, &.{ "-m", "addrtype", "--dst-type", "LOCAL" });
    try args.appendSlice(std.heap.page_allocator, &.{ "-j", target });
    run(args.items, null) catch {
        args.items[5] = "-A";
        try run(args.items, null);
    };
}

fn applyRules(alloc: Allocator, claims: []const Claim) !void {
    if (claims.len != 0) try nat.enableRouteLocalnet(@import("bridge.zig").default_bridge);
    const rules = try renderRules(alloc, claims);
    var buf: [paths.max_path]u8 = undefined;
    const path = try paths.dataPath(&buf, "network/published-ports.rules");
    // the cross-process lock also owns this scratch file. it contains only
    // validated addresses and numeric ports, never application-provided text.
    const file = try std.Io.Dir.cwd().createFile(io, path, .{ .read = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};
    try file.writeStreamingAll(io, rules);
    _ = try platform.posix.lseek(file.handle, 0, std.posix.SEEK.SET);
    try run(&.{ "iptables-restore", "--wait", "5", "--noflush" }, file);
    try ensureJump("filter", "FORWARD", "YOQ-PUBLISHED-FWD", false);
    try ensureJump("filter", "INPUT", "YOQ-PUBLISHED-IN", false);
    try ensureJump("nat", "POSTROUTING", "YOQ-PUBLISHED-SNAT", false);
    try ensureJump("nat", "PREROUTING", "YOQ-PUBLISHED", true);
    try ensureJump("nat", "OUTPUT", "YOQ-PUBLISHED", true);
}

test "published ports reject another service and retain sibling ownership" {
    const alloc = std.testing.allocator;
    var claims: Claims = .empty;
    defer claims.deinit(alloc);
    const first: Claim = .{ .app = "shop", .service = "web", .container = "one", .host_port = 8080, .target_port = 80 };
    try appendClaim(alloc, &claims, first);
    var second = first;
    second.container = "two";
    try appendClaim(alloc, &claims, second);
    try std.testing.expectEqual(@as(usize, 2), claims.items.len);
    second.app = "other";
    try std.testing.expectError(error.PortAlreadyPublished, appendClaim(alloc, &claims, second));
    second.app = "shop";
    second.target_port = 90;
    try std.testing.expectError(error.PortAlreadyPublished, appendClaim(alloc, &claims, second));
}

test "published ports balance eligible replicas and reject an empty service" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const claims = [_]Claim{
        .{ .app = "a", .service = "web", .container = "one", .host_port = 8080, .target_port = 80, .address = .{ 10, 42, 0, 2 }, .eligible = true },
        .{ .app = "a", .service = "web", .container = "two", .host_port = 8080, .target_port = 80, .address = .{ 10, 42, 0, 3 }, .eligible = true },
        .{ .app = "a", .service = "web", .container = "bad", .host_port = 8080, .target_port = 80, .address = .{ 10, 42, 0, 4 } },
        .{ .app = "a", .service = "empty", .container = "pending", .host_port = 9090, .target_port = 90 },
    };
    const rules = try renderRules(arena.allocator(), &claims);
    try std.testing.expect(std.mem.indexOf(u8, rules, "--probability 0.5000000000") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "10.42.0.2:80") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "10.42.0.3:80") != null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "10.42.0.4") == null);
    try std.testing.expect(std.mem.indexOf(u8, rules, "--dport 9090 -j REJECT") != null);
}
