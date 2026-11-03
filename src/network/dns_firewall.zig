// dns_firewall: the one place yoq opens the host's INPUT chain.
//
// containers resolve names through a resolver on their bridge gateway. a host
// whose INPUT policy is DROP discards those queries, so yoq appends one narrow
// rule for each bridge that needs it. this changes the host's firewall, so:
//
// - the rule is added only when the INPUT policy is DROP
// - it matches one managed bridge, one private gateway, and udp port 53
// - it is appended, so explicit administrator drops keep precedence
// - it carries a comment, so cleanup cannot match an administrator's rule
// - every change goes to the audit log and is reported to the user
// - YOQ_HOST_FIREWALL=off stops yoq from adding it
// - a failure warns and never blocks a container
//
// the default bridge rule is removed with the last container using that bridge.
// a named network's rule is removed with the network.

const std = @import("std");
const sqlite = @import("sqlite");
const log = @import("../lib/log.zig");
const cli = @import("../lib/cli.zig");
const audit = @import("../state/audit.zig");
const store = @import("../state/store.zig");
const common = @import("../state/store/common.zig");
const helper_io = @import("../lib/helper_io.zig");
const ip = @import("ip.zig");
const local_networks = @import("local_networks.zig");

pub const tag = "yoq-dns";
const add_action = audit.Action.host_firewall_add;
const remove_action = audit.Action.host_firewall_remove;
const default_allocations_sql = "SELECT COUNT(*) FROM ip_allocations WHERE container_id NOT IN (SELECT container_id FROM local_network_refs);";

/// set when this process already told the user, so the CLI summary stays silent.
var reported_here = std.atomic.Value(bool).init(false);

/// Only yoq's own bridges and private gateways can reach iptables.
pub fn isPermitted(bridge_name: []const u8, gateway: [4]u8) bool {
    if (bridge_name.len < 4 or bridge_name.len > 15) return false;
    if (!std.mem.startsWith(u8, bridge_name, "yoq")) return false;
    for (bridge_name) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
    }
    if (gateway[3] == 0 or gateway[3] == 255) return false;
    return gateway[0] == 10 or
        (gateway[0] == 172 and gateway[1] >= 16 and gateway[1] <= 31) or
        (gateway[0] == 192 and gateway[1] == 168);
}

/// Reads the policy from `iptables -S INPUT`. Other policies need no rule.
pub fn policyDrops(rules: []const u8) bool {
    var lines = std.mem.splitScalar(u8, rules, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "-P INPUT ")) return std.mem.eql(u8, line, "-P INPUT DROP");
    }
    return false;
}

pub fn countTagged(rules: []const u8) usize {
    return std.mem.count(u8, rules, "--comment " ++ tag);
}

fn ruleArgs(flag: []const u8, bridge_name: []const u8, gateway: []const u8) [19][]const u8 {
    return .{ "iptables", "--wait", "5", flag, "INPUT", "-i", bridge_name, "-d", gateway, "-p", "udp", "--dport", "53", "-m", "comment", "--comment", tag, "-j", "ACCEPT" };
}

fn exitCode(argv: []const []const u8) !u8 {
    var threaded = helper_io.init();
    defer threaded.deinit();
    const io = threaded.io();
    var child = try std.process.spawn(io, .{ .argv = argv, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore });
    defer child.kill(io);
    const term = try child.wait(io);
    if (term != .exited) return error.RuleFailed;
    return term.exited;
}

/// Returns `iptables -S INPUT` output, or null when it cannot be read.
pub fn readInputRules(alloc: std.mem.Allocator) ?[]u8 {
    var threaded = helper_io.init();
    defer threaded.deinit();
    const result = std.process.run(alloc, threaded.io(), .{ .argv = &.{ "iptables", "--wait", "5", "-S", "INPUT" } }) catch return null;
    defer alloc.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) {
        alloc.free(result.stdout);
        return null;
    }
    return result.stdout;
}

fn lockBridge(bridge_name: []const u8) !local_networks.Lock {
    var name_buf: [32]u8 = undefined;
    return local_networks.lock(try std.fmt.bufPrint(&name_buf, "dns-firewall-{s}", .{bridge_name}));
}

fn report(db: *sqlite.Db, action: audit.Action, bridge_name: []const u8, gateway: []const u8, outcome: audit.Outcome) void {
    var target_buf: [48]u8 = undefined;
    const target = std.fmt.bufPrint(&target_buf, "{s} {s}", .{ bridge_name, gateway }) catch bridge_name;
    audit.recordInDb(db, action, target, outcome);
    reported_here.store(true, .release);
    log.warn("{s}", .{noticeText(action, outcome)});
    log.warn("  udp port 53 from {s} to {s}, tagged {s}", .{ bridge_name, gateway, tag });
}

fn noticeText(action: audit.Action, outcome: audit.Outcome) []const u8 {
    if (outcome == .failed) return if (action == add_action)
        "host firewall: could not add yoq's dns rule, container dns may fail"
    else
        "host firewall: could not remove yoq's dns rule";
    return if (action == add_action) "host firewall: yoq added a dns rule to INPUT" else "host firewall: yoq removed its dns rule from INPUT";
}

pub fn ensure(db: *sqlite.Db, bridge_name: []const u8, gateway: [4]u8) void {
    if (std.c.getenv("YOQ_HOST_FIREWALL")) |value| {
        if (std.mem.eql(u8, std.mem.span(value), "off")) return;
    }
    if (!isPermitted(bridge_name, gateway)) {
        log.warn("host firewall: refusing a dns rule for bridge {s}", .{bridge_name});
        return;
    }
    const owned_lock = lockBridge(bridge_name) catch |err| {
        log.warn("host firewall: cannot lock dns rule for {s}: {}", .{ bridge_name, err });
        return;
    };
    defer owned_lock.deinit();

    var gateway_buf: [16]u8 = undefined;
    const gateway_text = ip.formatIp(gateway, &gateway_buf);
    const check = ruleArgs("-C", bridge_name, gateway_text);
    const exists = exitCode(&check) catch 255;
    if (exists == 0) return;
    // anything but "no such rule" means the firewall state is unknown.
    if (exists != 1) {
        log.warn("host firewall: cannot inspect INPUT, leaving it unchanged", .{});
        return;
    }
    const alloc = std.heap.page_allocator;
    const rules = readInputRules(alloc) orelse {
        log.warn("host firewall: cannot read INPUT policy, leaving it unchanged", .{});
        return;
    };
    defer alloc.free(rules);
    if (!policyDrops(rules)) return;

    const add = ruleArgs("-A", bridge_name, gateway_text);
    const added = (exitCode(&add) catch 255) == 0;
    report(db, add_action, bridge_name, gateway_text, if (added) .ok else .failed);
}

/// Removes yoq's tagged rule if present. The caller holds no firewall lock.
pub fn remove(db: *sqlite.Db, bridge_name: []const u8, gateway: [4]u8) !void {
    const owned_lock = try lockBridge(bridge_name);
    defer owned_lock.deinit();
    try removeLocked(db, bridge_name, gateway);
}

fn removeLocked(db: *sqlite.Db, bridge_name: []const u8, gateway: [4]u8) !void {
    if (!isPermitted(bridge_name, gateway)) return error.RuleFailed;
    var gateway_buf: [16]u8 = undefined;
    const gateway_text = ip.formatIp(gateway, &gateway_buf);
    const check = ruleArgs("-C", bridge_name, gateway_text);
    const exists = try exitCode(&check);
    if (exists == 1) return;
    if (exists != 0) return error.RuleFailed;
    const delete = ruleArgs("-D", bridge_name, gateway_text);
    const removed = (try exitCode(&delete)) == 0;
    report(db, remove_action, bridge_name, gateway_text, if (removed) .ok else .failed);
    if (!removed) return error.RuleFailed;
}

/// Containers on a named network have a reference row; the rest use the default
/// bridge. Allocations from crashed containers keep the rule, the safe direction.
pub fn removeDefaultIfUnused(db: *sqlite.Db, bridge_name: []const u8, gateway: [4]u8) void {
    removeDefaultChecked(db, bridge_name, gateway) catch |err| {
        log.warn("host firewall: cannot clean up dns rule for {s}: {}", .{ bridge_name, err });
    };
}

fn removeDefaultChecked(db: *sqlite.Db, bridge_name: []const u8, gateway: [4]u8) !void {
    const owned_lock = try lockBridge(bridge_name);
    defer owned_lock.deinit();
    const count = try db.one(i64, default_allocations_sql, .{}, .{});
    if ((count orelse 0) != 0) return;
    try removeLocked(db, bridge_name, gateway);
}

/// Detached supervisors have no terminal, so these commands show what their
/// supervisor recorded. `up`, `down`, and `network rm` report in-process.
pub fn commandReportsChanges(command: []const u8) bool {
    for ([_][]const u8{ "run", "start", "restart", "stop", "rm", "wait", "kill" }) |name| {
        if (std.mem.eql(u8, command, name)) return true;
    }
    return false;
}

pub fn changeMark() ?i64 {
    var db = store.openDb() catch return null;
    defer db.deinit();
    return db.one(i64, "SELECT COALESCE(MAX(id), 0) FROM audit_log;", .{}, .{}) catch null;
}

pub fn printChangesSince(mark: i64) void {
    if (reported_here.load(.acquire)) return;
    var db = store.openDb() catch return;
    defer db.deinit();
    const alloc = std.heap.page_allocator;
    const Row = struct { action: sqlite.Text, target: sqlite.Text, outcome: sqlite.Text };
    var statement = db.prepare("SELECT action, target, outcome FROM audit_log WHERE id > ? AND action IN ('host_firewall_add', 'host_firewall_remove') ORDER BY id;") catch return;
    defer statement.deinit();
    var iterator = statement.iterator(Row, .{mark}) catch return;
    while (iterator.nextAlloc(alloc, .{}) catch null) |row| {
        const action: audit.Action = if (std.mem.eql(u8, row.action.data, add_action.label())) add_action else remove_action;
        const outcome: audit.Outcome = if (std.mem.eql(u8, row.outcome.data, "ok")) .ok else .failed;
        cli.writeErr("{s} ({s})\n", .{ noticeText(action, outcome), row.target.data });
    }
}

test "only managed bridges and private gateways are permitted" {
    try std.testing.expect(isPermitted("yoq0", .{ 10, 42, 0, 1 }));
    try std.testing.expect(isPermitted("yoqn-abc123", .{ 172, 30, 1, 1 }));
    try std.testing.expect(isPermitted("yoq0", .{ 192, 168, 7, 1 }));
    for ([_][]const u8{ "eth0", "docker0", "yoq", "yoq+", "yoq0 -j DROP", "yoq-name-too-long-1", "" }) |name| {
        try std.testing.expect(!isPermitted(name, .{ 10, 42, 0, 1 }));
    }
    for ([_][4]u8{ .{ 8, 8, 8, 8 }, .{ 0, 0, 0, 0 }, .{ 127, 0, 0, 1 }, .{ 172, 32, 0, 1 }, .{ 10, 42, 0, 0 }, .{ 10, 42, 0, 255 } }) |gateway| {
        try std.testing.expect(!isPermitted("yoq0", gateway));
    }
}

test "the rule changes only drop-policy hosts" {
    try std.testing.expect(policyDrops("-P INPUT DROP\n-A INPUT -j ufw-before-input\n"));
    try std.testing.expect(!policyDrops("-P INPUT ACCEPT\n-A INPUT -j DROP\n"));
    try std.testing.expect(!policyDrops(""));
    try std.testing.expect(!policyDrops("-A INPUT -j DROP\n"));
}

test "the rule is narrow, tagged, and appended" {
    const expected = [_][]const u8{ "iptables", "--wait", "5", "-A", "INPUT", "-i", "yoq0", "-d", "10.42.0.1", "-p", "udp", "--dport", "53", "-m", "comment", "--comment", "yoq-dns", "-j", "ACCEPT" };
    const args = ruleArgs("-A", "yoq0", "10.42.0.1");
    for (expected, args) |want, got| try std.testing.expectEqualStrings(want, got);
}

test "tagged rules are counted and an administrator's identical rule is not" {
    const rules = "-P INPUT DROP\n-A INPUT -i yoq0 -d 10.42.0.1/32 -p udp -m udp --dport 53 -j ACCEPT\n-A INPUT -i yoq0 -d 10.42.0.1/32 -p udp -m udp --dport 53 -m comment --comment yoq-dns -j ACCEPT\n";
    try std.testing.expectEqual(@as(usize, 1), countTagged(rules));
}

test "default bridge cleanup keeps the rule while a default container remains" {
    try common.initTestDb();
    defer common.deinitTestDb();
    var lease = try common.leaseDb();
    defer lease.deinit();
    try lease.db.exec("INSERT INTO ip_allocations (container_id, ip_address, allocated_at) VALUES ('named', '172.30.1.2', 1), ('plain', '10.42.0.2', 1);", .{}, .{});
    try lease.db.exec("INSERT INTO local_networks (name, bridge, subnet, created_at) VALUES ('n', 'yoqn-test', 1, 1);", .{}, .{});
    try lease.db.exec("INSERT INTO local_network_refs (container_id, network_name, dns_name) VALUES ('named', 'n', 'named');", .{}, .{});
    try std.testing.expectEqual(@as(?i64, 1), try lease.db.one(i64, default_allocations_sql, .{}, .{}));
    try lease.db.exec("DELETE FROM ip_allocations WHERE container_id = 'plain';", .{}, .{});
    try std.testing.expectEqual(@as(?i64, 0), try lease.db.one(i64, default_allocations_sql, .{}, .{}));
}
