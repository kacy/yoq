const std = @import("std");
const nat = @import("nat.zig");
const ip = @import("ip.zig");

const chain = "YOQ-LOCAL-ISOLATION";
const Error = error{RuleFailed};

fn run(args: []const []const u8) Error!u8 {
    var helper_io = @import("../lib/helper_io.zig").init();
    defer helper_io.deinit();
    const io = helper_io.io();
    var child = std.process.spawn(io, .{ .argv = args, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore }) catch return error.RuleFailed;
    defer child.kill(io);
    const term = child.wait(io) catch return error.RuleFailed;
    if (term != .exited) return error.RuleFailed;
    return term.exited;
}

fn rule(args: []const []const u8, deleting: bool) Error!void {
    var check: [20][]const u8 = undefined;
    @memcpy(check[0..args.len], args);
    for (check[0..args.len]) |*arg| if (std.mem.eql(u8, arg.*, "-A") or std.mem.eql(u8, arg.*, "-I") or std.mem.eql(u8, arg.*, "-D")) {
        arg.* = "-C";
        break;
    };
    const exists = try run(check[0..args.len]);
    if (exists != 0 and exists != 1) return error.RuleFailed;
    if ((exists == 0) != deleting) return;
    if (try run(args) != 0) {
        const now = try run(check[0..args.len]);
        if (now != (if (deleting) @as(u8, 1) else @as(u8, 0))) return error.RuleFailed;
    }
}

pub fn ensure(bridge_name: []const u8, base: [4]u8) !void {
    const chain_status = try run(&.{ "iptables", "--wait", "5", "-S", chain });
    if (chain_status != 0) {
        if (chain_status != 1) return error.RuleFailed;
        if (try run(&.{ "iptables", "--wait", "5", "-N", chain }) != 0 and
            try run(&.{ "iptables", "--wait", "5", "-S", chain }) != 0) return error.RuleFailed;
    }
    // Same-bridge traffic returns to the ordinary forwarding rules. Traffic
    // between managed bridges is dropped before their egress accept rules.
    try isolationRules(bridge_name, false);
    try rule(&.{ "iptables", "--wait", "5", "-I", "FORWARD", "-j", chain }, false);
    var subnet_buf: [24]u8 = undefined;
    var address_buf: [16]u8 = undefined;
    const subnet = try std.fmt.bufPrint(&subnet_buf, "{s}/24", .{ip.formatIp(base, &address_buf)});
    try nat.enableForwarding();
    try nat.ensureContainerForwarding(bridge_name, subnet);
    try nat.ensureMasquerade(bridge_name, subnet);
}

fn isolationRules(bridge_name: []const u8, deleting: bool) !void {
    const action: []const u8 = if (deleting) "-D" else "-A";
    try rule(&.{ "iptables", "--wait", "5", action, chain, "-i", bridge_name, "-o", bridge_name, "-j", "RETURN" }, deleting);
    try rule(&.{ "iptables", "--wait", "5", action, chain, "-i", bridge_name, "-o", "yoq+", "-j", "DROP" }, deleting);
    try rule(&.{ "iptables", "--wait", "5", action, chain, "-i", "yoq+", "-o", bridge_name, "-j", "DROP" }, deleting);
}

pub fn remove(bridge_name: []const u8, base: [4]u8) !void {
    const exists = try run(&.{ "iptables", "--wait", "5", "-S", chain });
    if (exists == 0) try isolationRules(bridge_name, true) else if (exists != 1) return error.RuleFailed;
    var subnet_buf: [24]u8 = undefined;
    var address_buf: [16]u8 = undefined;
    const subnet = try std.fmt.bufPrint(&subnet_buf, "{s}/24", .{ip.formatIp(base, &address_buf)});
    try rule(&.{ "iptables", "--wait", "5", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "!", "-o", bridge_name, "-j", "MASQUERADE" }, true);
    try rule(&.{ "iptables", "--wait", "5", "-D", "FORWARD", "-i", bridge_name, "-s", subnet, "-j", "ACCEPT" }, true);
    try rule(&.{ "iptables", "--wait", "5", "-D", "FORWARD", "-o", bridge_name, "-d", subnet, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT" }, true);
}

test "named network subprocesses inherit PATH and preserve command exit codes" {
    try std.testing.expectEqual(@as(u8, 0), try run(&.{ "sh", "-c", "test -n \"$PATH\"" }));
    try std.testing.expectEqual(@as(u8, 1), try run(&.{ "sh", "-c", "exit 1" }));
}
