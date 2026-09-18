const std = @import("std");
const platform = @import("linux_platform");
const ip = @import("ip.zig");
const nat = @import("nat.zig");
const io = std.Options.debug_io;
const Allocator = std.mem.Allocator;

pub const Backend = struct {
    host_port: u16,
    target_port: u16,
    address: [4]u8 = .{ 0, 0, 0, 0 },
    eligible: bool = false,
};

fn firstForPort(claims: []const Backend, index: usize) bool {
    for (claims[0..index]) |earlier| if (earlier.host_port == claims[index].host_port) return false;
    return true;
}

/// each DNAT rule ends traversal. conditional probabilities give every healthy
/// replica the same share of new connections; conntrack pins subsequent packets.
pub fn renderRules(alloc: Allocator, claims: []const Backend) ![]const u8 {
    var output: std.Io.Writer.Allocating = .init(alloc);
    errdefer output.deinit();
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

fn run(child_io: std.Io, argv: []const []const u8, input: ?std.Io.File) !void {
    var child = try std.process.spawn(child_io, .{ .argv = argv, .stdin = if (input) |file| .{ .file = file } else .ignore, .stdout = .ignore, .stderr = .ignore });
    const term = try child.wait(child_io);
    if (term != .exited or term.exited != 0) return error.FirewallFailed;
}

fn ensureJump(child_io: std.Io, table: []const u8, source: []const u8, target: []const u8, local_only: bool) !void {
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(std.heap.page_allocator);
    try args.appendSlice(std.heap.page_allocator, &.{ "iptables", "--wait", "5", "-t", table, "-C", source });
    if (local_only) try args.appendSlice(std.heap.page_allocator, &.{ "-m", "addrtype", "--dst-type", "LOCAL" });
    try args.appendSlice(std.heap.page_allocator, &.{ "-j", target });
    run(child_io, args.items, null) catch {
        args.items[5] = "-A";
        try run(child_io, args.items, null);
    };
}

pub fn apply(alloc: Allocator, claims: []const Backend) !void {
    // debug_io deliberately has a failing allocator. subprocess startup needs
    // an owned io instance to allocate argv and inherit the host tool path.
    const environ: [*:null]const ?[*:0]const u8 = @ptrCast(std.c.environ);
    var threaded = std.Io.Threaded.init(std.heap.page_allocator, .{
        .environ = .{ .block = .{ .slice = std.mem.span(environ) } },
    });
    defer threaded.deinit();
    const child_io = threaded.io();
    if (claims.len != 0) try nat.enableRouteLocalnet(@import("bridge.zig").default_bridge);
    const rules = try renderRules(alloc, claims);
    defer alloc.free(rules);
    const linux = std.os.linux;
    const opened = linux.memfd_create("yoq-published-ports", linux.MFD.CLOEXEC);
    if (linux.errno(opened) != .SUCCESS) return error.ScratchFileFailed;
    const file: std.Io.File = .{ .handle = @intCast(opened), .flags = .{ .nonblocking = false } };
    defer file.close(io);
    try file.writeStreamingAll(io, rules);
    _ = try platform.posix.lseek(file.handle, 0, linux.SEEK.SET);
    try run(child_io, &.{ "iptables-restore", "--wait", "5", "--noflush" }, file);
    try ensureJump(child_io, "filter", "FORWARD", "YOQ-PUBLISHED-FWD", false);
    try ensureJump(child_io, "filter", "INPUT", "YOQ-PUBLISHED-IN", false);
    try ensureJump(child_io, "nat", "POSTROUTING", "YOQ-PUBLISHED-SNAT", false);
    try ensureJump(child_io, "nat", "PREROUTING", "YOQ-PUBLISHED", true);
    try ensureJump(child_io, "nat", "OUTPUT", "YOQ-PUBLISHED", true);
}
