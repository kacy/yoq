// nat — iptables-based NAT for container networking
//
// handles IP forwarding, masquerade (outbound NAT), and port mapping
// (DNAT + FORWARD rules) so containers can reach the internet and
// the host can reach containers.
//
// this is the fallback path used when eBPF is not available (no
// CAP_BPF, old kernel). when eBPF is available, the DNS interceptor
// and load balancer handle service discovery and traffic distribution
// in-kernel, but iptables is still used for:
//   - IP forwarding (sysctl)
//   - masquerade (outbound NAT for internet access)
//   - port mapping (host port → container DNAT)
//
// requires root / CAP_NET_ADMIN. all operations are non-fatal —
// containers work without NAT (just no internet or port mapping).

const std = @import("std");
const platform = @import("platform");
const cmd = @import("../lib/cmd.zig");
const log = @import("../lib/log.zig");
const network_bridge = @import("bridge.zig");

pub const NatError = error{
    /// an iptables command failed to execute or returned a non-zero exit code
    ExecFailed,
    /// failed to write to /proc/sys/net/ipv4/ip_forward
    ForwardingFailed,
    /// failed to enable route_localnet on the bridge for localhost port mapping
    RouteLocalnetFailed,
};

/// enable IPv4 forwarding by writing to /proc/sys/net/ipv4/ip_forward.
/// required for traffic to flow between container namespace and host.
pub fn enableForwarding() NatError!void {
    var file = std.Io.Dir.cwd().openFile(
        std.Options.debug_io,
        "/proc/sys/net/ipv4/ip_forward",
        .{ .mode = .write_only },
    ) catch return NatError.ForwardingFailed;
    defer file.close(std.Options.debug_io);

    file.writeStreamingAll(std.Options.debug_io, "1\n") catch return NatError.ForwardingFailed;
}

/// ensure masquerade rule exists for container subnet.
/// containers use source NAT to reach the internet.
///
/// equivalent to:
///   iptables -t nat -C POSTROUTING -s 10.42.0.0/16 ! -o yoq0 -j MASQUERADE
///   iptables -t nat -A POSTROUTING -s 10.42.0.0/16 ! -o yoq0 -j MASQUERADE (if not exists)
pub fn ensureMasquerade(bridge: []const u8, subnet: []const u8) NatError!void {
    // check if rule already exists (ignore exit code — fails if not present)
    const check_args = buildMasqueradeArgs(.check, bridge, subnet);
    _ = exec(&check_args) catch {
        // rule doesn't exist, add it
        const add_args = buildMasqueradeArgs(.add, bridge, subnet);
        _ = exec(&add_args) catch return NatError.ExecFailed;
        return;
    };
    // rule already exists, nothing to do
}

/// add port mapping rules (DNAT + FORWARD).
///
/// equivalent to:
///   iptables -t nat -A PREROUTING -p tcp --dport <host_port> -j DNAT --to-destination <ip>:<container_port>
///   iptables -t nat -A OUTPUT -d 127.0.0.1/32 -p tcp --dport <host_port> -j DNAT --to-destination <ip>:<container_port>
///   iptables -A FORWARD -p tcp -d <ip> --dport <container_port> -j ACCEPT
pub fn addPortMap(
    host_port: u16,
    container_ip: []const u8,
    container_port: u16,
    protocol: Protocol,
) NatError!void {
    enableRouteLocalnet(network_bridge.default_bridge) catch |e| {
        log.warn("nat: failed to enable route_localnet on {s}: {}", .{ network_bridge.default_bridge, e });
        return NatError.RouteLocalnetFailed;
    };

    var port_buf: [8]u8 = undefined;
    var dest_buf: [32]u8 = undefined;

    // DNAT rule for external traffic
    const prerouting_args = buildDnatArgs(.add, "PREROUTING", false, host_port, container_ip, container_port, protocol, &port_buf, &dest_buf);
    _ = exec(&prerouting_args) catch |e| {
        log.warn("nat: failed to add DNAT rule for port {d}: {}", .{ host_port, e });
        return NatError.ExecFailed;
    };

    // DNAT rule for host-local traffic (for example curl 127.0.0.1:<port>)
    var loopback_port_buf: [8]u8 = undefined;
    var loopback_dest_buf: [32]u8 = undefined;
    const output_args = buildDnatArgs(.add, "OUTPUT", true, host_port, container_ip, container_port, protocol, &loopback_port_buf, &loopback_dest_buf);
    _ = exec(&output_args) catch |e| {
        log.warn("nat: failed to add OUTPUT DNAT rule for port {d}: {}", .{ host_port, e });
        var cleanup_port_buf: [8]u8 = undefined;
        var cleanup_dest_buf: [32]u8 = undefined;
        const cleanup = buildDnatArgs(.delete, "PREROUTING", false, host_port, container_ip, container_port, protocol, &cleanup_port_buf, &cleanup_dest_buf);
        _ = exec(&cleanup) catch |cleanup_err| {
            log.warn("nat: failed to cleanup PREROUTING DNAT rule after OUTPUT failure: {}", .{cleanup_err});
        };
        return NatError.ExecFailed;
    };

    // SNAT/MASQUERADE localhost traffic so replies can return through conntrack.
    var hairpin_port_buf: [8]u8 = undefined;
    const hairpin_args = buildLoopbackMasqueradeArgs(.add, container_ip, container_port, protocol, &hairpin_port_buf);
    _ = exec(&hairpin_args) catch |e| {
        log.warn("nat: failed to add localhost hairpin MASQUERADE rule for {s}:{d}: {}", .{ container_ip, container_port, e });
        var cleanup_prerouting_port_buf: [8]u8 = undefined;
        var cleanup_prerouting_dest_buf: [32]u8 = undefined;
        const cleanup_prerouting = buildDnatArgs(.delete, "PREROUTING", false, host_port, container_ip, container_port, protocol, &cleanup_prerouting_port_buf, &cleanup_prerouting_dest_buf);
        _ = exec(&cleanup_prerouting) catch |cleanup_err| {
            log.warn("nat: failed to cleanup PREROUTING DNAT rule after hairpin MASQUERADE failure: {}", .{cleanup_err});
        };
        var cleanup_output_port_buf: [8]u8 = undefined;
        var cleanup_output_dest_buf: [32]u8 = undefined;
        const cleanup_output = buildDnatArgs(.delete, "OUTPUT", true, host_port, container_ip, container_port, protocol, &cleanup_output_port_buf, &cleanup_output_dest_buf);
        _ = exec(&cleanup_output) catch |cleanup_err| {
            log.warn("nat: failed to cleanup OUTPUT DNAT rule after hairpin MASQUERADE failure: {}", .{cleanup_err});
        };
        return NatError.ExecFailed;
    };

    // FORWARD rule
    var fwd_port_buf: [8]u8 = undefined;
    const fwd_args = buildForwardArgs(.add, container_ip, container_port, protocol, &fwd_port_buf);
    _ = exec(&fwd_args) catch |e| {
        log.warn("nat: failed to add FORWARD rule for {s}:{d}: {}", .{ container_ip, container_port, e });
        // try to clean up the DNAT rules we just added
        var cleanup_prerouting_port_buf: [8]u8 = undefined;
        var cleanup_prerouting_dest_buf: [32]u8 = undefined;
        const cleanup_prerouting = buildDnatArgs(.delete, "PREROUTING", false, host_port, container_ip, container_port, protocol, &cleanup_prerouting_port_buf, &cleanup_prerouting_dest_buf);
        _ = exec(&cleanup_prerouting) catch |cleanup_err| {
            log.warn("nat: failed to cleanup PREROUTING DNAT rule after FORWARD failure: {}", .{cleanup_err});
        };
        var cleanup_output_port_buf: [8]u8 = undefined;
        var cleanup_output_dest_buf: [32]u8 = undefined;
        const cleanup_output = buildDnatArgs(.delete, "OUTPUT", true, host_port, container_ip, container_port, protocol, &cleanup_output_port_buf, &cleanup_output_dest_buf);
        _ = exec(&cleanup_output) catch |cleanup_err| {
            log.warn("nat: failed to cleanup OUTPUT DNAT rule after FORWARD failure: {}", .{cleanup_err});
        };
        var cleanup_hairpin_port_buf: [8]u8 = undefined;
        const cleanup_hairpin = buildLoopbackMasqueradeArgs(.delete, container_ip, container_port, protocol, &cleanup_hairpin_port_buf);
        _ = exec(&cleanup_hairpin) catch |cleanup_err| {
            log.warn("nat: failed to cleanup localhost hairpin MASQUERADE rule after FORWARD failure: {}", .{cleanup_err});
        };
        return NatError.ExecFailed;
    };
}

/// remove port mapping rules
pub fn removePortMap(
    host_port: u16,
    container_ip: []const u8,
    container_port: u16,
    protocol: Protocol,
) void {
    var port_buf: [8]u8 = undefined;
    var dest_buf: [32]u8 = undefined;
    const prerouting_args = buildDnatArgs(.delete, "PREROUTING", false, host_port, container_ip, container_port, protocol, &port_buf, &dest_buf);
    _ = exec(&prerouting_args) catch |e| {
        log.debug("nat: failed to remove PREROUTING DNAT rule for port {d}: {}", .{ host_port, e });
    };

    var output_port_buf: [8]u8 = undefined;
    var output_dest_buf: [32]u8 = undefined;
    const output_args = buildDnatArgs(.delete, "OUTPUT", true, host_port, container_ip, container_port, protocol, &output_port_buf, &output_dest_buf);
    _ = exec(&output_args) catch |e| {
        log.debug("nat: failed to remove OUTPUT DNAT rule for port {d}: {}", .{ host_port, e });
    };

    var hairpin_port_buf: [8]u8 = undefined;
    const hairpin_args = buildLoopbackMasqueradeArgs(.delete, container_ip, container_port, protocol, &hairpin_port_buf);
    _ = exec(&hairpin_args) catch |e| {
        log.debug("nat: failed to remove localhost hairpin MASQUERADE rule for {s}:{d}: {}", .{ container_ip, container_port, e });
    };

    var fwd_port_buf: [8]u8 = undefined;
    const fwd_args = buildForwardArgs(.delete, container_ip, container_port, protocol, &fwd_port_buf);
    _ = exec(&fwd_args) catch |e| {
        log.debug("nat: failed to remove FORWARD rule for {s}:{d}: {}", .{ container_ip, container_port, e });
    };
}

pub const Protocol = enum {
    tcp,
    udp,

    pub fn str(self: Protocol) []const u8 {
        return switch (self) {
            .tcp => "tcp",
            .udp => "udp",
        };
    }
};

// -- argument builders --
//
// these build iptables argument arrays without executing them.
// separate from exec so we can test argument construction.

const Action = enum { add, delete, check };

fn actionFlag(action: Action) []const u8 {
    return switch (action) {
        .add => "-A",
        .delete => "-D",
        .check => "-C",
    };
}

const max_args = cmd.max_args;
const ArgList = cmd.ArgList;

fn buildMasqueradeArgs(action: Action, bridge: []const u8, subnet: []const u8) ArgList {
    var args: ArgList = .{null} ** max_args;
    args[0] = "iptables";
    args[1] = "-t";
    args[2] = "nat";
    args[3] = actionFlag(action);
    args[4] = "POSTROUTING";
    args[5] = "-s";
    args[6] = subnet;
    args[7] = "!";
    args[8] = "-o";
    args[9] = bridge;
    args[10] = "-j";
    args[11] = "MASQUERADE";
    return args;
}

fn buildDnatArgs(
    action: Action,
    chain: []const u8,
    loopback_only: bool,
    host_port: u16,
    container_ip: []const u8,
    container_port: u16,
    protocol: Protocol,
    port_buf: *[8]u8,
    dest_buf: *[32]u8,
) ArgList {
    var args: ArgList = .{null} ** max_args;
    const host_port_str = cmd.portStr(port_buf, host_port);
    const dest_str = destStr(dest_buf, container_ip, container_port);

    args[0] = "iptables";
    args[1] = "-t";
    args[2] = "nat";
    args[3] = actionFlag(action);
    args[4] = chain;

    var idx: usize = 5;
    if (loopback_only) {
        args[idx] = "-d";
        idx += 1;
        args[idx] = "127.0.0.1/32";
        idx += 1;
    }

    args[idx] = "-p";
    idx += 1;
    args[idx] = protocol.str();
    idx += 1;
    args[idx] = "--dport";
    idx += 1;
    args[idx] = host_port_str;
    idx += 1;
    args[idx] = "-j";
    idx += 1;
    args[idx] = "DNAT";
    idx += 1;
    args[idx] = "--to-destination";
    idx += 1;
    args[idx] = dest_str;
    return args;
}

fn buildForwardArgs(
    action: Action,
    container_ip: []const u8,
    container_port: u16,
    protocol: Protocol,
    port_buf: *[8]u8,
) ArgList {
    var args: ArgList = .{null} ** max_args;
    const port_str = cmd.portStr(port_buf, container_port);

    args[0] = "iptables";
    args[1] = actionFlag(action);
    args[2] = "FORWARD";
    args[3] = "-p";
    args[4] = protocol.str();
    args[5] = "-d";
    args[6] = container_ip;
    args[7] = "--dport";
    args[8] = port_str;
    args[9] = "-j";
    args[10] = "ACCEPT";
    return args;
}

fn buildLoopbackMasqueradeArgs(
    action: Action,
    container_ip: []const u8,
    container_port: u16,
    protocol: Protocol,
    port_buf: *[8]u8,
) ArgList {
    var args: ArgList = .{null} ** max_args;
    const port_str = cmd.portStr(port_buf, container_port);

    args[0] = "iptables";
    args[1] = "-t";
    args[2] = "nat";
    args[3] = actionFlag(action);
    args[4] = "POSTROUTING";
    args[5] = "-s";
    args[6] = "127.0.0.1/32";
    args[7] = "-d";
    args[8] = container_ip;
    args[9] = "-p";
    args[10] = protocol.str();
    args[11] = "--dport";
    args[12] = port_str;
    args[13] = "-j";
    args[14] = "MASQUERADE";
    return args;
}

fn enableRouteLocalnet(interface: []const u8) NatError!void {
    var path_buf: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/sys/net/ipv4/conf/{s}/route_localnet", .{interface}) catch
        return NatError.RouteLocalnetFailed;
    var file = std.Io.Dir.cwd().openFile(std.Options.debug_io, path, .{ .mode = .write_only }) catch return NatError.RouteLocalnetFailed;
    defer file.close(std.Options.debug_io);
    file.writeStreamingAll(std.Options.debug_io, "1\n") catch return NatError.RouteLocalnetFailed;
}

// -- string formatting --

fn destStr(buf: *[32]u8, ip: []const u8, port: u16) []const u8 {
    return std.fmt.bufPrint(buf, "{s}:{d}", .{ ip, port }) catch "0.0.0.0:0";
}

// -- exec helper --

fn exec(args: *const ArgList) NatError!void {
    cmd.exec(args) catch return NatError.ExecFailed;
}

// -- tests --

test "masquerade args construction" {
    const args = buildMasqueradeArgs(.add, "yoq0", "10.42.0.0/16");
    try std.testing.expectEqualStrings("iptables", args[0].?);
    try std.testing.expectEqualStrings("-t", args[1].?);
    try std.testing.expectEqualStrings("nat", args[2].?);
    try std.testing.expectEqualStrings("-A", args[3].?);
    try std.testing.expectEqualStrings("POSTROUTING", args[4].?);
    try std.testing.expectEqualStrings("-s", args[5].?);
    try std.testing.expectEqualStrings("10.42.0.0/16", args[6].?);
    try std.testing.expectEqualStrings("!", args[7].?);
    try std.testing.expectEqualStrings("-o", args[8].?);
    try std.testing.expectEqualStrings("yoq0", args[9].?);
    try std.testing.expectEqualStrings("-j", args[10].?);
    try std.testing.expectEqualStrings("MASQUERADE", args[11].?);
    try std.testing.expect(args[12] == null);
}

test "masquerade check uses -C flag" {
    const args = buildMasqueradeArgs(.check, "yoq0", "10.42.0.0/16");
    try std.testing.expectEqualStrings("-C", args[3].?);
}

test "masquerade delete uses -D flag" {
    const args = buildMasqueradeArgs(.delete, "yoq0", "10.42.0.0/16");
    try std.testing.expectEqualStrings("-D", args[3].?);
}

test "dnat args construction" {
    var port_buf: [8]u8 = undefined;
    var dest_buf: [32]u8 = undefined;
    const args = buildDnatArgs(.add, "PREROUTING", false, 8080, "10.42.0.2", 80, .tcp, &port_buf, &dest_buf);
    try std.testing.expectEqualStrings("iptables", args[0].?);
    try std.testing.expectEqualStrings("-t", args[1].?);
    try std.testing.expectEqualStrings("nat", args[2].?);
    try std.testing.expectEqualStrings("-A", args[3].?);
    try std.testing.expectEqualStrings("PREROUTING", args[4].?);
    try std.testing.expectEqualStrings("-p", args[5].?);
    try std.testing.expectEqualStrings("tcp", args[6].?);
    try std.testing.expectEqualStrings("--dport", args[7].?);
    try std.testing.expectEqualStrings("8080", args[8].?);
    try std.testing.expectEqualStrings("-j", args[9].?);
    try std.testing.expectEqualStrings("DNAT", args[10].?);
    try std.testing.expectEqualStrings("--to-destination", args[11].?);
    try std.testing.expectEqualStrings("10.42.0.2:80", args[12].?);
    try std.testing.expect(args[13] == null);
}

test "loopback dnat args target OUTPUT chain" {
    var port_buf: [8]u8 = undefined;
    var dest_buf: [32]u8 = undefined;
    const args = buildDnatArgs(.add, "OUTPUT", true, 8080, "10.42.0.2", 80, .tcp, &port_buf, &dest_buf);
    try std.testing.expectEqualStrings("iptables", args[0].?);
    try std.testing.expectEqualStrings("-t", args[1].?);
    try std.testing.expectEqualStrings("nat", args[2].?);
    try std.testing.expectEqualStrings("-A", args[3].?);
    try std.testing.expectEqualStrings("OUTPUT", args[4].?);
    try std.testing.expectEqualStrings("-d", args[5].?);
    try std.testing.expectEqualStrings("127.0.0.1/32", args[6].?);
    try std.testing.expectEqualStrings("-p", args[7].?);
    try std.testing.expectEqualStrings("tcp", args[8].?);
    try std.testing.expectEqualStrings("--dport", args[9].?);
    try std.testing.expectEqualStrings("8080", args[10].?);
    try std.testing.expectEqualStrings("-j", args[11].?);
    try std.testing.expectEqualStrings("DNAT", args[12].?);
    try std.testing.expectEqualStrings("--to-destination", args[13].?);
    try std.testing.expectEqualStrings("10.42.0.2:80", args[14].?);
    try std.testing.expect(args[15] == null);
}

test "forward args construction" {
    var port_buf: [8]u8 = undefined;
    const args = buildForwardArgs(.add, "10.42.0.5", 3000, .udp, &port_buf);
    try std.testing.expectEqualStrings("iptables", args[0].?);
    try std.testing.expectEqualStrings("-A", args[1].?);
    try std.testing.expectEqualStrings("FORWARD", args[2].?);
    try std.testing.expectEqualStrings("-p", args[3].?);
    try std.testing.expectEqualStrings("udp", args[4].?);
    try std.testing.expectEqualStrings("-d", args[5].?);
    try std.testing.expectEqualStrings("10.42.0.5", args[6].?);
    try std.testing.expectEqualStrings("--dport", args[7].?);
    try std.testing.expectEqualStrings("3000", args[8].?);
    try std.testing.expectEqualStrings("-j", args[9].?);
    try std.testing.expectEqualStrings("ACCEPT", args[10].?);
    try std.testing.expect(args[11] == null);
}

test "loopback masquerade args construction" {
    var port_buf: [8]u8 = undefined;
    const args = buildLoopbackMasqueradeArgs(.add, "10.42.0.2", 8080, .tcp, &port_buf);
    try std.testing.expectEqualStrings("iptables", args[0].?);
    try std.testing.expectEqualStrings("-t", args[1].?);
    try std.testing.expectEqualStrings("nat", args[2].?);
    try std.testing.expectEqualStrings("-A", args[3].?);
    try std.testing.expectEqualStrings("POSTROUTING", args[4].?);
    try std.testing.expectEqualStrings("-s", args[5].?);
    try std.testing.expectEqualStrings("127.0.0.1/32", args[6].?);
    try std.testing.expectEqualStrings("-d", args[7].?);
    try std.testing.expectEqualStrings("10.42.0.2", args[8].?);
    try std.testing.expectEqualStrings("-p", args[9].?);
    try std.testing.expectEqualStrings("tcp", args[10].?);
    try std.testing.expectEqualStrings("--dport", args[11].?);
    try std.testing.expectEqualStrings("8080", args[12].?);
    try std.testing.expectEqualStrings("-j", args[13].?);
    try std.testing.expectEqualStrings("MASQUERADE", args[14].?);
    try std.testing.expect(args[15] == null);
}

test "protocol strings" {
    try std.testing.expectEqualStrings("tcp", Protocol.tcp.str());
    try std.testing.expectEqualStrings("udp", Protocol.udp.str());
}

test "dnat args with port 1" {
    var port_buf: [8]u8 = undefined;
    var dest_buf: [32]u8 = undefined;
    const args = buildDnatArgs(.add, "PREROUTING", false, 1, "10.42.0.2", 80, .tcp, &port_buf, &dest_buf);
    try std.testing.expectEqualStrings("1", args[8].?);
    try std.testing.expectEqualStrings("10.42.0.2:80", args[12].?);
}

test "dnat args with port 65535" {
    var port_buf: [8]u8 = undefined;
    var dest_buf: [32]u8 = undefined;
    const args = buildDnatArgs(.add, "PREROUTING", false, 65535, "10.42.0.2", 65535, .tcp, &port_buf, &dest_buf);
    try std.testing.expectEqualStrings("65535", args[8].?);
    try std.testing.expectEqualStrings("10.42.0.2:65535", args[12].?);
}
