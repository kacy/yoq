const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;
const bytecode = @import("lb_bytecode");
const programs = @import("network/ebpf/program_support.zig");
const maps = @import("network/ebpf/map_support.zig");
const resources = @import("network/ebpf/resource_support.zig");

fn close(fd: std.posix.fd_t) void {
    _ = linux.close(fd);
    resources.releaseBpfFd();
}

pub fn main() !void {
    var map_fds: [bytecode.maps.len]std.posix.fd_t = undefined;
    var created: usize = 0;
    defer for (map_fds[0..created]) |fd| close(fd);
    for (bytecode.maps, &map_fds) |definition, *fd| {
        fd.* = try maps.createMap(@enumFromInt(definition.map_type), definition.key_size, definition.value_size, definition.max_entries);
        created += 1;
    }
    const ingress = try programs.loadProgram(bytecode, &map_fds);
    defer close(ingress);
    const egress = try programs.loadEgressProgram(bytecode, &map_fds);
    defer close(egress);

    const Backends = extern struct { count: u32, ips: [64][4]u8 };
    const vip = [4]u8{ 10, 43, 0, 1 };
    const counts = [_]u32{ 0, 1, 2, 63, 64, 65, std.math.maxInt(u32) };
    for (counts, 0..) |count, iteration| {
        var backends: Backends = .{ .count = count, .ips = undefined };
        for (&backends.ips, 0..) |*ip, index| ip.* = .{ 10, 60, 0, @intCast(index + 1) };
        try maps.mapUpdate(map_fds[0], &vip, std.mem.asBytes(&backends));
        const client = [4]u8{ 10, 42, 0, @intCast(iteration + 1) };
        const packet = tcpPacket(client, vip, 12000, 8080);
        const result = try runPacket(ingress, &packet);
        if (count == 0 or count > 64) {
            if (result.action != 2) return error.InvalidCountWasNotDropped;
            continue;
        }
        if (result.action != 0) return error.ValidCountWasDropped;
        const expected = backends.ips[clientHash(client) % count];
        if (!std.mem.eql(u8, result.packet[30..34], &expected)) return error.WrongBackend;
        // The same compiled map set also restores the VIP on return traffic.
        const reply = tcpPacket(expected, client, 8080, 12000);
        const reverse = try runPacket(egress, &reply);
        if (reverse.action != 0 or !std.mem.eql(u8, reverse.packet[26..30], &vip)) return error.ReverseTranslationFailed;
    }
    std.debug.print("load balancer kernel load, bounded backend selection, invalid counts and reverse translation passed\n", .{});
}

fn clientHash(client: [4]u8) u32 {
    var hash: u32 = 2166136261;
    for (client) |byte| hash = (hash ^ byte) *% 16777619;
    return hash;
}

fn tcpPacket(source: [4]u8, destination: [4]u8, source_port: u16, destination_port: u16) [54]u8 {
    var packet = [_]u8{0} ** 54;
    std.mem.writeInt(u16, packet[12..14], 0x0800, .big);
    packet[14] = 0x45;
    std.mem.writeInt(u16, packet[16..18], 40, .big);
    packet[22] = 64;
    packet[23] = 6;
    @memcpy(packet[26..30], &source);
    @memcpy(packet[30..34], &destination);
    std.mem.writeInt(u16, packet[34..36], source_port, .big);
    std.mem.writeInt(u16, packet[36..38], destination_port, .big);
    packet[46] = 0x50;
    packet[47] = 0x02;
    return packet;
}

const Result = struct { action: u32, packet: [54]u8 };

fn runPacket(fd: std.posix.fd_t, input: []const u8) !Result {
    var result: Result = .{ .action = undefined, .packet = undefined };
    var attr = BPF.Attr{ .test_run = std.mem.zeroes(BPF.TestRunAttr) };
    attr.test_run.prog_fd = fd;
    attr.test_run.data_size_in = @intCast(input.len);
    attr.test_run.data_size_out = result.packet.len;
    attr.test_run.data_in = @intFromPtr(input.ptr);
    attr.test_run.data_out = @intFromPtr(&result.packet);
    attr.test_run.repeat = 1;
    const rc = linux.bpf(.prog_test_run, &attr, @sizeOf(BPF.TestRunAttr));
    if (linux.errno(rc) != .SUCCESS) return error.PacketTestFailed;
    if (attr.test_run.data_size_out != result.packet.len) return error.UnexpectedPacketSize;
    result.action = attr.test_run.retval;
    return result;
}
