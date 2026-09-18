// run the compiled programs against packet fixtures without attaching to a device.
const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;
const programs = @import("network/ebpf/program_support.zig");
const maps = @import("network/ebpf/map_support.zig");
const resources = @import("network/ebpf/resource_support.zig");
const expect = std.testing.expect;
const equal = std.testing.expectEqual;
const bytesEqual = std.testing.expectEqualSlices;
const tc_continue = std.math.maxInt(u32);
const client = [4]u8{ 10, 42, 0, 2 };
const vip = [4]u8{ 10, 43, 0, 1 };
const backend = [4]u8{ 10, 60, 0, 9 };

fn close(fd: std.posix.fd_t) void {
    _ = linux.close(fd);
    resources.releaseBpfFd();
}

fn Loaded(comptime code: type) type {
    return struct {
        fds: [code.maps.len]std.posix.fd_t,
        fd: std.posix.fd_t,
        const Self = @This();

        fn init(kind: BPF.ProgType) !Self {
            var self: Self = undefined;
            var created: usize = 0;
            errdefer for (self.fds[0..created]) |fd| close(fd);
            for (code.maps, &self.fds) |definition, *fd| {
                fd.* = try maps.createMap(@enumFromInt(definition.map_type), definition.key_size, definition.value_size, definition.max_entries);
                created += 1;
            }
            self.fd = try programs.loadProgramWithType(code, &self.fds, kind);
            return self;
        }

        fn deinit(self: Self) void {
            close(self.fd);
            for (self.fds) |fd| close(fd);
        }
    };
}

const Packet = struct {
    data: [512]u8 = @splat(0),
    len: usize,

    fn bytes(self: *const Packet) []const u8 {
        return self.data[0..self.len];
    }
};

fn put16(packet: *Packet, offset: usize, value: u16) void {
    std.mem.writeInt(u16, packet.data[offset..][0..2], value, .big);
}

fn get16(packet: *const Packet, offset: usize) u16 {
    return std.mem.readInt(u16, packet.data[offset..][0..2], .big);
}

fn sumWords(bytes: []const u8) u32 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) sum += std.mem.readInt(u16, bytes[i..][0..2], .big);
    if (i < bytes.len) sum += @as(u32, bytes[i]) << 8;
    return sum;
}

fn fold(sum: u32) u16 {
    var value = sum;
    while (value > 0xffff) value = (value & 0xffff) + (value >> 16);
    return ~@as(u16, @intCast(value));
}

fn transportChecksum(packet: *const Packet) u16 {
    const length = get16(packet, 16) - 20;
    return fold(sumWords(packet.data[26..34]) + packet.data[23] + length + sumWords(packet.data[34..][0..length]));
}

fn checksums(packet: *Packet) void {
    put16(packet, 24, 0);
    put16(packet, 24, fold(sumWords(packet.data[14..34])));
    const offset: usize = if (packet.data[23] == 6) 50 else 40;
    put16(packet, offset, 0);
    const checksum = transportChecksum(packet);
    put16(packet, offset, if (checksum == 0 and packet.data[23] == 17) 0xffff else checksum);
}

fn expectChecksums(packet: *const Packet) !void {
    try equal(@as(u16, 0), fold(sumWords(packet.data[14..34])));
    try equal(@as(u16, 0), transportChecksum(packet));
}

fn transportPacket(protocol: u8, source: [4]u8, destination: [4]u8, source_port: u16, destination_port: u16) Packet {
    var packet: Packet = .{ .len = if (protocol == 6) 54 else 42 };
    @memcpy(packet.data[0..12], &[_]u8{ 2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2 });
    put16(&packet, 12, 0x0800);
    packet.data[14] = 0x45;
    put16(&packet, 16, @intCast(packet.len - 14));
    packet.data[22] = 255;
    packet.data[23] = protocol;
    @memcpy(packet.data[26..30], &source);
    @memcpy(packet.data[30..34], &destination);
    put16(&packet, 34, source_port);
    put16(&packet, 36, destination_port);
    if (protocol == 6) {
        packet.data[46] = 0x50;
        packet.data[47] = 0x02;
    } else put16(&packet, 38, 8);
    checksums(&packet);
    return packet;
}

const Result = struct { action: u32, packet: Packet };

fn run(fd: std.posix.fd_t, packet: *const Packet) !Result {
    var result: Result = .{ .action = undefined, .packet = .{ .len = undefined } };
    var attr = BPF.Attr{ .test_run = std.mem.zeroes(BPF.TestRunAttr) };
    attr.test_run.prog_fd = fd;
    attr.test_run.data_size_in = @intCast(packet.len);
    attr.test_run.data_size_out = result.packet.data.len;
    attr.test_run.data_in = @intFromPtr(&packet.data);
    attr.test_run.data_out = @intFromPtr(&result.packet.data);
    attr.test_run.repeat = 1;
    const rc = linux.bpf(.prog_test_run, &attr, @sizeOf(BPF.TestRunAttr));
    if (linux.errno(rc) != .SUCCESS) {
        std.debug.print("packet test failed: errno={s}, input length={d}\n", .{ @tagName(linux.errno(rc)), packet.len });
        return error.PacketTestFailed;
    }
    result.action = attr.test_run.retval;
    result.packet.len = attr.test_run.data_size_out;
    return result;
}

fn expectUnchanged(fd: std.posix.fd_t, packet: *const Packet, action: u32) !void {
    const result = try run(fd, packet);
    try equal(action, result.action);
    try bytesEqual(u8, packet.bytes(), result.packet.bytes());
}

fn malformedTransport(fd: std.posix.fd_t, protocol: u8, action: u32) !void {
    const good = transportPacket(protocol, client, vip, 12000, 8080);
    for ([_]u16{ 0x2000, 1, 0x2001 }) |fragment| {
        var packet = good;
        put16(&packet, 20, fragment);
        try expectUnchanged(fd, &packet, action);
    }
    var packet = good;
    packet.data[14] = 0x65;
    try expectUnchanged(fd, &packet, action);
    packet = good;
    put16(&packet, 16, @intCast(good.len - 15));
    try expectUnchanged(fd, &packet, action);
    packet = good;
    put16(&packet, 16, @intCast(good.len));
    try expectUnchanged(fd, &packet, action);
    packet = good;
    if (protocol == 6) packet.data[46] = 0x40 else put16(&packet, 38, 7);
    try expectUnchanged(fd, &packet, action);
}

// find an independently checksummed packet whose translated udp checksum is zero.
fn zeroChecksumPort(destination: [4]u8, destination_port: u16) !u16 {
    var port: u32 = 1;
    while (port <= std.math.maxInt(u16)) : (port += 1) {
        var packet = transportPacket(17, client, destination, @intCast(port), destination_port);
        put16(&packet, 40, 0);
        if (transportChecksum(&packet) == 0) return @intCast(port);
    }
    return error.NoZeroChecksumFixture;
}

fn testPortMap() !void {
    const code = @import("port_bytecode");
    const loaded = try Loaded(code).init(.xdp);
    defer loaded.deinit();
    const Key = extern struct { ip: [4]u8, port: [2]u8 = .{ 0x1f, 0x90 }, protocol: u8, pad: u8 = 0 };
    const Target = extern struct { ip: [4]u8, port: [2]u8, pad: u16 = 0 };
    const exact: Target = .{ .ip = backend, .port = .{ 0x23, 0x28 } };
    const wildcard: Target = .{ .ip = .{ 10, 60, 0, 10 }, .port = .{ 0x23, 0x29 } };
    for ([_]u8{ 6, 17 }) |protocol| {
        const key: Key = .{ .ip = vip, .protocol = protocol };
        const wildcard_key: Key = .{ .ip = @splat(0), .protocol = protocol };
        try maps.mapUpdate(loaded.fds[0], std.mem.asBytes(&key), std.mem.asBytes(&exact));
        try maps.mapUpdate(loaded.fds[0], std.mem.asBytes(&wildcard_key), std.mem.asBytes(&wildcard));
        const packet = transportPacket(protocol, client, vip, 12000, 8080);
        const result = try run(loaded.fd, &packet);
        try equal(@as(u32, 2), result.action);
        try bytesEqual(u8, &backend, result.packet.data[30..34]);
        try equal(@as(u16, 9000), get16(&result.packet, 36));
        try expectChecksums(&result.packet);
        try malformedTransport(loaded.fd, protocol, 2);
        try expect(maps.mapDelete(loaded.fds[0], std.mem.asBytes(&key)));
        const fallback = try run(loaded.fd, &packet);
        try bytesEqual(u8, &wildcard.ip, fallback.packet.data[30..34]);
        try equal(@as(u16, 9001), get16(&fallback.packet, 36));
        try expectChecksums(&fallback.packet);
        if (protocol == 17) {
            var unchecked = packet;
            put16(&unchecked, 40, 0);
            const translated = try run(loaded.fd, &unchecked);
            try equal(@as(u16, 0), get16(&translated.packet, 40));
            const source_port = try zeroChecksumPort(wildcard.ip, 9001);
            const zero_result = try run(loaded.fd, &transportPacket(17, client, vip, source_port, 8080));
            try equal(@as(u16, 0xffff), get16(&zero_result.packet, 40));
            try expectChecksums(&zero_result.packet);
        }
    }
    std.debug.print("port mapping: exact and wildcard matches, tcp/udp checksums, short udp and malformed packets passed\n", .{});
}

fn testLoadBalancer() !void {
    const code = @import("lb_bytecode");
    const loaded = try Loaded(code).init(.sched_cls);
    defer loaded.deinit();
    var fds = loaded.fds;
    const egress = try programs.loadEgressProgram(code, &fds);
    defer close(egress);
    const Backends = extern struct { count: u32 = 1, ips: [64][4]u8 = @splat(backend) };
    const backends: Backends = .{};
    try maps.mapUpdate(loaded.fds[0], &vip, std.mem.asBytes(&backends));
    for ([_]u8{ 6, 17 }) |protocol| {
        const packet = transportPacket(protocol, client, vip, 12000, 8080);
        const result = try run(loaded.fd, &packet);
        try equal(tc_continue, result.action);
        try bytesEqual(u8, &backend, result.packet.data[30..34]);
        try expectChecksums(&result.packet);
        const reply = transportPacket(protocol, backend, client, 8080, 12000);
        const reverse = try run(egress, &reply);
        try equal(tc_continue, reverse.action);
        try bytesEqual(u8, &vip, reverse.packet.data[26..30]);
        try expectChecksums(&reverse.packet);
        try malformedTransport(loaded.fd, protocol, tc_continue);
        // two vips cannot share the same backend reply tuple without snat.
        const second_vip = [4]u8{ 10, 43, 0, 2 };
        try maps.mapUpdate(loaded.fds[0], &second_vip, std.mem.asBytes(&backends));
        const conflict = transportPacket(protocol, client, second_vip, 12000, 8080);
        try expectUnchanged(loaded.fd, &conflict, 2);
        const still_original = try run(egress, &reply);
        try bytesEqual(u8, &vip, still_original.packet.data[26..30]);
        if (protocol == 17) {
            var unchecked = packet;
            put16(&unchecked, 40, 0);
            const translated = try run(loaded.fd, &unchecked);
            try equal(@as(u16, 0), get16(&translated.packet, 40));
        }
    }
    const source_port = try zeroChecksumPort(backend, 8080);
    const zero_result = try run(loaded.fd, &transportPacket(17, client, vip, source_port, 8080));
    try equal(@as(u16, 0xffff), get16(&zero_result.packet, 40));
    try expectChecksums(&zero_result.packet);

    // full hash maps force each conntrack insertion to fail without relying on
    // memory pressure or lru eviction. both failures must leave the packet alone.
    for ([_]usize{ 1, 2 }) |index| {
        const full_map = try maps.createMap(.hash, 16, 4, 1);
        defer close(full_map);
        try maps.mapUpdate(full_map, &(@as([16]u8, @splat(0))), &vip);
        var test_fds = loaded.fds;
        test_fds[index] = full_map;
        const fail_fd = try programs.loadProgram(code, &test_fds);
        defer close(fail_fd);
        const packet = transportPacket(6, client, vip, @intCast(13000 + index), 8080);
        try expectUnchanged(fail_fd, &packet, 2);
    }
    std.debug.print("load balancing: checksums, malformed packets, tuple conflicts and full conntrack maps passed\n", .{});
}

fn testPolicy() !void {
    const loaded = try Loaded(@import("policy_bytecode")).init(.sched_cls);
    defer loaded.deinit();
    var packet = transportPacket(17, client, vip, 12000, 8080);
    const pair = client ++ vip;
    try maps.mapUpdate(loaded.fds[1], &client, &.{1});
    try equal(@as(u32, 2), (try run(loaded.fd, &packet)).action);
    try maps.mapUpdate(loaded.fds[0], &pair, &.{1});
    try expectUnchanged(loaded.fd, &packet, tc_continue);
    put16(&packet, 20, 1);
    try expectUnchanged(loaded.fd, &packet, tc_continue);
    try maps.mapUpdate(loaded.fds[0], &pair, &.{0});
    try equal(@as(u32, 2), (try run(loaded.fd, &packet)).action);
    try maps.mapUpdate(loaded.fds[0], &pair, &.{1});
    for ([_]u16{ 19, 200 }) |length| {
        put16(&packet, 16, length);
        try equal(@as(u32, 2), (try run(loaded.fd, &packet)).action);
    }
    // the kernel test runner requires a base ipv4 header; truncate its options.
    packet.data[14] = 0x46;
    packet.len = 34;
    try equal(@as(u32, 2), (try run(loaded.fd, &packet)).action);
    std.debug.print("policy: isolation, allow/deny, fragments and truncated ipv4 passed\n", .{});
}

fn dnsPacket(name: []const u8) Packet {
    var packet = transportPacket(17, client, vip, 12000, 53);
    packet.len = 54 + name.len + 4;
    put16(&packet, 16, @intCast(packet.len - 14));
    put16(&packet, 38, @intCast(packet.len - 34));
    put16(&packet, 42, 0x1234);
    packet.data[44] = 1; // recursion desired must survive in the response.
    put16(&packet, 46, 1);
    @memcpy(packet.data[54..][0..name.len], name);
    put16(&packet, 54 + name.len, 1);
    put16(&packet, 56 + name.len, 1);
    checksums(&packet);
    return packet;
}

fn testDns() !void {
    const loaded = try Loaded(@import("dns_bytecode")).init(.sched_cls);
    defer loaded.deinit();
    const name = "\x03api\x03yoq\x00";
    var key = [_]u8{0} ** 64;
    @memcpy(key[0..name.len], name);
    try maps.mapUpdate(loaded.fds[0], &key, &backend);
    const good = dnsPacket(name);
    const result = try run(loaded.fd, &good);
    try equal(@as(u32, 7), result.action);
    try equal(good.len + 16, result.packet.len);
    try bytesEqual(u8, &client, result.packet.data[30..34]);
    try bytesEqual(u8, &vip, result.packet.data[26..30]);
    try bytesEqual(u8, &backend, result.packet.data[result.packet.len - 4 ..][0..4]);
    try equal(@as(u16, 0), fold(sumWords(result.packet.data[14..34])));
    try equal(@as(u8, 0x85), result.packet.data[44]);
    try equal(@as(u16, 1), get16(&result.packet, 48));
    try equal(@as(u16, 0), get16(&result.packet, 40));
    // a maximum supported name must leave room for the question fields.
    var long_name = [_]u8{'a'} ** 63;
    long_name[0] = 61;
    long_name[62] = 0;
    key = @splat(0);
    @memcpy(key[0..long_name.len], &long_name);
    try maps.mapUpdate(loaded.fds[0], &key, &backend);
    const long_query = dnsPacket(&long_name);
    try equal(@as(u32, 7), (try run(loaded.fd, &long_query)).action);
    for ([_]u16{ 0x2000, 1 }) |fragment| {
        var packet = good;
        put16(&packet, 20, fragment);
        try expectUnchanged(loaded.fd, &packet, tc_continue);
    }
    for ([_]usize{ 16, 38 }) |offset| {
        var packet = good;
        put16(&packet, offset, 20);
        try expectUnchanged(loaded.fd, &packet, tc_continue);
    }
    var packet = good;
    packet.data[44] |= 0x08; // unsupported opcode.
    try expectUnchanged(loaded.fd, &packet, tc_continue);
    packet = good;
    put16(&packet, good.len - 4, 28); // aaaa stays with the userspace resolver.
    try expectUnchanged(loaded.fd, &packet, tc_continue);
    // store a malformed name too: parsing must reject it before map lookup.
    const bad_name = "\x09api\x00";
    key = @splat(0);
    @memcpy(key[0..bad_name.len], bad_name);
    try maps.mapUpdate(loaded.fds[0], &key, &backend);
    packet = dnsPacket(bad_name);
    try expectUnchanged(loaded.fd, &packet, tc_continue);
    std.debug.print("dns: response bytes, long names, label boundaries, fragments and declared lengths passed\n", .{});
}

fn testMetrics() !void {
    const loaded = try Loaded(@import("metrics_bytecode")).init(.sched_cls);
    defer loaded.deinit();
    const IpMetrics = extern struct { packets: u64, bytes: u64 };
    const PairMetrics = extern struct { packets: u64, bytes: u64, connections: u64, errors: u64 };
    var packet = transportPacket(6, client, vip, 12000, 8080);
    try expectUnchanged(loaded.fd, &packet, tc_continue);
    var ip_metrics: IpMetrics = undefined;
    try expect(maps.mapLookup(loaded.fds[0], &client, std.mem.asBytes(&ip_metrics)));
    try equal(@as(u64, 1), ip_metrics.packets);
    try equal(@as(u64, 20), ip_metrics.bytes);
    const pair_key = client ++ vip ++ [_]u8{ 0x1f, 0x90, 0, 0 };
    var pair: PairMetrics = undefined;
    try expect(maps.mapLookup(loaded.fds[1], &pair_key, std.mem.asBytes(&pair)));
    try equal(@as(u64, 1), pair.connections);
    put16(&packet, 20, 1);
    try expectUnchanged(loaded.fd, &packet, tc_continue);
    try expect(maps.mapLookup(loaded.fds[0], &client, std.mem.asBytes(&ip_metrics)));
    try equal(@as(u64, 2), ip_metrics.packets);
    try expect(maps.mapLookup(loaded.fds[1], &pair_key, std.mem.asBytes(&pair)));
    try equal(@as(u64, 1), pair.packets);
    put16(&packet, 16, 200);
    try expectUnchanged(loaded.fd, &packet, tc_continue);
    try expect(maps.mapLookup(loaded.fds[0], &client, std.mem.asBytes(&ip_metrics)));
    try equal(@as(u64, 2), ip_metrics.packets);
    std.debug.print("metrics: counters, fragment handling and malformed lengths passed\n", .{});
}

pub fn main() !void {
    try testPortMap();
    try testLoadBalancer();
    try testPolicy();
    try testDns();
    try testMetrics();
    const storage = try Loaded(@import("storage_bytecode")).init(.tracepoint);
    defer storage.deinit();
    const gpu = try Loaded(@import("gpu_bytecode")).init(.sched_cls);
    defer gpu.deinit();
    const smoke = try Loaded(@import("test_bytecode")).init(.sched_cls);
    defer smoke.deinit();
    try expectUnchanged(smoke.fd, &transportPacket(17, client, vip, 12000, 8080), 0);
    std.debug.print("storage metrics, gpu priority and smoke program: kernel verifier load passed\n", .{});
}
