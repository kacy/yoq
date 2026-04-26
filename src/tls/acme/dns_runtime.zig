const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;

const dns = @import("../../network/dns.zig");
const types = @import("types.zig");

const fallback_nameserver = [4]u8{ 8, 8, 8, 8 };
const dns_port: u16 = 53;
const query_type_txt: u16 = 16;
const query_class_in: u16 = 1;

pub fn waitForTxt(
    record_name: []const u8,
    expected_value: []const u8,
    timeout_secs: u32,
    poll_interval_secs: u32,
) types.AcmeError!void {
    const deadline_ns = std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds() +
        std.Io.Duration.fromSeconds(timeout_secs).toNanoseconds();
    const poll_interval = std.Io.Duration.fromSeconds(@max(1, poll_interval_secs));

    while (std.Io.Clock.awake.now(std.Options.debug_io).toNanoseconds() < deadline_ns) {
        if (queryTxt(record_name, expected_value)) |found| {
            if (found) return;
        } else |_| {}

        std.Io.sleep(std.Options.debug_io, poll_interval, .awake) catch unreachable;
    }

    return types.AcmeError.Timeout;
}

fn queryTxt(record_name: []const u8, expected_value: []const u8) !bool {
    const nameserver = try loadResolverAddress();
    const sock = try linux_platform.posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.CLOEXEC, 0);
    defer linux_platform.posix.close(sock);

    var query_buf: [512]u8 = undefined;
    const query_len = try buildTxtQuery(record_name, &query_buf);

    const addr = linux_platform.net.Address.initIp4(nameserver, dns_port);
    _ = try linux_platform.posix.sendto(sock, query_buf[0..query_len], 0, &addr.any, addr.getOsSockLen());

    var poll_fds = [_]posix.pollfd{
        .{ .fd = sock, .events = posix.POLL.IN, .revents = 0 },
    };
    const ready = try posix.poll(&poll_fds, 2000);
    if (ready == 0 or (poll_fds[0].revents & posix.POLL.IN) == 0) return false;

    var response_buf: [1500]u8 = undefined;
    const response_len = try linux_platform.posix.recvfrom(sock, &response_buf, 0, null, null);
    return parseTxtResponse(response_buf[0..response_len], expected_value);
}

fn loadResolverAddress() ![4]u8 {
    const content = std.Io.Dir.cwd().readFileAlloc(
        std.Options.debug_io,
        "/etc/resolv.conf",
        std.heap.page_allocator,
        .limited(4096),
    ) catch return fallback_nameserver;
    defer std.heap.page_allocator.free(content);

    return dns.parseResolvConf(content) orelse fallback_nameserver;
}

fn buildTxtQuery(record_name: []const u8, out: *[512]u8) !usize {
    @memset(out, 0);

    const micros = std.Io.Clock.real.now(std.Options.debug_io).toMicroseconds();
    const id = @as(u16, @truncate(@as(u64, @intCast(@max(micros, 0)))));
    writeU16(out[0..2], id);
    writeU16(out[2..4], 0x0100);
    writeU16(out[4..6], 1);

    var pos: usize = 12;
    var labels = std.mem.splitScalar(u8, record_name, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.InvalidName;
        if (pos + 1 + label.len >= out.len) return error.BufferTooSmall;
        out[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(out[pos .. pos + label.len], label);
        pos += label.len;
    }

    if (pos + 5 >= out.len) return error.BufferTooSmall;
    out[pos] = 0;
    pos += 1;
    writeU16(out[pos .. pos + 2], query_type_txt);
    pos += 2;
    writeU16(out[pos .. pos + 2], query_class_in);
    pos += 2;
    return pos;
}

fn parseTxtResponse(packet: []const u8, expected_value: []const u8) !bool {
    if (packet.len < 12) return error.InvalidResponse;

    const question_count = readU16(packet[4..6]);
    const answer_count = readU16(packet[6..8]);
    var pos: usize = 12;

    var question_index: u16 = 0;
    while (question_index < question_count) : (question_index += 1) {
        pos = try skipName(packet, pos);
        if (pos + 4 > packet.len) return error.InvalidResponse;
        pos += 4;
    }

    var answer_index: u16 = 0;
    while (answer_index < answer_count) : (answer_index += 1) {
        pos = try skipName(packet, pos);
        if (pos + 10 > packet.len) return error.InvalidResponse;

        const rtype = readU16(packet[pos .. pos + 2]);
        const rclass = readU16(packet[pos + 2 .. pos + 4]);
        const rdlength = readU16(packet[pos + 8 .. pos + 10]);
        pos += 10;

        if (pos + rdlength > packet.len) return error.InvalidResponse;
        const rdata = packet[pos .. pos + rdlength];
        pos += rdlength;

        if (rtype != query_type_txt or rclass != query_class_in) continue;
        if (txtRecordMatches(rdata, expected_value)) return true;
    }

    return false;
}

fn txtRecordMatches(rdata: []const u8, expected_value: []const u8) bool {
    var pos: usize = 0;
    var value_buf: [1024]u8 = undefined;
    var out_len: usize = 0;

    while (pos < rdata.len) {
        const part_len = rdata[pos];
        pos += 1;
        if (pos + part_len > rdata.len) return false;
        if (out_len + part_len > value_buf.len) return false;
        @memcpy(value_buf[out_len .. out_len + part_len], rdata[pos .. pos + part_len]);
        out_len += part_len;
        pos += part_len;
    }

    return std.mem.eql(u8, value_buf[0..out_len], expected_value);
}

fn skipName(packet: []const u8, start: usize) !usize {
    var pos = start;
    while (true) {
        if (pos >= packet.len) return error.InvalidResponse;
        const len = packet[pos];
        if (len == 0) return pos + 1;
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= packet.len) return error.InvalidResponse;
            return pos + 2;
        }
        pos += 1;
        if (pos + len > packet.len) return error.InvalidResponse;
        pos += len;
    }
}

fn readU16(bytes: []const u8) u16 {
    return (@as(u16, bytes[0]) << 8) | @as(u16, bytes[1]);
}

fn writeU16(bytes: []u8, value: u16) void {
    bytes[0] = @truncate(value >> 8);
    bytes[1] = @truncate(value);
}

test "buildTxtQuery encodes qname and txt type" {
    var packet: [512]u8 = undefined;
    const len = try buildTxtQuery("_acme-challenge.example.com", &packet);

    try std.testing.expect(len > 12);
    try std.testing.expectEqual(@as(u8, 15), packet[12]);
    try std.testing.expectEqualStrings("_acme-challenge", packet[13 .. 13 + 15]);
    try std.testing.expectEqual(@as(u8, 7), packet[28]);
    try std.testing.expectEqualStrings("example", packet[29 .. 29 + 7]);
    try std.testing.expectEqual(query_type_txt, readU16(packet[len - 4 .. len - 2]));
}

test "parseTxtResponse matches expected txt answer" {
    const packet = [_]u8{
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x04, 't',  'e',  's',
        't',  0x03, 'c',  'o',  'm',  0x00, 0x00, 0x10,
        0x00, 0x01, 0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x3C, 0x00, 0x08, 0x07, 'a',
        'b',  'c',  '1',  '2',  '3',  '4',
    };

    try std.testing.expect(try parseTxtResponse(&packet, "abc1234"));
    try std.testing.expect(!(try parseTxtResponse(&packet, "wrong")));
}
