const std = @import("std");
const posix = std.posix;

const ipv4_loopback = [4]u8{ 127, 0, 0, 1 };
const dns_addr = [4]u8{ 10, 42, 0, 1 };

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const argv = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, argv);

    if (argv.len < 3) {
        usage();
    }

    const cmd = argv[1];
    if (std.mem.eql(u8, cmd, "resolve")) {
        if (argv.len != 3) usage();
        const addr = try resolveHost(argv[2]);
        try writeStdout("{d}.{d}.{d}.{d}\n", .{ addr[0], addr[1], addr[2], addr[3] });
        return;
    }

    if (std.mem.eql(u8, cmd, "http-get")) {
        if (argv.len != 5) usage();
        const port = std.fmt.parseUnsigned(u16, argv[3], 10) catch usage();
        const addr = try resolveHost(argv[2]);
        const body = try httpGet(alloc, addr, port, argv[4], argv[2]);
        defer alloc.free(body);
        try writeStdout("{s}", .{body});
        return;
    }

    usage();
}

fn usage() noreturn {
    std.debug.print("usage: yoq-test-net-probe <resolve host|http-get host port path>\n", .{});
    std.process.exit(1);
}

fn resolveHost(host: []const u8) ![4]u8 {
    if (std.mem.eql(u8, host, "localhost")) return ipv4_loopback;
    if (parseIpv4(host)) |addr| return addr;
    return try queryDnsARecord(host);
}

fn parseIpv4(host: []const u8) ?[4]u8 {
    var addr: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, host, '.');
    var idx: usize = 0;
    while (parts.next()) |part| : (idx += 1) {
        if (idx >= addr.len) return null;
        addr[idx] = std.fmt.parseUnsigned(u8, part, 10) catch return null;
    }
    if (idx != addr.len) return null;
    return addr;
}

fn queryDnsARecord(host: []const u8) ![4]u8 {
    var packet: [512]u8 = undefined;
    const query_len = try buildDnsQuery(host, &packet);

    const fd = posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch |err| {
        std.debug.print("dns socket failed: {}\n", .{err});
        return err;
    };
    defer posix.close(fd);

    const timeout = posix.timeval{ .sec = 1, .usec = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch |err| {
        std.debug.print("dns recv timeout failed: {}\n", .{err});
        return err;
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch |err| {
        std.debug.print("dns send timeout failed: {}\n", .{err});
        return err;
    };

    const addr = std.net.Address.initIp4(dns_addr, 53);
    _ = posix.sendto(fd, packet[0..query_len], 0, &addr.any, addr.getOsSockLen()) catch |err| {
        std.debug.print("dns sendto failed: {}\n", .{err});
        return err;
    };

    var response: [512]u8 = undefined;
    const response_len = posix.recv(fd, &response, 0) catch |err| {
        std.debug.print("dns recv failed: {}\n", .{err});
        return err;
    };
    return try parseDnsResponse(response[0..response_len]);
}

fn buildDnsQuery(host: []const u8, out: *[512]u8) !usize {
    @memset(out, 0);
    out[0] = 0x12;
    out[1] = 0x34;
    out[2] = 0x01;
    out[5] = 0x01;

    var pos: usize = 12;
    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or pos + 1 + label.len >= out.len) return error.InvalidDnsName;
        out[pos] = @intCast(label.len);
        pos += 1;
        @memcpy(out[pos..][0..label.len], label);
        pos += label.len;
    }
    if (pos + 5 >= out.len) return error.InvalidDnsName;
    out[pos] = 0;
    pos += 1;
    writeU16(out[pos..][0..2], 1);
    pos += 2;
    writeU16(out[pos..][0..2], 1);
    pos += 2;
    return pos;
}

fn parseDnsResponse(buf: []const u8) ![4]u8 {
    if (buf.len < 12) return error.InvalidDnsResponse;
    const flags = readU16(buf[2..4]);
    if ((flags & 0x8000) == 0) return error.InvalidDnsResponse;
    const rcode = flags & 0x000F;
    if (rcode != 0) return error.DnsLookupFailed;

    const qdcount = readU16(buf[4..6]);
    const ancount = readU16(buf[6..8]);
    if (qdcount != 1 or ancount == 0) return error.DnsLookupFailed;

    var pos: usize = 12;
    pos = try skipDnsName(buf, pos);
    if (pos + 4 > buf.len) return error.InvalidDnsResponse;
    pos += 4;

    var answer_idx: usize = 0;
    while (answer_idx < ancount) : (answer_idx += 1) {
        pos = try skipDnsName(buf, pos);
        if (pos + 10 > buf.len) return error.InvalidDnsResponse;
        const record_type = readU16(buf[pos .. pos + 2]);
        pos += 2;
        const record_class = readU16(buf[pos .. pos + 2]);
        pos += 2;
        pos += 4;
        const rdlength = readU16(buf[pos .. pos + 2]);
        pos += 2;
        if (pos + rdlength > buf.len) return error.InvalidDnsResponse;
        if (record_type == 1 and record_class == 1 and rdlength == 4) {
            return .{ buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3] };
        }
        pos += rdlength;
    }

    return error.DnsLookupFailed;
}

fn skipDnsName(buf: []const u8, start: usize) !usize {
    var pos = start;
    while (true) {
        if (pos >= buf.len) return error.InvalidDnsResponse;
        const len = buf[pos];
        if (len == 0) return pos + 1;
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= buf.len) return error.InvalidDnsResponse;
            return pos + 2;
        }
        if ((len & 0xC0) != 0 or len > 63) return error.InvalidDnsResponse;
        pos += 1 + len;
    }
}

fn httpGet(alloc: std.mem.Allocator, addr: [4]u8, port: u16, path: []const u8, host_header: []const u8) ![]u8 {
    const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch |err| {
        std.debug.print("http socket failed: {}\n", .{err});
        return err;
    };
    defer posix.close(fd);

    const timeout = posix.timeval{ .sec = 2, .usec = 0 };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch |err| {
        std.debug.print("http recv timeout failed: {}\n", .{err});
        return err;
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch |err| {
        std.debug.print("http send timeout failed: {}\n", .{err});
        return err;
    };

    const sock_addr = std.net.Address.initIp4(addr, port);
    posix.connect(fd, &sock_addr.any, sock_addr.getOsSockLen()) catch |err| {
        std.debug.print("http connect failed: {}\n", .{err});
        return err;
    };

    var req_buf: [1024]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &req_buf,
        "GET {s} HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n",
        .{ path, host_header },
    );
    try writeAll(fd, request);

    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(alloc);

    var buf: [1024]u8 = undefined;
    while (true) {
        const read_len = posix.read(fd, &buf) catch |err| switch (err) {
            error.WouldBlock => break,
            else => return err,
        };
        if (read_len == 0) break;
        try response.appendSlice(alloc, buf[0..read_len]);
    }

    const data = response.items;
    if (!std.mem.startsWith(u8, data, "HTTP/1.1 200")) return error.UnexpectedHttpStatus;
    const body_start = std.mem.indexOf(u8, data, "\r\n\r\n") orelse return error.InvalidHttpResponse;
    return try alloc.dupe(u8, data[body_start + 4 ..]);
}

fn writeAll(fd: posix.socket_t, data: []const u8) !void {
    var total: usize = 0;
    while (total < data.len) {
        const written = try posix.write(fd, data[total..]);
        if (written == 0) return error.WriteFailed;
        total += written;
    }
}

fn readU16(buf: []const u8) u16 {
    return (@as(u16, buf[0]) << 8) | @as(u16, buf[1]);
}

fn writeU16(buf: []u8, value: u16) void {
    buf[0] = @truncate(value >> 8);
    buf[1] = @truncate(value);
}

fn writeStdout(comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    var writer = std.fs.File.stdout().writer(&buf);
    const out = &writer.interface;
    try out.print(fmt, args);
    try out.flush();
}
