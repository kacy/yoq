const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const lposix = linux_platform.posix;

const ipv4_loopback = [4]u8{ 127, 0, 0, 1 };
pub fn main(init: std.process.Init) !void {
    const alloc = init.gpa;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());

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

    if (std.mem.eql(u8, cmd, "udp-serve")) {
        if (argv.len != 3) usage();
        return udpServe(try std.fmt.parseUnsigned(u16, argv[2], 10));
    }
    if (std.mem.eql(u8, cmd, "udp-get")) {
        if (argv.len != 5) usage();
        const address = try resolveHost(argv[2]);
        return udpGet(address, try std.fmt.parseUnsigned(u16, argv[3], 10), argv[4]);
    }
    if (std.mem.eql(u8, cmd, "bind-probe")) {
        if (argv.len != 5) usage();
        const address = try resolveHost(argv[2]);
        const kind: u32 = if (std.mem.eql(u8, argv[4], "tcp")) posix.SOCK.STREAM else if (std.mem.eql(u8, argv[4], "udp")) posix.SOCK.DGRAM else usage();
        const fd = try lposix.socket(posix.AF.INET, kind, 0);
        defer lposix.close(fd);
        const socket_address = linux_platform.net.Address.initIp4(address, try std.fmt.parseUnsigned(u16, argv[3], 10));
        try lposix.bind(fd, &socket_address.any, socket_address.getOsSockLen());
        return;
    }

    usage();
}

fn usage() noreturn {
    std.debug.print("usage: yoq-test-net-probe <resolve host|http-get host port path|udp-serve port|udp-get host port payload|bind-probe host port tcp|udp>\n", .{});
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

    const fd = lposix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0) catch |err| {
        std.debug.print("dns socket failed: {}\n", .{err});
        return err;
    };
    defer lposix.close(fd);

    const timeout = posix.timeval{ .sec = 1, .usec = 0 };
    lposix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch |err| {
        std.debug.print("dns recv timeout failed: {}\n", .{err});
        return err;
    };
    lposix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch |err| {
        std.debug.print("dns send timeout failed: {}\n", .{err});
        return err;
    };

    const dns_addr = try loadDnsServer();
    const addr = linux_platform.net.Address.initIp4(dns_addr, 53);
    _ = lposix.sendto(fd, packet[0..query_len], 0, &addr.any, addr.getOsSockLen()) catch |err| {
        std.debug.print("dns sendto failed: {}\n", .{err});
        return err;
    };

    var response: [512]u8 = undefined;
    const response_len = lposix.recv(fd, &response, 0) catch |err| {
        std.debug.print("dns recv failed: {}\n", .{err});
        return err;
    };
    return try parseDnsResponse(response[0..response_len]);
}

fn loadDnsServer() ![4]u8 {
    var buf: [256]u8 = undefined;
    const data = std.Io.Dir.cwd().readFile(std.Options.debug_io, "/etc/resolv.conf", &buf) catch return error.DnsLookupFailed;
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\t");
        if (!std.mem.startsWith(u8, trimmed, "nameserver")) continue;
        var parts = std.mem.tokenizeAny(u8, trimmed, " \t");
        _ = parts.next() orelse continue;
        const addr = parts.next() orelse continue;
        if (parseIpv4(addr)) |ip| return ip;
    }
    return error.DnsLookupFailed;
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
    const fd = lposix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch |err| {
        std.debug.print("http socket failed: {}\n", .{err});
        return err;
    };
    defer lposix.close(fd);

    const timeout = posix.timeval{ .sec = 2, .usec = 0 };
    lposix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch |err| {
        std.debug.print("http recv timeout failed: {}\n", .{err});
        return err;
    };
    lposix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch |err| {
        std.debug.print("http send timeout failed: {}\n", .{err});
        return err;
    };

    const sock_addr = linux_platform.net.Address.initIp4(addr, port);
    lposix.connect(fd, &sock_addr.any, sock_addr.getOsSockLen()) catch |err| {
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
        const read_len = lposix.read(fd, &buf) catch |err| switch (err) {
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
        const written = try lposix.write(fd, data[total..]);
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
    var writer = std.Io.File.stdout().writer(std.Options.debug_io, &buf);
    const out = &writer.interface;
    try out.print(fmt, args);
    try out.flush();
}

fn udpServe(port: u16) !void {
    const fd = try lposix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer lposix.close(fd);
    const address = linux_platform.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
    try lposix.bind(fd, &address.any, address.getOsSockLen());
    var buffer: [512]u8 = undefined;
    while (true) {
        var peer: posix.sockaddr.in = undefined;
        var length: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        const n = try lposix.recvfrom(fd, &buffer, 0, @ptrCast(&peer), &length);
        _ = try lposix.sendto(fd, buffer[0..n], 0, @ptrCast(&peer), length);
    }
}

fn udpGet(host: [4]u8, port: u16, payload: []const u8) !void {
    const fd = try lposix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer lposix.close(fd);
    const timeout = posix.timeval{ .sec = 1, .usec = 0 };
    try lposix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    const address = linux_platform.net.Address.initIp4(host, port);
    try lposix.connect(fd, &address.any, address.getOsSockLen());
    _ = try lposix.sendto(fd, payload, 0, &address.any, address.getOsSockLen());
    var response: [512]u8 = undefined;
    const n = try lposix.recv(fd, &response, 0);
    try writeStdout("{s}", .{response[0..n]});
}
