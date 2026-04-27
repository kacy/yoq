const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const lposix = linux_platform.posix;

pub fn main(init: std.process.Init) !void {
    const argv = try init.minimal.args.toSlice(init.arena.allocator());

    if (argv.len != 3) {
        std.debug.print("usage: yoq-test-http-server <port> <body>\n", .{});
        std.process.exit(1);
    }

    const port = std.fmt.parseUnsigned(u16, argv[1], 10) catch {
        std.debug.print("invalid port: {s}\n", .{argv[1]});
        std.process.exit(1);
    };
    const body = argv[2];

    const fd = lposix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch |err| {
        std.debug.print("socket failed: {}\n", .{err});
        return err;
    };
    defer lposix.close(fd);

    const reuse: c_int = 1;
    lposix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuse)) catch |err| {
        std.debug.print("setsockopt failed: {}\n", .{err});
        return err;
    };

    const addr = linux_platform.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
    lposix.bind(fd, &addr.any, addr.getOsSockLen()) catch |err| {
        std.debug.print("bind failed: {}\n", .{err});
        return err;
    };
    lposix.listen(fd, 16) catch |err| {
        std.debug.print("listen failed: {}\n", .{err});
        return err;
    };

    var response_buf: [2048]u8 = undefined;
    const response = try std.fmt.bufPrint(
        &response_buf,
        "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n{s}",
        .{ body.len, body },
    );

    while (true) {
        var client_addr: posix.sockaddr = undefined;
        var client_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        const client_fd = lposix.accept(fd, &client_addr, &client_len, 0) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        defer lposix.close(client_fd);

        var request_buf: [1024]u8 = undefined;
        _ = lposix.read(client_fd, &request_buf) catch 0;
        try writeAll(client_fd, response);
    }
}

fn writeAll(fd: posix.socket_t, data: []const u8) !void {
    var total: usize = 0;
    while (total < data.len) {
        const written = try lposix.write(fd, data[total..]);
        if (written == 0) return error.WriteFailed;
        total += written;
    }
}
