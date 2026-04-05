const std = @import("std");
const posix = std.posix;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const argv = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, argv);

    if (argv.len != 3) {
        std.debug.print("usage: yoq-test-http-server <port> <body>\n", .{});
        std.process.exit(1);
    }

    const port = std.fmt.parseUnsigned(u16, argv[1], 10) catch {
        std.debug.print("invalid port: {s}\n", .{argv[1]});
        std.process.exit(1);
    };
    const body = argv[2];

    const fd = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch |err| {
        std.debug.print("socket failed: {}\n", .{err});
        return err;
    };
    defer posix.close(fd);

    const reuse: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuse)) catch |err| {
        std.debug.print("setsockopt failed: {}\n", .{err});
        return err;
    };

    const addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
    posix.bind(fd, &addr.any, addr.getOsSockLen()) catch |err| {
        std.debug.print("bind failed: {}\n", .{err});
        return err;
    };
    posix.listen(fd, 16) catch |err| {
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
        const client_fd = posix.accept(fd, &client_addr, &client_len, 0) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        defer posix.close(client_fd);

        var request_buf: [1024]u8 = undefined;
        _ = posix.read(client_fd, &request_buf) catch 0;
        try writeAll(client_fd, response);
    }
}

fn writeAll(fd: posix.socket_t, data: []const u8) !void {
    var total: usize = 0;
    while (total < data.len) {
        const written = try posix.write(fd, data[total..]);
        if (written == 0) return error.WriteFailed;
        total += written;
    }
}
