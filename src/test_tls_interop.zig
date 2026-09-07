//! Socketpair driver for tools/test_tls_interop.py. OpenSSL owns the other
//! endpoint, so neither side can accidentally validate the same TLS mistake.
const std = @import("std");
const client = @import("tls/client_session.zig");
const server = @import("tls/proxy/session_runtime.zig");
const records = @import("tls/record_transport.zig");
const transport = @import("lib/socket_stream.zig");

pub fn main(init: std.process.Init) !void {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer args.deinit();
    _ = args.next();
    const mode = args.next() orelse return error.MissingMode;
    const fd = try std.fmt.parseInt(i32, args.next() orelse return error.MissingSocket, 10);
    const cert_fd = try std.fmt.parseInt(i32, args.next() orelse return error.MissingCertificate, 10);
    const key_fd = try std.fmt.parseInt(i32, args.next() orelse return error.MissingKey, 10);
    var cert_buffer: [8192]u8 = undefined;
    var key_buffer: [8192]u8 = undefined;
    const cert = try readFile(cert_fd, &cert_buffer);
    const key = try readFile(key_fd, &key_buffer);
    const wire = transport.Stream{ .fd = fd, .deadline = transport.Deadline.afterMilliseconds(5000) };
    const now = std.Io.Clock.real.now(init.io).toSeconds();
    if (std.mem.eql(u8, mode, "client")) {
        var session = try client.doHandshake(init.io, init.gpa, fd, .{ .ca_cert_pem = cert, .now_unix = now, .deadline = wire.deadline });
        defer session.deinit();
        _ = try session.write("ping");
        var reply: [4]u8 = undefined;
        var used: usize = 0;
        while (used < reply.len) {
            const n = try session.read(reply[used..]);
            if (n == 0) return error.UnexpectedEof;
            used += n;
        }
        if (!std.mem.eql(u8, &reply, "pong")) return error.BadReply;
    } else {
        var buffer: records.Buffer = undefined;
        const hello = try records.read(wire, &buffer);
        var complete = false;
        if (std.mem.eql(u8, mode, "relay")) {
            const port = try std.fmt.parseInt(u16, args.next() orelse return error.MissingBackend, 10);
            return server.handleTlsSession(init.io, fd, hello, cert, key, .{ .ip = "127.0.0.1", .port = port }, &complete, null);
        }
        var session = try server.acceptServerHandshake(init.io, init.gpa, fd, hello, cert, key, null, &complete);
        defer session.deinit(init.gpa);
        var read_seq: u64 = 0;
        var write_seq: u64 = 0;
        const request = try records.readEncrypted(wire, &buffer, session.app_keys.client, &read_seq, false);
        if (!std.mem.eql(u8, request.plaintext, "ping")) return error.BadRequest;
        try records.write(wire, session.app_keys.server, &write_seq, .application_data, "pong");
    }
}

fn readFile(fd: i32, buffer: []u8) ![]u8 {
    var used: usize = 0;
    while (used < buffer.len) {
        const n = try std.posix.read(fd, buffer[used..]);
        if (n == 0) return buffer[0..used];
        used += n;
    }
    return error.FileTooLarge;
}
