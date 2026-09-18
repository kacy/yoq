const std = @import("std");
const platform = @import("linux_platform");
const wire = @import("../../tls/client_transport.zig");
const session_runtime = @import("../../tls/proxy/session_runtime.zig");
const peer_identity = @import("../../tls/peer_identity.zig");
const client_session = @import("../../tls/client_session.zig");
pub const x509 = @import("../../tls/x509_gen.zig");
pub const csr = @import("../../tls/csr.zig");
pub const key = [_]u8{9} ** 32;

pub fn exec(sql: []const u8) !void {
    var lease = try @import("../../state/store/common.zig").leaseDb();
    defer lease.deinit();
    try lease.db.execDynamic(sql, .{}, .{});
}

pub fn publish(cert: []const u8, private_key: []const u8, now: i64) !void {
    const alloc = std.testing.allocator;
    const encrypted = try @import("../../state/secrets.zig").encrypt(alloc, private_key, key);
    defer alloc.free(encrypted.ciphertext);
    const sql = try @import("../../state/store/certificates_mtls.zig").buildProxyUpsertSql(alloc, cert, encrypted.ciphertext, &encrypted.nonce, &encrypted.tag, now + 86400, now);
    defer alloc.free(sql);
    try exec(sql);
}

pub fn listen() !struct { fd: std.posix.fd_t, port: u16 } {
    const fd = try platform.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC | std.posix.SOCK.NONBLOCK, 0);
    errdefer platform.posix.close(fd);
    var addr = platform.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    try platform.posix.bind(fd, &addr.any, addr.getOsSockLen());
    try platform.posix.listen(fd, 1);
    var length = addr.getOsSockLen();
    try platform.posix.getsockname(fd, &addr.any, &length);
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, addr.in.port) };
}

pub const Server = struct {
    fd: std.posix.fd_t,
    ca: []const u8,
    cert: []const u8,
    private_key: []const u8,
    now: i64,
    request: []const u8,
    response: []const u8,
    accepted: bool = false,
    saw_request: bool = false,
    failure: ?anyerror = null,

    pub fn run(self: *Server) void {
        self.serve() catch |err| {
            self.failure = err;
        };
    }

    fn readExactly(input: anytype, bytes: []u8) !void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            const count = try input.read(bytes[offset..]);
            if (count == 0) return error.UnexpectedEof;
            offset += count;
        }
    }

    fn serve(self: *Server) !void {
        const alloc = std.testing.allocator;
        const deadline = wire.Deadline.afterMilliseconds(3000);
        try (wire.Stream{ .fd = self.fd, .deadline = deadline }).wait(std.posix.POLL.IN);
        const fd = try platform.posix.accept(self.fd, null, null, std.posix.SOCK.CLOEXEC);
        defer platform.posix.close(fd);
        const socket = wire.Stream{ .fd = fd, .deadline = deadline };
        var hello: [4096]u8 = undefined;
        try readExactly(socket, hello[0..5]);
        const length = std.mem.readInt(u16, hello[3..5], .big);
        if (length > hello.len - 5) return error.InvalidClientHello;
        try readExactly(socket, hello[5..][0..length]);
        var complete = false;
        var server = try session_runtime.acceptServerHandshake(std.testing.io, alloc, fd, hello[0 .. 5 + length], self.cert, self.private_key, .{
            .require_client_cert = true,
            .trust_ca_pem = self.ca,
            .expected_identity = peer_identity.proxy_identity,
            .now_unix = self.now,
        }, &complete);
        defer server.deinit(alloc);
        self.accepted = true;
        var session = client_session.ClientSession{ .fd = fd, .alloc = alloc, .client_app = server.app_keys.server, .server_app = server.app_keys.client, .deadline = deadline };
        defer session.deinit();
        const request = try alloc.alloc(u8, self.request.len);
        defer alloc.free(request);
        try readExactly(&session, request);
        try std.testing.expectEqualStrings(self.request, request);
        self.saw_request = true;
        // split an h2 frame header between distinct encrypted records.
        _ = try session.write(self.response[0..7]);
        _ = try session.write(self.response[7..]);
    }
};
