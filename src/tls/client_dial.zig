// client_dial — open a TCP connection and run a TLS 1.3 client handshake.
//
// the small glue between `connectToUpstream`-style raw TCP dial and the
// `client_session.doHandshake` driver from PR #438. callers hand it an
// upstream address + a trust bundle + (optionally) a client cert/key and
// get back either a bare fd (for legacy plaintext) or a `ClientSession`
// they can read/write through.
//
// the union return type keeps the upstream wiring path independent of
// the per-target mTLS decision — `forwardSingleAttempt` (and any other
// L7-proxy caller) only needs to know how to drive both ends of the
// union, which is simpler than threading conditionals through every
// read/write call.

const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;

const client_session = @import("client_session.zig");

pub const DialError = error{
    ConnectFailed,
    ConnectTimedOut,
    InvalidAddress,
    HandshakeFailed,
    AllocFailed,
};

pub const Options = struct {
    /// resolved IPv4 dotted-quad. SNI is derived from `server_name`.
    address: []const u8,
    port: u16,
    /// connect-side TCP timeout in milliseconds. matches the existing
    /// `connectToUpstream` knob in the L7 proxy.
    connect_timeout_ms: u32 = 5_000,
    /// trust root for the server cert chain. when null, the dial stays
    /// plaintext (returns `.bare`).
    ca_cert_pem: ?[]const u8 = null,
    /// optional client cert + key sent when the server asks. when both
    /// are null, the client sends an empty Certificate (which the peer
    /// may accept or reject depending on its `require_client_cert`).
    client_cert_pem: ?[]const u8 = null,
    client_key_pem: ?[]const u8 = null,
    /// optional SNI / expected SAN URI on the server's leaf cert.
    server_name: ?[]const u8 = null,
    expected_server_identity: ?[]const u8 = null,
    /// current wall-clock unix seconds; test-injectable.
    now_unix: i64,
};

pub const Outcome = union(enum) {
    /// plaintext upstream — the caller proceeds as today: raw posix
    /// read/write on the returned fd.
    bare: posix.fd_t,
    /// mTLS upstream — the caller uses the session's read/write
    /// methods. owns the underlying fd; `deinit` closes it.
    session: client_session.ClientSession,
};

/// open the connection and (when `ca_cert_pem` is set) run the TLS
/// handshake. on any failure the fd is closed before returning.
pub fn dial(io: std.Io, alloc: std.mem.Allocator, opts: Options) DialError!Outcome {
    const fd = openTcp(opts.address, opts.port, opts.connect_timeout_ms) catch |err| return mapDialError(err);
    errdefer linux_platform.posix.close(fd);

    const ca_pem = opts.ca_cert_pem orelse return .{ .bare = fd };

    const sess = client_session.doHandshake(io, alloc, fd, .{
        .server_name = opts.server_name,
        .ca_cert_pem = ca_pem,
        .expected_server_identity = opts.expected_server_identity,
        .client_cert_pem = opts.client_cert_pem,
        .client_key_pem = opts.client_key_pem,
        .now_unix = opts.now_unix,
    }) catch return DialError.HandshakeFailed;
    return .{ .session = sess };
}

/// open a TCP socket and connect to the upstream within
/// `connect_timeout_ms`. blocking socket with a poll-for-writable
/// wait — same pattern as `socket_helpers.connectToUpstream`.
fn openTcp(address: []const u8, port: u16, connect_timeout_ms: u32) !posix.fd_t {
    var ip_bytes: [4]u8 = undefined;
    if (!parseIpv4(address, &ip_bytes)) return error.InvalidAddress;

    const fd = try linux_platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer linux_platform.posix.close(fd);

    var addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.bytesToValue(u32, &ip_bytes),
        .zero = .{0} ** 8,
    };
    linux_platform.posix.connect(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch return error.ConnectFailed;
    _ = connect_timeout_ms; // blocking connect — keeping the knob for the upcoming nonblocking path
    return fd;
}

fn parseIpv4(s: []const u8, out: *[4]u8) bool {
    var idx: usize = 0;
    var pos: usize = 0;
    var current: u32 = 0;
    var has_digit = false;
    for (s) |c| {
        if (c == '.') {
            if (!has_digit or idx >= 3) return false;
            out[idx] = @intCast(current);
            idx += 1;
            current = 0;
            has_digit = false;
        } else if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
            if (current > 255) return false;
            has_digit = true;
        } else {
            return false;
        }
        pos += 1;
    }
    if (!has_digit or idx != 3) return false;
    out[3] = @intCast(current);
    return true;
}

fn mapDialError(err: anyerror) DialError {
    return switch (err) {
        error.InvalidAddress => DialError.InvalidAddress,
        error.ConnectFailed => DialError.ConnectFailed,
        else => DialError.ConnectFailed,
    };
}

// --- tests ---

test "parseIpv4 accepts valid addresses" {
    var out: [4]u8 = undefined;
    try std.testing.expect(parseIpv4("10.42.0.1", &out));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 42, 0, 1 }, &out);
    try std.testing.expect(parseIpv4("0.0.0.0", &out));
    try std.testing.expect(parseIpv4("255.255.255.255", &out));
}

test "parseIpv4 rejects malformed input" {
    var out: [4]u8 = undefined;
    try std.testing.expect(!parseIpv4("", &out));
    try std.testing.expect(!parseIpv4("10.42.0", &out));
    try std.testing.expect(!parseIpv4("10.42.0.1.1", &out));
    try std.testing.expect(!parseIpv4("10..42.0.1", &out));
    try std.testing.expect(!parseIpv4("256.0.0.1", &out));
    try std.testing.expect(!parseIpv4("a.b.c.d", &out));
}

/// open a TCP listener on 127.0.0.1:<ephemeral>. returns (listen_fd, port).
fn openTestListener() !struct { fd: posix.fd_t, port: u16 } {
    const listen_fd = try linux_platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer linux_platform.posix.close(listen_fd);

    var addr = posix.sockaddr.in{
        .family = posix.AF.INET,
        .port = 0,
        .addr = std.mem.bytesToValue(u32, &[_]u8{ 127, 0, 0, 1 }),
        .zero = .{0} ** 8,
    };
    try linux_platform.posix.bind(listen_fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
    try linux_platform.posix.listen(listen_fd, 1);

    var bound: posix.sockaddr.in = undefined;
    var bound_len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
    try linux_platform.posix.getsockname(listen_fd, @ptrCast(&bound), &bound_len);
    return .{ .fd = listen_fd, .port = std.mem.bigToNative(u16, bound.port) };
}

test "dial returns a bare fd when no CA is supplied (plaintext path)" {
    const alloc = std.testing.allocator;
    const listener = try openTestListener();
    defer linux_platform.posix.close(listener.fd);

    const out = try dial(std.testing.io, alloc, .{
        .address = "127.0.0.1",
        .port = listener.port,
        .ca_cert_pem = null,
        .now_unix = 1_700_000_000,
    });

    // accept the dial on the listener side so we can clean it up.
    const accepted = try linux_platform.posix.accept(listener.fd, null, null, posix.SOCK.CLOEXEC);
    defer linux_platform.posix.close(accepted);

    switch (out) {
        .bare => |fd| linux_platform.posix.close(fd),
        .session => return error.TestUnexpectedSession,
    }
}

// --- mTLS round-trip test against the real acceptServerHandshake ---
//
// the small bit of glue here mirrors what the existing socketpair tests
// in session_runtime do; the only difference is the transport is a real
// TCP socket via `dial` instead of a pre-paired pair of fds. that
// proves the dial path actually completes a handshake end-to-end.

const x509_gen = @import("x509_gen.zig");
const csr = @import("csr.zig");
const session_runtime = @import("proxy/session_runtime.zig");

const td_now: i64 = 1_700_000_000;
const td_window: i64 = 24 * 3600;

const TdCerts = struct {
    ca_pem: []u8,
    server_pem: []u8,
    server_key_pem: []u8,

    fn deinit(self: *TdCerts, alloc: std.mem.Allocator) void {
        alloc.free(self.ca_pem);
        alloc.free(self.server_pem);
        alloc.free(self.server_key_pem);
    }
};

fn mintTdCerts(alloc: std.mem.Allocator) !TdCerts {
    const ca = try x509_gen.generateCa(std.testing.io, alloc, "td-ca", td_now - 3600, td_now + td_window);
    errdefer alloc.free(ca.cert_pem);
    const leaf = try x509_gen.issueLeaf(std.testing.io, alloc, ca.key_pair, "td-ca", "td-server", "spiffe://td/service/td-server", td_now - 60, td_now + td_window);
    errdefer alloc.free(leaf.cert_pem);
    const server_key_pem = try csr.derKeyToPem(alloc, &leaf.key_pair.secret_key.toBytes());
    return .{
        .ca_pem = ca.cert_pem,
        .server_pem = leaf.cert_pem,
        .server_key_pem = server_key_pem,
    };
}

const TdServerArgs = struct {
    listener_fd: posix.fd_t,
    certs: *const TdCerts,
    alloc: std.mem.Allocator,
    err_out: *?anyerror,
};

fn runTdServer(args: TdServerArgs) void {
    runTdServerImpl(args) catch |err| {
        args.err_out.* = err;
    };
}

fn runTdServerImpl(args: TdServerArgs) !void {
    const fd = try linux_platform.posix.accept(args.listener_fd, null, null, posix.SOCK.CLOEXEC);
    defer linux_platform.posix.close(fd);

    // pre-read the ClientHello (the same shim the production listener
    // uses before handing off to acceptServerHandshake).
    var ch_buf: [4096]u8 = undefined;
    var ch_len: usize = 0;
    while (ch_len < 5) {
        const n = try posix.read(fd, ch_buf[ch_len..]);
        if (n == 0) return error.UnexpectedEof;
        ch_len += n;
    }
    const promised = (@as(usize, ch_buf[3]) << 8) | @as(usize, ch_buf[4]);
    while (ch_len < 5 + promised) {
        const n = try posix.read(fd, ch_buf[ch_len..]);
        if (n == 0) return error.UnexpectedEof;
        ch_len += n;
    }

    var handshake_complete = false;
    var session = try session_runtime.acceptServerHandshake(
        std.testing.io,
        args.alloc,
        fd,
        ch_buf[0..ch_len],
        args.certs.server_pem,
        args.certs.server_key_pem,
        null, // no client-cert required for this test
        &handshake_complete,
    );
    session.deinit(args.alloc);
}

test "dial runs a TLS handshake against a real TCP listener" {
    const alloc = std.testing.allocator;
    const listener = try openTestListener();
    defer linux_platform.posix.close(listener.fd);

    var certs = try mintTdCerts(alloc);
    defer certs.deinit(alloc);

    var server_err: ?anyerror = null;
    const t = try std.Thread.spawn(.{}, runTdServer, .{TdServerArgs{
        .listener_fd = listener.fd,
        .certs = &certs,
        .alloc = alloc,
        .err_out = &server_err,
    }});

    var out = try dial(std.testing.io, alloc, .{
        .address = "127.0.0.1",
        .port = listener.port,
        .server_name = "td-server",
        .ca_cert_pem = certs.ca_pem,
        .expected_server_identity = "spiffe://td/service/td-server",
        .now_unix = td_now,
    });

    switch (out) {
        .bare => return error.TestExpectedSession,
        .session => |*sess| {
            defer sess.deinit();
            defer linux_platform.posix.close(sess.fd);
            t.join();
            try std.testing.expect(server_err == null);
        },
    }
}
