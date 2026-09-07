const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const log = @import("../../lib/log.zig");
const http2_request = @import("../../network/proxy/http2_request.zig");
const backend_mod = @import("../backend.zig");
const handshake = @import("../handshake.zig");
const message_build = @import("../handshake/message_build.zig");
const message_parse = @import("../handshake/message_parse.zig");
const pem = @import("../pem.zig");
const record = @import("../record.zig");
const record_transport = @import("../record_transport.zig");
const transport = @import("../../lib/socket_stream.zig");
const socket_support = @import("socket_support.zig");
const x509_verify = @import("../x509_verify.zig");
const mtls_metrics = @import("../mtls_metrics.zig");

const X25519 = std.crypto.dh.X25519;
const Sha384 = std.crypto.hash.sha2.Sha384;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const hash_len = Sha384.digest_length;

/// upper bound on a client's mTLS auth flight (Certificate + CertificateVerify
/// + Finished). real client cert chains are a few KB; 64 KB is generous.
/// prevents a malicious client from streaming handshake records without bound.
const max_client_auth_bytes: usize = 64 * 1024;

/// optional mTLS configuration for the server-side handshake. when set,
/// the server emits a CertificateRequest, requires (or merely inspects)
/// a client cert in response, and verifies it against `trust_ca_pem`.
pub const MtlsOpts = struct {
    /// when true an empty/absent client Certificate fails the handshake.
    /// when false the verified peer identity is `null` after handshake
    /// and the caller may decide what to do (PR 5 wires the "warn" mode).
    require_client_cert: bool,
    /// PEM bytes of the cluster CA.
    trust_ca_pem: []const u8,
    /// optional SAN URI to require on the client cert.
    expected_identity: ?[]const u8 = null,
    /// current unix seconds (test-injectable; production passes wall-clock).
    now_unix: i64,
};

/// what the handshake produced. owned by the caller; `deinit` frees the
/// optional peer-identity buffer.
pub const ServerSession = struct {
    selected_alpn: ?[]const u8,
    app_keys: handshake.ApplicationKeys,
    /// duplicate of the verified client SAN URI when mTLS succeeded with
    /// a valid client cert; null otherwise. allocator-owned.
    peer_identity: ?[]u8 = null,

    pub fn deinit(self: *ServerSession, alloc: std.mem.Allocator) void {
        if (self.peer_identity) |p| alloc.free(p);
    }
};

/// run the TLS 1.3 server handshake on `client_fd`. when `mtls_opts` is
/// non-null, the server emits CertificateRequest and verifies the client's
/// cert before sending its own Finished response — note that's a
/// per-side ordering quirk: TLS 1.3 has the server send all its
/// handshake messages and Finished first, then expects the client to
/// send Certificate + CertificateVerify + Finished. so client-cert
/// verify happens *after* the server's Finished, just like in regular
/// TLS 1.3 client auth.
pub fn acceptServerHandshake(
    io: std.Io,
    alloc: std.mem.Allocator,
    client_fd: posix.fd_t,
    client_hello: []const u8,
    cert_pem: []u8,
    key_pem: []u8,
    mtls_opts: ?MtlsOpts,
    handshake_complete: *bool,
) !ServerSession {
    const wire = transport.Stream{ .fd = client_fd, .deadline = transport.Deadline.afterMilliseconds(10_000) };
    // metrics are tracked only for mtls handshakes — the regular TLS
    // termination path has its own throughput surface elsewhere.
    errdefer if (mtls_opts != null) mtls_metrics.record(.server, .failed);
    if (client_hello.len < 9) return error.InvalidClientHello;
    const rec_len = (@as(usize, client_hello[3]) << 8) | @as(usize, client_hello[4]);
    if (client_hello.len < 5 + rec_len) return error.InvalidClientHello;
    const hs_body = client_hello[9 .. 5 + rec_len];

    const hello_info = handshake.parseClientHelloFields(hs_body) catch return error.InvalidClientHello;

    if (!hello_info.has_aes_256_gcm) return error.UnsupportedCipher;
    if (!hello_info.supported_versions_has_tls13) return error.UnsupportedVersion;
    const client_x25519_key = hello_info.x25519_key_share orelse return error.MissingKeyShare;
    const selected_alpn: ?[]const u8 = if (hello_info.offers_h2_alpn)
        "h2"
    else if (hello_info.offers_http11_alpn)
        "http/1.1"
    else
        null;

    const server_kp = X25519.KeyPair.generate(io);
    const shared_secret = X25519.scalarmult(server_kp.secret_key, client_x25519_key) catch
        return error.KeyExchangeFailed;

    var transcript = Sha384.init(.{});
    transcript.update(client_hello[5 .. 5 + rec_len]);

    var server_random: [32]u8 = undefined;
    linux_platform.randomBytes(&server_random);

    var sh_buf: [512]u8 = undefined;
    const sh_len = handshake.buildServerHello(
        &sh_buf,
        hello_info.client_random,
        server_random,
        hello_info.session_id,
        server_kp.public_key,
    ) catch return error.HandshakeFailed;

    var sh_record: [5 + 512]u8 = undefined;
    record.writeHeader(&sh_record, .handshake, @intCast(sh_len)) catch return error.HandshakeFailed;
    @memcpy(sh_record[5 .. 5 + sh_len], sh_buf[0..sh_len]);
    try wire.writeAll(sh_record[0 .. 5 + sh_len]);
    transcript.update(sh_buf[0..sh_len]);

    const ccs = [_]u8{
        0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
    };
    try wire.writeAll(&ccs);

    var transcript_hash: [hash_len]u8 = undefined;
    transcript_hash = transcript.peek();

    const early = handshake.deriveEarlySecret();
    const hs_secret = handshake.deriveHandshakeSecret(early, shared_secret);
    const hs_keys = handshake.deriveHandshakeTrafficSecrets(hs_secret, transcript_hash);

    const server_hs_traffic = handshake.deriveTrafficKeys(hs_keys.server_handshake_traffic_secret);
    const client_hs_traffic = handshake.deriveTrafficKeys(hs_keys.client_handshake_traffic_secret);

    var server_seq: u64 = 0;

    var ee_buf: [64]u8 = undefined;
    const ee_len = handshake.buildEncryptedExtensions(&ee_buf, selected_alpn) catch return error.HandshakeFailed;
    transcript.update(ee_buf[0..ee_len]);
    try sendEncryptedHandshake(wire, ee_buf[0..ee_len], server_hs_traffic, &server_seq);

    if (mtls_opts != null) {
        var cr_buf: [64]u8 = undefined;
        const cr_len = message_build.buildCertificateRequest(&cr_buf) catch return error.HandshakeFailed;
        transcript.update(cr_buf[0..cr_len]);
        try sendEncryptedHandshake(wire, cr_buf[0..cr_len], server_hs_traffic, &server_seq);
    }

    const cert_der = pem.parseCertDer(alloc, cert_pem) catch return error.CertParseFailed;
    defer alloc.free(cert_der);

    var cert_buf: [8192]u8 = undefined;
    const cert_len = handshake.buildCertificate(&cert_buf, cert_der) catch return error.HandshakeFailed;
    transcript.update(cert_buf[0..cert_len]);
    try sendEncryptedHandshake(wire, cert_buf[0..cert_len], server_hs_traffic, &server_seq);

    const private_key = pem.parseEcPrivateKey(key_pem) catch return error.KeyParseFailed;
    const cv_transcript_hash = transcript.peek();

    var cv_buf: [512]u8 = undefined;
    const cv_len = handshake.buildCertificateVerify(&cv_buf, .server, cv_transcript_hash, private_key) catch
        return error.HandshakeFailed;
    transcript.update(cv_buf[0..cv_len]);
    try sendEncryptedHandshake(wire, cv_buf[0..cv_len], server_hs_traffic, &server_seq);

    const fin_transcript_hash = transcript.peek();
    const verify_data = handshake.computeFinished(hs_keys.server_handshake_traffic_secret, fin_transcript_hash);

    var fin_buf: [128]u8 = undefined;
    const fin_len = handshake.buildFinished(&fin_buf, verify_data) catch return error.HandshakeFailed;
    transcript.update(fin_buf[0..fin_len]);
    try sendEncryptedHandshake(wire, fin_buf[0..fin_len], server_hs_traffic, &server_seq);

    // Application keys use the transcript through server Finished only.
    const app_transcript_hash = transcript.peek();

    var client_seq: u64 = 0;
    var peer_identity_out: ?[]u8 = null;
    errdefer if (peer_identity_out) |p| alloc.free(p);

    try acceptClientAuthAndFinished(alloc, wire, client_hs_traffic, &client_seq, &transcript, hs_keys, mtls_opts, &peer_identity_out);

    const master = handshake.deriveMasterSecret(hs_keys.handshake_secret);
    const app_keys = handshake.deriveApplicationSecrets(master, app_transcript_hash);

    handshake_complete.* = true;
    if (mtls_opts != null) mtls_metrics.record(.server, .ok);

    return .{
        .selected_alpn = selected_alpn,
        .app_keys = app_keys,
        .peer_identity = peer_identity_out,
    };
}

/// run the server handshake, then forward bytes between the encrypted
/// client and the plaintext backend until either side closes. preserves
/// the existing non-mTLS code path — no `MtlsOpts` are threaded through
/// here yet (PR 5 wires the listener-level decision).
pub fn handleTlsSession(
    io: std.Io,
    client_fd: posix.fd_t,
    client_hello: []const u8,
    cert_pem: []u8,
    key_pem: []u8,
    backend_info: backend_mod.Backend,
    handshake_complete: *bool,
    mtls_opts: ?MtlsOpts,
) !void {
    var session = try acceptServerHandshake(
        io,
        std.heap.page_allocator,
        client_fd,
        client_hello,
        cert_pem,
        key_pem,
        mtls_opts,
        handshake_complete,
    );
    defer session.deinit(std.heap.page_allocator);

    if (session.peer_identity) |peer| {
        log.info("tls: mtls peer accepted: {s}", .{peer});
    }

    const selected_alpn = session.selected_alpn;
    const app_keys = session.app_keys;

    const backend_fd = socket_support.connectToBackend(backend_info) catch return error.BackendConnectFailed;
    defer linux_platform.posix.close(backend_fd);

    var client_app_seq: u64 = 0;
    var server_app_seq: u64 = 0;
    var initial = RequestBuffer.init();
    defer initial.deinit();
    var initial_request_forwarded = false;
    const is_h2 = selected_alpn != null and std.mem.eql(u8, selected_alpn.?, "h2");
    var h2_rewrite_state = http2_request.StreamRewriteState{};

    var poll_fds = [_]posix.pollfd{
        .{ .fd = client_fd, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = backend_fd, .events = posix.POLL.IN, .revents = 0 },
    };

    while (true) {
        const pending_request = !initial_request_forwarded or initial.bytes.items.len > 0;
        const deadline = if (pending_request) initial.deadline else transport.Deadline.afterMilliseconds(30_000);
        const timeout = deadline.remaining() catch break;
        const poll_result = posix.poll(&poll_fds, timeout) catch break;
        if (poll_result == 0) break;

        if (poll_fds[0].revents & posix.POLL.IN != 0) {
            var buffer: record_transport.Buffer = undefined;
            const decrypted = record_transport.readEncrypted(.{ .fd = client_fd, .deadline = deadline }, &buffer, app_keys.client, &client_app_seq, false) catch break;
            if (decrypted.content_type == .alert) break;
            if (decrypted.content_type != .application_data) return error.UnexpectedRecord;
            const backend_wire = transport.Stream{ .fd = backend_fd, .deadline = deadline };

            if (decrypted.plaintext.len > 0) {
                if (is_h2) {
                    if (initial_request_forwarded and initial.bytes.items.len == 0) initial.deadline = transport.Deadline.afterMilliseconds(request_timeout_ms);
                    try initial.append(decrypted.plaintext);
                    while (try http2_request.rewriteClientStreamChunk(std.heap.page_allocator, initial.bytes.items, &h2_rewrite_state, "https")) |chunk| {
                        defer chunk.deinit(std.heap.page_allocator);
                        try backend_wire.writeAll(chunk.bytes);
                        try initial.bytes.replaceRange(std.heap.page_allocator, 0, chunk.consumed, "");
                        initial_request_forwarded = true;
                    }
                } else if (!initial_request_forwarded) {
                    try initial.append(decrypted.plaintext);
                    const first_request = prepareInitialRequest(std.heap.page_allocator, selected_alpn, initial.bytes.items) catch |err| switch (err) {
                        error.IncompleteRequest => null,
                        else => return err,
                    };
                    if (first_request) |request| {
                        defer std.heap.page_allocator.free(request);
                        try backend_wire.writeAll(request);
                        initial_request_forwarded = true;
                        initial.bytes.clearAndFree(std.heap.page_allocator);
                    }
                } else {
                    try backend_wire.writeAll(decrypted.plaintext);
                }
            }
        }

        if (poll_fds[1].revents & posix.POLL.IN != 0) {
            var plaintext: [record.max_record_size]u8 = undefined;
            const n = (transport.Stream{ .fd = backend_fd, .deadline = deadline }).read(&plaintext) catch break;
            if (n == 0) break;
            try record_transport.write(.{ .fd = client_fd, .deadline = deadline }, app_keys.server, &server_app_seq, .application_data, plaintext[0..n]);
        }
        // Drain readable bytes before honoring a simultaneous half-close.
        if (poll_fds[0].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) break;
        if (poll_fds[1].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) break;
    }

    sendEncryptedCloseNotify(client_fd, app_keys.server, &server_app_seq);
}

// This also bounds incomplete HTTP/2 frame/header sequences. With the listener's
// connection cap, retained request input has a finite process-wide upper bound.
const max_request_bytes = 64 * 1024;
const request_timeout_ms = 10_000;

const RequestBuffer = struct {
    bytes: std.ArrayList(u8) = .empty,
    deadline: transport.Deadline,

    fn init() RequestBuffer {
        return .{ .deadline = transport.Deadline.afterMilliseconds(request_timeout_ms) };
    }

    fn append(self: *RequestBuffer, bytes: []const u8) !void {
        _ = try self.deadline.remaining();
        if (bytes.len > max_request_bytes - self.bytes.items.len) return error.RequestTooLarge;
        try self.bytes.appendSlice(std.heap.page_allocator, bytes);
    }

    fn deinit(self: *RequestBuffer) void {
        self.bytes.deinit(std.heap.page_allocator);
    }
};

const InitialRequestError = error{IncompleteRequest} || http2_request.ParseError;

fn prepareInitialRequest(alloc: std.mem.Allocator, selected_alpn: ?[]const u8, plaintext: []const u8) InitialRequestError!?[]u8 {
    if (selected_alpn != null and std.mem.eql(u8, selected_alpn.?, "h2")) {
        return try http2_request.rewriteClientConnectionPreface(alloc, plaintext, null, null, "https");
    }

    if (std.mem.indexOf(u8, plaintext, "\r\n\r\n") == null) return error.IncompleteRequest;
    return try injectForwardedProtoHttp1(alloc, plaintext, "https");
}

fn injectForwardedProtoHttp1(alloc: std.mem.Allocator, request: []const u8, proto: []const u8) ![]u8 {
    const header_end = std.mem.indexOf(u8, request, "\r\n\r\n") orelse return error.IncompleteRequest;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);

    var line_start: usize = 0;
    while (line_start < header_end) {
        const line_end = std.mem.indexOfPos(u8, request, line_start, "\r\n") orelse header_end;
        const line = request[line_start..line_end];
        if (line.len > 0 and !std.ascii.startsWithIgnoreCase(line, "X-Forwarded-Proto:")) {
            try out.appendSlice(alloc, line);
            try out.appendSlice(alloc, "\r\n");
        }
        line_start = if (line_end + 2 <= header_end) line_end + 2 else header_end;
    }

    try out.appendSlice(alloc, "X-Forwarded-Proto: ");
    try out.appendSlice(alloc, proto);
    try out.appendSlice(alloc, "\r\n\r\n");
    try out.appendSlice(alloc, request[header_end + 4 ..]);
    return out.toOwnedSlice(alloc);
}

/// mTLS path: read the client's Certificate, optionally CertificateVerify,
/// then Finished. messages may arrive over one or more encrypted records;
/// accumulate plaintext in `pending` and dispatch by handshake message
/// type. on a verified non-empty client cert, dup the SAN URI into
/// `peer_identity_out` (caller frees).
fn acceptClientAuthAndFinished(
    alloc: std.mem.Allocator,
    wire: transport.Stream,
    keys: handshake.TrafficKeys,
    client_seq: *u64,
    transcript: *Sha384,
    hs_keys: handshake.HandshakeKeys,
    opts: ?MtlsOpts,
    peer_identity_out: *?[]u8,
) !void {
    var pending: std.ArrayList(u8) = .empty;
    defer pending.deinit(alloc);

    var client_cert_der: ?[]u8 = null;
    defer if (client_cert_der) |d| alloc.free(d);
    var client_cert_pem: ?[]u8 = null;
    defer if (client_cert_pem) |p| alloc.free(p);

    var got_cert_verify_sig: ?[]u8 = null;
    defer if (got_cert_verify_sig) |s| alloc.free(s);
    var transcript_hash_at_cv: ?[hash_len]u8 = null;

    var saw_finished = false;
    var saw_certificate = false;
    var total_client_auth_bytes: usize = 0;

    while (!saw_finished) {
        const plaintext = try readOneEncryptedHandshakeRecordAlloc(alloc, wire, keys, client_seq);
        defer alloc.free(plaintext);
        // bound the client's auth flight (Certificate + CertVerify + Finished):
        // a malicious client could otherwise stream handshake records forever.
        total_client_auth_bytes += plaintext.len;
        if (total_client_auth_bytes > max_client_auth_bytes) return error.InvalidClientFinished;
        try pending.appendSlice(alloc, plaintext);

        var pos: usize = 0;
        while (true) {
            const opt_msg = message_parse.nextMessage(pending.items, &pos) catch break;
            const msg = opt_msg orelse break;

            switch (msg.msg_type) {
                @intFromEnum(message_parse.HandshakeType.certificate) => {
                    if (opts == null or saw_certificate) return error.InvalidClientFinished;
                    saw_certificate = true;
                    const der = message_parse.parseCertificateMessage(msg.body) catch return error.InvalidClientFinished;
                    if (der.len > 0) {
                        client_cert_der = try alloc.dupe(u8, der);
                        client_cert_pem = try derToPemLocal(alloc, der);
                    }
                    transcript.update(msg.raw);
                },
                @intFromEnum(message_parse.HandshakeType.certificate_verify) => {
                    if (client_cert_der == null or got_cert_verify_sig != null) return error.InvalidClientFinished;
                    const cv = message_parse.parseCertificateVerify(msg.body) catch return error.InvalidClientFinished;
                    if (cv.algorithm != 0x0403) return error.InvalidClientFinished;
                    transcript_hash_at_cv = transcript.peek();
                    got_cert_verify_sig = try alloc.dupe(u8, cv.signature_der);
                    transcript.update(msg.raw);
                },
                @intFromEnum(message_parse.HandshakeType.finished) => {
                    const fin = message_parse.parseFinished(msg.body) catch return error.InvalidClientFinished;
                    const expected = handshake.computeFinished(hs_keys.client_handshake_traffic_secret, transcript.peek());
                    if (!std.mem.eql(u8, fin.verify_data, &expected)) return error.FinishedVerifyFailed;
                    transcript.update(msg.raw);
                    saw_finished = true;
                    break;
                },
                else => return error.InvalidClientFinished,
            }
        }

        if (pos > 0) {
            const remaining = pending.items.len - pos;
            std.mem.copyForwards(u8, pending.items[0..remaining], pending.items[pos..]);
            pending.shrinkRetainingCapacity(remaining);
        }
    }

    if (pending.items.len != 0) return error.InvalidClientFinished;

    // verify the client cert (if any) before declaring the handshake done.
    if (client_cert_pem) |cpem| {
        x509_verify.verifyLeafAgainstCa(alloc, cpem, opts.?.trust_ca_pem, opts.?.expected_identity, opts.?.now_unix) catch return error.UntrustedClientCert;

        // verify the client's CertificateVerify signature against the
        // cert's public key — the spec-required peer-of-keypair check.
        const sig = got_cert_verify_sig orelse return error.InvalidClientFinished;
        const cv_hash = transcript_hash_at_cv orelse return error.InvalidClientFinished;
        try verifyClientCertVerify(client_cert_der.?, sig, cv_hash);

        // surface the identity (use the SAN URI if present, fall back to
        // subject CN) so callers can audit / authorize.
        var san_buf: [x509_verify.max_san_uris][]const u8 = undefined;
        const parsed = x509_verify.parseDer(client_cert_der.?, &san_buf) catch return error.InvalidClientFinished;
        if (parsed.san_uris.len > 0) {
            peer_identity_out.* = try alloc.dupe(u8, parsed.san_uris[0]);
        } else {
            peer_identity_out.* = try alloc.dupe(u8, parsed.subject_cn);
        }
    } else if (opts != null and opts.?.require_client_cert) {
        return error.MissingClientCert;
    }
}

/// read one encrypted handshake record off the wire, decrypt, return the
/// plaintext. helper for the mTLS client-auth read loop.
fn readOneEncryptedHandshakeRecordAlloc(
    alloc: std.mem.Allocator,
    wire: transport.Stream,
    keys: handshake.TrafficKeys,
    seq: *u64,
) ![]u8 {
    var buffer: record_transport.Buffer = undefined;
    const dec = try record_transport.readEncrypted(wire, &buffer, keys, seq, true);
    if (dec.content_type != .handshake) return error.InvalidClientFinished;
    return try alloc.dupe(u8, dec.plaintext);
}

fn verifyClientCertVerify(client_cert_der: []const u8, sig_der: []const u8, transcript_hash: [hash_len]u8) !void {
    var san_buf: [x509_verify.max_san_uris][]const u8 = undefined;
    const parsed = x509_verify.parseDer(client_cert_der, &san_buf) catch return error.UntrustedClientCert;
    if (parsed.public_key_point.len != 65) return error.UntrustedClientCert;
    var sec1: [65]u8 = undefined;
    @memcpy(&sec1, parsed.public_key_point[0..65]);
    const pub_key = EcdsaP256.PublicKey.fromSec1(&sec1) catch return error.UntrustedClientCert;

    var signed_content: [64 + 33 + 1 + hash_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &signed_content);
    @memset(signed_content[0..64], 0x20);
    const ctx = "TLS 1.3, client CertificateVerify";
    @memcpy(signed_content[64 .. 64 + ctx.len], ctx);
    signed_content[64 + ctx.len] = 0x00;
    @memcpy(signed_content[64 + ctx.len + 1 ..], &transcript_hash);

    var sig_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    if (sig_der.len > sig_buf.len) return error.UntrustedClientCert;
    @memcpy(sig_buf[0..sig_der.len], sig_der);
    const sig = EcdsaP256.Signature.fromDer(sig_buf[0..sig_der.len]) catch return error.UntrustedClientCert;
    sig.verify(&signed_content, pub_key) catch return error.UntrustedClientCert;
}

fn derToPemLocal(alloc: std.mem.Allocator, der: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.appendSlice(alloc, "-----BEGIN CERTIFICATE-----\n");
    const enc_size = std.base64.standard.Encoder.calcSize(der.len);
    const tmp = try alloc.alloc(u8, enc_size);
    defer alloc.free(tmp);
    _ = std.base64.standard.Encoder.encode(tmp, der);
    try out.appendSlice(alloc, tmp);
    try out.appendSlice(alloc, "\n-----END CERTIFICATE-----\n");
    return out.toOwnedSlice(alloc);
}

pub fn sendEncryptedHandshake(wire: transport.Stream, msg: []const u8, keys: handshake.TrafficKeys, seq: *u64) !void {
    try record_transport.write(wire, keys, seq, .handshake, msg);
}

fn sendEncryptedCloseNotify(fd: posix.fd_t, keys: handshake.TrafficKeys, seq: *u64) void {
    record_transport.write(.{ .fd = fd, .deadline = transport.Deadline.afterMilliseconds(1000) }, keys, seq, .alert, &.{ 0x01, 0x00 }) catch {};
}

test "injectForwardedProtoHttp1 rewrites the first request headers" {
    const request =
        "GET / HTTP/1.1\r\n" ++
        "Host: demo.local\r\n" ++
        "X-Forwarded-Proto: http\r\n" ++
        "\r\n";
    const rewritten = try injectForwardedProtoHttp1(std.testing.allocator, request, "https");
    defer std.testing.allocator.free(rewritten);

    try std.testing.expect(std.mem.indexOf(u8, rewritten, "X-Forwarded-Proto: https\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, rewritten, "X-Forwarded-Proto: http\r\n") == null);
}

// --- mTLS round-trip tests ---
//
// these spin up a unix socketpair, run `acceptServerHandshake` with
// `MtlsOpts` on one side and the client driver (`client_session`) on the
// other, and assert the negotiated peer identity is the client cert's
// SAN URI.

const x509_gen = @import("../x509_gen.zig");
const csr = @import("../csr.zig");
const client_session = @import("../client_session.zig");

const mtls_test_now: i64 = 1_700_000_000;
const mtls_test_window: i64 = 24 * 3600;

const MtlsCerts = struct {
    ca_pem: []u8,
    server_pem: []u8,
    server_key_pem: []u8,
    client_pem: []u8,
    client_key_pem: []u8,

    fn deinit(self: *MtlsCerts, alloc: std.mem.Allocator) void {
        alloc.free(self.ca_pem);
        alloc.free(self.server_pem);
        alloc.free(self.server_key_pem);
        alloc.free(self.client_pem);
        alloc.free(self.client_key_pem);
    }
};

fn mintMtlsCerts(alloc: std.mem.Allocator) !MtlsCerts {
    const ca = try x509_gen.generateCa(std.testing.io, alloc, "mtls-ca", mtls_test_now - 3600, mtls_test_now + mtls_test_window);
    errdefer alloc.free(ca.cert_pem);

    const server = try x509_gen.issueLeaf(std.testing.io, alloc, ca.key_pair, "mtls-ca", "server", "spiffe://yoq/service/server", mtls_test_now - 60, mtls_test_now + mtls_test_window);
    errdefer alloc.free(server.cert_pem);
    const server_key_pem = try csr.derKeyToPem(alloc, &server.key_pair.secret_key.toBytes());
    errdefer alloc.free(server_key_pem);

    const client = try x509_gen.issueLeaf(std.testing.io, alloc, ca.key_pair, "mtls-ca", "client", "spiffe://yoq/service/client", mtls_test_now - 60, mtls_test_now + mtls_test_window);
    errdefer alloc.free(client.cert_pem);
    const client_key_pem = try csr.derKeyToPem(alloc, &client.key_pair.secret_key.toBytes());

    return .{
        .ca_pem = ca.cert_pem,
        .server_pem = server.cert_pem,
        .server_key_pem = server_key_pem,
        .client_pem = client.cert_pem,
        .client_key_pem = client_key_pem,
    };
}

const MtlsServerThreadArgs = struct {
    fd: posix.fd_t,
    certs: *const MtlsCerts,
    require_client_cert: bool,
    peer_identity_out: *?[]u8,
    err_out: *?anyerror,
    alloc: std.mem.Allocator,
};

fn runMtlsServer(args: MtlsServerThreadArgs) void {
    runMtlsServerImpl(args) catch |err| {
        args.err_out.* = err;
    };
}

fn runMtlsServerImpl(args: MtlsServerThreadArgs) !void {
    // pre-read the ClientHello record off the wire so acceptServerHandshake
    // can consume it (matching the production listener convention).
    var ch_buf: [4096]u8 = undefined;
    var ch_len: usize = 0;
    while (ch_len < 5) {
        const n = try posix.read(args.fd, ch_buf[ch_len..]);
        if (n == 0) return error.UnexpectedEof;
        ch_len += n;
    }
    const promised = (@as(usize, ch_buf[3]) << 8) | @as(usize, ch_buf[4]);
    while (ch_len < 5 + promised) {
        const n = try posix.read(args.fd, ch_buf[ch_len..]);
        if (n == 0) return error.UnexpectedEof;
        ch_len += n;
    }

    var handshake_complete = false;
    var session = try acceptServerHandshake(
        std.testing.io,
        args.alloc,
        args.fd,
        ch_buf[0..ch_len],
        args.certs.server_pem,
        args.certs.server_key_pem,
        .{
            .require_client_cert = args.require_client_cert,
            .trust_ca_pem = args.certs.ca_pem,
            .now_unix = mtls_test_now,
        },
        &handshake_complete,
    );

    // hand the identity back to the test before deinit frees it.
    if (session.peer_identity) |p| {
        args.peer_identity_out.* = try args.alloc.dupe(u8, p);
    }
    session.deinit(args.alloc);
}

test "mTLS round-trip — valid client cert is accepted and identity surfaces" {
    const alloc = std.testing.allocator;

    var fds: [2]i32 = undefined;
    const rc = std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SkipZigTest;
    defer linux_platform.posix.close(fds[0]);
    defer linux_platform.posix.close(fds[1]);

    var certs = try mintMtlsCerts(alloc);
    defer certs.deinit(alloc);

    var peer_id: ?[]u8 = null;
    defer if (peer_id) |p| alloc.free(p);
    var server_err: ?anyerror = null;

    const args: MtlsServerThreadArgs = .{
        .fd = fds[1],
        .certs = &certs,
        .require_client_cert = true,
        .peer_identity_out = &peer_id,
        .err_out = &server_err,
        .alloc = alloc,
    };
    const t = try std.Thread.spawn(.{}, runMtlsServer, .{args});

    var sess = try client_session.doHandshake(std.testing.io, alloc, fds[0], .{
        .ca_cert_pem = certs.ca_pem,
        .expected_server_identity = "spiffe://yoq/service/server",
        .client_cert_pem = certs.client_pem,
        .client_key_pem = certs.client_key_pem,
        .now_unix = mtls_test_now,
    });
    defer sess.deinit();

    t.join();
    try std.testing.expect(server_err == null);
    try std.testing.expect(peer_id != null);
    try std.testing.expectEqualStrings("spiffe://yoq/service/client", peer_id.?);
}

test "mTLS — require_client_cert rejects an empty client cert" {
    const alloc = std.testing.allocator;

    var fds: [2]i32 = undefined;
    const rc = std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SkipZigTest;
    defer linux_platform.posix.close(fds[0]);
    defer linux_platform.posix.close(fds[1]);

    var certs = try mintMtlsCerts(alloc);
    defer certs.deinit(alloc);

    var peer_id: ?[]u8 = null;
    defer if (peer_id) |p| alloc.free(p);
    var server_err: ?anyerror = null;

    const args: MtlsServerThreadArgs = .{
        .fd = fds[1],
        .certs = &certs,
        .require_client_cert = true,
        .peer_identity_out = &peer_id,
        .err_out = &server_err,
        .alloc = alloc,
    };
    const t = try std.Thread.spawn(.{}, runMtlsServer, .{args});

    // client doesn't pass client_cert_pem — the driver sends an empty
    // Certificate, the server rejects.
    const handshake_err = client_session.doHandshake(std.testing.io, alloc, fds[0], .{
        .ca_cert_pem = certs.ca_pem,
        .now_unix = mtls_test_now,
    });
    // the client doesn't see the rejection directly (server returns the
    // error after the client's Finished); the client typically reports
    // success or a later read failure. either is acceptable — we assert
    // on the server side instead.
    if (handshake_err) |*ok| {
        var ok_mut = ok.*;
        ok_mut.deinit();
    } else |_| {}

    _ = std.os.linux.shutdown(fds[0], 2); // SHUT_RDWR
    t.join();

    try std.testing.expect(peer_id == null);
    try std.testing.expect(server_err != null);
    try std.testing.expectEqual(@as(anyerror, error.MissingClientCert), server_err.?);
}

test "mTLS — warn mode accepts an empty client cert (no identity)" {
    const alloc = std.testing.allocator;

    var fds: [2]i32 = undefined;
    const rc = std.os.linux.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds);
    if (rc != 0) return error.SkipZigTest;
    defer linux_platform.posix.close(fds[0]);
    defer linux_platform.posix.close(fds[1]);

    var certs = try mintMtlsCerts(alloc);
    defer certs.deinit(alloc);

    var peer_id: ?[]u8 = null;
    defer if (peer_id) |p| alloc.free(p);
    var server_err: ?anyerror = null;

    const args: MtlsServerThreadArgs = .{
        .fd = fds[1],
        .certs = &certs,
        .require_client_cert = false, // warn mode
        .peer_identity_out = &peer_id,
        .err_out = &server_err,
        .alloc = alloc,
    };
    const t = try std.Thread.spawn(.{}, runMtlsServer, .{args});

    var sess = try client_session.doHandshake(std.testing.io, alloc, fds[0], .{
        .ca_cert_pem = certs.ca_pem,
        .now_unix = mtls_test_now,
    });
    defer sess.deinit();

    t.join();
    try std.testing.expect(server_err == null);
    try std.testing.expect(peer_id == null); // no identity surfaced
}

test "request buffering rejects oversized and expired incomplete headers" {
    var pending = RequestBuffer.init();
    defer pending.deinit();
    const chunk = [_]u8{'x'} ** 16384;
    for (0..4) |_| try pending.append(&chunk);
    try std.testing.expectError(error.RequestTooLarge, pending.append("x"));
    try std.testing.expectEqual(@as(usize, max_request_bytes), pending.bytes.items.len);
    pending.deadline = .{ .expires_ns = 0 };
    try std.testing.expectError(error.TimedOut, pending.append(""));
}
