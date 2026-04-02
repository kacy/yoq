const std = @import("std");
const posix = std.posix;
const log = @import("../../lib/log.zig");
const http2_request = @import("../../network/proxy/http2_request.zig");
const backend_mod = @import("../backend.zig");
const handshake = @import("../handshake.zig");
const pem = @import("../pem.zig");
const record = @import("../record.zig");
const socket_support = @import("socket_support.zig");

const X25519 = std.crypto.dh.X25519;
const Sha384 = std.crypto.hash.sha2.Sha384;

const hash_len = Sha384.digest_length;

pub fn handleTlsSession(
    client_fd: posix.fd_t,
    client_hello: []const u8,
    cert_pem: []u8,
    key_pem: []u8,
    backend_info: backend_mod.Backend,
    handshake_complete: *bool,
) !void {
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

    const server_kp = X25519.KeyPair.generate();
    const shared_secret = X25519.scalarmult(server_kp.secret_key, client_x25519_key) catch
        return error.KeyExchangeFailed;

    var transcript = Sha384.init(.{});
    transcript.update(client_hello[5 .. 5 + rec_len]);

    var server_random: [32]u8 = undefined;
    std.crypto.random.bytes(&server_random);

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
    _ = posix.write(client_fd, sh_record[0 .. 5 + sh_len]) catch return error.WriteFailed;
    transcript.update(sh_buf[0..sh_len]);

    const ccs = [_]u8{
        0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
    };
    _ = posix.write(client_fd, &ccs) catch return error.WriteFailed;

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
    try sendEncryptedHandshake(client_fd, ee_buf[0..ee_len], server_hs_traffic, &server_seq);

    const cert_der = pem.parseCertDer(std.heap.page_allocator, cert_pem) catch return error.CertParseFailed;
    defer std.heap.page_allocator.free(cert_der);

    var cert_buf: [8192]u8 = undefined;
    const cert_len = handshake.buildCertificate(&cert_buf, cert_der) catch return error.HandshakeFailed;
    transcript.update(cert_buf[0..cert_len]);
    try sendEncryptedHandshake(client_fd, cert_buf[0..cert_len], server_hs_traffic, &server_seq);

    const private_key = pem.parseEcPrivateKey(key_pem) catch return error.KeyParseFailed;
    const cv_transcript_hash = transcript.peek();

    var cv_buf: [512]u8 = undefined;
    const cv_len = handshake.buildCertificateVerify(&cv_buf, cv_transcript_hash, private_key) catch
        return error.HandshakeFailed;
    transcript.update(cv_buf[0..cv_len]);
    try sendEncryptedHandshake(client_fd, cv_buf[0..cv_len], server_hs_traffic, &server_seq);

    const fin_transcript_hash = transcript.peek();
    const verify_data = handshake.computeFinished(hs_keys.server_handshake_traffic_secret, fin_transcript_hash);

    var fin_buf: [128]u8 = undefined;
    const fin_len = handshake.buildFinished(&fin_buf, verify_data) catch return error.HandshakeFailed;
    transcript.update(fin_buf[0..fin_len]);
    try sendEncryptedHandshake(client_fd, fin_buf[0..fin_len], server_hs_traffic, &server_seq);

    var client_seq: u64 = 0;
    var client_finished_buf: [512]u8 = undefined;
    const client_rec_n = socket_support.readWithTimeout(client_fd, &client_finished_buf, 10000) catch
        return error.ReadFailed;
    if (client_rec_n < record.record_header_size + record.aead_tag_size + 1)
        return error.InvalidClientFinished;

    var client_data = client_finished_buf[0..client_rec_n];
    if (client_data[0] == 0x14) {
        if (client_data.len < 6) return error.InvalidClientFinished;
        const ccs_len: usize = 5 + @as(usize, (@as(u16, client_data[3]) << 8) | @as(u16, client_data[4]));
        if (ccs_len > client_data.len) return error.InvalidClientFinished;
        client_data = client_data[ccs_len..];
        if (client_data.len < record.record_header_size + record.aead_tag_size + 1)
            return error.InvalidClientFinished;
    }

    const client_rec_header = client_data[0..5].*;
    const client_ciphertext_len = (@as(usize, client_data[3]) << 8) | @as(usize, client_data[4]);
    if (5 + client_ciphertext_len > client_data.len) return error.InvalidClientFinished;
    const client_ciphertext = client_data[5 .. 5 + client_ciphertext_len];

    const client_decrypted = record.decryptRecord(
        client_hs_traffic.key,
        client_hs_traffic.iv,
        client_seq,
        client_ciphertext,
        client_rec_header,
    ) catch return error.InvalidClientFinished;
    client_seq += 1;

    if (client_decrypted.content_type != .handshake) return error.InvalidClientFinished;
    if (client_decrypted.plaintext.len < 4 + hash_len) return error.InvalidClientFinished;
    if (client_decrypted.plaintext[0] != 0x14) return error.InvalidClientFinished;

    const client_fin_transcript_hash = transcript.peek();
    const expected_verify = handshake.computeFinished(
        hs_keys.client_handshake_traffic_secret,
        client_fin_transcript_hash,
    );

    if (!std.mem.eql(u8, client_decrypted.plaintext[4 .. 4 + hash_len], &expected_verify))
        return error.FinishedVerifyFailed;

    transcript.update(client_decrypted.plaintext);

    var app_transcript_hash: [hash_len]u8 = undefined;
    transcript.final(&app_transcript_hash);

    const master = handshake.deriveMasterSecret(hs_keys.handshake_secret);
    const app_keys = handshake.deriveApplicationSecrets(master, app_transcript_hash);

    handshake_complete.* = true;

    const backend_fd = socket_support.connectToBackend(backend_info) catch return error.BackendConnectFailed;
    defer posix.close(backend_fd);

    var client_app_seq: u64 = 0;
    var server_app_seq: u64 = 0;
    var initial_plaintext: std.ArrayList(u8) = .empty;
    defer initial_plaintext.deinit(std.heap.page_allocator);
    var initial_request_forwarded = false;
    var h2_rewrite_state = http2_request.StreamRewriteState{};

    var poll_fds = [_]posix.pollfd{
        .{ .fd = client_fd, .events = posix.POLL.IN, .revents = 0 },
        .{ .fd = backend_fd, .events = posix.POLL.IN, .revents = 0 },
    };

    while (true) {
        const poll_result = posix.poll(&poll_fds, 30000) catch break;
        if (poll_result == 0) break;

        if (poll_fds[0].revents & (posix.POLL.HUP | posix.POLL.ERR) != 0) break;
        if (poll_fds[1].revents & (posix.POLL.HUP | posix.POLL.ERR) != 0) break;

        if (poll_fds[0].revents & posix.POLL.IN != 0) {
            var enc_buf: [record.max_ciphertext_size + record.record_header_size]u8 = undefined;
            const enc_n = posix.read(client_fd, &enc_buf) catch break;
            if (enc_n == 0) break;

            if (enc_n < record.record_header_size) break;
            const app_rec_header = enc_buf[0..5].*;
            const app_ct_len = (@as(usize, enc_buf[3]) << 8) | @as(usize, enc_buf[4]);
            if (5 + app_ct_len > enc_n) break;

            const app_ct = enc_buf[5 .. 5 + app_ct_len];
            const decrypted = record.decryptRecord(
                app_keys.client.key,
                app_keys.client.iv,
                client_app_seq,
                app_ct,
                app_rec_header,
            ) catch break;
            client_app_seq += 1;

            if (decrypted.content_type == .alert) break;

            if (decrypted.plaintext.len > 0) {
                if (selected_alpn != null and std.mem.eql(u8, selected_alpn.?, "h2")) {
                    initial_plaintext.appendSlice(std.heap.page_allocator, decrypted.plaintext) catch break;
                    while (true) {
                        const rewritten_chunk = http2_request.rewriteClientStreamChunk(
                            std.heap.page_allocator,
                            initial_plaintext.items,
                            &h2_rewrite_state,
                            "https",
                        ) catch break;
                        if (rewritten_chunk == null) break;
                        defer rewritten_chunk.?.deinit(std.heap.page_allocator);
                        if (rewritten_chunk.?.bytes.len > 0) {
                            _ = posix.write(backend_fd, rewritten_chunk.?.bytes) catch break;
                        }
                        initial_plaintext.replaceRange(std.heap.page_allocator, 0, rewritten_chunk.?.consumed, "") catch break;
                    }
                } else if (!initial_request_forwarded) {
                    initial_plaintext.appendSlice(std.heap.page_allocator, decrypted.plaintext) catch break;
                    const first_request = prepareInitialRequest(std.heap.page_allocator, selected_alpn, initial_plaintext.items) catch |err| switch (err) {
                        error.BufferTooShort, error.MissingHeaders, error.IncompleteRequest, error.MissingClientPreface => null,
                        else => break,
                    };
                    if (first_request) |request| {
                        defer std.heap.page_allocator.free(request);
                        _ = posix.write(backend_fd, request) catch break;
                        initial_request_forwarded = true;
                    }
                } else {
                    _ = posix.write(backend_fd, decrypted.plaintext) catch break;
                }
            }
        }

        if (poll_fds[1].revents & posix.POLL.IN != 0) {
            var plain_buf: [record.max_record_size]u8 = undefined;
            const plain_n = posix.read(backend_fd, &plain_buf) catch break;
            if (plain_n == 0) break;

            var ct_out: [record.max_ciphertext_size]u8 = undefined;
            const ct_len = record.encryptRecord(
                app_keys.server.key,
                app_keys.server.iv,
                server_app_seq,
                plain_buf[0..plain_n],
                .application_data,
                &ct_out,
            ) catch break;
            server_app_seq += 1;

            var out_rec: [5 + record.max_ciphertext_size]u8 = undefined;
            record.writeHeader(&out_rec, .application_data, @intCast(ct_len)) catch break;
            @memcpy(out_rec[5 .. 5 + ct_len], ct_out[0..ct_len]);
            _ = posix.write(client_fd, out_rec[0 .. 5 + ct_len]) catch break;
        }
    }

    sendEncryptedCloseNotify(client_fd, app_keys.server, &server_app_seq);
}

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

pub fn sendEncryptedHandshake(fd: posix.fd_t, msg: []const u8, keys: handshake.TrafficKeys, seq: *u64) !void {
    var ct_buf: [record.max_ciphertext_size]u8 = undefined;
    const ct_len = record.encryptRecord(
        keys.key,
        keys.iv,
        seq.*,
        msg,
        .handshake,
        &ct_buf,
    ) catch return error.EncryptFailed;

    var out: [5 + record.max_ciphertext_size]u8 = undefined;
    record.writeHeader(&out, .application_data, @intCast(ct_len)) catch return error.EncryptFailed;
    @memcpy(out[5 .. 5 + ct_len], ct_buf[0..ct_len]);
    _ = posix.write(fd, out[0 .. 5 + ct_len]) catch return error.WriteFailed;
    seq.* += 1;
}

pub fn sendEncryptedCloseNotify(fd: posix.fd_t, keys: handshake.TrafficKeys, seq: *u64) void {
    const alert = [_]u8{ 0x01, 0x00 };
    var ct_buf: [64]u8 = undefined;
    const ct_len = record.encryptRecord(
        keys.key,
        keys.iv,
        seq.*,
        &alert,
        .alert,
        &ct_buf,
    ) catch return;

    var out: [5 + 64]u8 = undefined;
    record.writeHeader(&out, .application_data, @intCast(ct_len)) catch return;
    @memcpy(out[5 .. 5 + ct_len], ct_buf[0..ct_len]);
    _ = posix.write(fd, out[0 .. 5 + ct_len]) catch |e| {
        log.warn("tls encrypted data write failed: {}", .{e});
        return;
    };
    seq.* += 1;
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
