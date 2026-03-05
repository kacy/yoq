// proxy — TLS reverse proxy for service traffic
//
// listens on port 443 (TLS) and port 80 (HTTP). on port 443, accepts
// connections, reads the ClientHello to extract SNI, looks up the
// certificate, completes the TLS 1.3 handshake, and pipes decrypted
// traffic to the container backend.
//
// port 80 serves ACME HTTP-01 challenges at /.well-known/acme-challenge/
// and redirects all other traffic to HTTPS.
//
// follows the same detached worker thread pattern as api/server.zig.
// each connection gets its own thread — fine for the expected load
// (TLS termination, not a CDN).
//
// containers serve plaintext HTTP. they never touch TLS.

const std = @import("std");
const posix = std.posix;
const log = @import("../lib/log.zig");
const sni = @import("sni.zig");
const cert_store = @import("cert_store.zig");
const backend_mod = @import("backend.zig");
const handshake = @import("handshake.zig");
const record = @import("record.zig");
const pem = @import("pem.zig");
const acme_mod = @import("acme.zig");
const jws = @import("jws.zig");

const X25519 = std.crypto.dh.X25519;
const Sha384 = std.crypto.hash.sha2.Sha384;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const max_connections: u32 = 256;
var active_connections: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

pub const ProxyError = error{
    BindFailed,
    ListenFailed,
    SocketFailed,
    CertStoreInitFailed,
};

/// ACME HTTP-01 challenge token store.
/// tokens are registered by the ACME client and served on port 80.
pub const ChallengeStore = struct {
    mutex: std.Thread.Mutex,
    tokens: std.StringHashMapUnmanaged([]const u8), // token -> key_authorization
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ChallengeStore {
        return .{
            .mutex = .{},
            .tokens = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ChallengeStore) void {
        var iter = self.tokens.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.tokens.deinit(self.allocator);
    }

    pub fn set(self: *ChallengeStore, token: []const u8, key_auth: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const owned_token = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(owned_token);
        const owned_auth = try self.allocator.dupe(u8, key_auth);
        errdefer self.allocator.free(owned_auth);

        try self.tokens.put(self.allocator, owned_token, owned_auth);
    }

    pub fn get(self: *ChallengeStore, token: []const u8) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.tokens.get(token);
    }

    pub fn remove(self: *ChallengeStore, token: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.tokens.fetchRemove(token)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }
    }
};

/// configuration for automatic certificate renewal.
/// if set, the proxy will periodically check for expiring certs and renew
/// them via ACME. the check runs every 12 hours by default.
pub const RenewalConfig = struct {
    email: []const u8,
    directory_url: []const u8,
    /// number of days before expiry to trigger renewal
    renewal_days: i64 = 30,
    /// interval between renewal checks in seconds (default: 12 hours)
    check_interval_s: u64 = 12 * 3600,
};

pub const TlsProxy = struct {
    allocator: std.mem.Allocator,
    backends: *backend_mod.BackendRegistry,
    certs: *cert_store.CertStore,
    challenges: ChallengeStore,
    tls_fd: posix.fd_t,
    http_fd: posix.fd_t,
    tls_port: u16,
    http_port: u16,
    running: std.atomic.Value(bool),
    renewal_config: ?RenewalConfig,

    pub fn init(
        allocator: std.mem.Allocator,
        backends: *backend_mod.BackendRegistry,
        certs: *cert_store.CertStore,
        tls_port: u16,
        http_port: u16,
    ) ProxyError!TlsProxy {
        const tls_fd = createListenSocket(tls_port) catch return ProxyError.SocketFailed;
        errdefer posix.close(tls_fd);

        const http_fd = createListenSocket(http_port) catch return ProxyError.SocketFailed;
        errdefer posix.close(http_fd);

        return .{
            .allocator = allocator,
            .backends = backends,
            .certs = certs,
            .challenges = ChallengeStore.init(allocator),
            .tls_fd = tls_fd,
            .http_fd = http_fd,
            .tls_port = tls_port,
            .http_port = http_port,
            .running = std.atomic.Value(bool).init(false),
            .renewal_config = null,
        };
    }

    /// set ACME renewal configuration. when set, the proxy will
    /// automatically renew certificates before they expire.
    pub fn setRenewalConfig(self: *TlsProxy, config: RenewalConfig) void {
        self.renewal_config = config;
    }

    pub fn deinit(self: *TlsProxy) void {
        self.stop();
        self.challenges.deinit();
        posix.close(self.tls_fd);
        posix.close(self.http_fd);
    }

    /// start accepting connections on both ports.
    /// spawns two accept loop threads (TLS and HTTP).
    pub fn start(self: *TlsProxy) void {
        self.running.store(true, .release);

        log.info("tls proxy listening on :{d} (tls) and :{d} (http)", .{ self.tls_port, self.http_port });

        // TLS accept loop
        const tls_thread = std.Thread.spawn(.{}, tlsAcceptLoop, .{self}) catch {
            log.err("failed to start TLS accept loop", .{});
            return;
        };
        tls_thread.detach();

        // HTTP accept loop
        const http_thread = std.Thread.spawn(.{}, httpAcceptLoop, .{self}) catch {
            log.err("failed to start HTTP accept loop", .{});
            return;
        };
        http_thread.detach();

        // renewal checker (only if configured)
        if (self.renewal_config != null) {
            const renewal_thread = std.Thread.spawn(.{}, renewalLoop, .{self}) catch {
                log.err("failed to start renewal checker", .{});
                return;
            };
            renewal_thread.detach();
        }
    }

    /// stop accepting new connections.
    pub fn stop(self: *TlsProxy) void {
        self.running.store(false, .release);
    }

    // -- accept loops --

    fn tlsAcceptLoop(self: *TlsProxy) void {
        while (self.running.load(.acquire)) {
            const client_fd = posix.accept(self.tls_fd, null, null, posix.SOCK.CLOEXEC) catch |err| {
                if (!self.running.load(.acquire)) break;
                log.warn("tls accept error: {}", .{err});
                continue;
            };

            const current = active_connections.load(.acquire);
            if (current >= max_connections) {
                posix.close(client_fd);
                continue;
            }
            _ = active_connections.fetchAdd(1, .acq_rel);

            const thread = std.Thread.spawn(.{}, tlsConnectionHandler, .{ self, client_fd }) catch {
                _ = active_connections.fetchSub(1, .acq_rel);
                posix.close(client_fd);
                continue;
            };
            thread.detach();
        }
    }

    fn httpAcceptLoop(self: *TlsProxy) void {
        while (self.running.load(.acquire)) {
            const client_fd = posix.accept(self.http_fd, null, null, posix.SOCK.CLOEXEC) catch |err| {
                if (!self.running.load(.acquire)) break;
                log.warn("http accept error: {}", .{err});
                continue;
            };

            const thread = std.Thread.spawn(.{}, httpConnectionHandler, .{ self, client_fd }) catch {
                posix.close(client_fd);
                continue;
            };
            thread.detach();
        }
    }

    // -- renewal --

    fn renewalLoop(self: *TlsProxy) void {
        const config = self.renewal_config orelse return;

        log.info("renewal checker started (every {d}h, renew within {d} days)", .{
            config.check_interval_s / 3600,
            config.renewal_days,
        });

        while (self.running.load(.acquire)) {
            // sleep in 30-second increments so we can check the running flag
            // without burning CPU. renewal checks are infrequent (every 12h)
            // so 30s granularity is fine for shutdown responsiveness.
            var elapsed: u64 = 0;
            while (elapsed < config.check_interval_s and self.running.load(.acquire)) {
                std.Thread.sleep(30 * std.time.ns_per_s);
                elapsed += 30;
            }
            if (!self.running.load(.acquire)) break;

            self.checkAndRenew(config);
        }

        log.info("renewal checker stopped", .{});
    }

    fn checkAndRenew(self: *TlsProxy, config: RenewalConfig) void {
        var expiring = self.certs.listExpiringSoon(config.renewal_days) catch {
            log.warn("failed to list expiring certificates", .{});
            return;
        };
        defer {
            for (expiring.items) |d| self.allocator.free(d);
            expiring.deinit(self.allocator);
        }

        if (expiring.items.len == 0) {
            log.info("renewal check: no certificates need renewal", .{});
            return;
        }

        log.info("renewal check: {d} certificate(s) need renewal", .{expiring.items.len});

        for (expiring.items) |domain| {
            if (!self.running.load(.acquire)) break;
            self.renewCertificate(domain, config) catch |err| {
                log.warn("failed to renew certificate for {s}: {}", .{ domain, err });
            };
        }
    }

    const RenewError = error{
        AcmeFailed,
        StoreFailed,
        AllocFailed,
    };

    fn renewCertificate(self: *TlsProxy, domain: []const u8, config: RenewalConfig) RenewError!void {
        log.info("renewing certificate for {s}", .{domain});

        var client = acme_mod.AcmeClient.init(self.allocator, config.directory_url);
        defer client.deinit();

        client.fetchDirectory() catch {
            log.warn("  renewal: failed to fetch ACME directory", .{});
            return RenewError.AcmeFailed;
        };

        client.createAccount(config.email) catch {
            log.warn("  renewal: failed to create/find ACME account", .{});
            return RenewError.AcmeFailed;
        };

        var order = client.createOrder(domain) catch {
            log.warn("  renewal: failed to create order for {s}", .{domain});
            return RenewError.AcmeFailed;
        };
        defer order.deinit();

        // handle HTTP-01 challenge — register token with our challenge store
        if (order.authorization_urls.len > 0) {
            var challenge = client.getHttpChallenge(order.authorization_urls[0]) catch {
                log.warn("  renewal: failed to get HTTP-01 challenge", .{});
                return RenewError.AcmeFailed;
            };
            defer challenge.deinit();

            // compute key authorization: token + "." + jwk_thumbprint
            const account_key = client.account_key orelse return RenewError.AcmeFailed;
            const thumbprint = jws.jwkThumbprint(self.allocator, account_key.public_key) catch
                return RenewError.AllocFailed;
            defer self.allocator.free(thumbprint);

            const key_auth = std.fmt.allocPrint(self.allocator, "{s}.{s}", .{
                challenge.token, thumbprint,
            }) catch return RenewError.AllocFailed;
            defer self.allocator.free(key_auth);

            // register the challenge token so port 80 handler can serve it
            self.challenges.set(challenge.token, key_auth) catch
                return RenewError.AllocFailed;
            defer self.challenges.remove(challenge.token);

            // tell the CA we're ready
            client.respondToChallenge(challenge.url) catch {
                log.warn("  renewal: failed to respond to challenge", .{});
                return RenewError.AcmeFailed;
            };

            // brief wait for CA to validate (the CA will hit our port 80)
            std.Thread.sleep(5 * std.time.ns_per_s);
        }

        // finalize — generates CSR, gets signed cert, exports as PEM
        var exported = client.finalizeAndExport(order.finalize_url, domain) catch {
            log.warn("  renewal: failed to finalize order", .{});
            return RenewError.AcmeFailed;
        };
        defer exported.deinit();

        // store the new certificate (cert_store.install replaces existing)
        self.certs.install(domain, exported.cert_pem, exported.key_pem, "acme") catch {
            log.warn("  renewal: failed to store renewed certificate", .{});
            return RenewError.StoreFailed;
        };

        // no in-memory cache to swap — cert_store.get() is called per-connection,
        // so the new cert will be used automatically on the next TLS handshake.
        log.info("  renewed certificate for {s}", .{domain});
    }

    // -- connection handlers --

    fn tlsConnectionHandler(self: *TlsProxy, client_fd: posix.fd_t) void {
        var handshake_complete = false;
        defer {
            _ = active_connections.fetchSub(1, .acq_rel);
            if (!handshake_complete) sendCloseNotify(client_fd);
            posix.close(client_fd);
        }

        // read ClientHello (up to 16KB — typical ClientHello is ~300 bytes)
        var client_hello_buf: [16384]u8 = undefined;
        const n = readWithTimeout(client_fd, &client_hello_buf, 5000) catch return;
        if (n == 0) return;

        const client_hello = client_hello_buf[0..n];

        // extract SNI to determine which certificate to use
        const server_name = sni.extractSni(client_hello) catch {
            log.warn("failed to extract SNI from ClientHello", .{});
            return;
        };

        // look up certificate
        const cert_result = self.certs.get(server_name) catch {
            log.warn("no certificate for domain: {s}", .{server_name});
            return;
        };
        defer {
            std.crypto.secureZero(u8, cert_result.key_pem);
            self.allocator.free(cert_result.key_pem);
            self.allocator.free(cert_result.cert_pem);
        }

        // look up backend
        const backend = self.backends.lookup(server_name) orelse {
            log.warn("no backend for domain: {s}", .{server_name});
            return;
        };

        // perform TLS handshake and proxy traffic
        self.handleTlsSession(
            client_fd,
            client_hello,
            cert_result.cert_pem,
            cert_result.key_pem,
            backend,
            &handshake_complete,
        ) catch |err| {
            log.warn("TLS session error for {s}: {}", .{ server_name, err });
        };
    }

    const hash_len = Sha384.digest_length; // 48

    fn handleTlsSession(
        self: *TlsProxy,
        client_fd: posix.fd_t,
        client_hello: []const u8,
        cert_pem: []u8,
        key_pem: []u8,
        backend_info: backend_mod.Backend,
        handshake_complete: *bool,
    ) !void {
        _ = self;

        // -- phase 1-2: parse ClientHello, X25519 key exchange --

        if (client_hello.len < 9) return error.InvalidClientHello;
        const rec_len = (@as(usize, client_hello[3]) << 8) | @as(usize, client_hello[4]);
        if (client_hello.len < 5 + rec_len) return error.InvalidClientHello;
        const hs_body = client_hello[9 .. 5 + rec_len];

        const hello_info = handshake.parseClientHelloFields(hs_body) catch return error.InvalidClientHello;

        if (!hello_info.has_aes_256_gcm) return error.UnsupportedCipher;
        if (!hello_info.supported_versions_has_tls13) return error.UnsupportedVersion;
        const client_x25519_key = hello_info.x25519_key_share orelse return error.MissingKeyShare;

        const server_kp = X25519.KeyPair.generate();
        const shared_secret = X25519.scalarmult(server_kp.secret_key, client_x25519_key) catch
            return error.KeyExchangeFailed;

        // -- phase 3: transcript hash --

        // hash the ClientHello handshake message body (after record header)
        var transcript = Sha384.init(.{});
        transcript.update(client_hello[5 .. 5 + rec_len]);

        // -- phase 4: build + send ServerHello as plaintext --

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

        // send as plaintext record
        var sh_record: [5 + 512]u8 = undefined;
        record.writeHeader(&sh_record, .handshake, @intCast(sh_len)) catch return error.HandshakeFailed;
        @memcpy(sh_record[5 .. 5 + sh_len], sh_buf[0..sh_len]);
        _ = posix.write(client_fd, sh_record[0 .. 5 + sh_len]) catch return error.WriteFailed;

        // add ServerHello to transcript
        transcript.update(sh_buf[0..sh_len]);

        // TLS 1.3 compatibility: send ChangeCipherSpec (ignored by TLS 1.3 peers
        // but needed for middlebox compatibility per RFC 8446 §5.1)
        const ccs = [_]u8{
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
        };
        _ = posix.write(client_fd, &ccs) catch return error.WriteFailed;

        // -- phase 5: derive handshake traffic keys --

        var transcript_hash: [hash_len]u8 = undefined;
        transcript_hash = transcript.peek();

        const early = handshake.deriveEarlySecret();
        const hs_secret = handshake.deriveHandshakeSecret(early, shared_secret);
        const hs_keys = handshake.deriveHandshakeTrafficSecrets(hs_secret, transcript_hash);

        const server_hs_traffic = handshake.deriveTrafficKeys(hs_keys.server_handshake_traffic_secret);
        const client_hs_traffic = handshake.deriveTrafficKeys(hs_keys.client_handshake_traffic_secret);

        // -- phase 6: send encrypted handshake messages --

        var server_seq: u64 = 0;

        // 6a. EncryptedExtensions
        var ee_buf: [64]u8 = undefined;
        const ee_len = handshake.buildEncryptedExtensions(&ee_buf) catch return error.HandshakeFailed;
        transcript.update(ee_buf[0..ee_len]);
        try sendEncryptedHandshake(client_fd, ee_buf[0..ee_len], server_hs_traffic, &server_seq);

        // 6b. Certificate — parse PEM cert to DER
        const cert_der = pem.parseCertDer(std.heap.page_allocator, cert_pem) catch return error.CertParseFailed;
        defer std.heap.page_allocator.free(cert_der);

        var cert_buf: [8192]u8 = undefined;
        const cert_len = handshake.buildCertificate(&cert_buf, cert_der) catch return error.HandshakeFailed;
        transcript.update(cert_buf[0..cert_len]);
        try sendEncryptedHandshake(client_fd, cert_buf[0..cert_len], server_hs_traffic, &server_seq);

        // 6c. CertificateVerify — sign transcript with private key
        const private_key = pem.parseEcPrivateKey(key_pem) catch return error.KeyParseFailed;

        const cv_transcript_hash = transcript.peek();

        var cv_buf: [512]u8 = undefined;
        const cv_len = handshake.buildCertificateVerify(&cv_buf, cv_transcript_hash, private_key) catch
            return error.HandshakeFailed;
        transcript.update(cv_buf[0..cv_len]);
        try sendEncryptedHandshake(client_fd, cv_buf[0..cv_len], server_hs_traffic, &server_seq);

        // 6d. Finished
        const fin_transcript_hash = transcript.peek();

        const verify_data = handshake.computeFinished(hs_keys.server_handshake_traffic_secret, fin_transcript_hash);

        var fin_buf: [128]u8 = undefined;
        const fin_len = handshake.buildFinished(&fin_buf, verify_data) catch return error.HandshakeFailed;
        transcript.update(fin_buf[0..fin_len]);
        try sendEncryptedHandshake(client_fd, fin_buf[0..fin_len], server_hs_traffic, &server_seq);

        // -- phase 7: read + decrypt client Finished --

        var client_seq: u64 = 0;
        var client_finished_buf: [512]u8 = undefined;
        const client_rec_n = readWithTimeout(client_fd, &client_finished_buf, 10000) catch
            return error.ReadFailed;
        if (client_rec_n < record.record_header_size + record.aead_tag_size + 1)
            return error.InvalidClientFinished;

        // client may send CCS before Finished — skip it
        var client_data = client_finished_buf[0..client_rec_n];
        if (client_data[0] == 0x14) {
            // ChangeCipherSpec record — skip
            if (client_data.len < 6) return error.InvalidClientFinished;
            const ccs_len: usize = 5 + @as(usize, (@as(u16, client_data[3]) << 8) | @as(u16, client_data[4]));
            if (ccs_len > client_data.len) return error.InvalidClientFinished;
            client_data = client_data[ccs_len..];
            if (client_data.len < record.record_header_size + record.aead_tag_size + 1)
                return error.InvalidClientFinished;
        }

        // parse the encrypted record
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
        if (client_decrypted.plaintext[0] != 0x14) return error.InvalidClientFinished; // Finished type

        // verify the client's Finished
        const client_fin_transcript_hash = transcript.peek();

        const expected_verify = handshake.computeFinished(
            hs_keys.client_handshake_traffic_secret,
            client_fin_transcript_hash,
        );

        if (!std.mem.eql(u8, client_decrypted.plaintext[4 .. 4 + hash_len], &expected_verify))
            return error.FinishedVerifyFailed;

        // add client Finished to transcript
        transcript.update(client_decrypted.plaintext);

        // -- phase 8: derive application keys --

        var app_transcript_hash: [hash_len]u8 = undefined;
        transcript.final(&app_transcript_hash);

        const master = handshake.deriveMasterSecret(hs_keys.handshake_secret);
        const app_keys = handshake.deriveApplicationSecrets(master, app_transcript_hash);

        handshake_complete.* = true;

        // -- phase 9: bidirectional proxy --

        const backend_fd = connectToBackend(backend_info) catch return error.BackendConnectFailed;
        defer posix.close(backend_fd);

        var client_app_seq: u64 = 0;
        var server_app_seq: u64 = 0;

        var poll_fds = [_]posix.pollfd{
            .{ .fd = client_fd, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = backend_fd, .events = posix.POLL.IN, .revents = 0 },
        };

        while (true) {
            const poll_result = posix.poll(&poll_fds, 30000) catch break;
            if (poll_result == 0) break; // timeout

            // check for errors/hangup
            if (poll_fds[0].revents & (posix.POLL.HUP | posix.POLL.ERR) != 0) break;
            if (poll_fds[1].revents & (posix.POLL.HUP | posix.POLL.ERR) != 0) break;

            // client → backend: decrypt TLS, forward plaintext
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

                // close_notify from client
                if (decrypted.content_type == .alert) break;

                if (decrypted.plaintext.len > 0) {
                    _ = posix.write(backend_fd, decrypted.plaintext) catch break;
                }
            }

            // backend → client: read plaintext, encrypt, send TLS
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

                // send TLS record: header + ciphertext
                var out_rec: [5 + record.max_ciphertext_size]u8 = undefined;
                record.writeHeader(&out_rec, .application_data, @intCast(ct_len)) catch break;
                @memcpy(out_rec[5 .. 5 + ct_len], ct_out[0..ct_len]);
                _ = posix.write(client_fd, out_rec[0 .. 5 + ct_len]) catch break;
            }
        }

        // send encrypted close_notify before exiting
        sendEncryptedCloseNotify(client_fd, app_keys.server, &server_app_seq);
    }

    fn httpConnectionHandler(self: *TlsProxy, client_fd: posix.fd_t) void {
        defer posix.close(client_fd);

        var buf: [4096]u8 = undefined;
        const n = readWithTimeout(client_fd, &buf, 5000) catch return;
        if (n == 0) return;

        const request = buf[0..n];

        // check for ACME challenge path
        if (std.mem.indexOf(u8, request, "GET /.well-known/acme-challenge/")) |_| {
            self.serveAcmeChallenge(client_fd, request);
            return;
        }

        // extract Host header for redirect
        const host = extractHost(request) orelse {
            sendHttpResponse(client_fd, "400 Bad Request", "missing Host header");
            return;
        };

        // redirect to HTTPS
        var redirect_buf: [512]u8 = undefined;
        const location = std.fmt.bufPrint(&redirect_buf, "https://{s}/", .{host}) catch {
            sendHttpResponse(client_fd, "500 Internal Server Error", "redirect failed");
            return;
        };

        var response_buf: [1024]u8 = undefined;
        const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 301 Moved Permanently\r\nLocation: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", .{location}) catch return;
        _ = posix.write(client_fd, response) catch {};
    }

    fn serveAcmeChallenge(self: *TlsProxy, client_fd: posix.fd_t, request: []const u8) void {
        const prefix = "GET /.well-known/acme-challenge/";
        const token_start = (std.mem.indexOf(u8, request, prefix) orelse return) + prefix.len;

        // find end of token (space or newline)
        var end = token_start;
        while (end < request.len and request[end] != ' ' and request[end] != '\r' and request[end] != '\n') {
            end += 1;
        }

        const token = request[token_start..end];
        if (token.len == 0) {
            sendHttpResponse(client_fd, "404 Not Found", "not found");
            return;
        }

        const key_auth = self.challenges.get(token) orelse {
            sendHttpResponse(client_fd, "404 Not Found", "not found");
            return;
        };

        var response_buf: [1024]u8 = undefined;
        const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ key_auth.len, key_auth }) catch return;
        _ = posix.write(client_fd, response) catch {};
    }
};

// -- TLS helpers --

/// encrypt a handshake message and send as a TLS record.
fn sendEncryptedHandshake(
    fd: posix.fd_t,
    msg: []const u8,
    keys: handshake.TrafficKeys,
    seq: *u64,
) !void {
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

/// send an encrypted close_notify alert.
fn sendEncryptedCloseNotify(fd: posix.fd_t, keys: handshake.TrafficKeys, seq: *u64) void {
    const alert = [_]u8{ 0x01, 0x00 }; // warning, close_notify
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
    _ = posix.write(fd, out[0 .. 5 + ct_len]) catch {};
    seq.* += 1;
}

// -- helpers --

fn createListenSocket(port: u16) !posix.fd_t {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    errdefer posix.close(fd);

    // allow port reuse
    const reuseaddr: i32 = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&reuseaddr)) catch {};

    const addr = posix.sockaddr.in{
        .port = std.mem.nativeTo(u16, port, .big),
        .addr = 0, // INADDR_ANY
    };

    try posix.bind(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in));
    try posix.listen(fd, 128);

    return fd;
}

fn connectToBackend(backend: backend_mod.Backend) !posix.fd_t {
    const fd = try posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0);
    errdefer posix.close(fd);

    const ip_addr = parseIpv4(backend.ip) orelse return error.InvalidBackendAddress;

    const addr = posix.sockaddr.in{
        .port = std.mem.nativeTo(u16, backend.port, .big),
        .addr = ip_addr,
    };

    posix.connect(fd, @ptrCast(&addr), @sizeOf(posix.sockaddr.in)) catch
        return error.BackendConnectFailed;

    return fd;
}

fn parseIpv4(ip: []const u8) ?u32 {
    var parts: [4]u8 = undefined;
    var part_idx: usize = 0;
    var current: u16 = 0;
    var has_digit = false;

    for (ip) |c| {
        if (c == '.') {
            if (!has_digit or part_idx >= 3) return null;
            if (current > 255) return null;
            parts[part_idx] = @intCast(current);
            part_idx += 1;
            current = 0;
            has_digit = false;
        } else if (c >= '0' and c <= '9') {
            current = current * 10 + (c - '0');
            has_digit = true;
        } else {
            return null;
        }
    }

    if (!has_digit or part_idx != 3) return null;
    if (current > 255) return null;
    parts[part_idx] = @intCast(current);

    return std.mem.bytesToValue(u32, &parts);
}

fn readWithTimeout(fd: posix.fd_t, buf: []u8, timeout_ms: i32) !usize {
    // set receive timeout
    const tv = posix.timeval{
        .sec = @divTrunc(timeout_ms, 1000),
        .usec = @rem(timeout_ms, 1000) * 1000,
    };
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch {};

    return posix.read(fd, buf) catch return error.ReadFailed;
}

fn extractHost(request: []const u8) ?[]const u8 {
    // look for "Host: " header (case-insensitive would be better, but
    // all major HTTP clients send it as "Host:")
    const marker = "Host: ";
    const pos = std.mem.indexOf(u8, request, marker) orelse {
        // try lowercase
        const lower = "host: ";
        const lpos = std.mem.indexOf(u8, request, lower) orelse return null;
        const start = lpos + lower.len;
        const end = std.mem.indexOfPos(u8, request, start, "\r") orelse request.len;
        const host = request[start..end];
        return if (host.len > 0) host else null;
    };
    const start = pos + marker.len;
    const end = std.mem.indexOfPos(u8, request, start, "\r") orelse request.len;
    const host = request[start..end];
    return if (host.len > 0) host else null;
}

/// send a plaintext TLS close_notify alert.
///
/// used only before the handshake completes. after handshake completion,
/// tlsConnectionHandler skips this and handleTlsSession sends an
/// encrypted close_notify via sendEncryptedCloseNotify instead.
///
/// best-effort — we don't care if the write fails (connection may already
/// be closed by the client).
fn sendCloseNotify(fd: posix.fd_t) void {
    const close_notify = [_]u8{
        0x15, // content type: alert
        0x03, 0x03, // protocol version: TLS 1.2 (wire format)
        0x00, 0x02, // length: 2
        0x01, // level: warning
        0x00, // description: close_notify
    };
    _ = posix.write(fd, &close_notify) catch {};
}

fn sendHttpResponse(fd: posix.fd_t, status: []const u8, body: []const u8) void {
    var buf: [512]u8 = undefined;
    const response = std.fmt.bufPrint(&buf, "HTTP/1.1 {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ status, body.len, body }) catch return;
    _ = posix.write(fd, response) catch {};
}

// -- tests --

test "parseIpv4" {
    const result = parseIpv4("10.42.0.5");
    try std.testing.expect(result != null);

    // verify by converting back
    const bytes = std.mem.asBytes(&result.?);
    try std.testing.expectEqual(@as(u8, 10), bytes[0]);
    try std.testing.expectEqual(@as(u8, 42), bytes[1]);
    try std.testing.expectEqual(@as(u8, 0), bytes[2]);
    try std.testing.expectEqual(@as(u8, 5), bytes[3]);
}

test "parseIpv4 invalid" {
    try std.testing.expect(parseIpv4("") == null);
    try std.testing.expect(parseIpv4("not-an-ip") == null);
    try std.testing.expect(parseIpv4("256.0.0.1") == null);
    try std.testing.expect(parseIpv4("1.2.3") == null);
    try std.testing.expect(parseIpv4("1.2.3.4.5") == null);
}

test "extractHost" {
    const req = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    const host = extractHost(req);
    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("example.com", host.?);
}

test "extractHost lowercase" {
    const req = "GET / HTTP/1.1\r\nhost: test.org\r\n\r\n";
    const host = extractHost(req);
    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("test.org", host.?);
}

test "extractHost missing" {
    const req = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    try std.testing.expect(extractHost(req) == null);
}

test "ChallengeStore round-trip" {
    const alloc = std.testing.allocator;
    var cs = ChallengeStore.init(alloc);
    defer cs.deinit();

    try cs.set("token123", "auth-value");
    const auth = cs.get("token123");
    try std.testing.expect(auth != null);
    try std.testing.expectEqualStrings("auth-value", auth.?);
}

test "ChallengeStore remove" {
    const alloc = std.testing.allocator;
    var cs = ChallengeStore.init(alloc);
    defer cs.deinit();

    try cs.set("token123", "auth-value");
    cs.remove("token123");
    try std.testing.expect(cs.get("token123") == null);
}
