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
// HTTP and TLS share bounded, owned connection workers. Stop cancels sockets
// and joins every worker before certificates, challenges, or I/O are freed.
//
// containers serve plaintext HTTP. they never touch TLS.

const std = @import("std");
const linux_platform = @import("linux_platform");
const posix = std.posix;
const log = @import("../lib/log.zig");
const http_support = @import("proxy/http_support.zig");
const session_runtime = @import("proxy/session_runtime.zig");
const socket_support = @import("proxy/socket_support.zig");
const sni = @import("sni.zig");
const cert_store = @import("cert_store.zig");
const backend_mod = @import("backend.zig");
const acme_mod = @import("acme.zig");
const managed_runtime = @import("acme/managed_runtime.zig");
const runtime_wait = @import("../lib/runtime_wait.zig");
const store_mod = @import("../state/store.zig");

const max_connections = 256;
const WorkerGroup = @import("proxy/worker_group.zig").Group(max_connections);
const accept_support = @import("proxy/accept_support.zig");

pub const ProxyError = error{
    BindFailed,
    ListenFailed,
    SocketFailed,
    CertStoreInitFailed,
};

/// ACME HTTP-01 challenge token store.
/// tokens are registered by the ACME client and served on port 80.
pub const ChallengeStore = struct {
    mutex: std.Io.Mutex,
    tokens: std.StringHashMapUnmanaged([]const u8), // token -> key_authorization
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ChallengeStore {
        return .{
            .mutex = .init,
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
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        if (self.tokens.fetchRemove(token)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }

        const owned_token = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(owned_token);
        const owned_auth = try self.allocator.dupe(u8, key_auth);
        errdefer self.allocator.free(owned_auth);

        try self.tokens.put(self.allocator, owned_token, owned_auth);
    }

    pub fn get(self: *ChallengeStore, token: []const u8) ?[]const u8 {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        return self.tokens.get(token);
    }

    pub fn getOwned(self: *ChallengeStore, alloc: std.mem.Allocator, token: []const u8) !?[]u8 {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

        const value = self.tokens.get(token) orelse return null;
        return try alloc.dupe(u8, value);
    }

    pub fn remove(self: *ChallengeStore, token: []const u8) void {
        self.mutex.lockUncancelable(std.Options.debug_io);
        defer self.mutex.unlock(std.Options.debug_io);

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
    /// number of days before expiry to trigger renewal
    renewal_days: i64 = 30,
    /// interval between renewal checks in seconds (default: 12 hours)
    check_interval_s: u64 = 12 * 3600,
};

pub const TlsProxy = struct {
    allocator: std.mem.Allocator,
    lifecycle_mutex: std.Io.Mutex = .init,
    workers: WorkerGroup = .{},
    threaded_io: std.Io.Threaded,
    backends: *backend_mod.BackendRegistry,
    certs: *cert_store.CertStore,
    challenges: ChallengeStore,
    tls_fd: posix.fd_t,
    http_fd: posix.fd_t,
    tls_port: u16,
    http_port: u16,
    running: std.atomic.Value(bool),
    listener_failed: std.atomic.Value(bool) = .init(false),
    renewal_config: ?RenewalConfig,
    tls_thread: ?std.Thread,
    http_thread: ?std.Thread,
    renewal_thread: ?std.Thread,

    pub fn init(
        allocator: std.mem.Allocator,
        backends: *backend_mod.BackendRegistry,
        certs: *cert_store.CertStore,
        tls_port: u16,
        http_port: u16,
    ) ProxyError!TlsProxy {
        const tls_fd = socket_support.createListenSocket(tls_port) catch return ProxyError.SocketFailed;
        errdefer linux_platform.posix.close(tls_fd);

        const http_fd = socket_support.createListenSocket(http_port) catch return ProxyError.SocketFailed;
        errdefer linux_platform.posix.close(http_fd);

        const bound_tls_port = socket_support.boundPort(tls_fd) catch return ProxyError.SocketFailed;
        const bound_http_port = socket_support.boundPort(http_fd) catch return ProxyError.SocketFailed;
        return .{
            .allocator = allocator,
            .threaded_io = std.Io.Threaded.init(allocator, .{}),
            .backends = backends,
            .certs = certs,
            .challenges = ChallengeStore.init(allocator),
            .tls_fd = tls_fd,
            .http_fd = http_fd,
            .tls_port = bound_tls_port,
            .http_port = bound_http_port,
            .running = std.atomic.Value(bool).init(false),
            .renewal_config = null,
            .tls_thread = null,
            .http_thread = null,
            .renewal_thread = null,
        };
    }

    /// set ACME renewal configuration. when set, the proxy will
    /// automatically renew certificates before they expire.
    pub fn setRenewalConfig(self: *TlsProxy, config: RenewalConfig) void {
        self.renewal_config = config;
    }

    pub fn deinit(self: *TlsProxy) void {
        self.stop();
        self.threaded_io.deinit();
        self.challenges.deinit();
        linux_platform.posix.close(self.tls_fd);
        linux_platform.posix.close(self.http_fd);
    }

    /// start accepting connections on both ports.
    /// spawns two accept loop threads (TLS and HTTP).
    pub fn start(self: *TlsProxy) void {
        self.lifecycle_mutex.lockUncancelable(std.Options.debug_io);
        defer self.lifecycle_mutex.unlock(std.Options.debug_io);
        if (self.running.load(.acquire)) return;
        self.stopLocked();
        if (self.listener_failed.load(.acquire)) {
            self.reopenListeners() catch {
                log.warn("failed to reopen TLS proxy listeners", .{});
                return;
            };
            self.listener_failed.store(false, .release);
        }
        self.workers.restart();
        self.running.store(true, .release);

        log.info("tls proxy listening on :{d} (tls) and :{d} (http)", .{ self.tls_port, self.http_port });

        self.tls_thread = std.Thread.spawn(.{}, tlsAcceptLoop, .{self}) catch {
            log.err("failed to start TLS accept loop", .{});
            self.running.store(false, .release);
            return;
        };

        self.http_thread = std.Thread.spawn(.{}, httpAcceptLoop, .{self}) catch {
            log.err("failed to start HTTP accept loop", .{});
            self.stopLocked();
            return;
        };

        if (self.renewal_config != null) {
            self.renewal_thread = std.Thread.spawn(.{}, renewalLoop, .{self}) catch {
                log.err("failed to start renewal checker", .{});
                self.stopLocked();
                return;
            };
        }
    }

    /// stop accepting new connections.
    pub fn stop(self: *TlsProxy) void {
        self.lifecycle_mutex.lockUncancelable(std.Options.debug_io);
        defer self.lifecycle_mutex.unlock(std.Options.debug_io);
        self.stopLocked();
    }

    fn stopLocked(self: *TlsProxy) void {
        self.running.store(false, .release);
        self.workers.cancel();
        if (self.tls_thread) |thread| {
            thread.join();
            self.tls_thread = null;
        }
        if (self.http_thread) |thread| {
            thread.join();
            self.http_thread = null;
        }
        if (self.renewal_thread) |thread| {
            thread.join();
            self.renewal_thread = null;
        }
        self.workers.join();
    }

    fn reopenListeners(self: *TlsProxy) !void {
        if (self.tls_fd >= 0) linux_platform.posix.close(self.tls_fd);
        if (self.http_fd >= 0) linux_platform.posix.close(self.http_fd);
        self.tls_fd = -1;
        self.http_fd = -1;
        const tls_fd = try socket_support.createListenSocket(self.tls_port);
        errdefer linux_platform.posix.close(tls_fd);
        const http_fd = try socket_support.createListenSocket(self.http_port);
        self.tls_fd = tls_fd;
        self.http_fd = http_fd;
    }

    fn listenerFailed(self: *TlsProxy) void {
        self.listener_failed.store(true, .release);
        self.running.store(false, .release);
        self.workers.cancel();
    }

    // -- accept loops --

    fn tlsAcceptLoop(self: *TlsProxy) void {
        self.acceptLoop(self.tls_fd, tlsConnectionHandler);
    }

    fn httpAcceptLoop(self: *TlsProxy) void {
        self.acceptLoop(self.http_fd, httpConnectionHandler);
    }

    fn acceptLoop(self: *TlsProxy, fd: posix.fd_t, comptime handler: anytype) void {
        var backoff = accept_support.Backoff{};
        while (self.running.load(.acquire)) {
            const ready = accept_support.ready(fd) catch |err| {
                if (err == error.Retry) {
                    backoff.pause();
                    continue;
                }
                self.listenerFailed();
                return;
            };
            if (!ready) continue;
            const client_fd = accept_support.accept(fd) catch |err| switch (err) {
                error.WouldBlock => continue,
                error.Retry => {
                    backoff.pause();
                    continue;
                },
                error.Fatal => {
                    self.listenerFailed();
                    return;
                },
            };
            backoff.reset();
            self.workers.spawn(client_fd, handler, .{ self, client_fd }) catch |err| {
                linux_platform.posix.close(client_fd);
                if (err != error.ConnectionLimit and err != error.Stopping) backoff.pause();
            };
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
            var elapsed: u64 = 0;
            while (elapsed < config.check_interval_s and self.running.load(.acquire)) {
                const step: u64 = @min(5, config.check_interval_s - elapsed);
                if (!runtime_wait.sleep(std.Io.Duration.fromSeconds(@intCast(step)), "tls renewal wait")) return;
                elapsed += step;
            }
            if (!self.running.load(.acquire)) break;

            self.checkAndRenew(config);
        }

        log.info("renewal checker stopped", .{});
    }

    fn checkAndRenew(self: *TlsProxy, config: RenewalConfig) void {
        var expiring = self.certs.listExpiringManagedSoon(config.renewal_days) catch {
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
            self.renewCertificate(domain) catch |err| {
                log.warn("failed to renew certificate for {s}: {}", .{ domain, err });
            };
        }
    }

    const RenewError = error{
        AcmeFailed,
        StoreFailed,
        AllocFailed,
    };

    fn renewCertificate(self: *TlsProxy, domain: []const u8) RenewError!void {
        log.info("renewing certificate for {s}", .{domain});

        var managed_config = self.certs.getAcmeConfig(domain) catch {
            log.warn("  renewal: failed to load ACME metadata", .{});
            return RenewError.StoreFailed;
        };
        defer managed_config.deinit(self.allocator);

        if (managed_runtime.preflightProblem(self.allocator, self.certs.db, managed_config, true) catch {
            log.warn("  renewal: failed to validate ACME metadata", .{});
            return RenewError.AllocFailed;
        }) |problem| {
            defer self.allocator.free(problem);
            log.warn("  renewal: invalid ACME metadata for {s}: {s}", .{ domain, problem });
            return RenewError.AcmeFailed;
        }

        var client = acme_mod.AcmeClient.init(self.threaded_io.io(), self.allocator, managed_config.directory_url);
        defer client.deinit();

        var exported = managed_runtime.issueAndExport(
            self.threaded_io.io(),
            self.allocator,
            self.certs.db,
            &client,
            domain,
            managed_config,
            challengeRegistrar(&self.challenges),
        ) catch {
            log.warn("  renewal: failed to finalize order", .{});
            return RenewError.AcmeFailed;
        };
        defer exported.deinit();

        // store the new certificate (cert_store.install replaces existing)
        self.certs.install(domain, exported.cert_pem, exported.key_pem, "acme") catch {
            log.warn("  renewal: failed to store renewed certificate", .{});
            return RenewError.StoreFailed;
        };
        self.certs.setAcmeConfig(domain, managed_config) catch {
            log.warn("  renewal: failed to persist renewal metadata", .{});
            return RenewError.StoreFailed;
        };

        // no in-memory cache to swap — cert_store.get() is called per-connection,
        // so the new cert will be used automatically on the next TLS handshake.
        log.info("  renewed certificate for {s}", .{domain});
    }

    fn challengeRegistrar(store: *ChallengeStore) acme_mod.ChallengeRegistrar {
        return .{
            .ctx = store,
            .set_fn = registerChallenge,
            .remove_fn = removeChallenge,
        };
    }

    fn registerChallenge(ctx: *anyopaque, token: []const u8, key_authorization: []const u8) acme_mod.AcmeError!void {
        const store: *ChallengeStore = @ptrCast(@alignCast(ctx));
        store.set(token, key_authorization) catch return acme_mod.AcmeError.AllocFailed;
    }

    fn removeChallenge(ctx: *anyopaque, token: []const u8) void {
        const store: *ChallengeStore = @ptrCast(@alignCast(ctx));
        store.remove(token);
    }

    // -- connection handlers --

    fn tlsConnectionHandler(self: *TlsProxy, client_fd: posix.fd_t) void {
        self.tlsConnectionHandlerWithCa(client_fd, store_mod);
    }

    fn tlsConnectionHandlerWithCa(self: *TlsProxy, client_fd: posix.fd_t, ca_store: anytype) void {
        var handshake_complete = false;
        defer {
            if (!handshake_complete) http_support.sendCloseNotify(client_fd);
            linux_platform.posix.close(client_fd);
        }

        // read ClientHello (up to 16KB — typical ClientHello is ~300 bytes)
        var client_hello_buf: [16384]u8 = undefined;
        const bytes_read = socket_support.readWithTimeout(client_fd, &client_hello_buf, 5000) catch return;
        if (bytes_read == 0) return;

        const client_hello = client_hello_buf[0..bytes_read];

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
        const backend = self.backends.lookupOwned(self.allocator, server_name) catch {
            log.warn("failed to copy backend for domain: {s}", .{server_name});
            return;
        } orelse {
            log.warn("no backend for domain: {s}", .{server_name});
            return;
        };
        defer self.allocator.free(backend.ip);

        // Required peer authentication must stay required while trust is
        // unavailable. Warn mode remains permissive and reports the failure.
        var mtls_ca_rec: ?store_mod.ClusterCaRecord = null;
        defer if (mtls_ca_rec) |rec| rec.deinit(self.allocator);

        const mtls_opts: ?session_runtime.MtlsOpts = blk: {
            if (backend.peer_mode == .off) break :blk null;
            const loaded = ca_store.getClusterCa(self.allocator) catch |err| {
                log.warn("failed to load peer trust for {s}: {}", .{ server_name, err });
                if (backend.peer_mode == .require) return;
                break :blk null;
            };
            const rec = loaded orelse {
                log.warn("peer trust unavailable for {s}: cluster CA not yet seeded", .{server_name});
                if (backend.peer_mode == .require) return;
                break :blk null;
            };
            mtls_ca_rec = rec;
            break :blk session_runtime.MtlsOpts{
                .require_client_cert = backend.peer_mode == .require,
                .trust_ca_pem = rec.cert_pem,
                .now_unix = std.Io.Clock.real.now(std.Options.debug_io).toSeconds(),
            };
        };

        // perform TLS handshake and proxy traffic
        session_runtime.handleTlsSession(
            self.threaded_io.io(),
            client_fd,
            client_hello,
            cert_result.cert_pem,
            cert_result.key_pem,
            backend,
            &handshake_complete,
            mtls_opts,
        ) catch |err| {
            log.warn("TLS session error for {s}: {}", .{ server_name, err });
        };
    }

    fn httpConnectionHandler(self: *TlsProxy, client_fd: posix.fd_t) void {
        defer linux_platform.posix.close(client_fd);

        var buf: [4096]u8 = undefined;
        const bytes_read = socket_support.readWithTimeout(client_fd, &buf, 5000) catch return;
        if (bytes_read == 0) return;

        const request = buf[0..bytes_read];

        if (http_support.extractAcmeChallengeToken(request)) |token| {
            self.serveAcmeChallenge(client_fd, token);
            return;
        }

        // extract Host header for redirect
        const host = http_support.extractHost(request) orelse {
            http_support.sendHttpResponse(client_fd, "400 Bad Request", "missing Host header");
            return;
        };

        // redirect to HTTPS
        const target = http_support.extractRequestTarget(request) orelse "/";

        var redirect_buf: [1024]u8 = undefined;
        const location = std.fmt.bufPrint(&redirect_buf, "https://{s}{s}", .{ host, target }) catch {
            http_support.sendHttpResponse(client_fd, "500 Internal Server Error", "redirect failed");
            return;
        };

        var response_buf: [1024]u8 = undefined;
        const response = http_support.formatRedirectResponse(&response_buf, location) catch return;
        _ = linux_platform.posix.send(client_fd, response, posix.MSG.NOSIGNAL) catch |e| {
            log.warn("tls proxy redirect write failed: {}", .{e});
        };
    }

    fn serveAcmeChallenge(self: *TlsProxy, client_fd: posix.fd_t, token: []const u8) void {
        const key_auth = self.challenges.getOwned(self.allocator, token) catch {
            http_support.sendHttpResponse(client_fd, "500 Internal Server Error", "challenge lookup failed");
            return;
        } orelse {
            http_support.sendHttpResponse(client_fd, "404 Not Found", "not found");
            return;
        };
        defer self.allocator.free(key_auth);

        var response_buf: [1024]u8 = undefined;
        const response = std.fmt.bufPrint(&response_buf, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{ key_auth.len, key_auth }) catch return;
        _ = linux_platform.posix.send(client_fd, response, posix.MSG.NOSIGNAL) catch |e| {
            log.warn("tls proxy acme challenge write failed: {}", .{e});
        };
    }
};

// -- tests --

test "parseIpv4" {
    const result = socket_support.parseIpv4("10.42.0.5");
    try std.testing.expect(result != null);

    // verify by converting back
    const bytes = std.mem.asBytes(&result.?);
    try std.testing.expectEqual(@as(u8, 10), bytes[0]);
    try std.testing.expectEqual(@as(u8, 42), bytes[1]);
    try std.testing.expectEqual(@as(u8, 0), bytes[2]);
    try std.testing.expectEqual(@as(u8, 5), bytes[3]);
}

test "parseIpv4 invalid" {
    try std.testing.expect(socket_support.parseIpv4("") == null);
    try std.testing.expect(socket_support.parseIpv4("not-an-ip") == null);
    try std.testing.expect(socket_support.parseIpv4("256.0.0.1") == null);
    try std.testing.expect(socket_support.parseIpv4("1.2.3") == null);
    try std.testing.expect(socket_support.parseIpv4("1.2.3.4.5") == null);
}

test "extractHost" {
    const req = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    const host = http_support.extractHost(req);
    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("example.com", host.?);
}

test "extractHost lowercase" {
    const req = "GET / HTTP/1.1\r\nhost: test.org\r\n\r\n";
    const host = http_support.extractHost(req);
    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("test.org", host.?);
}

test "extractHost missing" {
    const req = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    try std.testing.expect(http_support.extractHost(req) == null);
}

test "extractHost ignores body text that looks like a header" {
    const req = "GET / HTTP/1.1\r\nConnection: close\r\n\r\nHost: attacker.example";
    try std.testing.expect(http_support.extractHost(req) == null);
}

test "extractHost rejects unsafe redirect host values" {
    const req = "GET / HTTP/1.1\r\nHost: example.com/evil\r\n\r\n";
    try std.testing.expect(http_support.extractHost(req) == null);
}

test "extractAcmeChallengeToken parses request line only" {
    const req = "GET /.well-known/acme-challenge/token-123_abc HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const token = http_support.extractAcmeChallengeToken(req);
    try std.testing.expect(token != null);
    try std.testing.expectEqualStrings("token-123_abc", token.?);
}

test "extractAcmeChallengeToken ignores body text" {
    const req = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 37\r\n\r\nGET /.well-known/acme-challenge/token";
    try std.testing.expect(http_support.extractAcmeChallengeToken(req) == null);
}

test "extractRequestTarget preserves path and query" {
    const req = "GET /grpc.Service/Call?debug=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const target = http_support.extractRequestTarget(req);
    try std.testing.expect(target != null);
    try std.testing.expectEqualStrings("/grpc.Service/Call?debug=1", target.?);
}

test "extractRequestTarget rejects absolute-form target" {
    const req = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    try std.testing.expect(http_support.extractRequestTarget(req) == null);
}

test "formatRedirectResponse preserves method-safe redirect semantics" {
    var buf: [1024]u8 = undefined;
    const response = try http_support.formatRedirectResponse(&buf, "https://example.com/upload?id=7");
    try std.testing.expect(std.mem.indexOf(u8, response, "HTTP/1.1 308 Permanent Redirect\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Location: https://example.com/upload?id=7\r\n") != null);
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

test "ChallengeStore getOwned returns stable copy" {
    const alloc = std.testing.allocator;
    var cs = ChallengeStore.init(alloc);
    defer cs.deinit();

    try cs.set("token123", "auth-value");
    const owned = (try cs.getOwned(alloc, "token123")).?;
    defer alloc.free(owned);

    cs.remove("token123");
    try std.testing.expectEqualStrings("auth-value", owned);
}

test "ChallengeStore set overwrites existing token safely" {
    const alloc = std.testing.allocator;
    var cs = ChallengeStore.init(alloc);
    defer cs.deinit();

    try cs.set("token123", "first");
    try cs.set("token123", "second");

    const auth = cs.get("token123");
    try std.testing.expect(auth != null);
    try std.testing.expectEqualStrings("second", auth.?);
}

const PeerTrustFixture = struct {
    const Trust = enum { missing, failed, present, malformed };
    const PeerMode = @import("../manifest/spec.zig").TlsConfig.PeerMode;

    trust: Trust,
    ca_pem: []const u8,
    calls: usize = 0,

    fn getClusterCa(self: *PeerTrustFixture, alloc: std.mem.Allocator) !?store_mod.ClusterCaRecord {
        self.calls += 1;
        switch (self.trust) {
            .missing => return null,
            .failed => return error.ReadFailed,
            .present, .malformed => return .{
                .cert_pem = try alloc.dupe(u8, if (self.trust == .malformed) "invalid CA" else self.ca_pem),
                .encrypted_key = &.{},
                .key_nonce = &.{},
                .key_tag = &.{},
                .created_at = 0,
                .not_after = 0,
            },
        }
    }

    fn boundPort(fd: posix.fd_t) !u16 {
        var addr: posix.sockaddr.in = undefined;
        var len: posix.socklen_t = @sizeOf(@TypeOf(addr));
        try linux_platform.posix.getsockname(fd, @ptrCast(&addr), &len);
        return std.mem.bigToNative(u16, addr.port);
    }

    fn setTimeouts(fd: posix.fd_t) !void {
        const timeout = posix.timeval{ .sec = 5, .usec = 0 };
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
        try posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.SNDTIMEO, std.mem.asBytes(&timeout));
    }

    fn serve(proxy: *TlsProxy, fd: posix.fd_t, source: *PeerTrustFixture) void {
        proxy.tlsConnectionHandlerWithCa(fd, source);
    }

    fn check(
        certs: *cert_store.CertStore,
        ca_pem: []const u8,
        mode: PeerMode,
        trust: Trust,
        client_cert: ?[]const u8,
        client_key: ?[]const u8,
        allowed: bool,
    ) !void {
        const alloc = std.testing.allocator;
        const backend_fd = try socket_support.createListenSocket(0);
        defer linux_platform.posix.close(backend_fd);
        var backends = backend_mod.BackendRegistry.init(alloc);
        defer backends.deinit();
        try backends.register("peer.test", "127.0.0.1", try boundPort(backend_fd), mode);
        var proxy = try TlsProxy.init(alloc, &backends, certs, 0, 0);
        defer proxy.deinit();
        const client_fd = try socket_support.connectToBackend(.{ .ip = "127.0.0.1", .port = try boundPort(proxy.tls_fd) });
        defer linux_platform.posix.close(client_fd);
        try setTimeouts(client_fd);
        const server_fd = try linux_platform.posix.accept(proxy.tls_fd, null, null, posix.SOCK.CLOEXEC);
        var owns_server = true;
        defer if (owns_server) linux_platform.posix.close(server_fd);
        try setTimeouts(server_fd);

        var source = PeerTrustFixture{ .trust = trust, .ca_pem = ca_pem };
        const worker = std.Thread.spawn(.{}, serve, .{ &proxy, server_fd, &source }) catch |err| {
            return err;
        };
        owns_server = false;
        var joined = false;
        defer if (!joined) {
            _ = std.os.linux.shutdown(client_fd, 2);
            worker.join();
        };

        const client_session = @import("client_session.zig");
        var handshake_succeeded = false;
        if (client_session.doHandshake(std.testing.io, alloc, client_fd, .{
            .server_name = "peer.test",
            .ca_cert_pem = ca_pem,
            .expected_server_identity = "spiffe://yoq/service/server",
            .client_cert_pem = client_cert,
            .client_key_pem = client_key,
            .now_unix = std.Io.Clock.real.now(std.Options.debug_io).toSeconds(),
        })) |session| {
            var owned_session = session;
            owned_session.deinit();
            handshake_succeeded = true;
        } else |err| {
            if (allowed) return err;
        }
        _ = std.os.linux.shutdown(client_fd, 2);
        worker.join();
        joined = true;

        // A TLS client can finish before the server rejects its certificate.
        // The backend connection proves that server-side authorization passed.
        var fds = [_]posix.pollfd{.{ .fd = backend_fd, .events = posix.POLL.IN, .revents = 0 }};
        const ready = try posix.poll(&fds, 0);
        try std.testing.expectEqual(allowed, ready > 0 and fds[0].revents & posix.POLL.IN != 0);
        if (allowed) {
            try std.testing.expect(handshake_succeeded);
            const accepted = try linux_platform.posix.accept(backend_fd, null, null, posix.SOCK.CLOEXEC);
            linux_platform.posix.close(accepted);
        }
        try std.testing.expectEqual(@as(usize, if (mode == .off) 0 else 1), source.calls);
    }
};

test "peer trust listener preserves off and warn and never downgrades require" {
    const alloc = std.testing.allocator;
    const x509_gen = @import("x509_gen.zig");
    const csr = @import("csr.zig");
    const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
    const ca = try x509_gen.generateCa(std.testing.io, alloc, "peer-ca", now - 3600, now + 86400);
    defer alloc.free(ca.cert_pem);
    const server = try x509_gen.issueLeaf(std.testing.io, alloc, ca.key_pair, "peer-ca", "server", "spiffe://yoq/service/server", now - 60, now + 86400);
    defer alloc.free(server.cert_pem);
    const server_key = try csr.derKeyToPem(alloc, &server.key_pair.secret_key.toBytes());
    defer alloc.free(server_key);
    const client = try x509_gen.issueLeaf(std.testing.io, alloc, ca.key_pair, "peer-ca", "client", "spiffe://yoq/service/client", now - 60, now + 86400);
    defer alloc.free(client.cert_pem);
    const client_key = try csr.derKeyToPem(alloc, &client.key_pair.secret_key.toBytes());
    defer alloc.free(client_key);
    var db = try @import("sqlite").Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    var certs = try cert_store.CertStore.initWithKey(&db, alloc, [_]u8{0xAB} ** cert_store.key_length);
    try certs.install("peer.test", server.cert_pem, server_key, "manual");

    for ([_]PeerTrustFixture.PeerMode{ .off, .warn, .require }) |mode| {
        for ([_]PeerTrustFixture.Trust{ .missing, .failed, .present }) |trust| {
            try PeerTrustFixture.check(&certs, ca.cert_pem, mode, trust, null, null, mode != .require);
        }
    }
    try PeerTrustFixture.check(&certs, ca.cert_pem, .require, .present, client.cert_pem, client_key, true);
    try PeerTrustFixture.check(&certs, ca.cert_pem, .require, .malformed, client.cert_pem, client_key, false);

    const other_ca = try x509_gen.generateCa(std.testing.io, alloc, "other-ca", now - 3600, now + 86400);
    defer alloc.free(other_ca.cert_pem);
    const untrusted = try x509_gen.issueLeaf(std.testing.io, alloc, other_ca.key_pair, "other-ca", "client", "spiffe://yoq/service/client", now - 60, now + 86400);
    defer alloc.free(untrusted.cert_pem);
    const untrusted_key = try csr.derKeyToPem(alloc, &untrusted.key_pair.secret_key.toBytes());
    defer alloc.free(untrusted_key);
    try PeerTrustFixture.check(&certs, ca.cert_pem, .require, .present, untrusted.cert_pem, untrusted_key, false);
}

const LifecycleFixture = struct {
    fn connect(fd: posix.fd_t) !posix.fd_t {
        return socket_support.connectToBackend(.{ .ip = "127.0.0.1", .port = try socket_support.boundPort(fd) });
    }

    fn waitActive(proxy: *TlsProxy, expected: usize) !void {
        const deadline = @import("client_transport.zig").Deadline.afterMilliseconds(2000);
        while (proxy.workers.count() != expected) {
            _ = try deadline.remaining();
            try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
        }
    }
};

test "listener lifecycle TLS and HTTP share admission and join idle workers before restart" {
    const alloc = std.testing.allocator;
    var db = try @import("sqlite").Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    var certs = try cert_store.CertStore.initWithKey(&db, alloc, [_]u8{0xAB} ** cert_store.key_length);
    var backends = backend_mod.BackendRegistry.init(alloc);
    defer backends.deinit();
    var proxy = try TlsProxy.init(alloc, &backends, &certs, 0, 0);
    defer proxy.deinit();
    proxy.workers.limit = 2;
    try proxy.challenges.set("lifecycle", "challenge-response");
    proxy.start();

    const http = try LifecycleFixture.connect(proxy.http_fd);
    defer linux_platform.posix.close(http);
    const tls = try LifecycleFixture.connect(proxy.tls_fd);
    defer linux_platform.posix.close(tls);
    try LifecycleFixture.waitActive(&proxy, 2);
    const shed = try LifecycleFixture.connect(proxy.http_fd);
    defer linux_platform.posix.close(shed);
    var byte: [1]u8 = undefined;
    const wire = @import("client_transport.zig");
    try std.testing.expectEqual(@as(usize, 0), try (wire.Stream{ .fd = shed, .deadline = wire.Deadline.afterMilliseconds(2000) }).read(&byte));
    try std.testing.expectEqual(@as(usize, 2), proxy.workers.count());

    // Finishing HTTP releases its slot even while TLS remains idle.
    const request = "GET /.well-known/acme-challenge/lifecycle HTTP/1.1\r\nHost: local\r\n\r\n";
    try (wire.Stream{ .fd = http, .deadline = wire.Deadline.afterMilliseconds(2000) }).writeAll(request);
    var response: [512]u8 = undefined;
    var length: usize = 0;
    const response_wire = wire.Stream{ .fd = http, .deadline = wire.Deadline.afterMilliseconds(2000) };
    while (length < response.len) {
        const n = try response_wire.read(response[length..]);
        if (n == 0) break;
        length += n;
    }
    try std.testing.expect(std.mem.endsWith(u8, response[0..length], "challenge-response"));
    try LifecycleFixture.waitActive(&proxy, 1);
    proxy.stop();
    try std.testing.expectEqual(@as(usize, 0), proxy.workers.count());
    try std.testing.expect(proxy.tls_thread == null and proxy.http_thread == null);

    proxy.start();
    const next = try LifecycleFixture.connect(proxy.http_fd);
    defer linux_platform.posix.close(next);
    try LifecycleFixture.waitActive(&proxy, 1);
    proxy.stop();
    try std.testing.expectEqual(@as(usize, 0), proxy.workers.count());
}

test "listener lifecycle TLS fatal listener state can reopen" {
    const alloc = std.testing.allocator;
    var db = try @import("sqlite").Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();
    var certs = try cert_store.CertStore.initWithKey(&db, alloc, [_]u8{0xAB} ** cert_store.key_length);
    var backends = backend_mod.BackendRegistry.init(alloc);
    defer backends.deinit();
    var proxy = try TlsProxy.init(alloc, &backends, &certs, 0, 0);
    defer proxy.deinit();
    proxy.start();
    _ = std.os.linux.shutdown(proxy.http_fd, 2);
    const deadline = @import("client_transport.zig").Deadline.afterMilliseconds(2000);
    while (proxy.running.load(.acquire)) {
        _ = try deadline.remaining();
        try std.Io.sleep(std.testing.io, .fromMilliseconds(1), .awake);
    }
    proxy.start();
    try std.testing.expect(proxy.running.load(.acquire));
    const client = try LifecycleFixture.connect(proxy.http_fd);
    defer linux_platform.posix.close(client);
    try LifecycleFixture.waitActive(&proxy, 1);
    proxy.stop();
    try std.testing.expectEqual(@as(usize, 0), proxy.workers.count());
}
