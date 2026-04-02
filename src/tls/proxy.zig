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
const http_support = @import("proxy/http_support.zig");
const session_runtime = @import("proxy/session_runtime.zig");
const socket_support = @import("proxy/socket_support.zig");
const sni = @import("sni.zig");
const cert_store = @import("cert_store.zig");
const backend_mod = @import("backend.zig");
const acme_mod = @import("acme.zig");

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
        self.mutex.lock();
        defer self.mutex.unlock();

        return self.tokens.get(token);
    }

    pub fn getOwned(self: *ChallengeStore, alloc: std.mem.Allocator, token: []const u8) !?[]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const value = self.tokens.get(token) orelse return null;
        return try alloc.dupe(u8, value);
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
        errdefer posix.close(tls_fd);

        const http_fd = socket_support.createListenSocket(http_port) catch return ProxyError.SocketFailed;
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
        self.challenges.deinit();
        posix.close(self.tls_fd);
        posix.close(self.http_fd);
    }

    /// start accepting connections on both ports.
    /// spawns two accept loop threads (TLS and HTTP).
    pub fn start(self: *TlsProxy) void {
        if (self.running.load(.acquire)) return;
        self.running.store(true, .release);

        log.info("tls proxy listening on :{d} (tls) and :{d} (http)", .{ self.tls_port, self.http_port });

        self.tls_thread = std.Thread.spawn(.{}, tlsAcceptLoop, .{self}) catch {
            log.err("failed to start TLS accept loop", .{});
            self.running.store(false, .release);
            return;
        };

        self.http_thread = std.Thread.spawn(.{}, httpAcceptLoop, .{self}) catch {
            log.err("failed to start HTTP accept loop", .{});
            self.stop();
            return;
        };

        if (self.renewal_config != null) {
            self.renewal_thread = std.Thread.spawn(.{}, renewalLoop, .{self}) catch {
                log.err("failed to start renewal checker", .{});
                self.stop();
                return;
            };
        }
    }

    /// stop accepting new connections.
    pub fn stop(self: *TlsProxy) void {
        self.running.store(false, .release);
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
    }

    // -- accept loops --

    fn tlsAcceptLoop(self: *TlsProxy) void {
        while (self.running.load(.acquire)) {
            var poll_fds = [_]posix.pollfd{
                .{ .fd = self.tls_fd, .events = posix.POLL.IN, .revents = 0 },
            };
            const poll_result = posix.poll(&poll_fds, 1000) catch continue;
            if (poll_result == 0) continue;

            const client_fd = posix.accept(self.tls_fd, null, null, posix.SOCK.CLOEXEC) catch |err| {
                if (err == error.WouldBlock) continue;
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
            var poll_fds = [_]posix.pollfd{
                .{ .fd = self.http_fd, .events = posix.POLL.IN, .revents = 0 },
            };
            const poll_result = posix.poll(&poll_fds, 1000) catch continue;
            if (poll_result == 0) continue;

            const client_fd = posix.accept(self.http_fd, null, null, posix.SOCK.CLOEXEC) catch |err| {
                if (err == error.WouldBlock) continue;
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
            var elapsed: u64 = 0;
            while (elapsed < config.check_interval_s and self.running.load(.acquire)) {
                const step: u64 = @min(5, config.check_interval_s - elapsed);
                std.Thread.sleep(step * std.time.ns_per_s);
                elapsed += step;
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

        var exported = client.issueAndExport(.{
            .domain = domain,
            .email = config.email,
            .directory_url = config.directory_url,
            .challenge_registrar = challengeRegistrar(&self.challenges),
        }) catch {
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
        var handshake_complete = false;
        defer {
            _ = active_connections.fetchSub(1, .acq_rel);
            if (!handshake_complete) http_support.sendCloseNotify(client_fd);
            posix.close(client_fd);
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

        // perform TLS handshake and proxy traffic
        session_runtime.handleTlsSession(
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

    fn httpConnectionHandler(self: *TlsProxy, client_fd: posix.fd_t) void {
        defer posix.close(client_fd);

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
        _ = posix.write(client_fd, response) catch |e| {
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
        _ = posix.write(client_fd, response) catch |e| {
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
