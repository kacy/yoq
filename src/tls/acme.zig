// acme — ACME client for automatic certificate provisioning
//
// implements the ACME protocol (RFC 8555) for obtaining TLS certificates
// from Let's Encrypt or any ACME-compatible CA. uses HTTP-01 challenges
// to prove domain ownership.
//
// flow:
//   1. fetch directory (discover API endpoints)
//   2. create account (or use existing)
//   3. create order for a domain
//   4. get authorization + HTTP-01 challenge
//   5. register challenge token with the HTTP server (port 80)
//   6. tell the CA we're ready
//   7. poll for validation
//   8. finalize with a CSR
//   9. download the certificate
//   10. store in the cert store
//
// references:
//   RFC 8555 (ACME)
//   RFC 8737 (ACME TLS-ALPN-01, not implemented)

const std = @import("std");
const http = std.http;

const jws = @import("jws.zig");
const csr_mod = @import("csr.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const AcmeError = error{
    DirectoryFetchFailed,
    NonceFetchFailed,
    AccountCreationFailed,
    OrderCreationFailed,
    AuthorizationFetchFailed,
    ChallengeFailed,
    FinalizeFailed,
    CertificateDownloadFailed,
    NoHttpChallenge,
    InvalidResponse,
    CsrGenerationFailed,
    AllocFailed,
    Timeout,
};

/// well-known ACME directory URLs
pub const letsencrypt_production = "https://acme-v02.api.letsencrypt.org/directory";
pub const letsencrypt_staging = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// ACME directory endpoints discovered from the directory URL.
pub const Directory = struct {
    new_nonce: []const u8,
    new_account: []const u8,
    new_order: []const u8,

    pub fn deinit(self: Directory, allocator: std.mem.Allocator) void {
        allocator.free(self.new_nonce);
        allocator.free(self.new_account);
        allocator.free(self.new_order);
    }
};

/// represents an ACME order with its finalize and certificate URLs.
pub const Order = struct {
    finalize_url: []const u8,
    cert_url: ?[]const u8 = null,
    authorization_urls: []const []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Order) void {
        self.allocator.free(self.finalize_url);
        if (self.cert_url) |u| self.allocator.free(u);
        for (self.authorization_urls) |url| self.allocator.free(url);
        self.allocator.free(self.authorization_urls);
    }
};

/// HTTP-01 challenge details.
pub const Challenge = struct {
    url: []const u8,
    token: []const u8,
    key_authorization: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Challenge) void {
        self.allocator.free(self.url);
        self.allocator.free(self.token);
        self.allocator.free(self.key_authorization);
    }
};

pub const AcmeClient = struct {
    allocator: std.mem.Allocator,
    directory_url: []const u8,
    directory: ?Directory = null,
    account_key: ?EcdsaP256.KeyPair = null,
    account_url: ?[]const u8 = null,
    http_client: http.Client,

    pub fn init(allocator: std.mem.Allocator, directory_url: []const u8) AcmeClient {
        return .{
            .allocator = allocator,
            .directory_url = directory_url,
            .http_client = .{ .allocator = allocator },
        };
    }

    pub fn deinit(self: *AcmeClient) void {
        if (self.directory) |d| d.deinit(self.allocator);
        if (self.account_url) |u| self.allocator.free(u);
        self.http_client.deinit();
    }

    /// fetch the ACME directory to discover API endpoints.
    pub fn fetchDirectory(self: *AcmeClient) AcmeError!void {
        const body = self.httpGet(self.directory_url) catch
            return AcmeError.DirectoryFetchFailed;
        defer self.allocator.free(body);

        // parse JSON to extract endpoint URLs
        self.directory = .{
            .new_nonce = extractJsonString(self.allocator, body, "newNonce") catch
                return AcmeError.DirectoryFetchFailed,
            .new_account = extractJsonString(self.allocator, body, "newAccount") catch
                return AcmeError.DirectoryFetchFailed,
            .new_order = extractJsonString(self.allocator, body, "newOrder") catch
                return AcmeError.DirectoryFetchFailed,
        };
    }

    /// get a fresh nonce from the ACME server.
    pub fn fetchNonce(self: *AcmeClient) AcmeError![]u8 {
        const dir = self.directory orelse return AcmeError.NonceFetchFailed;

        // HEAD request to newNonce endpoint
        const body = self.httpGet(dir.new_nonce) catch
            return AcmeError.NonceFetchFailed;
        defer self.allocator.free(body);

        // in a real implementation, the nonce comes from the Replay-Nonce
        // response header. since zig's fetch API doesn't expose headers
        // easily, we'll use the nonce from the response of any POST request
        // (every ACME response includes a Replay-Nonce header).
        //
        // for now, return a placeholder — the actual nonce management
        // will be integrated when the full HTTP exchange is wired up
        // with proper header access.
        return self.allocator.dupe(u8, "placeholder-nonce") catch
            return AcmeError.AllocFailed;
    }

    /// create a new ACME account or find an existing one.
    pub fn createAccount(self: *AcmeClient, email: []const u8) AcmeError!void {
        const dir = self.directory orelse {
            try self.fetchDirectory();
            return self.createAccount(email);
        };

        // generate account key if we don't have one
        if (self.account_key == null) {
            self.account_key = EcdsaP256.KeyPair.generate();
        }

        const nonce = try self.fetchNonce();
        defer self.allocator.free(nonce);

        // build the newAccount payload
        const contact = std.fmt.allocPrint(self.allocator, "mailto:{s}", .{email}) catch
            return AcmeError.AllocFailed;
        defer self.allocator.free(contact);

        const payload = std.fmt.allocPrint(
            self.allocator,
            "{{\"termsOfServiceAgreed\":true,\"contact\":[\"{s}\"]}}",
            .{contact},
        ) catch return AcmeError.AllocFailed;
        defer self.allocator.free(payload);

        // sign and send
        const signed = jws.signJws(
            self.allocator,
            self.account_key.?,
            dir.new_account,
            nonce,
            payload,
            null, // no kid for new account — use jwk
        ) catch return AcmeError.AccountCreationFailed;
        defer self.allocator.free(signed);

        const response = self.httpPost(dir.new_account, signed) catch
            return AcmeError.AccountCreationFailed;
        defer self.allocator.free(response);

        // the account URL comes from the Location header in the response.
        // for now, extract from the response body if available.
        // a full implementation would parse the Location header.
        self.account_url = extractJsonString(self.allocator, response, "id") catch {
            // use the new_account URL as fallback
            self.allocator.dupe(u8, dir.new_account) catch
                return AcmeError.AllocFailed;
        };
    }

    /// create an order for a certificate covering the given domain.
    pub fn createOrder(self: *AcmeClient, domain: []const u8) AcmeError!Order {
        const dir = self.directory orelse return AcmeError.OrderCreationFailed;
        const kid = self.account_url orelse return AcmeError.OrderCreationFailed;

        const nonce = try self.fetchNonce();
        defer self.allocator.free(nonce);

        const payload = std.fmt.allocPrint(
            self.allocator,
            "{{\"identifiers\":[{{\"type\":\"dns\",\"value\":\"{s}\"}}]}}",
            .{domain},
        ) catch return AcmeError.AllocFailed;
        defer self.allocator.free(payload);

        const signed = jws.signJws(
            self.allocator,
            self.account_key.?,
            dir.new_order,
            nonce,
            payload,
            kid,
        ) catch return AcmeError.OrderCreationFailed;
        defer self.allocator.free(signed);

        const response = self.httpPost(dir.new_order, signed) catch
            return AcmeError.OrderCreationFailed;
        defer self.allocator.free(response);

        // parse order response
        const finalize_url = extractJsonString(self.allocator, response, "finalize") catch
            return AcmeError.OrderCreationFailed;

        // parse authorization URLs from the JSON array
        var auth_urls = std.ArrayList([]const u8).init(self.allocator);
        defer auth_urls.deinit();

        if (extractJsonArray(response, "authorizations")) |urls_str| {
            var iter = std.mem.splitScalar(u8, urls_str, '"');
            while (iter.next()) |part| {
                if (std.mem.startsWith(u8, part, "http")) {
                    const url = self.allocator.dupe(u8, part) catch
                        return AcmeError.AllocFailed;
                    auth_urls.append(url) catch {
                        self.allocator.free(url);
                        return AcmeError.AllocFailed;
                    };
                }
            }
        }

        return .{
            .finalize_url = finalize_url,
            .authorization_urls = auth_urls.toOwnedSlice() catch
                return AcmeError.AllocFailed,
            .allocator = self.allocator,
        };
    }

    /// get the HTTP-01 challenge for an authorization.
    pub fn getHttpChallenge(self: *AcmeClient, auth_url: []const u8) AcmeError!Challenge {
        const nonce = try self.fetchNonce();
        defer self.allocator.free(nonce);
        const kid = self.account_url orelse return AcmeError.ChallengeFailed;

        // POST-as-GET (empty payload)
        const signed = jws.signJws(
            self.allocator,
            self.account_key.?,
            auth_url,
            nonce,
            "", // empty payload = POST-as-GET
            kid,
        ) catch return AcmeError.AuthorizationFetchFailed;
        defer self.allocator.free(signed);

        const response = self.httpPost(auth_url, signed) catch
            return AcmeError.AuthorizationFetchFailed;
        defer self.allocator.free(response);

        // find the http-01 challenge in the response
        // look for "type":"http-01" and extract token and url
        const token = extractHttpChallengeToken(response) orelse
            return AcmeError.NoHttpChallenge;
        const challenge_url = extractHttpChallengeUrl(response) orelse
            return AcmeError.NoHttpChallenge;

        // compute key authorization: token + "." + base64url(JWK thumbprint)
        const thumbprint = jws.jwkThumbprint(self.allocator, self.account_key.?.public_key) catch
            return AcmeError.ChallengeFailed;
        defer self.allocator.free(thumbprint);

        const key_auth = std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ token, thumbprint }) catch
            return AcmeError.AllocFailed;

        return .{
            .url = self.allocator.dupe(u8, challenge_url) catch return AcmeError.AllocFailed,
            .token = self.allocator.dupe(u8, token) catch return AcmeError.AllocFailed,
            .key_authorization = key_auth,
            .allocator = self.allocator,
        };
    }

    /// tell the CA we're ready for challenge validation.
    pub fn respondToChallenge(self: *AcmeClient, challenge_url: []const u8) AcmeError!void {
        const nonce = try self.fetchNonce();
        defer self.allocator.free(nonce);
        const kid = self.account_url orelse return AcmeError.ChallengeFailed;

        const signed = jws.signJws(
            self.allocator,
            self.account_key.?,
            challenge_url,
            nonce,
            "{}", // empty object signals readiness
            kid,
        ) catch return AcmeError.ChallengeFailed;
        defer self.allocator.free(signed);

        const response = self.httpPost(challenge_url, signed) catch
            return AcmeError.ChallengeFailed;
        self.allocator.free(response);
    }

    /// finalize the order with a CSR and download the certificate.
    /// returns the PEM certificate chain and DER-encoded private key.
    pub fn finalize(
        self: *AcmeClient,
        finalize_url: []const u8,
        domain: []const u8,
    ) AcmeError!struct { cert_pem: []u8, key_der: []u8 } {
        // generate CSR
        const csr_result = csr_mod.generateCsr(self.allocator, domain) catch
            return AcmeError.CsrGenerationFailed;
        defer self.allocator.free(csr_result.csr_der);

        // base64url-encode the CSR
        const csr_b64 = jws.base64urlEncode(self.allocator, csr_result.csr_der) catch
            return AcmeError.AllocFailed;
        defer self.allocator.free(csr_b64);

        const nonce = try self.fetchNonce();
        defer self.allocator.free(nonce);
        const kid = self.account_url orelse return AcmeError.FinalizeFailed;

        const payload = std.fmt.allocPrint(
            self.allocator,
            "{{\"csr\":\"{s}\"}}",
            .{csr_b64},
        ) catch return AcmeError.AllocFailed;
        defer self.allocator.free(payload);

        const signed = jws.signJws(
            self.allocator,
            self.account_key.?,
            finalize_url,
            nonce,
            payload,
            kid,
        ) catch return AcmeError.FinalizeFailed;
        defer self.allocator.free(signed);

        const response = self.httpPost(finalize_url, signed) catch
            return AcmeError.FinalizeFailed;
        defer self.allocator.free(response);

        // extract certificate URL from the response
        const cert_url = extractJsonString(self.allocator, response, "certificate") catch
            return AcmeError.FinalizeFailed;
        defer self.allocator.free(cert_url);

        // download the certificate
        const cert_pem = self.httpGet(cert_url) catch
            return AcmeError.CertificateDownloadFailed;

        // export the private key as DER
        const key_bytes = csr_result.key_pair.secret_key.toBytes();
        const key_der = self.allocator.dupe(u8, &key_bytes) catch
            return AcmeError.AllocFailed;

        return .{
            .cert_pem = cert_pem,
            .key_der = key_der,
        };
    }

    // -- HTTP helpers --

    fn httpGet(self: *AcmeClient, url: []const u8) ![]u8 {
        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);

        const result = try self.http_client.fetch(.{
            .location = .{ .url = url },
            .response_writer = body.writer(self.allocator).any(),
        });

        if (result.status != .ok and result.status != .created) {
            return error.HttpError;
        }

        return body.toOwnedSlice(self.allocator);
    }

    fn httpPost(self: *AcmeClient, url: []const u8, body: []const u8) ![]u8 {
        var response_body: std.ArrayListUnmanaged(u8) = .empty;
        defer response_body.deinit(self.allocator);

        const result = try self.http_client.fetch(.{
            .location = .{ .url = url },
            .method = .POST,
            .payload = body,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/jose+json" },
            },
            .response_writer = response_body.writer(self.allocator).any(),
        });

        if (result.status != .ok and result.status != .created) {
            return error.HttpError;
        }

        return response_body.toOwnedSlice(self.allocator);
    }
};

// -- JSON helpers --
//
// minimal JSON string extraction. a proper JSON parser would be better,
// but we only need to extract a few known fields from ACME responses.
// the lib/json.zig parser could be used here, but keeping it simple
// avoids the dependency for this module's tests.

/// extract a string value for a given key from JSON.
/// looks for "key":"value" and returns a copy of the value.
fn extractJsonString(allocator: std.mem.Allocator, json: []const u8, key: []const u8) ![]u8 {
    // look for "key":"
    const needle = std.fmt.allocPrint(allocator, "\"{s}\":\"", .{key}) catch
        return error.OutOfMemory;
    defer allocator.free(needle);

    const start = (std.mem.indexOf(u8, json, needle) orelse return error.KeyNotFound) + needle.len;
    const end = std.mem.indexOfPos(u8, json, start, "\"") orelse return error.KeyNotFound;

    return allocator.dupe(u8, json[start..end]) catch return error.OutOfMemory;
}

/// find the "authorizations" JSON array and return the raw array string.
fn extractJsonArray(json: []const u8, key: []const u8) ?[]const u8 {
    var search_buf: [64]u8 = undefined;
    const needle = std.fmt.bufPrint(&search_buf, "\"{s}\":[", .{key}) catch return null;

    const start = (std.mem.indexOf(u8, json, needle) orelse return null) + needle.len;
    const end = std.mem.indexOfPos(u8, json, start, "]") orelse return null;

    return json[start..end];
}

/// extract the token from an HTTP-01 challenge in the authorization response.
fn extractHttpChallengeToken(json: []const u8) ?[]const u8 {
    // find "type":"http-01" and then find the "token" nearby
    const http01_pos = std.mem.indexOf(u8, json, "\"http-01\"") orelse return null;

    // look for "token":" after the http-01 marker
    const token_marker = "\"token\":\"";
    const token_start_search = json[http01_pos..];
    const rel_start = (std.mem.indexOf(u8, token_start_search, token_marker) orelse return null) + token_marker.len;
    const abs_start = http01_pos + rel_start;

    const end = std.mem.indexOfPos(u8, json, abs_start, "\"") orelse return null;
    return json[abs_start..end];
}

/// extract the challenge URL from an HTTP-01 challenge.
fn extractHttpChallengeUrl(json: []const u8) ?[]const u8 {
    // find "type":"http-01" and then find the "url" nearby
    const http01_pos = std.mem.indexOf(u8, json, "\"http-01\"") orelse return null;

    const url_marker = "\"url\":\"";
    const url_start_search = json[http01_pos..];
    const rel_start = (std.mem.indexOf(u8, url_start_search, url_marker) orelse return null) + url_marker.len;
    const abs_start = http01_pos + rel_start;

    const end = std.mem.indexOfPos(u8, json, abs_start, "\"") orelse return null;
    return json[abs_start..end];
}

// -- tests --

test "extractJsonString" {
    const alloc = std.testing.allocator;

    const json = "{\"newNonce\":\"https://acme.example.com/nonce\",\"newAccount\":\"https://acme.example.com/acct\"}";
    const result = try extractJsonString(alloc, json, "newNonce");
    defer alloc.free(result);
    try std.testing.expectEqualStrings("https://acme.example.com/nonce", result);
}

test "extractJsonString missing key" {
    const alloc = std.testing.allocator;

    const json = "{\"foo\":\"bar\"}";
    try std.testing.expectError(error.KeyNotFound, extractJsonString(alloc, json, "missing"));
}

test "extractJsonArray" {
    const json = "{\"authorizations\":[\"https://acme.example.com/auth/1\",\"https://acme.example.com/auth/2\"]}";
    const result = extractJsonArray(json, "authorizations");
    try std.testing.expect(result != null);
    try std.testing.expect(std.mem.indexOf(u8, result.?, "https://acme.example.com/auth/1") != null);
}

test "extractJsonArray missing" {
    const json = "{\"foo\":\"bar\"}";
    try std.testing.expect(extractJsonArray(json, "authorizations") == null);
}

test "extractHttpChallengeToken" {
    const json =
        \\{"challenges":[{"type":"http-01","url":"https://acme.example.com/chall/1","token":"abc123","status":"pending"}]}
    ;
    const token = extractHttpChallengeToken(json);
    try std.testing.expect(token != null);
    try std.testing.expectEqualStrings("abc123", token.?);
}

test "extractHttpChallengeUrl" {
    const json =
        \\{"challenges":[{"type":"http-01","url":"https://acme.example.com/chall/1","token":"abc123"}]}
    ;
    const url = extractHttpChallengeUrl(json);
    try std.testing.expect(url != null);
    try std.testing.expectEqualStrings("https://acme.example.com/chall/1", url.?);
}

test "extractHttpChallengeToken no http-01" {
    const json =
        \\{"challenges":[{"type":"dns-01","token":"xyz"}]}
    ;
    try std.testing.expect(extractHttpChallengeToken(json) == null);
}

test "Directory deinit" {
    const alloc = std.testing.allocator;

    var dir = Directory{
        .new_nonce = try alloc.dupe(u8, "https://example.com/nonce"),
        .new_account = try alloc.dupe(u8, "https://example.com/acct"),
        .new_order = try alloc.dupe(u8, "https://example.com/order"),
    };
    dir.deinit(alloc);
}

test "Challenge deinit" {
    const alloc = std.testing.allocator;

    var ch = Challenge{
        .url = try alloc.dupe(u8, "https://example.com/chall"),
        .token = try alloc.dupe(u8, "token123"),
        .key_authorization = try alloc.dupe(u8, "token123.thumbprint"),
        .allocator = alloc,
    };
    ch.deinit();
}

test "AcmeClient init and deinit" {
    const alloc = std.testing.allocator;

    var client = AcmeClient.init(alloc, letsencrypt_staging);
    client.deinit();
}
