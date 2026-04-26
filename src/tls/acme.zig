// acme — ACME client for automatic certificate provisioning
//
// implements the ACME protocol (RFC 8555) for obtaining TLS certificates
// from Let's Encrypt or any ACME-compatible CA. uses HTTP-01 or DNS-01 challenges
// to prove domain ownership.
//
// flow:
//   1. fetch directory (discover API endpoints)
//   2. create account (or use existing)
//   3. create order for a domain
//   4. get authorization + supported challenge
//   5. publish the challenge response
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

const client_runtime = @import("acme/client_runtime.zig");
const issuance_runtime = @import("acme/issuance_runtime.zig");
const json_support = @import("acme/json_support.zig");
const types = @import("acme/types.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const extractJsonString = json_support.extractJsonString;
const extractJsonStringView = json_support.extractJsonStringView;
const extractJsonArray = json_support.extractJsonArray;
const extractHttpChallengeToken = json_support.extractHttpChallengeToken;
const extractHttpChallengeUrl = json_support.extractHttpChallengeUrl;

pub const AcmeError = types.AcmeError;

/// well-known ACME directory URLs
pub const letsencrypt_production = "https://acme-v02.api.letsencrypt.org/directory";
pub const letsencrypt_staging = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// ACME directory endpoints discovered from the directory URL.
pub const Directory = types.Directory;

/// represents an ACME order with its finalize and certificate URLs.
pub const Order = types.Order;

/// HTTP-01 challenge details.
pub const HttpChallenge = types.HttpChallenge;
pub const DnsChallenge = types.DnsChallenge;
pub const ChallengeType = @import("acme/config.zig").ChallengeType;
pub const DnsProvider = @import("acme/config.zig").DnsProvider;
pub const DnsConfig = @import("acme/config.zig").DnsConfig;
pub const ChallengeConfig = @import("acme/config.zig").ChallengeConfig;
pub const ManagedConfig = @import("acme/config.zig").ManagedConfig;
pub const KeyValueRef = @import("acme/config.zig").KeyValueRef;
pub const cloneKeyValueRefs = @import("acme/config.zig").cloneKeyValueRefs;
pub const cloneStringArray = @import("acme/config.zig").cloneStringArray;
pub const freeKeyValueRefs = @import("acme/config.zig").freeKeyValueRefs;
pub const freeStringArray = @import("acme/config.zig").freeStringArray;

/// result of finalizing an ACME order.
/// cert_pem is the PEM certificate chain, key_der is the raw private key.
/// caller is responsible for securely zeroing key_der before freeing.
pub const FinalizeResult = types.FinalizeResult;

/// result of finalizing and exporting an ACME order as PEM.
/// both cert and key are PEM-encoded strings ready for storage.
pub const ExportResult = types.ExportResult;

pub const ChallengeRegistrar = types.ChallengeRegistrar;
pub const IssuanceOptions = types.IssuanceOptions;

pub const AcmeClient = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    directory_url: []const u8,
    directory: ?Directory = null,
    account_key: ?EcdsaP256.KeyPair = null,
    account_url: ?[]const u8 = null,
    http_client: http.Client,

    pub fn init(io: std.Io, allocator: std.mem.Allocator, directory_url: []const u8) AcmeClient {
        return .{
            .allocator = allocator,
            .io = io,
            .directory_url = directory_url,
            .http_client = .{ .io = io, .allocator = allocator },
        };
    }

    pub fn deinit(self: *AcmeClient) void {
        if (self.directory) |d| d.deinit(self.allocator);
        if (self.account_url) |u| self.allocator.free(u);
        self.http_client.deinit();
    }

    /// fetch the ACME directory to discover API endpoints.
    pub fn fetchDirectory(self: *AcmeClient) AcmeError!void {
        return client_runtime.fetchDirectory(self);
    }

    /// get a fresh nonce from the ACME server.
    pub fn fetchNonce(self: *AcmeClient) AcmeError![]u8 {
        return client_runtime.fetchNonce(self);
    }

    /// create a new ACME account or find an existing one.
    pub fn createAccount(self: *AcmeClient, email: []const u8) AcmeError!void {
        return client_runtime.createAccount(self, email);
    }

    /// create an order for a certificate covering the given domain.
    pub fn createOrder(self: *AcmeClient, domain: []const u8) AcmeError!Order {
        return client_runtime.createOrder(self, domain);
    }

    /// get the HTTP-01 challenge for an authorization.
    pub fn getHttpChallenge(self: *AcmeClient, auth_url: []const u8) AcmeError!HttpChallenge {
        return client_runtime.getHttpChallenge(self, auth_url);
    }

    pub fn getDnsChallenge(self: *AcmeClient, auth_url: []const u8, domain: []const u8) AcmeError!DnsChallenge {
        return client_runtime.getDnsChallenge(self, auth_url, domain);
    }

    /// tell the CA we're ready for challenge validation.
    pub fn respondToChallenge(self: *AcmeClient, challenge_url: []const u8) AcmeError!void {
        return client_runtime.respondToChallenge(self, challenge_url);
    }

    pub fn waitForAuthorizationValid(self: *AcmeClient, auth_url: []const u8) AcmeError!void {
        return client_runtime.waitForAuthorizationValid(self, auth_url);
    }

    pub fn waitForOrderReady(self: *AcmeClient, order: *Order) AcmeError!void {
        return client_runtime.waitForOrderReady(self, order);
    }

    /// finalize the order with a CSR and download the certificate.
    /// returns the PEM certificate chain and DER-encoded private key.
    pub fn finalize(
        self: *AcmeClient,
        order: *Order,
        domain: []const u8,
    ) AcmeError!FinalizeResult {
        return client_runtime.finalize(self, order, domain);
    }

    /// finalize the order and export as PEM-encoded cert + key.
    /// combines finalize() + derKeyToPem into one call. this is the
    /// common path used by CLI provisioning, orchestrator startup,
    /// and auto-renewal — all need PEM output for the cert store.
    pub fn finalizeAndExport(
        self: *AcmeClient,
        order: *Order,
        domain: []const u8,
    ) AcmeError!ExportResult {
        return client_runtime.finalizeAndExport(self, order, domain);
    }

    pub fn issueAndExport(self: *AcmeClient, options: IssuanceOptions) AcmeError!ExportResult {
        return issuance_runtime.issueAndExport(self, options);
    }

    // -- HTTP helpers --

    fn httpGet(self: *AcmeClient, url: []const u8) ![]u8 {
        return client_runtime.httpGet(self, url);
    }

    fn httpPost(self: *AcmeClient, url: []const u8, body: []const u8) ![]u8 {
        return client_runtime.httpPost(self, url, body);
    }
};

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

test "extractJsonStringView" {
    const json = "{\"status\":\"ready\",\"certificate\":\"https://acme.example.com/cert/1\"}";
    try std.testing.expectEqualStrings("ready", extractJsonStringView(json, "status").?);
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

test "HttpChallenge deinit" {
    const alloc = std.testing.allocator;

    var ch = HttpChallenge{
        .url = try alloc.dupe(u8, "https://example.com/chall"),
        .token = try alloc.dupe(u8, "token123"),
        .key_authorization = try alloc.dupe(u8, "token123.thumbprint"),
        .allocator = alloc,
    };
    ch.deinit();
}

test "Order deinit frees order url" {
    const alloc = std.testing.allocator;

    var order = Order{
        .order_url = try alloc.dupe(u8, "https://example.com/order/1"),
        .finalize_url = try alloc.dupe(u8, "https://example.com/order/1/finalize"),
        .cert_url = try alloc.dupe(u8, "https://example.com/cert/1"),
        .authorization_urls = try alloc.dupe([]const u8, &[_][]const u8{
            try alloc.dupe(u8, "https://example.com/auth/1"),
        }),
        .allocator = alloc,
    };
    order.deinit();
}

test "AcmeClient init and deinit" {
    const alloc = std.testing.allocator;

    var client = AcmeClient.init(std.testing.io, alloc, letsencrypt_staging);
    client.deinit();
}
