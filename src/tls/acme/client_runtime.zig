const std = @import("std");
const http = std.http;

const csr_mod = @import("../csr.zig");
const jws = @import("../jws.zig");
const json_support = @import("json_support.zig");
const types = @import("types.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub fn fetchDirectory(self: anytype) types.AcmeError!void {
    const body = httpGet(self, self.directory_url) catch return types.AcmeError.DirectoryFetchFailed;
    defer self.allocator.free(body);

    self.directory = .{
        .new_nonce = json_support.extractJsonString(self.allocator, body, "newNonce") catch
            return types.AcmeError.DirectoryFetchFailed,
        .new_account = json_support.extractJsonString(self.allocator, body, "newAccount") catch
            return types.AcmeError.DirectoryFetchFailed,
        .new_order = json_support.extractJsonString(self.allocator, body, "newOrder") catch
            return types.AcmeError.DirectoryFetchFailed,
    };
}

pub fn fetchNonce(self: anytype) types.AcmeError![]u8 {
    const dir = self.directory orelse return types.AcmeError.NonceFetchFailed;
    const body = httpGet(self, dir.new_nonce) catch return types.AcmeError.NonceFetchFailed;
    defer self.allocator.free(body);

    return self.allocator.dupe(u8, "placeholder-nonce") catch return types.AcmeError.AllocFailed;
}

pub fn createAccount(self: anytype, email: []const u8) types.AcmeError!void {
    const dir = self.directory orelse {
        try fetchDirectory(self);
        return createAccount(self, email);
    };

    if (self.account_key == null) {
        self.account_key = EcdsaP256.KeyPair.generate();
    }

    const nonce = try fetchNonce(self);
    defer self.allocator.free(nonce);

    const contact = std.fmt.allocPrint(self.allocator, "mailto:{s}", .{email}) catch
        return types.AcmeError.AllocFailed;
    defer self.allocator.free(contact);

    const payload = std.fmt.allocPrint(
        self.allocator,
        "{{\"termsOfServiceAgreed\":true,\"contact\":[\"{s}\"]}}",
        .{contact},
    ) catch return types.AcmeError.AllocFailed;
    defer self.allocator.free(payload);

    const signed = jws.signJws(
        self.allocator,
        self.account_key.?,
        dir.new_account,
        nonce,
        payload,
        null,
    ) catch return types.AcmeError.AccountCreationFailed;
    defer self.allocator.free(signed);

    const response = httpPost(self, dir.new_account, signed) catch return types.AcmeError.AccountCreationFailed;
    defer self.allocator.free(response);

    self.account_url = json_support.extractJsonString(self.allocator, response, "id") catch blk: {
        break :blk self.allocator.dupe(u8, dir.new_account) catch return types.AcmeError.AllocFailed;
    };
}

pub fn createOrder(self: anytype, domain: []const u8) types.AcmeError!types.Order {
    const dir = self.directory orelse return types.AcmeError.OrderCreationFailed;
    const kid = self.account_url orelse return types.AcmeError.OrderCreationFailed;

    const nonce = try fetchNonce(self);
    defer self.allocator.free(nonce);

    const payload = std.fmt.allocPrint(
        self.allocator,
        "{{\"identifiers\":[{{\"type\":\"dns\",\"value\":\"{s}\"}}]}}",
        .{domain},
    ) catch return types.AcmeError.AllocFailed;
    defer self.allocator.free(payload);

    const signed = jws.signJws(
        self.allocator,
        self.account_key.?,
        dir.new_order,
        nonce,
        payload,
        kid,
    ) catch return types.AcmeError.OrderCreationFailed;
    defer self.allocator.free(signed);

    const response = httpPost(self, dir.new_order, signed) catch return types.AcmeError.OrderCreationFailed;
    defer self.allocator.free(response);

    const finalize_url = json_support.extractJsonString(self.allocator, response, "finalize") catch
        return types.AcmeError.OrderCreationFailed;

    var auth_urls: std.ArrayList([]const u8) = .empty;
    if (json_support.extractJsonArray(response, "authorizations")) |urls_str| {
        var iter = std.mem.splitScalar(u8, urls_str, '"');
        while (iter.next()) |part| {
            if (std.mem.startsWith(u8, part, "http")) {
                const url = self.allocator.dupe(u8, part) catch return types.AcmeError.AllocFailed;
                auth_urls.append(self.allocator, url) catch {
                    self.allocator.free(url);
                    return types.AcmeError.AllocFailed;
                };
            }
        }
    }

    return .{
        .finalize_url = finalize_url,
        .authorization_urls = auth_urls.toOwnedSlice(self.allocator) catch return types.AcmeError.AllocFailed,
        .allocator = self.allocator,
    };
}

pub fn getHttpChallenge(self: anytype, auth_url: []const u8) types.AcmeError!types.Challenge {
    const nonce = try fetchNonce(self);
    defer self.allocator.free(nonce);
    const kid = self.account_url orelse return types.AcmeError.ChallengeFailed;

    const signed = jws.signJws(
        self.allocator,
        self.account_key.?,
        auth_url,
        nonce,
        "",
        kid,
    ) catch return types.AcmeError.AuthorizationFetchFailed;
    defer self.allocator.free(signed);

    const response = httpPost(self, auth_url, signed) catch return types.AcmeError.AuthorizationFetchFailed;
    defer self.allocator.free(response);

    const token = json_support.extractHttpChallengeToken(response) orelse return types.AcmeError.NoHttpChallenge;
    const challenge_url = json_support.extractHttpChallengeUrl(response) orelse return types.AcmeError.NoHttpChallenge;

    const thumbprint = jws.jwkThumbprint(self.allocator, self.account_key.?.public_key) catch
        return types.AcmeError.ChallengeFailed;
    defer self.allocator.free(thumbprint);

    const key_auth = std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ token, thumbprint }) catch
        return types.AcmeError.AllocFailed;

    return .{
        .url = self.allocator.dupe(u8, challenge_url) catch return types.AcmeError.AllocFailed,
        .token = self.allocator.dupe(u8, token) catch return types.AcmeError.AllocFailed,
        .key_authorization = key_auth,
        .allocator = self.allocator,
    };
}

pub fn respondToChallenge(self: anytype, challenge_url: []const u8) types.AcmeError!void {
    const nonce = try fetchNonce(self);
    defer self.allocator.free(nonce);
    const kid = self.account_url orelse return types.AcmeError.ChallengeFailed;

    const signed = jws.signJws(
        self.allocator,
        self.account_key.?,
        challenge_url,
        nonce,
        "{}",
        kid,
    ) catch return types.AcmeError.ChallengeFailed;
    defer self.allocator.free(signed);

    const response = httpPost(self, challenge_url, signed) catch return types.AcmeError.ChallengeFailed;
    self.allocator.free(response);
}

pub fn finalize(self: anytype, finalize_url: []const u8, domain: []const u8) types.AcmeError!types.FinalizeResult {
    const csr_result = csr_mod.generateCsr(self.allocator, domain) catch return types.AcmeError.CsrGenerationFailed;
    defer self.allocator.free(csr_result.csr_der);

    const csr_b64 = jws.base64urlEncode(self.allocator, csr_result.csr_der) catch return types.AcmeError.AllocFailed;
    defer self.allocator.free(csr_b64);

    const nonce = try fetchNonce(self);
    defer self.allocator.free(nonce);
    const kid = self.account_url orelse return types.AcmeError.FinalizeFailed;

    const payload = std.fmt.allocPrint(self.allocator, "{{\"csr\":\"{s}\"}}", .{csr_b64}) catch
        return types.AcmeError.AllocFailed;
    defer self.allocator.free(payload);

    const signed = jws.signJws(
        self.allocator,
        self.account_key.?,
        finalize_url,
        nonce,
        payload,
        kid,
    ) catch return types.AcmeError.FinalizeFailed;
    defer self.allocator.free(signed);

    const response = httpPost(self, finalize_url, signed) catch return types.AcmeError.FinalizeFailed;
    defer self.allocator.free(response);

    const cert_url = json_support.extractJsonString(self.allocator, response, "certificate") catch
        return types.AcmeError.FinalizeFailed;
    defer self.allocator.free(cert_url);

    const cert_pem = httpGet(self, cert_url) catch return types.AcmeError.CertificateDownloadFailed;
    const key_bytes = csr_result.key_pair.secret_key.toBytes();
    const key_der = self.allocator.dupe(u8, &key_bytes) catch return types.AcmeError.AllocFailed;

    return .{
        .cert_pem = cert_pem,
        .key_der = key_der,
        .allocator = self.allocator,
    };
}

pub fn finalizeAndExport(self: anytype, finalize_url: []const u8, domain: []const u8) types.AcmeError!types.ExportResult {
    var result = try finalize(self, finalize_url, domain);

    const key_pem = csr_mod.derKeyToPem(self.allocator, result.key_der) catch {
        result.deinit();
        return types.AcmeError.CsrGenerationFailed;
    };

    std.crypto.secureZero(u8, result.key_der);
    self.allocator.free(result.key_der);

    return .{
        .cert_pem = result.cert_pem,
        .key_pem = key_pem,
        .allocator = self.allocator,
    };
}

pub fn httpGet(self: anytype, url: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(self.allocator);
    defer aw.deinit();

    const result = try self.http_client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &aw.writer,
    });

    if (result.status != .ok and result.status != .created) {
        return error.HttpError;
    }

    return self.allocator.dupe(u8, aw.writer.buffer[0..aw.writer.end]) catch return error.HttpError;
}

pub fn httpPost(self: anytype, url: []const u8, body: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(self.allocator);
    defer aw.deinit();

    const result = try self.http_client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .payload = body,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/jose+json" },
        },
        .response_writer = &aw.writer,
    });

    if (result.status != .ok and result.status != .created) {
        return error.HttpError;
    }

    return self.allocator.dupe(u8, aw.writer.buffer[0..aw.writer.end]) catch return error.HttpError;
}
