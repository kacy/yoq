const std = @import("std");
const platform = @import("platform");
const http = std.http;

const csr_mod = @import("../csr.zig");
const jws = @import("../jws.zig");
const json_support = @import("json_support.zig");
const types = @import("types.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const poll_interval_ns = 2 * std.time.ns_per_s;
const poll_timeout_ns = 60 * std.time.ns_per_s;

const HttpResponse = struct {
    status: http.Status,
    body: []u8,
    replay_nonce: ?[]u8,
    location: ?[]u8,
    allocator: std.mem.Allocator,

    fn deinit(self: *HttpResponse) void {
        self.allocator.free(self.body);
        if (self.replay_nonce) |nonce| self.allocator.free(nonce);
        if (self.location) |location| self.allocator.free(location);
    }
};

const OrderSnapshot = struct {
    status: []u8,
    cert_url: ?[]u8,
    allocator: std.mem.Allocator,

    fn deinit(self: *OrderSnapshot) void {
        self.allocator.free(self.status);
        if (self.cert_url) |cert_url| self.allocator.free(cert_url);
    }
};

pub fn fetchDirectory(self: anytype) types.AcmeError!void {
    var response = httpGetResponse(self, self.directory_url) catch return types.AcmeError.DirectoryFetchFailed;
    defer response.deinit();

    if (response.status != .ok) return types.AcmeError.DirectoryFetchFailed;

    self.directory = .{
        .new_nonce = json_support.extractJsonString(self.allocator, response.body, "newNonce") catch
            return types.AcmeError.DirectoryFetchFailed,
        .new_account = json_support.extractJsonString(self.allocator, response.body, "newAccount") catch
            return types.AcmeError.DirectoryFetchFailed,
        .new_order = json_support.extractJsonString(self.allocator, response.body, "newOrder") catch
            return types.AcmeError.DirectoryFetchFailed,
    };
}

pub fn fetchNonce(self: anytype) types.AcmeError![]u8 {
    const dir = self.directory orelse return types.AcmeError.NonceFetchFailed;
    var response = sendRequest(self, .HEAD, dir.new_nonce, null, null) catch
        return types.AcmeError.NonceFetchFailed;
    defer response.deinit();

    if (response.status != .ok and response.status != .no_content) {
        return types.AcmeError.NonceFetchFailed;
    }

    const nonce = response.replay_nonce orelse return types.AcmeError.NonceFetchFailed;
    return self.allocator.dupe(u8, nonce) catch return types.AcmeError.AllocFailed;
}

pub fn createAccount(self: anytype, email: []const u8) types.AcmeError!void {
    const dir = self.directory orelse {
        try fetchDirectory(self);
        return createAccount(self, email);
    };

    if (self.account_key == null) {
        self.account_key = EcdsaP256.KeyPair.generate(self.io);
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

    var response = httpPostResponse(self, dir.new_account, signed) catch
        return types.AcmeError.AccountCreationFailed;
    defer response.deinit();

    if (response.status != .ok and response.status != .created) {
        return types.AcmeError.AccountCreationFailed;
    }

    const account_url = if (response.location) |location|
        location
    else if (json_support.extractJsonStringView(response.body, "id")) |id|
        id
    else
        return types.AcmeError.AccountCreationFailed;

    if (self.account_url) |old_url| self.allocator.free(old_url);
    self.account_url = self.allocator.dupe(u8, account_url) catch
        return types.AcmeError.AllocFailed;
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

    var response = httpPostResponse(self, dir.new_order, signed) catch
        return types.AcmeError.OrderCreationFailed;
    defer response.deinit();

    if (response.status != .ok and response.status != .created) {
        return types.AcmeError.OrderCreationFailed;
    }

    const order_url = response.location orelse return types.AcmeError.OrderCreationFailed;
    const finalize_url = json_support.extractJsonString(self.allocator, response.body, "finalize") catch
        return types.AcmeError.OrderCreationFailed;

    var auth_urls: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (auth_urls.items) |url| self.allocator.free(url);
        auth_urls.deinit(self.allocator);
        self.allocator.free(finalize_url);
    }

    if (json_support.extractJsonArray(response.body, "authorizations")) |urls_str| {
        var iter = std.mem.splitScalar(u8, urls_str, '"');
        while (iter.next()) |part| {
            if (!std.mem.startsWith(u8, part, "http")) continue;
            const url = self.allocator.dupe(u8, part) catch return types.AcmeError.AllocFailed;
            auth_urls.append(self.allocator, url) catch {
                self.allocator.free(url);
                return types.AcmeError.AllocFailed;
            };
        }
    }

    const cert_url = if (json_support.extractJsonStringView(response.body, "certificate")) |value|
        self.allocator.dupe(u8, value) catch return types.AcmeError.AllocFailed
    else
        null;
    errdefer if (cert_url) |value| self.allocator.free(value);

    return .{
        .order_url = self.allocator.dupe(u8, order_url) catch return types.AcmeError.AllocFailed,
        .finalize_url = finalize_url,
        .cert_url = cert_url,
        .authorization_urls = auth_urls.toOwnedSlice(self.allocator) catch
            return types.AcmeError.AllocFailed,
        .allocator = self.allocator,
    };
}

pub fn getHttpChallenge(self: anytype, auth_url: []const u8) types.AcmeError!types.Challenge {
    var response = postAsGet(self, auth_url, types.AcmeError.AuthorizationFetchFailed) catch
        return types.AcmeError.AuthorizationFetchFailed;
    defer response.deinit();

    if (response.status != .ok) return types.AcmeError.AuthorizationFetchFailed;

    const token = json_support.extractHttpChallengeToken(response.body) orelse
        return types.AcmeError.NoHttpChallenge;
    const challenge_url = json_support.extractHttpChallengeUrl(response.body) orelse
        return types.AcmeError.NoHttpChallenge;

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

    var response = httpPostResponse(self, challenge_url, signed) catch
        return types.AcmeError.ChallengeFailed;
    defer response.deinit();

    if (response.status != .ok and response.status != .accepted) {
        return types.AcmeError.ChallengeFailed;
    }
}

pub fn waitForAuthorizationValid(self: anytype, auth_url: []const u8) types.AcmeError!void {
    const start = platform.nanoTimestamp();
    while (platform.nanoTimestamp() - start < pollTimeoutNs()) {
        var response = postAsGet(self, auth_url, types.AcmeError.AuthorizationFetchFailed) catch
            return types.AcmeError.AuthorizationFetchFailed;
        defer response.deinit();

        if (response.status != .ok) return types.AcmeError.AuthorizationFetchFailed;

        const status = json_support.extractJsonStringView(response.body, "status") orelse
            return types.AcmeError.AuthorizationFetchFailed;
        if (std.mem.eql(u8, status, "valid")) return;
        if (std.mem.eql(u8, status, "invalid")) return types.AcmeError.ChallengeFailed;

        std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromNanoseconds(@intCast(poll_interval_ns)), .awake) catch unreachable;
    }

    return types.AcmeError.Timeout;
}

pub fn waitForOrderReady(self: anytype, order: *types.Order) types.AcmeError!void {
    const start = platform.nanoTimestamp();
    while (platform.nanoTimestamp() - start < pollTimeoutNs()) {
        var snapshot = fetchOrderSnapshot(self, order.order_url, types.AcmeError.OrderCreationFailed) catch
            return types.AcmeError.OrderCreationFailed;
        defer snapshot.deinit();

        if (std.mem.eql(u8, snapshot.status, "ready") or std.mem.eql(u8, snapshot.status, "valid")) {
            if (order.cert_url == null) {
                if (snapshot.cert_url) |cert_url| {
                    order.cert_url = self.allocator.dupe(u8, cert_url) catch return types.AcmeError.AllocFailed;
                }
            }
            return;
        }
        if (std.mem.eql(u8, snapshot.status, "invalid")) return types.AcmeError.OrderCreationFailed;

        std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromNanoseconds(@intCast(poll_interval_ns)), .awake) catch unreachable;
    }

    return types.AcmeError.Timeout;
}

pub fn finalize(self: anytype, order: *types.Order, domain: []const u8) types.AcmeError!types.FinalizeResult {
    const csr_result = csr_mod.generateCsr(self.io, self.allocator, domain) catch return types.AcmeError.CsrGenerationFailed;
    defer self.allocator.free(csr_result.csr_der);

    const csr_b64 = jws.base64urlEncode(self.allocator, csr_result.csr_der) catch
        return types.AcmeError.AllocFailed;
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
        order.finalize_url,
        nonce,
        payload,
        kid,
    ) catch return types.AcmeError.FinalizeFailed;
    defer self.allocator.free(signed);

    var response = httpPostResponse(self, order.finalize_url, signed) catch
        return types.AcmeError.FinalizeFailed;
    defer response.deinit();

    if (response.status != .ok and response.status != .created and response.status != .accepted) {
        return types.AcmeError.FinalizeFailed;
    }

    if (json_support.extractJsonStringView(response.body, "certificate")) |cert_url| {
        if (order.cert_url) |old_url| self.allocator.free(old_url);
        order.cert_url = self.allocator.dupe(u8, cert_url) catch return types.AcmeError.AllocFailed;
    }

    if (order.cert_url == null) {
        try waitForOrderValid(order, self);
    }

    const cert_url = order.cert_url orelse return types.AcmeError.FinalizeFailed;
    var cert_response = httpGetResponse(self, cert_url) catch return types.AcmeError.CertificateDownloadFailed;
    defer cert_response.deinit();

    if (cert_response.status != .ok) return types.AcmeError.CertificateDownloadFailed;

    const cert_pem = self.allocator.dupe(u8, cert_response.body) catch
        return types.AcmeError.AllocFailed;
    const key_bytes = csr_result.key_pair.secret_key.toBytes();
    const key_der = self.allocator.dupe(u8, &key_bytes) catch return types.AcmeError.AllocFailed;

    return .{
        .cert_pem = cert_pem,
        .key_der = key_der,
        .allocator = self.allocator,
    };
}

pub fn finalizeAndExport(self: anytype, order: *types.Order, domain: []const u8) types.AcmeError!types.ExportResult {
    var result = try finalize(self, order, domain);

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
    var response = try httpGetResponse(self, url);
    defer response.deinit();

    if (response.status != .ok and response.status != .created) return error.HttpError;
    return self.allocator.dupe(u8, response.body) catch return error.HttpError;
}

pub fn httpPost(self: anytype, url: []const u8, body: []const u8) ![]u8 {
    var response = try httpPostResponse(self, url, body);
    defer response.deinit();

    if (response.status != .ok and response.status != .created and response.status != .accepted) {
        return error.HttpError;
    }

    return self.allocator.dupe(u8, response.body) catch return error.HttpError;
}

fn waitForOrderValid(order: *types.Order, self: anytype) types.AcmeError!void {
    const start = platform.nanoTimestamp();
    while (platform.nanoTimestamp() - start < pollTimeoutNs()) {
        var snapshot = fetchOrderSnapshot(self, order.order_url, types.AcmeError.FinalizeFailed) catch
            return types.AcmeError.FinalizeFailed;
        defer snapshot.deinit();

        if (snapshot.cert_url) |cert_url| {
            if (order.cert_url) |old_url| self.allocator.free(old_url);
            order.cert_url = self.allocator.dupe(u8, cert_url) catch return types.AcmeError.AllocFailed;
        }

        if (std.mem.eql(u8, snapshot.status, "valid") and order.cert_url != null) return;
        if (std.mem.eql(u8, snapshot.status, "invalid")) return types.AcmeError.FinalizeFailed;

        std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromNanoseconds(@intCast(poll_interval_ns)), .awake) catch unreachable;
    }

    return types.AcmeError.Timeout;
}

fn fetchOrderSnapshot(self: anytype, order_url: []const u8, comptime err_value: types.AcmeError) types.AcmeError!OrderSnapshot {
    var response = postAsGet(self, order_url, err_value) catch return err_value;
    defer response.deinit();

    if (response.status != .ok) return err_value;

    const status = json_support.extractJsonString(self.allocator, response.body, "status") catch
        return err_value;
    errdefer self.allocator.free(status);

    const cert_url = if (json_support.extractJsonStringView(response.body, "certificate")) |value|
        self.allocator.dupe(u8, value) catch return types.AcmeError.AllocFailed
    else
        null;

    return .{
        .status = status,
        .cert_url = cert_url,
        .allocator = self.allocator,
    };
}

fn postAsGet(self: anytype, url: []const u8, comptime err_value: types.AcmeError) types.AcmeError!HttpResponse {
    const nonce = fetchNonce(self) catch return err_value;
    defer self.allocator.free(nonce);
    const kid = self.account_url orelse return err_value;

    const signed = jws.signJws(
        self.allocator,
        self.account_key.?,
        url,
        nonce,
        "",
        kid,
    ) catch return err_value;
    defer self.allocator.free(signed);

    return httpPostResponse(self, url, signed) catch err_value;
}

fn httpGetResponse(self: anytype, url: []const u8) !HttpResponse {
    return sendRequest(self, .GET, url, null, null);
}

fn httpPostResponse(self: anytype, url: []const u8, body: []const u8) !HttpResponse {
    return sendRequest(self, .POST, url, "application/jose+json", body);
}

fn sendRequest(
    self: anytype,
    method: http.Method,
    url: []const u8,
    content_type: ?[]const u8,
    body: ?[]const u8,
) !HttpResponse {
    const uri = try std.Uri.parse(url);
    var req = try self.http_client.request(method, uri, .{
        .redirect_behavior = .not_allowed,
        .keep_alive = false,
        .headers = .{
            .content_type = if (content_type) |value| .{ .override = value } else .default,
        },
    });
    defer req.deinit();

    if (body) |payload| {
        try req.sendBodyComplete(@constCast(payload));
    } else {
        try req.sendBodiless();
    }

    var head_buf: [16384]u8 = undefined;
    var response = try req.receiveHead(&head_buf);

    var transfer_buf: [8192]u8 = undefined;
    const body_reader = response.reader(&transfer_buf);
    var aw: std.Io.Writer.Allocating = .init(self.allocator);
    defer aw.deinit();
    _ = try body_reader.streamRemaining(&aw.writer);

    const replay_nonce = try dupHeader(self.allocator, response.head, "replay-nonce");
    errdefer if (replay_nonce) |nonce| self.allocator.free(nonce);
    const location = try dupHeader(self.allocator, response.head, "location");
    errdefer if (location) |value| self.allocator.free(value);

    return .{
        .status = response.head.status,
        .body = try self.allocator.dupe(u8, aw.writer.buffer[0..aw.writer.end]),
        .replay_nonce = replay_nonce,
        .location = location,
        .allocator = self.allocator,
    };
}

fn dupHeader(allocator: std.mem.Allocator, head: http.Client.Response.Head, name: []const u8) !?[]u8 {
    var iter = head.iterateHeaders();
    while (iter.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, name)) continue;
        return allocator.dupe(u8, header.value) catch return error.OutOfMemory;
    }
    return null;
}

fn pollTimeoutNs() i128 {
    return @as(i128, poll_timeout_ns);
}
