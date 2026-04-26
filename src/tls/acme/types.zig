const std = @import("std");
const config = @import("config.zig");

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
    NoDnsChallenge,
    InvalidResponse,
    CsrGenerationFailed,
    AllocFailed,
    Timeout,
};

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

pub const Order = struct {
    order_url: []const u8,
    finalize_url: []const u8,
    cert_url: ?[]const u8 = null,
    authorization_urls: []const []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Order) void {
        self.allocator.free(self.order_url);
        self.allocator.free(self.finalize_url);
        if (self.cert_url) |url| self.allocator.free(url);
        for (self.authorization_urls) |url| self.allocator.free(url);
        self.allocator.free(self.authorization_urls);
    }
};

pub const HttpChallenge = struct {
    url: []const u8,
    token: []const u8,
    key_authorization: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *HttpChallenge) void {
        self.allocator.free(self.url);
        self.allocator.free(self.token);
        self.allocator.free(self.key_authorization);
    }
};

pub const DnsChallenge = struct {
    url: []const u8,
    record_name: []const u8,
    record_value: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *DnsChallenge) void {
        self.allocator.free(self.url);
        self.allocator.free(self.record_name);
        self.allocator.free(self.record_value);
    }
};

pub const FinalizeResult = struct {
    cert_pem: []u8,
    key_der: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *FinalizeResult) void {
        self.allocator.free(self.cert_pem);
        std.crypto.secureZero(u8, self.key_der);
        self.allocator.free(self.key_der);
    }
};

pub const ExportResult = struct {
    cert_pem: []u8,
    key_pem: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ExportResult) void {
        self.allocator.free(self.cert_pem);
        std.crypto.secureZero(u8, self.key_pem);
        self.allocator.free(self.key_pem);
    }
};

pub const ChallengeRegistrar = struct {
    ctx: *anyopaque,
    set_fn: *const fn (ctx: *anyopaque, token: []const u8, key_authorization: []const u8) AcmeError!void,
    remove_fn: *const fn (ctx: *anyopaque, token: []const u8) void,

    pub fn set(self: ChallengeRegistrar, token: []const u8, key_authorization: []const u8) AcmeError!void {
        return self.set_fn(self.ctx, token, key_authorization);
    }

    pub fn remove(self: ChallengeRegistrar, token: []const u8) void {
        self.remove_fn(self.ctx, token);
    }
};

pub const DnsSolver = struct {
    ctx: *anyopaque,
    present_fn: *const fn (ctx: *anyopaque, record_name: []const u8, value: []const u8) AcmeError!void,
    cleanup_fn: *const fn (ctx: *anyopaque, record_name: []const u8, value: []const u8) void,

    pub fn present(self: DnsSolver, record_name: []const u8, value: []const u8) AcmeError!void {
        return self.present_fn(self.ctx, record_name, value);
    }

    pub fn cleanup(self: DnsSolver, record_name: []const u8, value: []const u8) void {
        self.cleanup_fn(self.ctx, record_name, value);
    }
};

pub const IssuanceOptions = struct {
    domain: []const u8,
    email: []const u8,
    directory_url: []const u8,
    challenge_type: config.ChallengeType = .http_01,
    challenge_registrar: ?ChallengeRegistrar = null,
    dns_solver: ?DnsSolver = null,
    dns_propagation_timeout_secs: u32 = 300,
    dns_poll_interval_secs: u32 = 5,
};
