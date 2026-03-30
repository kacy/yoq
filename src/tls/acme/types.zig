const std = @import("std");

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

pub const IssuanceOptions = struct {
    domain: []const u8,
    email: []const u8,
    directory_url: []const u8,
    challenge_registrar: ChallengeRegistrar,
};
