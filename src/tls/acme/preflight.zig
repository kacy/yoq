const std = @import("std");
const sqlite = @import("sqlite");

const config_mod = @import("config.zig");
const secrets = @import("../../state/secrets.zig");

pub const Options = struct {
    http_registrar_available: bool = false,
    secrets_store: ?*secrets.SecretsStore = null,
};

pub fn needsSecretStore(dns: config_mod.DnsConfig) bool {
    return dns.provider != .exec or dns.secret_refs.len > 0;
}

pub fn firstProblem(
    alloc: std.mem.Allocator,
    config: config_mod.ManagedConfig,
    options: Options,
) error{OutOfMemory}!?[]u8 {
    if (config.email.len == 0) return try dupProblem(alloc, "acme email is required");
    if (config.directory_url.len == 0) return try dupProblem(alloc, "acme directory url is required");

    return switch (config.challenge) {
        .http_01 => if (options.http_registrar_available)
            null
        else
            try dupProblem(alloc, "http-01 requires an HTTP challenge registrar"),
        .dns_01 => |dns| firstDnsProblem(alloc, dns, options.secrets_store),
    };
}

fn firstDnsProblem(
    alloc: std.mem.Allocator,
    dns: config_mod.DnsConfig,
    store: ?*secrets.SecretsStore,
) error{OutOfMemory}!?[]u8 {
    if (dns.propagation_timeout_secs == 0)
        return try dupProblem(alloc, "dns propagation timeout must be greater than 0");
    if (dns.poll_interval_secs == 0)
        return try dupProblem(alloc, "dns poll interval must be greater than 0");
    if (dns.poll_interval_secs > dns.propagation_timeout_secs)
        return try dupProblem(alloc, "dns poll interval cannot exceed propagation timeout");

    switch (dns.provider) {
        .cloudflare => {
            if (try requiredSecretProblem(alloc, dns, store, "api_token")) |problem| return problem;
            if (try requiredConfigProblem(alloc, dns, "zone_id")) |problem| return problem;
        },
        .route53 => {
            if (try requiredSecretProblem(alloc, dns, store, "access_key_id")) |problem| return problem;
            if (try requiredSecretProblem(alloc, dns, store, "secret_access_key")) |problem| return problem;
            if (try requiredConfigProblem(alloc, dns, "hosted_zone_id")) |problem| return problem;
        },
        .gcloud => {
            if (try requiredSecretProblem(alloc, dns, store, "access_token")) |problem| return problem;
            if (try requiredConfigProblem(alloc, dns, "project")) |problem| return problem;
            if (try requiredConfigProblem(alloc, dns, "managed_zone")) |problem| return problem;
        },
        .exec => {
            if (dns.hook.len == 0) return try dupProblem(alloc, "exec dns provider requires a hook command");
        },
    }

    return null;
}

fn requiredSecretProblem(
    alloc: std.mem.Allocator,
    dns: config_mod.DnsConfig,
    store: ?*secrets.SecretsStore,
    key: []const u8,
) error{OutOfMemory}!?[]u8 {
    const secret_name = valueForKey(dns.secret_refs, key) orelse
        return std.fmt.allocPrint(alloc, "missing dns secret ref {s}", .{key}) catch return error.OutOfMemory;

    const actual_store = store orelse return null;
    const value = actual_store.get(secret_name) catch |err| {
        if (err == secrets.SecretsError.NotFound) {
            return std.fmt.allocPrint(alloc, "referenced dns secret not found: {s}", .{secret_name}) catch
                return error.OutOfMemory;
        }
        return std.fmt.allocPrint(alloc, "failed to read referenced dns secret: {s}", .{secret_name}) catch
            return error.OutOfMemory;
    };
    defer {
        std.crypto.secureZero(u8, value);
        actual_store.allocator.free(value);
    }

    return null;
}

fn requiredConfigProblem(
    alloc: std.mem.Allocator,
    dns: config_mod.DnsConfig,
    key: []const u8,
) error{OutOfMemory}!?[]u8 {
    if (valueForKey(dns.config, key) != null) return null;
    return std.fmt.allocPrint(alloc, "missing dns config {s}", .{key}) catch return error.OutOfMemory;
}

fn valueForKey(entries: []const config_mod.KeyValueRef, key: []const u8) ?[]const u8 {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.key, key)) return entry.value;
    }
    return null;
}

fn dupProblem(alloc: std.mem.Allocator, problem: []const u8) error{OutOfMemory}![]u8 {
    return alloc.dupe(u8, problem) catch return error.OutOfMemory;
}

test "preflight accepts complete cloudflare dns config" {
    const alloc = std.testing.allocator;
    const config = config_mod.ManagedConfig{
        .email = "ops@example.com",
        .directory_url = "https://acme.example.com/directory",
        .challenge = .{ .dns_01 = .{
            .provider = .cloudflare,
            .secret_refs = &.{.{ .key = "api_token", .value = "cf-token" }},
            .config = &.{.{ .key = "zone_id", .value = "zone-123" }},
        } },
    };

    const problem = try firstProblem(alloc, config, .{});
    try std.testing.expect(problem == null);
}

test "preflight reports missing provider secret ref" {
    const alloc = std.testing.allocator;
    const config = config_mod.ManagedConfig{
        .email = "ops@example.com",
        .directory_url = "https://acme.example.com/directory",
        .challenge = .{ .dns_01 = .{
            .provider = .cloudflare,
            .secret_refs = &.{},
            .config = &.{.{ .key = "zone_id", .value = "zone-123" }},
        } },
    };

    const problem = (try firstProblem(alloc, config, .{})).?;
    defer alloc.free(problem);
    try std.testing.expectEqualStrings("missing dns secret ref api_token", problem);
}

test "preflight reports missing referenced secret" {
    const alloc = std.testing.allocator;
    var db = try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{ .write = true } });
    defer db.deinit();

    const key = [_]u8{0xAB} ** secrets.key_length;
    var store = try secrets.SecretsStore.initWithKey(&db, alloc, key);
    const config = config_mod.ManagedConfig{
        .email = "ops@example.com",
        .directory_url = "https://acme.example.com/directory",
        .challenge = .{ .dns_01 = .{
            .provider = .cloudflare,
            .secret_refs = &.{.{ .key = "api_token", .value = "cf-token" }},
            .config = &.{.{ .key = "zone_id", .value = "zone-123" }},
        } },
    };

    const problem = (try firstProblem(alloc, config, .{ .secrets_store = &store })).?;
    defer alloc.free(problem);
    try std.testing.expectEqualStrings("referenced dns secret not found: cf-token", problem);
}

test "preflight reports missing provider config" {
    const alloc = std.testing.allocator;
    const config = config_mod.ManagedConfig{
        .email = "ops@example.com",
        .directory_url = "https://acme.example.com/directory",
        .challenge = .{ .dns_01 = .{
            .provider = .gcloud,
            .secret_refs = &.{.{ .key = "access_token", .value = "gcloud-token" }},
            .config = &.{.{ .key = "project", .value = "demo" }},
        } },
    };

    const problem = (try firstProblem(alloc, config, .{})).?;
    defer alloc.free(problem);
    try std.testing.expectEqualStrings("missing dns config managed_zone", problem);
}

test "preflight reports exec without hook" {
    const alloc = std.testing.allocator;
    const config = config_mod.ManagedConfig{
        .email = "ops@example.com",
        .directory_url = "https://acme.example.com/directory",
        .challenge = .{ .dns_01 = .{
            .provider = .exec,
        } },
    };

    const problem = (try firstProblem(alloc, config, .{})).?;
    defer alloc.free(problem);
    try std.testing.expectEqualStrings("exec dns provider requires a hook command", problem);
}

test "preflight reports invalid dns intervals" {
    const alloc = std.testing.allocator;
    const config = config_mod.ManagedConfig{
        .email = "ops@example.com",
        .directory_url = "https://acme.example.com/directory",
        .challenge = .{ .dns_01 = .{
            .provider = .exec,
            .hook = &.{"./hook"},
            .propagation_timeout_secs = 5,
            .poll_interval_secs = 10,
        } },
    };

    const problem = (try firstProblem(alloc, config, .{})).?;
    defer alloc.free(problem);
    try std.testing.expectEqualStrings("dns poll interval cannot exceed propagation timeout", problem);
}
