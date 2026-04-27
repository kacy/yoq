const std = @import("std");

const cli = @import("../../lib/cli.zig");
const acme = @import("../acme.zig");
const managed_runtime = @import("../acme/managed_runtime.zig");
const cert_store = @import("../cert_store.zig");
const challenge_server = @import("../challenge_server.zig");
const proxy = @import("../proxy.zig");
const common = @import("common.zig");
const store_support = @import("store_support.zig");

const write = cli.write;
const writeErr = cli.writeErr;

pub fn provision(io: std.Io, args: *std.process.Args.Iterator, alloc: std.mem.Allocator) common.TlsCommandsError!void {
    const parsed = parseArgs(alloc, args) catch |err| return err;
    defer parsed.deinit(alloc);
    try runAcmeCommand(io, alloc, parsed, false);
}

pub fn renew(io: std.Io, args: *std.process.Args.Iterator, alloc: std.mem.Allocator) common.TlsCommandsError!void {
    const parsed = parseArgs(alloc, args) catch |err| return err;
    defer parsed.deinit(alloc);
    try runAcmeCommand(io, alloc, parsed, true);
}

const BorrowedKeyValue = acme.KeyValueRef;

const ParsedArgs = struct {
    domain: []const u8,
    email: ?[]const u8,
    directory_url: []const u8,
    dns_provider: ?acme.DnsProvider = null,
    dns_secret_refs: []const BorrowedKeyValue,
    dns_config: []const BorrowedKeyValue,
    dns_hook: []const []const u8,
    propagation_timeout_secs: ?u32 = null,
    poll_interval_secs: ?u32 = null,

    fn deinit(self: ParsedArgs, alloc: std.mem.Allocator) void {
        alloc.free(self.dns_secret_refs);
        alloc.free(self.dns_config);
        alloc.free(self.dns_hook);
    }
};

fn parseArgs(alloc: std.mem.Allocator, args: *std.process.Args.Iterator) common.TlsCommandsError!ParsedArgs {
    var domain: ?[]const u8 = null;
    var email: ?[]const u8 = null;
    var directory_url: []const u8 = acme.letsencrypt_production;
    var provider: ?acme.DnsProvider = null;
    var dns_secret_refs: std.ArrayListUnmanaged(BorrowedKeyValue) = .empty;
    errdefer dns_secret_refs.deinit(alloc);
    var dns_config: std.ArrayListUnmanaged(BorrowedKeyValue) = .empty;
    errdefer dns_config.deinit(alloc);
    var dns_hook: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer dns_hook.deinit(alloc);
    var propagation_timeout_secs: ?u32 = null;
    var poll_interval_secs: ?u32 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--email")) {
            email = args.next() orelse return invalidArg("--email requires a value\n");
            continue;
        }
        if (std.mem.eql(u8, arg, "--staging")) {
            directory_url = acme.letsencrypt_staging;
            continue;
        }
        if (std.mem.eql(u8, arg, "--dns-provider")) {
            const value = args.next() orelse return invalidArg("--dns-provider requires a value\n");
            provider = parseDnsProvider(value) orelse
                return invalidArg("--dns-provider must be cloudflare, route53, gcloud, or exec\n");
            continue;
        }
        if (std.mem.eql(u8, arg, "--dns-secret")) {
            const value = args.next() orelse return invalidArg("--dns-secret requires key=name\n");
            appendKeyValue(alloc, &dns_secret_refs, value) catch |err| return switch (err) {
                error.InvalidKeyValue => invalidArg("--dns-secret requires key=name\n"),
                error.OutOfMemory => common.TlsCommandsError.OutOfMemory,
            };
            continue;
        }
        if (std.mem.eql(u8, arg, "--dns-config")) {
            const value = args.next() orelse return invalidArg("--dns-config requires key=value\n");
            appendKeyValue(alloc, &dns_config, value) catch |err| return switch (err) {
                error.InvalidKeyValue => invalidArg("--dns-config requires key=value\n"),
                error.OutOfMemory => common.TlsCommandsError.OutOfMemory,
            };
            continue;
        }
        if (std.mem.eql(u8, arg, "--dns-hook")) {
            const value = args.next() orelse return invalidArg("--dns-hook requires a value\n");
            dns_hook.append(alloc, value) catch return common.TlsCommandsError.OutOfMemory;
            continue;
        }
        if (std.mem.eql(u8, arg, "--dns-hook-arg")) {
            const value = args.next() orelse return invalidArg("--dns-hook-arg requires a value\n");
            dns_hook.append(alloc, value) catch return common.TlsCommandsError.OutOfMemory;
            continue;
        }
        if (std.mem.eql(u8, arg, "--dns-propagation-timeout-secs")) {
            const value = args.next() orelse return invalidArg("--dns-propagation-timeout-secs requires a value\n");
            propagation_timeout_secs = std.fmt.parseInt(u32, value, 10) catch
                return invalidArg("--dns-propagation-timeout-secs must be an integer\n");
            continue;
        }
        if (std.mem.eql(u8, arg, "--dns-poll-interval-secs")) {
            const value = args.next() orelse return invalidArg("--dns-poll-interval-secs requires a value\n");
            poll_interval_secs = std.fmt.parseInt(u32, value, 10) catch
                return invalidArg("--dns-poll-interval-secs must be an integer\n");
            continue;
        }
        if (domain == null) {
            domain = arg;
            continue;
        }
        return invalidArgFmt("unexpected argument: {s}\n", .{arg});
    }

    return .{
        .domain = domain orelse return invalidArg("domain is required\n"),
        .email = email,
        .directory_url = directory_url,
        .dns_provider = provider,
        .dns_secret_refs = dns_secret_refs.toOwnedSlice(alloc) catch return common.TlsCommandsError.OutOfMemory,
        .dns_config = dns_config.toOwnedSlice(alloc) catch return common.TlsCommandsError.OutOfMemory,
        .dns_hook = dns_hook.toOwnedSlice(alloc) catch return common.TlsCommandsError.OutOfMemory,
        .propagation_timeout_secs = propagation_timeout_secs,
        .poll_interval_secs = poll_interval_secs,
    };
}

fn runAcmeCommand(
    io: std.Io,
    alloc: std.mem.Allocator,
    parsed: ParsedArgs,
    require_existing: bool,
) common.TlsCommandsError!void {
    var opened = store_support.openCertStore(alloc) catch |err|
        return store_support.reportOpenStoreError(err);
    defer store_support.closeCertStore(alloc, &opened);

    if (require_existing) {
        const existing = opened.store.get(parsed.domain) catch |err| {
            if (err == cert_store.CertError.NotFound) {
                writeErr("certificate not found: {s}\n", .{parsed.domain});
                return common.TlsCommandsError.CertificateNotFound;
            }
            writeErr("failed to read existing certificate\n", .{});
            return common.TlsCommandsError.StoreFailed;
        };
        defer {
            alloc.free(existing.cert_pem);
            std.crypto.secureZero(u8, existing.key_pem);
            alloc.free(existing.key_pem);
        }
    }

    const existing_config = opened.store.getAcmeConfig(parsed.domain) catch |err| blk: {
        if (err == cert_store.CertError.NotFound) break :blk null;
        writeErr("failed to read existing ACME configuration\n", .{});
        return common.TlsCommandsError.StoreFailed;
    };
    defer if (existing_config) |cfg| cfg.deinit(alloc);

    const account_email = resolveAccountEmail(
        alloc,
        parsed.domain,
        parsed.email orelse if (existing_config) |cfg| cfg.email else null,
    ) catch return common.TlsCommandsError.OutOfMemory;
    defer alloc.free(account_email);

    var managed_config = buildManagedConfig(
        alloc,
        parsed,
        existing_config,
        account_email,
    ) catch {
        writeErr("invalid ACME DNS configuration\n", .{});
        return common.TlsCommandsError.InvalidArgument;
    };
    defer managed_config.deinit(alloc);

    if (try managed_runtime.preflightProblem(alloc, opened.db, managed_config, true)) |problem| {
        defer alloc.free(problem);
        writeErr("invalid ACME configuration: {s}\n", .{problem});
        return common.TlsCommandsError.InvalidArgument;
    }

    var client = acme.AcmeClient.init(io, alloc, managed_config.directory_url);
    defer client.deinit();

    var exported = switch (managed_config.challengeType()) {
        .http_01 => issueHttp01(io, alloc, &client, parsed.domain, managed_config),
        .dns_01 => managed_runtime.issueAndExport(io, alloc, opened.db, &client, parsed.domain, managed_config, null),
    } catch |err| {
        writeErr("acme certificate issuance failed: {}\n", .{err});
        return common.TlsCommandsError.AcmeFailed;
    };
    defer exported.deinit();

    opened.store.install(parsed.domain, exported.cert_pem, exported.key_pem, "acme") catch {
        writeErr("failed to store certificate\n", .{});
        return common.TlsCommandsError.StoreFailed;
    };
    opened.store.setAcmeConfig(parsed.domain, managed_config) catch {
        writeErr("failed to store ACME renewal metadata\n", .{});
        return common.TlsCommandsError.StoreFailed;
    };

    write("{s}\n", .{parsed.domain});
}

fn issueHttp01(
    io: std.Io,
    alloc: std.mem.Allocator,
    client: *acme.AcmeClient,
    domain: []const u8,
    managed_config: acme.ManagedConfig,
) common.TlsCommandsError!acme.ExportResult {
    var challenges = proxy.ChallengeStore.init(alloc);
    defer challenges.deinit();

    var server = challenge_server.ChallengeServer.init(&challenges, 80) catch {
        writeErr("failed to bind port 80 for ACME HTTP-01 challenge handling\n", .{});
        return common.TlsCommandsError.NetworkFailed;
    };
    defer server.deinit();
    server.start();

    return managed_runtime.issueAndExport(io, alloc, null, client, domain, managed_config, challengeRegistrar(&challenges)) catch
        return common.TlsCommandsError.AcmeFailed;
}

fn buildManagedConfig(
    alloc: std.mem.Allocator,
    parsed: ParsedArgs,
    existing: ?acme.ManagedConfig,
    account_email: []const u8,
) !acme.ManagedConfig {
    const owned_email = try alloc.dupe(u8, account_email);
    errdefer alloc.free(owned_email);
    const owned_directory_url = try alloc.dupe(u8, selectedDirectoryUrl(parsed, existing));
    errdefer alloc.free(owned_directory_url);
    const challenge = if (hasDnsOverrides(parsed))
        try buildDnsChallenge(alloc, parsed, existing)
    else if (existing) |cfg|
        try cfg.challenge.clone(alloc)
    else
        @as(acme.ChallengeConfig, .http_01);
    errdefer challenge.deinit(alloc);

    return .{
        .email = owned_email,
        .directory_url = owned_directory_url,
        .challenge = challenge,
    };
}

const KeyValueSource = enum {
    secret_refs,
    config,
};

fn hasDnsOverrides(parsed: ParsedArgs) bool {
    return parsed.dns_provider != null or
        parsed.dns_secret_refs.len > 0 or
        parsed.dns_config.len > 0 or
        parsed.dns_hook.len > 0 or
        parsed.propagation_timeout_secs != null or
        parsed.poll_interval_secs != null;
}

fn buildDnsChallenge(
    alloc: std.mem.Allocator,
    parsed: ParsedArgs,
    existing: ?acme.ManagedConfig,
) !acme.ChallengeConfig {
    const existing_dns = if (existing) |cfg| cfg.dnsConfig() else null;
    const provider = parsed.dns_provider orelse
        if (parsed.dns_hook.len > 0)
            acme.DnsProvider.exec
        else if (existing_dns) |dns|
            dns.provider
        else
            return error.InvalidConfig;

    const secret_refs = try selectedKeyValues(alloc, parsed.dns_secret_refs, existing_dns, .secret_refs);
    defer acme.freeKeyValueRefs(alloc, secret_refs);
    const config = try selectedKeyValues(alloc, parsed.dns_config, existing_dns, .config);
    defer acme.freeKeyValueRefs(alloc, config);
    const hook = try selectedHook(alloc, parsed.dns_hook, existing_dns);
    defer acme.freeStringArray(alloc, hook);

    return acme.buildDnsChallenge(
        alloc,
        provider,
        secret_refs,
        config,
        hook,
        parsed.propagation_timeout_secs orelse if (existing_dns) |dns| dns.propagation_timeout_secs else 300,
        parsed.poll_interval_secs orelse if (existing_dns) |dns| dns.poll_interval_secs else 5,
    );
}

fn selectedKeyValues(
    alloc: std.mem.Allocator,
    parsed_values: []const BorrowedKeyValue,
    existing: ?acme.DnsConfig,
    source: KeyValueSource,
) ![]const acme.KeyValueRef {
    if (parsed_values.len > 0) return acme.cloneKeyValueRefs(alloc, parsed_values);
    if (existing) |cfg| {
        return acme.cloneKeyValueRefs(alloc, switch (source) {
            .secret_refs => cfg.secret_refs,
            .config => cfg.config,
        });
    }
    return try alloc.alloc(acme.KeyValueRef, 0);
}

fn selectedHook(
    alloc: std.mem.Allocator,
    parsed_hook: []const []const u8,
    existing: ?acme.DnsConfig,
) ![]const []const u8 {
    if (parsed_hook.len > 0) return acme.cloneStringArray(alloc, parsed_hook);
    if (existing) |cfg| return acme.cloneStringArray(alloc, cfg.hook);
    return try alloc.alloc([]const u8, 0);
}

fn selectedDirectoryUrl(parsed: ParsedArgs, existing: ?acme.ManagedConfig) []const u8 {
    const cfg = existing orelse return parsed.directory_url;
    if (std.mem.eql(u8, parsed.directory_url, acme.letsencrypt_production) and
        std.mem.eql(u8, cfg.directory_url, acme.letsencrypt_staging))
    {
        return cfg.directory_url;
    }
    return parsed.directory_url;
}

fn resolveAccountEmail(
    alloc: std.mem.Allocator,
    domain: []const u8,
    explicit_email: ?[]const u8,
) ![]u8 {
    const env_email = lookupEnvOwned(alloc, "YOQ_ACME_EMAIL") catch return error.OutOfMemory;
    errdefer if (env_email) |email| alloc.free(email);
    return resolveAccountEmailWithFallback(alloc, domain, explicit_email, env_email);
}

fn resolveAccountEmailWithFallback(
    alloc: std.mem.Allocator,
    domain: []const u8,
    explicit_email: ?[]const u8,
    env_email: ?[]u8,
) ![]u8 {
    if (explicit_email) |email| {
        if (env_email) |owned_env_email| alloc.free(owned_env_email);
        return alloc.dupe(u8, email);
    }
    if (env_email) |email| {
        return email;
    }

    return std.fmt.allocPrint(alloc, "admin@{s}", .{domain});
}

fn challengeRegistrar(store: *proxy.ChallengeStore) acme.ChallengeRegistrar {
    return .{
        .ctx = store,
        .set_fn = registerChallenge,
        .remove_fn = removeChallenge,
    };
}

fn registerChallenge(ctx: *anyopaque, token: []const u8, key_authorization: []const u8) acme.AcmeError!void {
    const store: *proxy.ChallengeStore = @ptrCast(@alignCast(ctx));
    store.set(token, key_authorization) catch return acme.AcmeError.AllocFailed;
}

fn removeChallenge(ctx: *anyopaque, token: []const u8) void {
    const store: *proxy.ChallengeStore = @ptrCast(@alignCast(ctx));
    store.remove(token);
}

fn parseDnsProvider(value: []const u8) ?acme.DnsProvider {
    return acme.DnsProvider.parse(value);
}

fn appendKeyValue(
    alloc: std.mem.Allocator,
    list: *std.ArrayListUnmanaged(BorrowedKeyValue),
    raw: []const u8,
) !void {
    const idx = std.mem.indexOfScalar(u8, raw, '=') orelse return error.InvalidKeyValue;
    if (idx == 0 or idx == raw.len - 1) return error.InvalidKeyValue;
    try list.append(alloc, .{
        .key = raw[0..idx],
        .value = raw[idx + 1 ..],
    });
}

fn invalidArg(message: []const u8) common.TlsCommandsError {
    writeErr("{s}", .{message});
    return common.TlsCommandsError.InvalidArgument;
}

fn invalidArgFmt(comptime fmt: []const u8, args: anytype) common.TlsCommandsError {
    writeErr(fmt, args);
    return common.TlsCommandsError.InvalidArgument;
}

test "resolveAccountEmail prefers explicit email" {
    const alloc = std.testing.allocator;
    const email = try resolveAccountEmailForTest(alloc, "example.com", "ops@example.com", "env@example.com");
    defer alloc.free(email);

    try std.testing.expectEqualStrings("ops@example.com", email);
}

test "resolveAccountEmail uses env email when flag is omitted" {
    const alloc = std.testing.allocator;
    const email = try resolveAccountEmailForTest(alloc, "example.com", null, "env@example.com");
    defer alloc.free(email);

    try std.testing.expectEqualStrings("env@example.com", email);
}

test "resolveAccountEmail falls back to admin at domain" {
    const alloc = std.testing.allocator;
    const email = try resolveAccountEmailForTest(alloc, "example.com", null, null);
    defer alloc.free(email);

    try std.testing.expectEqualStrings("admin@example.com", email);
}

test "buildManagedConfig uses existing dns metadata by default" {
    const alloc = std.testing.allocator;
    var existing = acme.ManagedConfig{
        .email = try alloc.dupe(u8, "ops@example.com"),
        .directory_url = try alloc.dupe(u8, acme.letsencrypt_staging),
        .challenge = .{ .dns_01 = .{
            .provider = .cloudflare,
            .secret_refs = try acme.cloneKeyValueRefs(alloc, &.{.{ .key = "api_token", .value = "cf-token" }}),
            .config = try acme.cloneKeyValueRefs(alloc, &.{.{ .key = "zone_id", .value = "zone123" }}),
            .hook = try acme.cloneStringArray(alloc, &.{}),
        } },
    };
    defer existing.deinit(alloc);

    const parsed = ParsedArgs{
        .domain = "example.com",
        .email = null,
        .directory_url = acme.letsencrypt_production,
        .dns_secret_refs = &.{},
        .dns_config = &.{},
        .dns_hook = &.{},
    };
    var built = try buildManagedConfig(alloc, parsed, existing, "ops@example.com");
    defer built.deinit(alloc);

    try std.testing.expectEqual(acme.ChallengeType.dns_01, built.challengeType());
    try std.testing.expectEqual(acme.DnsProvider.cloudflare, built.dnsConfig().?.provider);
    try std.testing.expectEqualStrings(acme.letsencrypt_staging, built.directory_url);
}

fn resolveAccountEmailForTest(
    alloc: std.mem.Allocator,
    domain: []const u8,
    explicit_email: ?[]const u8,
    env_email: ?[]const u8,
) ![]u8 {
    const owned_env_email = if (env_email) |email| try alloc.dupe(u8, email) else null;
    return resolveAccountEmailWithFallback(alloc, domain, explicit_email, owned_env_email);
}

fn lookupEnvOwned(alloc: std.mem.Allocator, name: [:0]const u8) error{OutOfMemory}!?[]u8 {
    const value = std.c.getenv(name.ptr) orelse return null;
    return try alloc.dupe(u8, std.mem.span(value));
}
