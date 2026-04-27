const std = @import("std");
const sqlite = @import("sqlite");

const acme = @import("../acme.zig");
const dns_provider = @import("dns_provider.zig");
const preflight = @import("preflight.zig");
const secrets = @import("../../state/secrets.zig");

pub fn issueAndExport(
    io: std.Io,
    alloc: std.mem.Allocator,
    db: ?*sqlite.Db,
    client: *acme.AcmeClient,
    domain: []const u8,
    config: acme.ManagedConfig,
    http_registrar: ?acme.ChallengeRegistrar,
) acme.AcmeError!acme.ExportResult {
    return switch (config.challengeType()) {
        .http_01 => issueHttp01(client, domain, config, http_registrar),
        .dns_01 => issueDns01(io, alloc, db, client, domain, config),
    };
}

pub fn preflightProblem(
    alloc: std.mem.Allocator,
    db: ?*sqlite.Db,
    config: acme.ManagedConfig,
    http_registrar_available: bool,
) error{OutOfMemory}!?[]u8 {
    var maybe_secret_store: ?secrets.SecretsStore = null;
    if (config.dnsConfig()) |dns| {
        if (preflight.needsSecretStore(dns)) {
            const actual_db = db orelse
                return try preflightMessage(alloc, "dns-01 requires a certificate database for secret lookup");
            maybe_secret_store = secrets.SecretsStore.init(actual_db, alloc) catch
                return try preflightMessage(alloc, "failed to open secret store for dns-01 preflight");
        }
    }

    return preflight.firstProblem(alloc, config, .{
        .http_registrar_available = http_registrar_available,
        .secrets_store = if (maybe_secret_store) |*store| store else null,
    });
}

fn preflightMessage(alloc: std.mem.Allocator, message: []const u8) error{OutOfMemory}![]u8 {
    return alloc.dupe(u8, message) catch return error.OutOfMemory;
}

fn issueHttp01(
    client: *acme.AcmeClient,
    domain: []const u8,
    config: acme.ManagedConfig,
    registrar: ?acme.ChallengeRegistrar,
) acme.AcmeError!acme.ExportResult {
    if (preflight.firstProblem(client.allocator, config, .{ .http_registrar_available = registrar != null }) catch
        return acme.AcmeError.AllocFailed) |problem|
    {
        client.allocator.free(problem);
        return acme.AcmeError.InvalidConfig;
    }

    return client.issueAndExport(.{
        .domain = domain,
        .email = config.email,
        .directory_url = config.directory_url,
        .challenge_type = .http_01,
        .challenge_registrar = registrar orelse return acme.AcmeError.ChallengeFailed,
    });
}

fn issueDns01(
    io: std.Io,
    alloc: std.mem.Allocator,
    db: ?*sqlite.Db,
    client: *acme.AcmeClient,
    domain: []const u8,
    config: acme.ManagedConfig,
) acme.AcmeError!acme.ExportResult {
    const dns = config.dnsConfig() orelse return acme.AcmeError.ChallengeFailed;

    var maybe_secret_store: ?secrets.SecretsStore = null;
    if (preflight.needsSecretStore(dns)) {
        const actual_db = db orelse return acme.AcmeError.ChallengeFailed;
        maybe_secret_store = secrets.SecretsStore.init(actual_db, alloc) catch
            return acme.AcmeError.ChallengeFailed;
    }

    if (preflight.firstProblem(alloc, config, .{
        .secrets_store = if (maybe_secret_store) |*store| store else null,
    }) catch return acme.AcmeError.AllocFailed) |problem| {
        alloc.free(problem);
        return acme.AcmeError.InvalidConfig;
    }

    var runtime = try dns_provider.Runtime.init(
        io,
        alloc,
        config,
        if (maybe_secret_store) |*store| store else null,
    );
    defer runtime.deinit();

    return client.issueAndExport(.{
        .domain = domain,
        .email = config.email,
        .directory_url = config.directory_url,
        .challenge_type = .dns_01,
        .dns_solver = runtime.solver(),
        .dns_propagation_timeout_secs = dns.propagation_timeout_secs,
        .dns_poll_interval_secs = dns.poll_interval_secs,
    });
}
