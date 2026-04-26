const std = @import("std");

const cli = @import("../../lib/cli.zig");
const spec = @import("../spec.zig");
const cert_store_mod = @import("../../tls/cert_store.zig");
const acme_mod = @import("../../tls/acme.zig");
const dns_provider = @import("../../tls/acme/dns_provider.zig");
const tls_proxy = @import("../../tls/proxy.zig");
const secrets = @import("../../state/secrets.zig");

const writeErr = cli.writeErr;

pub fn provisionAcmeCert(
    alloc: std.mem.Allocator,
    certs: *cert_store_mod.CertStore,
    challenges: *tls_proxy.ChallengeStore,
    tls: spec.TlsConfig,
) void {
    var threaded_io = std.Io.Threaded.init(alloc, .{});
    defer threaded_io.deinit();

    provisionAcmeCertWithIo(threaded_io.io(), alloc, certs, challenges, tls);
}

pub fn provisionAcmeCertWithIo(
    io: std.Io,
    alloc: std.mem.Allocator,
    certs: *cert_store_mod.CertStore,
    challenges: *tls_proxy.ChallengeStore,
    tls: spec.TlsConfig,
) void {
    var managed_config = buildManagedConfig(alloc, tls) catch {
        writeErr("    invalid ACME TLS configuration\n", .{});
        return;
    };
    defer managed_config.deinit(alloc);

    var client = acme_mod.AcmeClient.init(io, alloc, managed_config.directory_url);
    defer client.deinit();

    var exported = switch (managed_config.challenge_type) {
        .http_01 => client.issueAndExport(.{
            .domain = tls.domain,
            .email = managed_config.email,
            .directory_url = managed_config.directory_url,
            .challenge_type = .http_01,
            .challenge_registrar = challengeRegistrar(challenges),
        }),
        .dns_01 => issueDns01(io, alloc, certs, &client, tls.domain, managed_config),
    } catch {
        writeErr("    failed to finalize certificate order\n", .{});
        return;
    };
    defer exported.deinit();

    certs.install(tls.domain, exported.cert_pem, exported.key_pem, "acme") catch {
        writeErr("    failed to store certificate\n", .{});
        return;
    };
    certs.setAcmeConfig(tls.domain, managed_config) catch {
        writeErr("    failed to store ACME renewal metadata\n", .{});
        return;
    };

    writeErr("    provisioned certificate for {s}\n", .{tls.domain});
}

fn issueDns01(
    io: std.Io,
    alloc: std.mem.Allocator,
    certs: *cert_store_mod.CertStore,
    client: *acme_mod.AcmeClient,
    domain: []const u8,
    managed_config: acme_mod.ManagedConfig,
) acme_mod.AcmeError!acme_mod.ExportResult {
    var maybe_secret_store: ?secrets.SecretsStore = null;
    if (managed_config.dns_provider) |provider| {
        if (provider != .exec or managed_config.secret_refs.len > 0) {
            maybe_secret_store = secrets.SecretsStore.init(certs.db, alloc) catch
                return acme_mod.AcmeError.ChallengeFailed;
        }
    }

    var runtime = try dns_provider.Runtime.init(io, alloc, managed_config, if (maybe_secret_store) |*store| store else null);
    defer runtime.deinit();

    return client.issueAndExport(.{
        .domain = domain,
        .email = managed_config.email,
        .directory_url = managed_config.directory_url,
        .challenge_type = .dns_01,
        .dns_solver = runtime.solver(),
        .dns_propagation_timeout_secs = managed_config.propagation_timeout_secs,
        .dns_poll_interval_secs = managed_config.poll_interval_secs,
    });
}

fn buildManagedConfig(alloc: std.mem.Allocator, tls: spec.TlsConfig) !acme_mod.ManagedConfig {
    if (!tls.acme) return error.InvalidConfig;
    const email = tls.email orelse return error.InvalidConfig;

    return .{
        .email = try alloc.dupe(u8, email),
        .directory_url = try alloc.dupe(u8, acme_mod.letsencrypt_production),
        .challenge_type = switch (tls.acme_challenge) {
            .http_01 => .http_01,
            .dns_01 => .dns_01,
        },
        .dns_provider = if (tls.acme_dns_provider) |provider| switch (provider) {
            .cloudflare => .cloudflare,
            .route53 => .route53,
            .gcloud => .gcloud,
            .exec => .exec,
        } else null,
        .secret_refs = try cloneKeyValueRefs(alloc, tls.acme_dns_secret_refs),
        .config_pairs = try cloneKeyValueRefs(alloc, tls.acme_dns_config),
        .hook_command = try cloneStrings(alloc, tls.acme_dns_hook),
        .propagation_timeout_secs = tls.acme_dns_propagation_timeout_secs,
        .poll_interval_secs = tls.acme_dns_poll_interval_secs,
    };
}

fn cloneKeyValueRefs(alloc: std.mem.Allocator, input: []const spec.TlsConfig.KeyValueRef) ![]const acme_mod.KeyValueRef {
    var out: std.ArrayListUnmanaged(acme_mod.KeyValueRef) = .empty;
    errdefer {
        for (out.items) |entry| entry.deinit(alloc);
        out.deinit(alloc);
    }
    for (input) |entry| {
        try out.append(alloc, .{
            .key = try alloc.dupe(u8, entry.key),
            .value = try alloc.dupe(u8, entry.value),
        });
    }
    return try out.toOwnedSlice(alloc);
}

fn cloneStrings(alloc: std.mem.Allocator, input: []const []const u8) ![]const []const u8 {
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (out.items) |entry| alloc.free(entry);
        out.deinit(alloc);
    }
    for (input) |entry| {
        try out.append(alloc, try alloc.dupe(u8, entry));
    }
    return try out.toOwnedSlice(alloc);
}

fn challengeRegistrar(store: *tls_proxy.ChallengeStore) acme_mod.ChallengeRegistrar {
    return .{
        .ctx = store,
        .set_fn = registerChallenge,
        .remove_fn = removeChallenge,
    };
}

fn registerChallenge(ctx: *anyopaque, token: []const u8, key_authorization: []const u8) acme_mod.AcmeError!void {
    const store: *tls_proxy.ChallengeStore = @ptrCast(@alignCast(ctx));
    store.set(token, key_authorization) catch return acme_mod.AcmeError.AllocFailed;
}

fn removeChallenge(ctx: *anyopaque, token: []const u8) void {
    const store: *tls_proxy.ChallengeStore = @ptrCast(@alignCast(ctx));
    store.remove(token);
}
