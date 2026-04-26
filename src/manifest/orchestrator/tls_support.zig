const std = @import("std");

const cli = @import("../../lib/cli.zig");
const spec = @import("../spec.zig");
const cert_store_mod = @import("../../tls/cert_store.zig");
const acme_mod = @import("../../tls/acme.zig");
const managed_runtime = @import("../../tls/acme/managed_runtime.zig");
const tls_proxy = @import("../../tls/proxy.zig");

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

    var exported = managed_runtime.issueAndExport(
        io,
        alloc,
        certs.db,
        &client,
        tls.domain,
        managed_config,
        challengeRegistrar(challenges),
    ) catch {
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

fn buildManagedConfig(alloc: std.mem.Allocator, tls: spec.TlsConfig) !acme_mod.ManagedConfig {
    const acme = tls.acme orelse return error.InvalidConfig;
    const challenge = try buildChallengeConfig(alloc, acme);
    errdefer challenge.deinit(alloc);
    const email = try alloc.dupe(u8, acme.email);
    errdefer alloc.free(email);
    const directory_url = try alloc.dupe(u8, acme.directory_url);
    errdefer alloc.free(directory_url);

    return .{
        .email = email,
        .directory_url = directory_url,
        .challenge = challenge,
    };
}

fn buildChallengeConfig(alloc: std.mem.Allocator, config: spec.TlsConfig.AcmeConfig) !acme_mod.ChallengeConfig {
    return switch (config.challenge) {
        .http_01 => .http_01,
        .dns_01 => blk: {
            const dns = config.dns orelse return error.InvalidConfig;
            const secret_refs = try cloneKeyValueRefs(alloc, dns.secrets);
            errdefer acme_mod.freeKeyValueRefs(alloc, secret_refs);
            const config_pairs = try cloneKeyValueRefs(alloc, dns.config);
            errdefer acme_mod.freeKeyValueRefs(alloc, config_pairs);
            const hook = try cloneStrings(alloc, dns.hook);
            errdefer acme_mod.freeStringArray(alloc, hook);

            break :blk .{ .dns_01 = .{
                .provider = switch (dns.provider) {
                    .cloudflare => .cloudflare,
                    .route53 => .route53,
                    .gcloud => .gcloud,
                    .exec => .exec,
                },
                .secret_refs = secret_refs,
                .config = config_pairs,
                .hook = hook,
                .propagation_timeout_secs = dns.propagation_timeout_secs,
                .poll_interval_secs = dns.poll_interval_secs,
            } };
        },
    };
}

fn cloneKeyValueRefs(alloc: std.mem.Allocator, input: []const spec.TlsConfig.KeyValueRef) ![]const acme_mod.KeyValueRef {
    var out: std.ArrayListUnmanaged(acme_mod.KeyValueRef) = .empty;
    errdefer {
        for (out.items) |entry| entry.deinit(alloc);
        out.deinit(alloc);
    }
    for (input) |entry| {
        const cloned = blk: {
            const key = try alloc.dupe(u8, entry.key);
            errdefer alloc.free(key);
            break :blk acme_mod.KeyValueRef{
                .key = key,
                .value = try alloc.dupe(u8, entry.value),
            };
        };
        try out.append(alloc, cloned);
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
