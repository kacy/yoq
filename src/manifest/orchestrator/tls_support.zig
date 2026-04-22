const std = @import("std");

const cli = @import("../../lib/cli.zig");
const cert_store_mod = @import("../../tls/cert_store.zig");
const acme_mod = @import("../../tls/acme.zig");
const tls_proxy = @import("../../tls/proxy.zig");

const writeErr = cli.writeErr;

pub fn provisionAcmeCert(
    alloc: std.mem.Allocator,
    certs: *cert_store_mod.CertStore,
    challenges: *tls_proxy.ChallengeStore,
    domain: []const u8,
    email: []const u8,
) void {
    var threaded_io = std.Io.Threaded.init(alloc, .{});
    defer threaded_io.deinit();

    var client = acme_mod.AcmeClient.init(threaded_io.io(), alloc, acme_mod.letsencrypt_production);
    defer client.deinit();

    var exported = client.issueAndExport(.{
        .domain = domain,
        .email = email,
        .directory_url = acme_mod.letsencrypt_production,
        .challenge_registrar = challengeRegistrar(challenges),
    }) catch {
        writeErr("    failed to finalize certificate order\n", .{});
        return;
    };
    defer exported.deinit();

    certs.install(domain, exported.cert_pem, exported.key_pem, "acme") catch {
        writeErr("    failed to store certificate\n", .{});
        return;
    };

    writeErr("    provisioned certificate for {s}\n", .{domain});
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
