const std = @import("std");

const cli = @import("../../lib/cli.zig");
const cert_store_mod = @import("../../tls/cert_store.zig");
const acme_mod = @import("../../tls/acme.zig");

const writeErr = cli.writeErr;

pub fn provisionAcmeCert(
    alloc: std.mem.Allocator,
    certs: *cert_store_mod.CertStore,
    domain: []const u8,
    email: []const u8,
) void {
    var client = acme_mod.AcmeClient.init(alloc, acme_mod.letsencrypt_production);
    defer client.deinit();

    client.fetchDirectory() catch {
        writeErr("    failed to fetch ACME directory\n", .{});
        return;
    };

    client.createAccount(email) catch {
        writeErr("    failed to create ACME account\n", .{});
        return;
    };

    var order = client.createOrder(domain) catch {
        writeErr("    failed to create certificate order\n", .{});
        return;
    };
    defer order.deinit();

    if (order.authorization_urls.len > 0) {
        var challenge = client.getHttpChallenge(order.authorization_urls[0]) catch {
            writeErr("    failed to get HTTP-01 challenge (is DNS configured?)\n", .{});
            return;
        };
        defer challenge.deinit();

        client.respondToChallenge(challenge.url) catch {
            writeErr("    failed to respond to challenge\n", .{});
            return;
        };

        std.Thread.sleep(5 * std.time.ns_per_s);
    }

    var exported = client.finalizeAndExport(order.finalize_url, domain) catch {
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
