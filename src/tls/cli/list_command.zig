const std = @import("std");
const acme = @import("../acme.zig");
const cert_store = @import("../cert_store.zig");
const cli = @import("../../lib/cli.zig");
const json_out = @import("../../lib/json_output.zig");
const common = @import("common.zig");
const store_support = @import("store_support.zig");

const write = cli.write;
const writeErr = cli.writeErr;
const formatTimestamp = cli.formatTimestamp;

pub fn run(alloc: std.mem.Allocator) common.TlsCommandsError!void {
    var opened = store_support.openCertStore(alloc) catch |err|
        return store_support.reportOpenStoreError(err);
    defer store_support.closeCertStore(alloc, &opened);

    var certs = opened.store.list() catch {
        writeErr("failed to list certificates\n", .{});
        return common.TlsCommandsError.StoreFailed;
    };
    defer {
        for (certs.items) |c| c.deinit(alloc);
        certs.deinit(alloc);
    }

    if (cli.output_mode == .json) {
        var w = json_out.JsonWriter{};
        w.beginArray();
        for (certs.items) |c| {
            const acme_config = loadAcmeConfig(&opened.store, c.domain) catch {
                writeErr("failed to read certificate ACME metadata\n", .{});
                return common.TlsCommandsError.StoreFailed;
            };
            defer if (acme_config) |cfg| cfg.deinit(alloc);

            w.beginObject();
            w.stringField("domain", c.domain);
            w.intField("not_after", c.not_after);
            w.stringField("source", c.source);
            w.intField("created_at", c.created_at);
            writeManagedJsonFields(&w, acme_config);
            w.endObject();
        }
        w.endArray();
        w.flush();
        return;
    }

    if (certs.items.len == 0) {
        write("no certificates\n", .{});
        return;
    }

    for (certs.items) |c| {
        const acme_config = loadAcmeConfig(&opened.store, c.domain) catch {
            writeErr("failed to read certificate ACME metadata\n", .{});
            return common.TlsCommandsError.StoreFailed;
        };
        defer if (acme_config) |cfg| cfg.deinit(alloc);

        var ts_buf: [20]u8 = undefined;
        const expires = formatTimestamp(&ts_buf, c.not_after);
        write("{s}  expires={s}  source={s}", .{ c.domain, expires, c.source });
        if (acme_config) |cfg| {
            write("  managed={s}", .{cfg.challengeType().label()});
            if (cfg.dnsConfig()) |dns| write("  provider={s}", .{dns.provider.label()});
        }
        write("\n", .{});
    }
}

fn loadAcmeConfig(store: *cert_store.CertStore, domain: []const u8) common.TlsCommandsError!?acme.ManagedConfig {
    return store.getAcmeConfig(domain) catch |err| {
        if (err == cert_store.CertError.NotFound) return null;
        return common.TlsCommandsError.StoreFailed;
    };
}

fn writeManagedJsonFields(w: *json_out.JsonWriter, config: ?acme.ManagedConfig) void {
    const cfg = config orelse {
        w.boolField("managed", false);
        return;
    };

    w.boolField("managed", true);
    w.stringField("challenge", cfg.challengeType().label());
    w.stringField("directory_url", cfg.directory_url);
    if (cfg.dnsConfig()) |dns| {
        w.stringField("provider", dns.provider.label());
        w.uintField("propagation_timeout_secs", dns.propagation_timeout_secs);
        w.uintField("poll_interval_secs", dns.poll_interval_secs);
    } else {
        w.nullField("provider");
        w.nullField("propagation_timeout_secs");
        w.nullField("poll_interval_secs");
    }
}

test "managed JSON fields include dns renewal metadata" {
    var w = json_out.JsonWriter{};
    w.beginObject();
    writeManagedJsonFields(&w, .{
        .email = "ops@example.com",
        .directory_url = "https://acme.example.com/directory",
        .challenge = .{ .dns_01 = .{
            .provider = .cloudflare,
            .propagation_timeout_secs = 120,
            .poll_interval_secs = 10,
        } },
    });
    w.endObject();

    const expected =
        "{\"managed\":true,\"challenge\":\"dns-01\",\"directory_url\":\"https://acme.example.com/directory\"," ++
        "\"provider\":\"cloudflare\",\"propagation_timeout_secs\":120,\"poll_interval_secs\":10}";
    try std.testing.expectEqualStrings(expected, w.buf[0..w.pos]);
}
