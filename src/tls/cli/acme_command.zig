const std = @import("std");
const platform = @import("platform");

const cli = @import("../../lib/cli.zig");
const acme = @import("../acme.zig");
const cert_store = @import("../cert_store.zig");
const challenge_server = @import("../challenge_server.zig");
const proxy = @import("../proxy.zig");
const common = @import("common.zig");
const store_support = @import("store_support.zig");

const write = cli.write;
const writeErr = cli.writeErr;

pub fn provision(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) common.TlsCommandsError!void {
    const parsed = parseArgs(args) catch |err| return err;
    try runAcmeCommand(alloc, parsed, false);
}

pub fn renew(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) common.TlsCommandsError!void {
    const parsed = parseArgs(args) catch |err| return err;
    try runAcmeCommand(alloc, parsed, true);
}

const ParsedArgs = struct {
    domain: []const u8,
    email: ?[]const u8,
    directory_url: []const u8,
};

fn parseArgs(args: *std.process.Args.Iterator) common.TlsCommandsError!ParsedArgs {
    var domain: ?[]const u8 = null;
    var email: ?[]const u8 = null;
    var use_staging = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--email")) {
            email = args.next() orelse {
                writeErr("--email requires a value\n", .{});
                return common.TlsCommandsError.InvalidArgument;
            };
            continue;
        }
        if (std.mem.eql(u8, arg, "--staging")) {
            use_staging = true;
            continue;
        }
        if (domain == null) {
            domain = arg;
            continue;
        }
        writeErr("unexpected argument: {s}\n", .{arg});
        return common.TlsCommandsError.InvalidArgument;
    }

    return .{
        .domain = domain orelse {
            writeErr("domain is required\n", .{});
            return common.TlsCommandsError.InvalidArgument;
        },
        .email = email,
        .directory_url = if (use_staging) acme.letsencrypt_staging else acme.letsencrypt_production,
    };
}

fn runAcmeCommand(
    alloc: std.mem.Allocator,
    parsed: ParsedArgs,
    require_existing: bool,
) common.TlsCommandsError!void {
    var opened = store_support.openCertStore(alloc) catch |err|
        return store_support.reportOpenStoreError(err);
    defer store_support.closeCertStore(alloc, &opened);

    const account_email = resolveAccountEmail(alloc, parsed.domain, parsed.email) catch
        return common.TlsCommandsError.OutOfMemory;
    defer alloc.free(account_email);

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

    var challenges = proxy.ChallengeStore.init(alloc);
    defer challenges.deinit();

    var server = challenge_server.ChallengeServer.init(&challenges, 80) catch {
        writeErr("failed to bind port 80 for ACME HTTP-01 challenge handling\n", .{});
        return common.TlsCommandsError.NetworkFailed;
    };
    defer server.deinit();
    server.start();

    var client = acme.AcmeClient.init(alloc, parsed.directory_url);
    defer client.deinit();

    var exported = client.issueAndExport(.{
        .domain = parsed.domain,
        .email = account_email,
        .directory_url = parsed.directory_url,
        .challenge_registrar = challengeRegistrar(&challenges),
    }) catch |err| {
        writeErr("acme certificate issuance failed: {}\n", .{err});
        return common.TlsCommandsError.AcmeFailed;
    };
    defer exported.deinit();

    opened.store.install(parsed.domain, exported.cert_pem, exported.key_pem, "acme") catch {
        writeErr("failed to store certificate\n", .{});
        return common.TlsCommandsError.StoreFailed;
    };

    write("{s}\n", .{parsed.domain});
}

fn resolveAccountEmail(
    alloc: std.mem.Allocator,
    domain: []const u8,
    explicit_email: ?[]const u8,
) ![]u8 {
    const env_email = platform.getEnvVarOwned(alloc, "YOQ_ACME_EMAIL") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        error.OutOfMemory => return error.OutOfMemory,
        else => null,
    };
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

fn resolveAccountEmailForTest(
    alloc: std.mem.Allocator,
    domain: []const u8,
    explicit_email: ?[]const u8,
    env_email: ?[]const u8,
) ![]u8 {
    const owned_env_email = if (env_email) |email| try alloc.dupe(u8, email) else null;
    return resolveAccountEmailWithFallback(alloc, domain, explicit_email, owned_env_email);
}
