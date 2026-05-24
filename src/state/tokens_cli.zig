// tokens_cli — `yoq token create|list|revoke` for named, scoped API tokens.
//
// runs in the local CLI process and writes directly to the state DB (like
// `secret` and `backup`). secrets are never stored — only sha256(secret) — and
// the secret is printed exactly once, at create time.

const std = @import("std");
const AppContext = @import("../lib/app_context.zig").AppContext;
const cli = @import("../lib/cli.zig");
const store = @import("store.zig");
const scopes = @import("../lib/scopes.zig");
const audit = @import("audit.zig");
const linux_platform = @import("linux_platform");

const write = cli.write;
const writeErr = cli.writeErr;
const requireArg = cli.requireArg;

const TokenCommandError = error{
    InvalidArgument,
    StoreFailed,
    NotFound,
};

const max_scopes = 16;

fn nowSeconds() i64 {
    return std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
}

fn sha256Hex(input: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// parse a TTL like "30m", "12h", "7d" into seconds; null if malformed.
fn parseTtlSeconds(s: []const u8) ?i64 {
    if (s.len < 2) return null;
    const suffix = s[s.len - 1];
    const value = std.fmt.parseInt(i64, s[0 .. s.len - 1], 10) catch return null;
    if (value <= 0) return null;
    return switch (suffix) {
        's' => value,
        'm' => value * 60,
        'h' => value * 3600,
        'd' => value * 86400,
        else => null,
    };
}

pub fn token(args: *std.process.Args.Iterator, ctx: AppContext) !void {
    const alloc = ctx.alloc;
    var subcmd: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else {
            subcmd = arg;
            break;
        }
    }

    const cmd = subcmd orelse {
        writeErr(
            \\usage: yoq token <command> [options]
            \\
            \\commands:
            \\  create <name> --scope <s> [--scope <s> ...] [--ttl 30d]  create a token
            \\  list                                                     list tokens
            \\  revoke <name>                                            revoke a token
            \\
            \\scopes: "*", "<resource>:read|write|*", or "cluster:admin"
            \\
        , .{});
        return TokenCommandError.InvalidArgument;
    };

    if (std.mem.eql(u8, cmd, "create")) return create(args, alloc);
    if (std.mem.eql(u8, cmd, "list")) {
        while (args.next()) |arg| {
            if (std.mem.eql(u8, arg, "--json")) cli.output_mode = .json;
        }
        return list(alloc);
    }
    if (std.mem.eql(u8, cmd, "revoke")) return revoke(args, alloc);

    writeErr("unknown token command: {s}\n", .{cmd});
    return TokenCommandError.InvalidArgument;
}

fn create(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    var name: ?[]const u8 = null;
    var scope_list: [max_scopes][]const u8 = undefined;
    var scope_n: usize = 0;
    var ttl_secs: ?i64 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--scope")) {
            const s = requireArg(args, "--scope requires a value\n");
            if (!scopes.isValidScope(s)) {
                writeErr("invalid scope: {s}\n", .{s});
                return TokenCommandError.InvalidArgument;
            }
            if (scope_n >= max_scopes) {
                writeErr("too many scopes (max {d})\n", .{max_scopes});
                return TokenCommandError.InvalidArgument;
            }
            scope_list[scope_n] = s;
            scope_n += 1;
        } else if (std.mem.eql(u8, arg, "--ttl")) {
            const t = requireArg(args, "--ttl requires a value like 30m, 12h, 7d\n");
            ttl_secs = parseTtlSeconds(t) orelse {
                writeErr("invalid --ttl: {s}\n", .{t});
                return TokenCommandError.InvalidArgument;
            };
        } else if (std.mem.eql(u8, arg, "--json")) {
            cli.output_mode = .json;
        } else if (name == null and !std.mem.startsWith(u8, arg, "--")) {
            name = arg;
        } else {
            writeErr("unexpected argument: {s}\n", .{arg});
            return TokenCommandError.InvalidArgument;
        }
    }

    const token_name = name orelse {
        writeErr("usage: yoq token create <name> --scope <s> [--ttl 30d]\n", .{});
        return TokenCommandError.InvalidArgument;
    };
    if (scope_n == 0) {
        writeErr("at least one --scope is required\n", .{});
        return TokenCommandError.InvalidArgument;
    }

    const scopes_csv = std.mem.join(alloc, ",", scope_list[0..scope_n]) catch return TokenCommandError.StoreFailed;
    defer alloc.free(scopes_csv);

    var raw: [32]u8 = undefined;
    linux_platform.randomBytes(&raw);
    var secret = std.fmt.bytesToHex(raw, .lower);
    std.crypto.secureZero(u8, &raw);
    defer std.crypto.secureZero(u8, &secret);

    const hash = sha256Hex(&secret);
    const now = nowSeconds();
    const expires_at: ?i64 = if (ttl_secs) |t| now + t else null;

    store.createToken(token_name, &hash, scopes_csv, now, expires_at) catch {
        writeErr("failed to create token (does '{s}' already exist?)\n", .{token_name});
        audit.record(.token_create, token_name, .failed);
        return TokenCommandError.StoreFailed;
    };
    audit.record(.token_create, token_name, .ok);

    if (cli.output_mode == .json) {
        write("{{\"name\":\"{s}\",\"scopes\":\"{s}\",\"token\":\"{s}\"}}\n", .{ token_name, scopes_csv, secret[0..] });
    } else {
        write("token created: {s}\n", .{token_name});
        write("  scopes: {s}\n", .{scopes_csv});
        write("  token:  {s}\n", .{secret[0..]});
        write("  save this now — it will not be shown again\n", .{});
    }
}

fn list(alloc: std.mem.Allocator) !void {
    var tokens = store.listTokens(alloc) catch {
        writeErr("failed to read tokens\n", .{});
        return TokenCommandError.StoreFailed;
    };
    defer {
        for (tokens.items) |t| t.deinit(alloc);
        tokens.deinit(alloc);
    }
    const now = nowSeconds();

    if (cli.output_mode == .json) {
        write("[", .{});
        for (tokens.items, 0..) |t, i| {
            if (i > 0) write(",", .{});
            write("{{\"name\":\"{s}\",\"scopes\":\"{s}\",\"status\":\"{s}\",\"created_at\":{d}", .{ t.name, t.scopes, statusOf(t, now), t.created_at });
            if (t.expires_at) |e| write(",\"expires_at\":{d}", .{e}) else write(",\"expires_at\":null", .{});
            write("}}", .{});
        }
        write("]\n", .{});
        return;
    }

    write("{s:<20} {s:<10} {s:<40} {s}\n", .{ "NAME", "STATUS", "SCOPES", "EXPIRES" });
    for (tokens.items) |t| {
        if (t.expires_at) |e| {
            write("{s:<20} {s:<10} {s:<40} {d}\n", .{ t.name, statusOf(t, now), t.scopes, e });
        } else {
            write("{s:<20} {s:<10} {s:<40} never\n", .{ t.name, statusOf(t, now), t.scopes });
        }
    }
}

fn statusOf(t: store.TokenRecord, now: i64) []const u8 {
    if (t.revoked_at != null) return "revoked";
    if (t.expires_at) |e| {
        if (e <= now) return "expired";
    }
    return "active";
}

fn revoke(args: *std.process.Args.Iterator, alloc: std.mem.Allocator) !void {
    const name = requireArg(args, "usage: yoq token revoke <name>\n");
    const ok = store.revokeToken(alloc, name, nowSeconds()) catch {
        writeErr("failed to revoke token\n", .{});
        return TokenCommandError.StoreFailed;
    };
    if (!ok) {
        writeErr("token not found: {s}\n", .{name});
        return TokenCommandError.NotFound;
    }
    audit.record(.token_revoke, name, .ok);
    write("revoked {s}\n", .{name});
}
