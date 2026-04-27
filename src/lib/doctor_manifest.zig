const std = @import("std");
const sqlite = @import("sqlite");

const acme = @import("../tls/acme.zig");
const acme_preflight = @import("../tls/acme/preflight.zig");
const doctor = @import("doctor.zig");
const linux_platform = @import("linux_platform");
const manifest_loader = @import("../manifest/loader.zig");
const manifest_spec = @import("../manifest/spec.zig");
const manifest_validate = @import("../manifest/validate.zig");
const paths = @import("paths.zig");

pub const PortAvailability = enum {
    available,
    unavailable,
    unknown,
};

pub const PortChecker = struct {
    ctx: *anyopaque,
    check_fn: *const fn (ctx: *anyopaque, port: u16) PortAvailability,

    pub fn check(self: PortChecker, port: u16) PortAvailability {
        return self.check_fn(self.ctx, port);
    }
};

var empty_port_checker_context: u8 = 0;

pub const Options = struct {
    secret_lookup: ?acme_preflight.SecretLookup = null,
    port_checker: ?PortChecker = null,
};

pub const ManifestCheckResult = struct {
    checks: []const doctor.Check,
    alloc: std.mem.Allocator,

    pub fn deinit(self: *ManifestCheckResult) void {
        self.alloc.free(self.checks);
    }

    pub fn hasFailures(self: *const ManifestCheckResult) bool {
        return doctor.checkSliceHasFailures(self.checks);
    }
};

pub fn run(alloc: std.mem.Allocator, manifest_path: []const u8) !ManifestCheckResult {
    var checks: std.ArrayList(doctor.Check) = .empty;
    errdefer checks.deinit(alloc);

    var manifest = manifest_loader.load(alloc, manifest_path) catch |err| {
        try appendFmt(alloc, &checks, "manifest-load", .fail, "failed to load {s}: {}", .{ manifest_path, err });
        return .{
            .checks = try checks.toOwnedSlice(alloc),
            .alloc = alloc,
        };
    };
    defer manifest.deinit();

    try appendFmt(
        alloc,
        &checks,
        "manifest-load",
        .pass,
        "{s} loaded ({d} service{s})",
        .{ manifest_path, manifest.services.len, if (manifest.services.len == 1) "" else "s" },
    );

    var secret_lookup = try RuntimeSecretLookup.init(alloc);
    defer secret_lookup.deinit();

    try appendManifestChecks(alloc, &checks, &manifest, .{
        .secret_lookup = secret_lookup.lookup(),
        .port_checker = defaultPortChecker(),
    });

    return .{
        .checks = try checks.toOwnedSlice(alloc),
        .alloc = alloc,
    };
}

pub fn checkLoadedManifest(
    alloc: std.mem.Allocator,
    manifest: *const manifest_spec.Manifest,
    options: Options,
) !ManifestCheckResult {
    var checks: std.ArrayList(doctor.Check) = .empty;
    errdefer checks.deinit(alloc);

    try appendManifestChecks(alloc, &checks, manifest, options);

    return .{
        .checks = try checks.toOwnedSlice(alloc),
        .alloc = alloc,
    };
}

pub fn checkLoadedManifestForHost(
    alloc: std.mem.Allocator,
    manifest: *const manifest_spec.Manifest,
) !ManifestCheckResult {
    var secret_lookup = try RuntimeSecretLookup.init(alloc);
    defer secret_lookup.deinit();

    return checkLoadedManifest(alloc, manifest, .{
        .secret_lookup = secret_lookup.lookup(),
        .port_checker = defaultPortChecker(),
    });
}

fn appendManifestChecks(
    alloc: std.mem.Allocator,
    checks: *std.ArrayList(doctor.Check),
    manifest: *const manifest_spec.Manifest,
    options: Options,
) !void {
    try appendValidationChecks(alloc, checks, manifest);
    try appendTlsChecks(alloc, checks, manifest, options);
}

fn appendValidationChecks(
    alloc: std.mem.Allocator,
    checks: *std.ArrayList(doctor.Check),
    manifest: *const manifest_spec.Manifest,
) !void {
    var result = try manifest_validate.check(alloc, manifest);
    defer result.deinit();

    if (result.diagnostics.len == 0) {
        try appendCheck(alloc, checks, "manifest", .pass, "semantic validation passed");
        return;
    }

    for (result.diagnostics) |diagnostic| {
        try appendCheck(
            alloc,
            checks,
            "manifest",
            if (diagnostic.severity == .@"error") .fail else .warn,
            diagnostic.message,
        );
    }
}

fn appendTlsChecks(
    alloc: std.mem.Allocator,
    checks: *std.ArrayList(doctor.Check),
    manifest: *const manifest_spec.Manifest,
    options: Options,
) !void {
    var saw_acme = false;
    var warned_http_01_port = false;

    for (manifest.services) |service| {
        const tls = service.tls orelse continue;
        warnOnTlsRouteMismatch(alloc, checks, service, tls) catch |err| return err;

        const acme_config = tls.acme orelse continue;
        saw_acme = true;

        var managed = try buildManagedConfig(alloc, acme_config);
        defer managed.deinit(alloc);

        const problem = try acme_preflight.firstProblem(alloc, managed, .{
            .http_registrar_available = true,
            .secret_lookup = options.secret_lookup,
        });
        if (problem) |message| {
            defer alloc.free(message);
            try appendFmt(alloc, checks, "acme", .fail, "service {s}: {s}", .{ service.name, message });
        } else {
            try appendFmt(
                alloc,
                checks,
                "acme",
                .pass,
                "service {s}: {s} config ok",
                .{ service.name, acme_config.challenge.label() },
            );
        }

        if (acme_config.challenge == .http_01 and !warned_http_01_port) {
            warned_http_01_port = true;
            const availability = if (options.port_checker) |checker| checker.check(80) else defaultCheckPort(80);
            if (availability == .unavailable) {
                try appendCheck(alloc, checks, "http-01", .warn, "port 80 is not currently available on this host");
            }
        }
    }

    if (!saw_acme) {
        try appendCheck(alloc, checks, "acme", .pass, "no managed ACME certificates configured");
    }
}

fn warnOnTlsRouteMismatch(
    alloc: std.mem.Allocator,
    checks: *std.ArrayList(doctor.Check),
    service: manifest_spec.Service,
    tls: manifest_spec.TlsConfig,
) !void {
    if (service.http_routes.len == 0) return;
    for (service.http_routes) |route| {
        if (std.mem.eql(u8, route.host, tls.domain)) return;
    }
    try appendFmt(
        alloc,
        checks,
        "tls-route",
        .warn,
        "service {s}: tls.domain {s} does not match any http route host",
        .{ service.name, tls.domain },
    );
}

fn buildManagedConfig(
    alloc: std.mem.Allocator,
    config: manifest_spec.TlsConfig.AcmeConfig,
) !acme.ManagedConfig {
    const email = try alloc.dupe(u8, config.email);
    errdefer alloc.free(email);
    const directory_url = try alloc.dupe(u8, config.directory_url);
    errdefer alloc.free(directory_url);
    const challenge = switch (config.challenge) {
        .http_01 => acme.ChallengeConfig.http_01,
        .dns_01 => blk: {
            const dns = config.dns orelse return error.InvalidConfig;
            break :blk try acme.buildDnsChallenge(
                alloc,
                switch (dns.provider) {
                    .cloudflare => .cloudflare,
                    .route53 => .route53,
                    .gcloud => .gcloud,
                    .exec => .exec,
                },
                dns.secrets,
                dns.config,
                dns.hook,
                dns.propagation_timeout_secs,
                dns.poll_interval_secs,
            );
        },
    };
    errdefer challenge.deinit(alloc);

    return .{
        .email = email,
        .directory_url = directory_url,
        .challenge = challenge,
    };
}

fn appendCheck(
    alloc: std.mem.Allocator,
    checks: *std.ArrayList(doctor.Check),
    name: []const u8,
    status: doctor.CheckStatus,
    message: []const u8,
) !void {
    try checks.append(alloc, doctor.makeCheck(name, status, message));
}

fn appendFmt(
    alloc: std.mem.Allocator,
    checks: *std.ArrayList(doctor.Check),
    name: []const u8,
    status: doctor.CheckStatus,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    const message = try std.fmt.allocPrint(alloc, fmt, args);
    defer alloc.free(message);
    try appendCheck(alloc, checks, name, status, message);
}

fn defaultPortChecker() PortChecker {
    return .{
        .ctx = &empty_port_checker_context,
        .check_fn = struct {
            fn check(_: *anyopaque, port: u16) PortAvailability {
                return defaultCheckPort(port);
            }
        }.check,
    };
}

fn defaultCheckPort(port: u16) PortAvailability {
    const posix = std.posix;
    const fd = linux_platform.posix.socket(posix.AF.INET, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0) catch
        return .unknown;
    defer linux_platform.posix.close(fd);

    const optval: c_int = 1;
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, std.mem.asBytes(&optval)) catch {};

    const addr = linux_platform.net.Address.initIp4(.{ 0, 0, 0, 0 }, port);
    const rc = std.os.linux.bind(fd, &addr.any, addr.getOsSockLen());
    return switch (std.os.linux.errno(rc)) {
        .SUCCESS => .available,
        .ACCES, .ADDRINUSE, .PERM => .unavailable,
        else => .unknown,
    };
}

const RuntimeSecretLookup = struct {
    db: ?sqlite.Db = null,

    fn init(_: std.mem.Allocator) !RuntimeSecretLookup {
        var path_buf: [paths.max_path]u8 = undefined;
        const raw_path = paths.dataPath(&path_buf, "yoq.db") catch return .{};
        if (raw_path.len >= path_buf.len) return .{};
        path_buf[raw_path.len] = 0;
        const path = path_buf[0..raw_path.len :0];
        return .{
            .db = sqlite.Db.init(.{
                .mode = .{ .File = path },
                .open_flags = .{},
            }) catch null,
        };
    }

    fn deinit(self: *RuntimeSecretLookup) void {
        if (self.db) |*db| db.deinit();
    }

    fn lookup(self: *RuntimeSecretLookup) acme_preflight.SecretLookup {
        return .{
            .ctx = self,
            .exists_fn = exists,
        };
    }

    fn exists(ctx: *anyopaque, name: []const u8) error{LookupFailed}!bool {
        const self: *RuntimeSecretLookup = @ptrCast(@alignCast(ctx));
        const db = if (self.db) |*db| db else return false;
        const Row = struct { found: i64 };
        const row = db.one(
            Row,
            "SELECT 1 AS found FROM secrets WHERE name = ? LIMIT 1;",
            .{},
            .{name},
        ) catch return error.LookupFailed;
        return row != null;
    }
};

test "valid manifest produces manifest and acme pass checks" {
    const alloc = std.testing.allocator;
    var manifest = try manifest_loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.tls]
        \\domain = "example.com"
        \\
        \\[service.web.tls.acme]
        \\email = "ops@example.com"
        \\
    );
    defer manifest.deinit();

    var result = try checkLoadedManifest(alloc, &manifest, .{ .port_checker = alwaysAvailablePortChecker() });
    defer result.deinit();

    try expectCheck(&result, "manifest", .pass);
    try expectCheck(&result, "acme", .pass);
    try std.testing.expect(!result.hasFailures());
}

test "dns acme reports missing referenced secret" {
    const alloc = std.testing.allocator;
    var manifest = try manifest_loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.tls]
        \\domain = "example.com"
        \\
        \\[service.web.tls.acme]
        \\email = "ops@example.com"
        \\challenge = "dns-01"
        \\
        \\[service.web.tls.acme.dns]
        \\provider = "cloudflare"
        \\secrets = ["api_token=cf-token"]
        \\config = ["zone_id=zone-123"]
        \\
    );
    defer manifest.deinit();

    var exists = false;
    var result = try checkLoadedManifest(alloc, &manifest, .{
        .secret_lookup = fakeSecretLookup(&exists),
    });
    defer result.deinit();

    try expectCheck(&result, "acme", .fail);
    try std.testing.expect(result.hasFailures());
}

test "tls route host mismatch is a warning" {
    const alloc = std.testing.allocator;
    var manifest = try manifest_loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.tls]
        \\domain = "secure.example.com"
        \\
        \\[service.web.http_routes.main]
        \\host = "app.example.com"
        \\path_prefix = "/"
        \\
    );
    defer manifest.deinit();

    var result = try checkLoadedManifest(alloc, &manifest, .{});
    defer result.deinit();

    try expectCheck(&result, "tls-route", .warn);
    try std.testing.expect(!result.hasFailures());
}

test "http-01 unavailable port reports warning" {
    const alloc = std.testing.allocator;
    var manifest = try manifest_loader.loadFromString(alloc,
        \\[service.web]
        \\image = "nginx:latest"
        \\
        \\[service.web.tls]
        \\domain = "example.com"
        \\
        \\[service.web.tls.acme]
        \\email = "ops@example.com"
        \\
    );
    defer manifest.deinit();

    var result = try checkLoadedManifest(alloc, &manifest, .{
        .port_checker = alwaysUnavailablePortChecker(),
    });
    defer result.deinit();

    try expectCheck(&result, "http-01", .warn);
}

fn expectCheck(result: *const ManifestCheckResult, name: []const u8, status: doctor.CheckStatus) !void {
    for (result.checks) |check| {
        if (std.mem.eql(u8, check.getName(), name) and check.status == status) return;
    }
    return error.CheckNotFound;
}

fn fakeSecretLookup(found: *bool) acme_preflight.SecretLookup {
    return .{
        .ctx = found,
        .exists_fn = struct {
            fn exists(ctx: *anyopaque, _: []const u8) error{LookupFailed}!bool {
                const value: *bool = @ptrCast(@alignCast(ctx));
                return value.*;
            }
        }.exists,
    };
}

fn alwaysAvailablePortChecker() PortChecker {
    return .{
        .ctx = &empty_port_checker_context,
        .check_fn = struct {
            fn check(_: *anyopaque, _: u16) PortAvailability {
                return .available;
            }
        }.check,
    };
}

fn alwaysUnavailablePortChecker() PortChecker {
    return .{
        .ctx = &empty_port_checker_context,
        .check_fn = struct {
            fn check(_: *anyopaque, _: u16) PortAvailability {
                return .unavailable;
            }
        }.check,
    };
}
