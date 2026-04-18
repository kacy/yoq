const std = @import("std");
const log = @import("../lib/log.zig");

pub const Flags = struct {
    service_registry_v2: bool = false,
    service_registry_reconciler: bool = false,
    dns_returns_vip: bool = false,
    l7_proxy_http: bool = false,
};

pub const Mode = enum {
    legacy,
    shadow,
};

var flags_mutex: std.Thread.Mutex = .{};
var flags_initialized: bool = false;
var flags: Flags = .{};
var logged_rollout_state: bool = false;

pub fn current() Flags {
    ensureInitialized();
    return flags;
}

pub fn canonicalFlags() Flags {
    return .{
        .service_registry_v2 = true,
        .service_registry_reconciler = true,
        .dns_returns_vip = true,
        .l7_proxy_http = true,
    };
}

pub fn mode() Mode {
    return modeFromFlags(current());
}

pub fn logStartupSummary() void {
    ensureInitialized();

    flags_mutex.lock();
    defer flags_mutex.unlock();
    logRolloutStateLocked();
}

pub fn resetForTest() void {
    flags_mutex.lock();
    defer flags_mutex.unlock();
    flags_initialized = false;
    flags = .{};
    logged_rollout_state = false;
}

pub fn setForTest(new_flags: Flags) void {
    flags_mutex.lock();
    defer flags_mutex.unlock();
    flags = new_flags;
    flags_initialized = true;
    logged_rollout_state = false;
}

fn ensureInitialized() void {
    flags_mutex.lock();
    defer flags_mutex.unlock();

    if (flags_initialized) return;

    flags = .{
        .service_registry_v2 = readDeprecatedAlwaysOnBoolEnv("YOQ_SERVICE_REGISTRY_V2", "service registry v2 is always on"),
        .service_registry_reconciler = readDeprecatedAlwaysOnBoolEnv("YOQ_SERVICE_REGISTRY_RECONCILER", "the reconciler is always authoritative"),
        .dns_returns_vip = readDeprecatedAlwaysOnBoolEnv("YOQ_DNS_RETURNS_VIP", "DNS always returns the service VIP"),
        .l7_proxy_http = readAlwaysOnBoolEnv("YOQ_L7_PROXY_HTTP"),
    };
    flags_initialized = true;
}

fn logRolloutStateLocked() void {
    if (logged_rollout_state) return;
    logged_rollout_state = true;

    log.info(
        "service discovery: mode={s}, registry_v2={}, reconciler={}, dns_returns_vip={}, l7_proxy_http={}",
        .{
            modeLabel(modeFromFlags(flags)),
            flags.service_registry_v2,
            flags.service_registry_reconciler,
            flags.dns_returns_vip,
            flags.l7_proxy_http,
        },
    );
}

fn modeFromFlags(current_flags: Flags) Mode {
    if (current_flags.service_registry_v2 or current_flags.service_registry_reconciler) return .shadow;
    return .legacy;
}

fn modeLabel(current_mode: Mode) []const u8 {
    return switch (current_mode) {
        .legacy => "legacy",
        .shadow => "canonical",
    };
}

fn readDeprecatedAlwaysOnBoolEnv(name: []const u8, replacement: []const u8) bool {
    const raw = std.posix.getenv(name) orelse return true;
    _ = parseBool(name, raw);
    log.warn("service discovery compatibility flag {s} is deprecated and ignored; {s}", .{ name, replacement });
    return true;
}

fn readAlwaysOnBoolEnv(name: []const u8) bool {
    const raw = std.posix.getenv(name) orelse return true;
    _ = parseBool(name, raw);
    log.warn("service discovery compatibility flag {s} is deprecated and ignored; HTTP proxy routing is always on", .{name});
    return true;
}

fn parseBool(name: []const u8, raw: []const u8) bool {
    if (std.mem.eql(u8, raw, "1") or std.ascii.eqlIgnoreCase(raw, "true") or
        std.ascii.eqlIgnoreCase(raw, "yes") or std.ascii.eqlIgnoreCase(raw, "on"))
    {
        return true;
    }

    if (std.mem.eql(u8, raw, "0") or std.ascii.eqlIgnoreCase(raw, "false") or
        std.ascii.eqlIgnoreCase(raw, "no") or std.ascii.eqlIgnoreCase(raw, "off"))
    {
        return false;
    }

    log.warn("service discovery compatibility flag {s} has invalid value '{s}', defaulting to false", .{ name, raw });
    return false;
}

test "mode defaults to shadow" {
    resetForTest();
    try std.testing.expectEqual(Mode.shadow, mode());
}

test "mode becomes shadow when registry v2 is enabled" {
    setForTest(.{ .service_registry_v2 = true });
    defer resetForTest();

    try std.testing.expectEqual(Mode.shadow, mode());
}

test "mode becomes shadow when reconciler flag is enabled" {
    setForTest(.{ .service_registry_reconciler = true });
    defer resetForTest();

    try std.testing.expectEqual(Mode.shadow, mode());
}

test "mode stays legacy when only dns_returns_vip is enabled" {
    setForTest(.{ .dns_returns_vip = true });
    defer resetForTest();

    try std.testing.expectEqual(Mode.legacy, mode());
}

test "mode stays legacy when only l7_proxy_http is enabled" {
    setForTest(.{ .l7_proxy_http = true });
    defer resetForTest();

    try std.testing.expectEqual(Mode.legacy, mode());
}

test "setForTest overrides all rollout flags" {
    setForTest(.{
        .service_registry_v2 = true,
        .service_registry_reconciler = true,
        .dns_returns_vip = true,
        .l7_proxy_http = true,
    });
    defer resetForTest();

    const current_flags = current();
    try std.testing.expect(current_flags.service_registry_v2);
    try std.testing.expect(current_flags.service_registry_reconciler);
    try std.testing.expect(current_flags.dns_returns_vip);
    try std.testing.expect(current_flags.l7_proxy_http);
}

test "resetForTest clears overrides" {
    setForTest(.{ .service_registry_v2 = true, .dns_returns_vip = true });
    resetForTest();

    const current_flags = current();
    try std.testing.expect(current_flags.service_registry_v2);
    try std.testing.expect(current_flags.service_registry_reconciler);
    try std.testing.expect(current_flags.dns_returns_vip);
    try std.testing.expect(current_flags.l7_proxy_http);
}
