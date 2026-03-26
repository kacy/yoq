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

pub fn mode() Mode {
    const current_flags = current();
    if (current_flags.service_registry_v2 or current_flags.service_registry_reconciler) return .shadow;
    return .legacy;
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
        .service_registry_v2 = readBoolEnv("YOQ_SERVICE_REGISTRY_V2"),
        .service_registry_reconciler = readBoolEnv("YOQ_SERVICE_REGISTRY_RECONCILER"),
        .dns_returns_vip = readBoolEnv("YOQ_DNS_RETURNS_VIP"),
        .l7_proxy_http = readBoolEnv("YOQ_L7_PROXY_HTTP"),
    };
    flags_initialized = true;
    logRolloutStateLocked();
}

fn logRolloutStateLocked() void {
    if (logged_rollout_state) return;
    logged_rollout_state = true;

    if (!flags.service_registry_v2 and
        !flags.service_registry_reconciler and
        !flags.dns_returns_vip and
        !flags.l7_proxy_http)
    {
        return;
    }

    log.info(
        "service rollout flags: registry_v2={}, reconciler={}, dns_returns_vip={}, l7_proxy_http={}",
        .{
            flags.service_registry_v2,
            flags.service_registry_reconciler,
            flags.dns_returns_vip,
            flags.l7_proxy_http,
        },
    );
}

fn readBoolEnv(name: []const u8) bool {
    const raw = std.posix.getenv(name) orelse return false;
    return parseBool(name, raw);
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

    log.warn("service rollout flag {s} has invalid value '{s}', defaulting to false", .{ name, raw });
    return false;
}

test "mode defaults to legacy" {
    resetForTest();
    try std.testing.expectEqual(Mode.legacy, mode());
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
    try std.testing.expect(!current_flags.service_registry_v2);
    try std.testing.expect(!current_flags.service_registry_reconciler);
    try std.testing.expect(!current_flags.dns_returns_vip);
    try std.testing.expect(!current_flags.l7_proxy_http);
}

