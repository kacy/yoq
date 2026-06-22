// mtls_metrics — global counters for service-to-service mtls handshakes.
//
// counts are split by side (client / server) and outcome (ok / failed) so
// /metrics dashboards can show both throughput and error rate. there is
// no per-service breakdown here — the per-service cert state lives in
// the cert_issuer snapshot (already surfaced as yoq_service_mtls_*).
// these counters cover what happens in the data plane after issuance.

const std = @import("std");

pub const Side = enum { client, server };
pub const Outcome = enum { ok, failed };

var lock: std.Io.Mutex = .init;
var counters: [4]u64 = .{ 0, 0, 0, 0 };

fn slot(side: Side, outcome: Outcome) usize {
    return @as(usize, @intFromEnum(side)) * 2 + @as(usize, @intFromEnum(outcome));
}

pub fn record(side: Side, outcome: Outcome) void {
    lock.lockUncancelable(std.Options.debug_io);
    defer lock.unlock(std.Options.debug_io);
    counters[slot(side, outcome)] += 1;
}

pub fn snapshot() [4]u64 {
    lock.lockUncancelable(std.Options.debug_io);
    defer lock.unlock(std.Options.debug_io);
    return counters;
}

pub fn resetForTest() void {
    lock.lockUncancelable(std.Options.debug_io);
    defer lock.unlock(std.Options.debug_io);
    counters = .{ 0, 0, 0, 0 };
}

test "record increments per side+outcome bucket independently" {
    resetForTest();
    defer resetForTest();

    record(.client, .ok);
    record(.client, .ok);
    record(.client, .failed);
    record(.server, .ok);

    const snap = snapshot();
    try std.testing.expectEqual(@as(u64, 2), snap[slot(.client, .ok)]);
    try std.testing.expectEqual(@as(u64, 1), snap[slot(.client, .failed)]);
    try std.testing.expectEqual(@as(u64, 1), snap[slot(.server, .ok)]);
    try std.testing.expectEqual(@as(u64, 0), snap[slot(.server, .failed)]);
}
