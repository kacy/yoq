// doctor_cluster — cluster-aware preflight checks for `yoq upgrade preflight`.
//
// the doctor CLI is short-lived and only reaches the local agent, so the agent
// aggregates per-node data (GET /cluster/peers/info). this module fetches that,
// plus bpf map headroom (GET /v1/status/bpf), and turns them into the same
// doctor.Check results the local checks use. the comparison logic is pure and
// unit-tested; run() wires it to the HTTP responses.

const std = @import("std");
const doctor = @import("doctor.zig");
const http_client = @import("../cluster/http_client.zig");
const json_helpers = @import("json_helpers.zig");

/// upper bound on nodes considered for skew (matches a reasonable cluster size).
pub const max_peers = 32;

/// per-node data gathered by the agent aggregator. `version` points into the
/// HTTP response body and is empty for an unreachable node.
pub const PeerInfo = struct {
    id: i64,
    version: []const u8,
    unix_ms: i64,
    reachable: bool,
};

pub const max_cluster_checks = 3;

pub const ClusterCheckResult = struct {
    checks: [max_cluster_checks]doctor.Check,
    count: usize,

    pub fn slice(self: *const ClusterCheckResult) []const doctor.Check {
        return self.checks[0..self.count];
    }

    pub fn hasFailures(self: *const ClusterCheckResult) bool {
        return doctor.checkSliceHasFailures(self.slice());
    }
};

/// flag version mismatch across reachable nodes. a single differing version is a
/// failure (a rolling upgrade should not be started mid-skew); unreachable nodes
/// downgrade an otherwise-clean result to a warning.
pub fn analyzeVersionSkew(peers: []const PeerInfo) doctor.Check {
    var first: ?[]const u8 = null;
    var mismatch = false;
    var reachable: usize = 0;
    var unreachable_count: usize = 0;

    for (peers) |peer| {
        if (!peer.reachable) {
            unreachable_count += 1;
            continue;
        }
        reachable += 1;
        if (first) |f| {
            if (!std.mem.eql(u8, f, peer.version)) mismatch = true;
        } else {
            first = peer.version;
        }
    }

    if (reachable == 0) return doctor.makeCheck("version-skew", .warn, "no reachable nodes");

    var buf: [128]u8 = undefined;
    if (mismatch) {
        const msg = std.fmt.bufPrint(&buf, "version mismatch across {d} reachable nodes", .{reachable}) catch "version mismatch";
        return doctor.makeCheck("version-skew", .fail, msg);
    }
    if (unreachable_count > 0) {
        const msg = std.fmt.bufPrint(&buf, "{d} nodes on {s}, {d} unreachable", .{ reachable, first.?, unreachable_count }) catch "ok";
        return doctor.makeCheck("version-skew", .warn, msg);
    }
    const msg = std.fmt.bufPrint(&buf, "all {d} nodes on {s}", .{ reachable, first.? }) catch "ok";
    return doctor.makeCheck("version-skew", .pass, msg);
}

/// flag wall-clock drift across reachable nodes, measured against a reference
/// clock (the local node's). this is rtt-naive: peers are sampled sequentially,
/// so the thresholds are deliberately loose (warn > 1s, fail > 5s).
pub fn analyzeClockSkew(peers: []const PeerInfo, reference_unix_ms: i64) doctor.Check {
    var max_drift: i64 = 0;
    var reachable: usize = 0;

    for (peers) |peer| {
        if (!peer.reachable) continue;
        reachable += 1;
        const drift = if (peer.unix_ms >= reference_unix_ms)
            peer.unix_ms - reference_unix_ms
        else
            reference_unix_ms - peer.unix_ms;
        if (drift > max_drift) max_drift = drift;
    }

    if (reachable == 0) return doctor.makeCheck("clock-skew", .warn, "no reachable nodes");

    var buf: [128]u8 = undefined;
    if (max_drift > 5000) {
        const msg = std.fmt.bufPrint(&buf, "max clock drift {d} ms (> 5s; rtt-naive)", .{max_drift}) catch "high clock drift";
        return doctor.makeCheck("clock-skew", .fail, msg);
    }
    if (max_drift > 1000) {
        const msg = std.fmt.bufPrint(&buf, "max clock drift {d} ms (> 1s; rtt-naive)", .{max_drift}) catch "clock drift";
        return doctor.makeCheck("clock-skew", .warn, msg);
    }
    const msg = std.fmt.bufPrint(&buf, "max clock drift {d} ms", .{max_drift}) catch "ok";
    return doctor.makeCheck("clock-skew", .pass, msg);
}

/// run cluster preflight against the local agent at ip:port. version- and
/// clock-skew come from /cluster/peers/info; bpf headroom from /v1/status/bpf.
pub fn run(alloc: std.mem.Allocator, ip: [4]u8, port: u16, token: ?[]const u8) ClusterCheckResult {
    var result = ClusterCheckResult{ .checks = undefined, .count = 0 };

    var resp = http_client.getWithAuth(alloc, ip, port, "/cluster/peers/info", token) catch {
        result.checks[0] = doctor.makeCheck("cluster", .fail, "could not reach local agent at /cluster/peers/info");
        result.count = 1;
        return result;
    };
    defer resp.deinit(alloc);

    var peers: [max_peers]PeerInfo = undefined;
    var n: usize = 0;
    var it = json_helpers.extractJsonObjects(resp.body);
    while (it.next()) |obj| {
        if (n >= max_peers) break;
        peers[n] = .{
            .id = json_helpers.extractJsonInt(obj, "id") orelse 0,
            .version = json_helpers.extractJsonString(obj, "software_version") orelse "",
            .unix_ms = json_helpers.extractJsonInt(obj, "unix_ms") orelse 0,
            .reachable = (json_helpers.extractJsonInt(obj, "reachable") orelse 0) == 1,
        };
        n += 1;
    }
    const list = peers[0..n];
    // the first entry is the local node, whose clock is the reference.
    const reference = if (n > 0) list[0].unix_ms else 0;

    result.checks[result.count] = analyzeVersionSkew(list);
    result.count += 1;
    result.checks[result.count] = analyzeClockSkew(list, reference);
    result.count += 1;
    result.checks[result.count] = bpfHeadroomCheck(alloc, ip, port, token);
    result.count += 1;

    return result;
}

/// summarize bpf map headroom into a single check. best-effort: a missing or
/// empty endpoint is treated as "no maps loaded" rather than a failure.
fn bpfHeadroomCheck(alloc: std.mem.Allocator, ip: [4]u8, port: u16, token: ?[]const u8) doctor.Check {
    var resp = http_client.getWithAuth(alloc, ip, port, "/v1/status/bpf", token) catch
        return doctor.makeCheck("bpf-headroom", .warn, "could not reach /v1/status/bpf");
    defer resp.deinit(alloc);

    var max_pct: i64 = 0;
    var fullest: []const u8 = "";
    var any = false;
    var it = json_helpers.extractJsonObjects(resp.body);
    while (it.next()) |obj| {
        any = true;
        const pct = json_helpers.extractJsonInt(obj, "pct") orelse 0;
        if (pct > max_pct) {
            max_pct = pct;
            fullest = json_helpers.extractJsonString(obj, "name") orelse "";
        }
    }

    if (!any) return doctor.makeCheck("bpf-headroom", .pass, "no bpf maps loaded");

    var buf: [128]u8 = undefined;
    if (max_pct >= 95) {
        const msg = std.fmt.bufPrint(&buf, "{s} at {d}% (>= 95%)", .{ fullest, max_pct }) catch "map nearly full";
        return doctor.makeCheck("bpf-headroom", .fail, msg);
    }
    if (max_pct >= 80) {
        const msg = std.fmt.bufPrint(&buf, "{s} at {d}% (>= 80%)", .{ fullest, max_pct }) catch "map filling";
        return doctor.makeCheck("bpf-headroom", .warn, msg);
    }
    const msg = std.fmt.bufPrint(&buf, "fullest map {s} at {d}%", .{ fullest, max_pct }) catch "ok";
    return doctor.makeCheck("bpf-headroom", .pass, msg);
}

// -- tests --

test "analyzeVersionSkew passes when all reachable nodes match" {
    const peers = [_]PeerInfo{
        .{ .id = 1, .version = "0.2.0", .unix_ms = 0, .reachable = true },
        .{ .id = 2, .version = "0.2.0", .unix_ms = 0, .reachable = true },
    };
    try std.testing.expectEqual(doctor.CheckStatus.pass, analyzeVersionSkew(&peers).status);
}

test "analyzeVersionSkew fails on a version mismatch" {
    const peers = [_]PeerInfo{
        .{ .id = 1, .version = "0.2.0", .unix_ms = 0, .reachable = true },
        .{ .id = 2, .version = "0.3.0", .unix_ms = 0, .reachable = true },
    };
    try std.testing.expectEqual(doctor.CheckStatus.fail, analyzeVersionSkew(&peers).status);
}

test "analyzeVersionSkew warns when a node is unreachable" {
    const peers = [_]PeerInfo{
        .{ .id = 1, .version = "0.2.0", .unix_ms = 0, .reachable = true },
        .{ .id = 2, .version = "", .unix_ms = 0, .reachable = false },
    };
    try std.testing.expectEqual(doctor.CheckStatus.warn, analyzeVersionSkew(&peers).status);
}

test "analyzeClockSkew grades drift against the reference" {
    const synced = [_]PeerInfo{
        .{ .id = 1, .version = "", .unix_ms = 1000, .reachable = true },
        .{ .id = 2, .version = "", .unix_ms = 1200, .reachable = true },
    };
    try std.testing.expectEqual(doctor.CheckStatus.pass, analyzeClockSkew(&synced, 1000).status);

    const drifting = [_]PeerInfo{
        .{ .id = 1, .version = "", .unix_ms = 1000, .reachable = true },
        .{ .id = 2, .version = "", .unix_ms = 3500, .reachable = true },
    };
    try std.testing.expectEqual(doctor.CheckStatus.warn, analyzeClockSkew(&drifting, 1000).status);

    const skewed = [_]PeerInfo{
        .{ .id = 1, .version = "", .unix_ms = 1000, .reachable = true },
        .{ .id = 2, .version = "", .unix_ms = 12000, .reachable = true },
    };
    try std.testing.expectEqual(doctor.CheckStatus.fail, analyzeClockSkew(&skewed, 1000).status);
}
