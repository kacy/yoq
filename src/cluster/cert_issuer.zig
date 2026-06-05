// cert_issuer — leader-only background loop that issues + rotates per-service
// mTLS leaf certs once `service_mtls` is opted into.
//
// every tick (60s):
//   - bail if this node is not the leader (followers see new certs via raft
//     when the leader proposes them)
//   - bail if the cluster CA hasn't been bootstrapped yet
//   - snapshot the service registry
//   - for each service: if there's no mtls cert OR the existing one is past
//     the rotation watermark (less than 1/3 of its TTL remaining), mint a
//     fresh leaf and propose it through raft
//
// failures are tracked per-service so /metrics can surface them. an issuance
// failure for one service never stops the loop or affects siblings; the
// service is marked degraded so the existing /v1/status surface picks it up.
//
// design notes:
//   - this loop is intentionally separate from service_reconciler.zig:
//     reconciliation runs on every node, but issuance must be leader-only,
//     and mixing the two would litter the reconciler with `if (isLeader())`
//     branches.
//   - issuance is idempotent at the raft layer (upsert by domain), so a
//     duplicate proposal across overlapping leader terms is harmless.

const std = @import("std");
const cluster_node = @import("node.zig");
const ca_access = @import("ca_access.zig");
const x509_gen = @import("../tls/x509_gen.zig");
const store = @import("../state/store.zig");
const secrets = @import("../state/secrets.zig");
const rollout = @import("../network/service_rollout.zig");
const service_registry_runtime = @import("../network/service_registry_runtime.zig");
const service_reconciler = @import("../network/service_reconciler.zig");
const log = @import("../lib/log.zig");

pub const tick_interval_secs: u64 = 60;
pub const leaf_validity_secs: i64 = 24 * 60 * 60; // 24h leaf TTL
/// rotate when less than this fraction of the TTL remains. with a 24h TTL
/// this means we issue a new leaf around the 16h mark, leaving ~8h of
/// headroom for raft replication + reconciliation on every follower.
pub const rotation_fraction_remaining: f64 = 1.0 / 3.0;
pub const identity_cluster_label = "yoq-cluster";
pub const ca_common_name = "yoq-cluster-ca";

/// per-service failure counters; reset only on success. snapshotted by the
/// metrics route. small enough that an ArrayList is the simplest thing.
const FailureEntry = struct {
    service_name: []u8,
    count: u64,
};

const State = struct {
    mutex: std.Io.Mutex = .init,
    failures: std.ArrayList(FailureEntry) = .empty,
};

var state: State = .{};

const Ctx = struct {
    node: *cluster_node.Node,
    alloc: std.mem.Allocator,
    join_token_owned: []u8,
    running: bool = true,
};

/// spawn the leader-only issuer loop. callable once at server startup.
/// safe if `service_mtls` is off (the tick body returns early).
pub fn spawn(node: *cluster_node.Node, alloc: std.mem.Allocator, join_token: []const u8) void {
    const token_copy = alloc.dupe(u8, join_token) catch {
        log.warn("cert issuer: failed to copy join token", .{});
        return;
    };

    const ctx = alloc.create(Ctx) catch {
        alloc.free(token_copy);
        log.warn("cert issuer: failed to allocate context", .{});
        return;
    };
    ctx.* = .{ .node = node, .alloc = alloc, .join_token_owned = token_copy };

    const thread = std.Thread.spawn(.{}, run, .{ctx}) catch |err| {
        log.warn("cert issuer: failed to spawn thread: {}", .{err});
        alloc.free(token_copy);
        alloc.destroy(ctx);
        return;
    };
    thread.detach();
}

fn run(ctx: *Ctx) void {
    defer {
        std.crypto.secureZero(u8, ctx.join_token_owned);
        ctx.alloc.free(ctx.join_token_owned);
        ctx.alloc.destroy(ctx);
    }

    while (ctx.running) {
        tick(ctx) catch |err| {
            log.warn("cert issuer: tick failed: {}", .{err});
        };
        std.Io.sleep(
            std.Options.debug_io,
            std.Io.Duration.fromMilliseconds(tick_interval_secs * 1000),
            .awake,
        ) catch return;
    }
}

fn tick(ctx: *Ctx) !void {
    if (!rollout.current().service_mtls) return;
    if (!ctx.node.isLeader()) return;
    if (!store.clusterCaExistsInDb(ctx.node.stateMachineDb())) return;

    var services = service_registry_runtime.snapshotServices(ctx.alloc) catch |err| {
        log.warn("cert issuer: failed to snapshot services: {}", .{err});
        return;
    };
    defer {
        for (services.items) |service| service.deinit(ctx.alloc);
        services.deinit(ctx.alloc);
    }

    if (services.items.len == 0) return;

    var loaded = ca_access.load(ctx.alloc, ctx.join_token_owned) catch |err| {
        log.warn("cert issuer: failed to load CA: {}", .{err});
        return;
    };
    defer loaded.deinit(ctx.alloc);

    const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();

    for (services.items) |service| {
        ensureCertForService(ctx, &loaded, service.service_name, now) catch |err| {
            log.warn("cert issuer: {s}: {}", .{ service.service_name, err });
            recordFailureLocked(ctx.alloc, service.service_name);
            service_reconciler.markDegraded(service.service_name);
        };
    }
}

fn ensureCertForService(ctx: *Ctx, loaded: *ca_access.Loaded, service_name: []const u8, now: i64) !void {
    const existing = try store.getMtlsCert(ctx.alloc, service_name);
    if (existing) |rec| {
        defer rec.deinit(ctx.alloc);
        if (!shouldRotate(rec.created_at, rec.not_after, now)) return;
    }

    try issueAndPropose(ctx, loaded, service_name, now);
}

/// decide whether a cert with the given lifetime needs rotation now.
/// `created_at` and `not_after` are unix seconds; `now` is the current
/// wall-clock second. exported for tests.
pub fn shouldRotate(created_at: i64, not_after: i64, now: i64) bool {
    if (now >= not_after) return true; // already expired
    const ttl = not_after - created_at;
    if (ttl <= 0) return true; // pathological row; rotate to repair
    const remaining = not_after - now;
    const watermark_f = @as(f64, @floatFromInt(ttl)) * rotation_fraction_remaining;
    const watermark: i64 = @intFromFloat(watermark_f);
    return remaining <= watermark;
}

fn issueAndPropose(ctx: *Ctx, loaded: *ca_access.Loaded, service_name: []const u8, now: i64) !void {
    const identity = try std.fmt.allocPrint(
        ctx.alloc,
        "spiffe://{s}/service/{s}",
        .{ identity_cluster_label, service_name },
    );
    defer ctx.alloc.free(identity);

    const not_after = now + leaf_validity_secs;
    var minted = try x509_gen.issueLeaf(
        std.Options.debug_io,
        ctx.alloc,
        loaded.key_pair,
        ca_common_name,
        service_name,
        identity,
        now,
        not_after,
    );
    defer ctx.alloc.free(minted.cert_pem);

    // encrypt the leaf key with the same join-token-derived key the CA
    // uses, so any node decrypts identically when reading the row back.
    var raw_key = minted.key_pair.secret_key.toBytes();
    defer std.crypto.secureZero(u8, &raw_key);
    const derived = deriveKey(ctx.join_token_owned);
    var enc = try secrets.encrypt(ctx.alloc, &raw_key, derived);
    defer ctx.alloc.free(enc.ciphertext);

    const sql = try store.buildMtlsCertUpsertSql(
        ctx.alloc,
        service_name,
        minted.cert_pem,
        enc.ciphertext,
        &enc.nonce,
        &enc.tag,
        not_after,
        now,
    );
    defer ctx.alloc.free(sql);

    _ = try ctx.node.propose(sql);
    clearFailureLocked(ctx.alloc, service_name);
    log.info("cert issuer: issued mtls leaf for {s} (valid through unix {d})", .{ service_name, not_after });
}

fn deriveKey(join_token: []const u8) [secrets.key_length]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(join_token, &digest, .{});
    return digest;
}

fn recordFailureLocked(alloc: std.mem.Allocator, service_name: []const u8) void {
    state.mutex.lockUncancelable(std.Options.debug_io);
    defer state.mutex.unlock(std.Options.debug_io);

    for (state.failures.items) |*entry| {
        if (std.mem.eql(u8, entry.service_name, service_name)) {
            entry.count += 1;
            return;
        }
    }
    const name = alloc.dupe(u8, service_name) catch return;
    state.failures.append(alloc, .{ .service_name = name, .count = 1 }) catch alloc.free(name);
}

fn clearFailureLocked(alloc: std.mem.Allocator, service_name: []const u8) void {
    state.mutex.lockUncancelable(std.Options.debug_io);
    defer state.mutex.unlock(std.Options.debug_io);

    var i: usize = 0;
    while (i < state.failures.items.len) : (i += 1) {
        if (std.mem.eql(u8, state.failures.items[i].service_name, service_name)) {
            const entry = state.failures.orderedRemove(i);
            alloc.free(entry.service_name);
            return;
        }
    }
}

/// snapshot of (service_name, failure_count) pairs for the metrics route.
/// caller owns the returned list — call deinit on each name + the list.
pub const FailureSnapshot = struct {
    service_name: []u8,
    count: u64,
};

pub fn snapshotFailures(alloc: std.mem.Allocator) !std.ArrayList(FailureSnapshot) {
    state.mutex.lockUncancelable(std.Options.debug_io);
    defer state.mutex.unlock(std.Options.debug_io);

    var out: std.ArrayList(FailureSnapshot) = .empty;
    errdefer {
        for (out.items) |entry| alloc.free(entry.service_name);
        out.deinit(alloc);
    }
    for (state.failures.items) |entry| {
        const name = try alloc.dupe(u8, entry.service_name);
        try out.append(alloc, .{ .service_name = name, .count = entry.count });
    }
    return out;
}

pub fn resetForTest(alloc: std.mem.Allocator) void {
    state.mutex.lockUncancelable(std.Options.debug_io);
    defer state.mutex.unlock(std.Options.debug_io);
    for (state.failures.items) |entry| alloc.free(entry.service_name);
    state.failures.deinit(alloc);
    state.failures = .empty;
}

test "shouldRotate truth table" {
    // fresh cert (just issued): no rotation.
    try std.testing.expect(!shouldRotate(1000, 1000 + 24 * 3600, 1000));
    // halfway through: still > 1/3 remaining.
    try std.testing.expect(!shouldRotate(1000, 1000 + 24 * 3600, 1000 + 12 * 3600));
    // 2/3 in: exactly at the 1/3-remaining watermark — rotate.
    try std.testing.expect(shouldRotate(1000, 1000 + 24 * 3600, 1000 + 16 * 3600));
    // expired: rotate.
    try std.testing.expect(shouldRotate(1000, 1100, 2000));
    // pathological zero-ttl row: rotate (treat as broken, replace).
    try std.testing.expect(shouldRotate(1000, 1000, 999));
}

test "failure counter increments and clears" {
    const alloc = std.testing.allocator;
    resetForTest(alloc);
    defer resetForTest(alloc);

    recordFailureLocked(alloc, "billing");
    recordFailureLocked(alloc, "billing");
    recordFailureLocked(alloc, "checkout");

    var snap = try snapshotFailures(alloc);
    defer {
        for (snap.items) |entry| alloc.free(entry.service_name);
        snap.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 2), snap.items.len);

    // counts are not order-guaranteed; find each.
    var billing_count: u64 = 0;
    var checkout_count: u64 = 0;
    for (snap.items) |entry| {
        if (std.mem.eql(u8, entry.service_name, "billing")) billing_count = entry.count;
        if (std.mem.eql(u8, entry.service_name, "checkout")) checkout_count = entry.count;
    }
    try std.testing.expectEqual(@as(u64, 2), billing_count);
    try std.testing.expectEqual(@as(u64, 1), checkout_count);

    clearFailureLocked(alloc, "billing");
    var snap2 = try snapshotFailures(alloc);
    defer {
        for (snap2.items) |entry| alloc.free(entry.service_name);
        snap2.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 1), snap2.items.len);
    try std.testing.expectEqualStrings("checkout", snap2.items[0].service_name);
}
