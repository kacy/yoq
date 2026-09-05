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
const peer_identity = @import("../tls/peer_identity.zig");
const mtls_store = @import("../state/store/certificates_mtls.zig");
pub const identity_cluster_label = peer_identity.cluster_label;
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
    return tickAt(ctx, std.Io.Clock.real.now(std.Options.debug_io).toSeconds());
}

fn tickAt(ctx: *Ctx, now: i64) !void {
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

    var loaded = ca_access.load(ctx.alloc, ctx.join_token_owned) catch |err| {
        log.warn("cert issuer: failed to load CA: {}", .{err});
        return;
    };
    defer loaded.deinit(ctx.alloc);

    ensureProxyCert(ctx, &loaded, now) catch |err| {
        log.warn("cert issuer: ingress proxy: {}", .{err});
    };

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

fn ensureProxyCert(ctx: *Ctx, loaded: *ca_access.Loaded, now: i64) !void {
    if (try mtls_store.getProxy(ctx.alloc)) |rec| {
        defer rec.deinit(ctx.alloc);
        if (!shouldRotate(rec.created_at, rec.not_after, now)) return;
    }
    try issueIdentity(ctx, loaded, "ingress", peer_identity.proxy_identity, true, now);
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
    const identity = try peer_identity.service(ctx.alloc, service_name);
    defer ctx.alloc.free(identity);
    try issueIdentity(ctx, loaded, service_name, identity, false, now);
}

fn issueIdentity(ctx: *Ctx, loaded: *ca_access.Loaded, service_name: []const u8, identity: []const u8, proxy: bool, now: i64) !void {
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
    var derived = deriveKey(ctx.join_token_owned);
    defer std.crypto.secureZero(u8, &derived);
    var enc = try secrets.encrypt(ctx.alloc, &raw_key, derived);
    defer ctx.alloc.free(enc.ciphertext);

    const sql = if (proxy) try mtls_store.buildProxyUpsertSql(
        ctx.alloc,
        minted.cert_pem,
        enc.ciphertext,
        &enc.nonce,
        &enc.tag,
        not_after,
        now,
    ) else try store.buildMtlsCertUpsertSql(
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
    if (!proxy) clearFailureLocked(ctx.alloc, service_name);
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

test "proxy issuer lifecycle issues and rotates with no registered services" {
    const alloc = std.testing.allocator;
    const db_runtime = @import("state_machine/db_runtime.zig");
    const store_common = @import("../state/store/common.zig");
    const credentials = @import("../tls/proxy_credentials.zig");
    try store.initTestDb();
    defer store.deinitTestDb();
    rollout.setForTest(.{ .service_registry_v2 = true, .service_mtls = true });
    defer rollout.resetForTest();
    service_registry_runtime.resetForTest();
    defer service_registry_runtime.resetForTest();

    var node = try cluster_node.Node.initForTests(alloc, .{ .id = 1, .port = 0, .peers = &.{}, .data_dir = "/tmp" });
    defer node.deinit();
    node.raft.log = &node.log;
    node.raft.role = .leader;
    try std.testing.expect(node.log.setCurrentTerm(1));

    // The issuer checks the node DB but its store readers use the process DB.
    // Share the test connection so real Raft apply publishes what readers see.
    // Restore the node's owned connection before either owner closes its DB.
    const owned_db = node.state_machine.db;
    {
        var lease = try store_common.leaseDb();
        defer lease.deinit();
        try db_runtime.initMeta(lease.db);
        node.state_machine.db = lease.db.*;
    }
    defer node.state_machine.db = owned_db;

    const now: i64 = 1_700_000_000;
    const token = try alloc.dupe(u8, "issuer-lifecycle-token");
    defer {
        std.crypto.secureZero(u8, token);
        alloc.free(token);
    }
    var key = deriveKey(token);
    defer std.crypto.secureZero(u8, &key);
    const ca = try x509_gen.generateCa(std.testing.io, alloc, ca_common_name, now - 60, now + 7 * leaf_validity_secs);
    defer alloc.free(ca.cert_pem);
    var ca_secret = ca.key_pair.secret_key.toBytes();
    defer std.crypto.secureZero(u8, &ca_secret);
    const encrypted = try secrets.encrypt(alloc, &ca_secret, key);
    defer alloc.free(encrypted.ciphertext);
    const seed = try store.buildClusterCaInsertSql(alloc, ca.cert_pem, encrypted.ciphertext, &encrypted.nonce, &encrypted.tag, now, now + 7 * leaf_validity_secs);
    defer alloc.free(seed);
    try node.state_machine.db.execDynamic(seed, .{}, .{});
    var services = try service_registry_runtime.snapshotServices(alloc);
    defer {
        for (services.items) |entry| entry.deinit(alloc);
        services.deinit(alloc);
    }
    try std.testing.expectEqual(@as(usize, 0), services.items.len);
    try std.testing.expect((try mtls_store.getProxy(alloc)) == null);
    var ctx = Ctx{ .node = &node, .alloc = alloc, .join_token_owned = token };

    try tickAt(&ctx, now);
    const first_index = node.log.lastIndex();
    try std.testing.expectEqual(@as(u64, 1), first_index);
    node.state_machine.applyUpTo(&node.log, alloc, first_index);
    try std.testing.expectEqual(first_index, node.state_machine.last_applied);
    const first = try credentials.load(alloc, key, ca.cert_pem, now);
    defer first.deinit(alloc);
    const issued = (try mtls_store.getProxy(alloc)).?;
    defer issued.deinit(alloc);
    try std.testing.expectEqualStrings("proxy:ingress", issued.domain);
    try std.testing.expectEqual(now, issued.created_at);
    try std.testing.expectEqual(now + leaf_validity_secs, issued.not_after);

    const threshold = now + 16 * 3600;
    try tickAt(&ctx, threshold - 1);
    try std.testing.expectEqual(first_index, node.log.lastIndex());
    const unchanged = try credentials.load(alloc, key, ca.cert_pem, threshold - 1);
    defer unchanged.deinit(alloc);
    try std.testing.expectEqualStrings(first.cert_pem, unchanged.cert_pem);

    try tickAt(&ctx, threshold);
    const rotated_index = node.log.lastIndex();
    try std.testing.expectEqual(first_index + 1, rotated_index);
    node.state_machine.applyUpTo(&node.log, alloc, rotated_index);
    try std.testing.expectEqual(rotated_index, node.state_machine.last_applied);
    const rotated = try credentials.load(alloc, key, ca.cert_pem, threshold);
    defer rotated.deinit(alloc);
    try std.testing.expect(!std.mem.eql(u8, first.cert_pem, rotated.cert_pem));
    try std.testing.expect(!std.mem.eql(u8, first.key_pem, rotated.key_pem));
    const record = (try mtls_store.getProxy(alloc)).?;
    defer record.deinit(alloc);
    try std.testing.expectEqual(threshold, record.created_at);
    try std.testing.expectEqual(threshold + leaf_validity_secs, record.not_after);
}
