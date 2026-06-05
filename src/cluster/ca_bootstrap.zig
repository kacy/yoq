// ca_bootstrap — generate the cluster's mTLS CA once and distribute it via raft.
//
// runs in a small background thread after the raft node starts. when this node
// is elected leader and the cluster_ca row is still empty, generates a CA cert
// + key, encrypts the key with sha256(join_token) (so every node in the cluster
// can decrypt it without per-node key distribution), and proposes the row
// through raft so every follower receives it on the next apply.
//
// the thread exits as soon as either condition is met:
//   - the cluster_ca row exists (we or another leader bootstrapped it), or
//   - the timeout elapses (logged warning; /v1/cluster/ca will be empty until a
//     subsequent leadership change retries — caller can re-spawn).

const std = @import("std");
const cluster_node = @import("node.zig");
const x509_gen = @import("../tls/x509_gen.zig");
const csr = @import("../tls/csr.zig");
const store = @import("../state/store.zig");
const secrets = @import("../state/secrets.zig");
const log = @import("../lib/log.zig");

const max_attempts: u32 = 300; // 60s at 200ms cadence
const poll_interval_ms: u64 = 200;
const ca_validity_secs: i64 = 10 * 365 * 24 * 3600; // 10 years

const Ctx = struct {
    node: *cluster_node.Node,
    alloc: std.mem.Allocator,
    derived_key: [secrets.key_length]u8,
};

/// spawn the bootstrap thread. callable once at server startup; safe if the
/// cluster CA already exists (the thread will see the row and exit).
pub fn spawn(node: *cluster_node.Node, alloc: std.mem.Allocator, join_token: []const u8) void {
    const ctx = alloc.create(Ctx) catch {
        log.warn("ca bootstrap: failed to allocate context", .{});
        return;
    };
    ctx.* = .{
        .node = node,
        .alloc = alloc,
        .derived_key = deriveKey(join_token),
    };

    const thread = std.Thread.spawn(.{}, run, .{ctx}) catch |err| {
        log.warn("ca bootstrap: failed to spawn thread: {}", .{err});
        alloc.destroy(ctx);
        return;
    };
    thread.detach();
}

fn deriveKey(join_token: []const u8) [secrets.key_length]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(join_token, &digest, .{});
    return digest;
}

fn run(ctx: *Ctx) void {
    defer ctx.alloc.destroy(ctx);

    var attempt: u32 = 0;
    while (attempt < max_attempts) : (attempt += 1) {
        if (store.clusterCaExistsInDb(ctx.node.stateMachineDb())) return;
        if (ctx.node.isLeader()) {
            if (bootstrap(ctx)) |_| {
                return;
            } else |err| {
                log.warn("ca bootstrap: attempt {d} failed: {}", .{ attempt, err });
            }
        }
        std.Io.sleep(std.Options.debug_io, std.Io.Duration.fromMilliseconds(poll_interval_ms), .awake) catch return;
    }
    log.warn("ca bootstrap: timed out waiting for leader / quorum", .{});
}

fn bootstrap(ctx: *Ctx) !void {
    const now = std.Io.Clock.real.now(std.Options.debug_io).toSeconds();
    const not_after = now + ca_validity_secs;

    const ca = try x509_gen.generateCa(std.Options.debug_io, ctx.alloc, "yoq-cluster-ca", now, not_after);
    defer ctx.alloc.free(ca.cert_pem);

    // encrypt the CA private key with the join-token-derived key so any node in
    // the cluster can later decrypt and use it.
    var raw_key = ca.key_pair.secret_key.toBytes();
    defer std.crypto.secureZero(u8, &raw_key);
    var enc = try secrets.encrypt(ctx.alloc, &raw_key, ctx.derived_key);
    defer ctx.alloc.free(enc.ciphertext);

    const sql = try store.buildClusterCaInsertSql(
        ctx.alloc,
        ca.cert_pem,
        enc.ciphertext,
        &enc.nonce,
        &enc.tag,
        now,
        not_after,
    );
    defer ctx.alloc.free(sql);

    _ = ctx.node.propose(sql) catch |err| {
        // most likely we lost leadership between the check and the propose;
        // the caller loop will see the row on the next pass if a peer wins.
        return err;
    };
    log.info("ca bootstrap: cluster CA seeded (valid through unix {d})", .{not_after});
}
